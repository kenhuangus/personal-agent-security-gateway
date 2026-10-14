"""OPA sidecar client (ontology -> intent -> OPEN POLICY).

Supervised ``opa run --server`` process management plus a keep-alive
decision client. The sidecar is STATELESS: every input document carries
the rules, the intent, and the ontology snapshot, so a restart loses
nothing and no per-version data sync is needed.

Two modes:
- Sidecar (default): launches and supervises ``opa run --server`` as a
  child process (UDS transport default, TCP fallback).
- External (``GATEWAY_OPA_URL`` set, e.g. ``http://opa:8181``): no
  subprocess is launched; decisions go to the given OPA server over
  HTTP. This is how deployments run OPA (separate container/service).

Transports: TCP keep-alive (127.0.0.1) or Unix-domain socket. The UDS
transport is the default: the spike measured ~2.3 ms of the sidecar
p50 in OPA's HTTP layer, and the UDS path avoids TCP loopback
overhead (see ``benchmark_transport`` and docs/build-log.md).

Fail-closed (03 §7): ANY sidecar failure — unreachable, timeout,
non-2xx, malformed decision — raises :class:`OpaUnavailable`. The
policy engine catches it and denies (the pinned default-deny), never
passes through. The external mode keeps the identical contract: the
Rego decision contract is unchanged (policy decides; this client only
transports).
"""

from __future__ import annotations

import hashlib
import http.client
import json
import logging
import os
import socket
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Optional

import httpx

log = logging.getLogger(__name__)

#: Pinned OPA release (spike-verified; checksum in third_party/opa/SHA256SUMS).
#: Single source of truth: third_party/opa/OPA_VERSION (also consumed by
#: scripts/verify_opa.sh and docker-compose.yml). Falls back to the
#: last-known version when the file is absent (installed package).
def _read_opa_version() -> str:
    try:
        return (
            Path(__file__).resolve().parent.parent.parent
            / "third_party"
            / "opa"
            / "OPA_VERSION"
        ).read_text(encoding="utf-8").strip()
    except OSError:
        return "1.8.0"


OPA_VERSION = _read_opa_version()

#: Decision endpoint (the contract in policies/v1/authz.rego).
DECISION_PATH = "/v1/data/gateway/authz/decision"

#: Bundle-identity endpoint. The pinned bundle ships
#: policies/v1/bundle_info.json (written by
#: scripts/pin_bundle_fingerprint.py); OPA serves it as
#: data.gateway.bundle.info.
BUNDLE_INFO_PATH = "/v1/data/gateway/bundle/info"

#: Name of the fingerprint file inside the bundle (excluded from the
#: fingerprint itself — it carries the fingerprint).
BUNDLE_INFO_NAME = "bundle_info.json"

#: Effects the sidecar may return.
EFFECTS: tuple[str, ...] = ("allow", "deny", "ask")


class OpaError(Exception):
    """Base OPA client error."""


class OpaUnavailable(OpaError):
    """The sidecar cannot serve a decision: fail closed (deny)."""


def resolve_binary(explicit: Optional[str] = None) -> Path:
    """Locate the pinned OPA binary.

    Precedence: explicit path > ``GATEWAY_OPA_BIN`` env >
    ``<repo>/third_party/opa/opa`` > ``~/workspace/opa-spike-bin/opa``
    (the spike's checksum-verified copy). Raises OpaUnavailable when
    nothing usable is found.
    """
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    env = os.environ.get("GATEWAY_OPA_BIN")
    if env:
        candidates.append(Path(env))
    # <repo>/third_party/opa/opa (this file: src/gateway/opa_client.py).
    candidates.append(
        Path(__file__).resolve().parent.parent.parent / "third_party" / "opa" / "opa"
    )
    candidates.append(Path.home() / "workspace" / "opa-spike-bin" / "opa")
    for cand in candidates:
        if cand.is_file() and os.access(cand, os.X_OK):
            return cand
    raise OpaUnavailable(
        "no executable OPA binary found (checked explicit path, "
        "GATEWAY_OPA_BIN, third_party/opa/opa, ~/workspace/opa-spike-bin/opa)"
    )


def default_policies_dir() -> Path:
    """The versioned Rego policy directory served by the sidecar."""
    return Path(__file__).resolve().parent / "policies" / "v1"


def bundle_fingerprint(policies_dir: Optional[Path] = None) -> str:
    """Content fingerprint (hex SHA-256) of the pinned policy bundle.

    Covers every file under policies/v1 (sorted by relative path),
    EXCEPT bundle_info.json itself — that file carries the fingerprint
    (written by scripts/pin_bundle_fingerprint.py), so hashing it
    would be circular. Deterministic across checkouts: same bundle →
    same fingerprint.
    """
    root = Path(policies_dir) if policies_dir is not None else default_policies_dir()
    digest = hashlib.sha256()
    files = sorted(
        (p for p in root.rglob("*") if p.is_file() and p.name != BUNDLE_INFO_NAME),
        key=lambda p: p.relative_to(root).as_posix(),
    )
    for path in files:
        rel = path.relative_to(root).as_posix()
        digest.update(rel.encode("utf-8") + b"\x00")
        digest.update(path.read_bytes())
        digest.update(b"\x00")
    return digest.hexdigest()


class _UnixHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection over a Unix-domain socket (for opa --addr unix://...)."""

    def __init__(self, socket_path: str, timeout: Optional[float] = None) -> None:
        super().__init__("localhost", timeout=timeout)
        self._socket_path = socket_path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if self.timeout is not None:
            self.sock.settimeout(self.timeout)
        self.sock.connect(self._socket_path)


class OpaClient:
    """Supervised OPA sidecar + keep-alive decision client.

    ``start()`` launches ``opa run --server`` (idempotent); ``stop()``
    terminates it. ``decide(input_doc)`` POSTs the versioned input
    document and returns the decision object
    (``{"effect", "rule", ...}``). Any failure raises OpaUnavailable.

    External mode: pass ``external_url`` (or set ``GATEWAY_OPA_URL``).
    No subprocess is launched and no binary is needed; ``start()``
    becomes a readiness probe against the URL and ``decide()`` POSTs
    to it. Fail-closed semantics are identical.
    """

    def __init__(
        self,
        *,
        binary: Optional[str] = None,
        policies_dir: Optional[str] = None,
        host: str = "127.0.0.1",
        port: int = 8181,
        unix_socket: Optional[str] = None,
        startup_timeout: float = 20.0,
        request_timeout: float = 5.0,
        external_url: Optional[str] = None,
    ) -> None:
        env_url = os.environ.get("GATEWAY_OPA_URL")
        self.external_url: Optional[str] = (
            external_url if external_url is not None else env_url
        ) or None
        if self.external_url:
            self.external_url = self.external_url.rstrip("/")
        #: True when talking to an external OPA server (no sidecar).
        self._external = self.external_url is not None
        self._external_up = False
        if self._external:
            # No binary, no socket: the server is someone else's
            # responsibility (the compose ``opa`` service). Binary
            # resolution is skipped so a missing vendored binary is not
            # an error in this mode.
            self.binary: Optional[Path] = None
            self.policies_dir = (
                Path(policies_dir) if policies_dir else default_policies_dir()
            )
            self.unix_socket: Optional[str] = None
        else:
            self.binary = resolve_binary(binary)
            self.policies_dir = (
                Path(policies_dir) if policies_dir else default_policies_dir()
            )
            # UDS is the default transport (measured faster; see build log).
            # An explicit unix_socket=None + host/port keeps TCP available.
            self._want_uds = unix_socket != ""
            if unix_socket is None and self._want_uds:
                self.unix_socket = str(
                    Path(tempfile.gettempdir())
                    / f"gateway-opa-{os.getpid()}-{uuid.uuid4().hex[:8]}.sock"
                )
            else:
                self.unix_socket = unix_socket
        self.host = host
        self.port = port
        self.startup_timeout = startup_timeout
        self.request_timeout = request_timeout
        self._proc: Optional[subprocess.Popen] = None
        self._lock = threading.Lock()
        self._http: Optional[httpx.Client] = None
        # GH #17: external-bundle verification state. _bundle_ok flips
        # False when the periodic re-check fails; decide() refuses to
        # serve then (fail closed) until the bundle verifies again.
        self._bundle_ok = True
        self._bundle_watchdog: Optional[threading.Thread] = None
        self._bundle_check_seconds = float(
            os.environ.get("GATEWAY_OPA_BUNDLE_CHECK_SECONDS", "300") or 0
        )

    # -- lifecycle ----------------------------------------------------

    @property
    def transport(self) -> str:
        return "uds" if self.unix_socket else "tcp"

    @property
    def running(self) -> bool:
        if self._external:
            return self._external_up
        return self._proc is not None and self._proc.poll() is None

    def start(self) -> None:
        """Launch the sidecar (idempotent). Raises OpaUnavailable.

        External mode: no subprocess — readiness-probe the URL instead.
        """
        with self._lock:
            if self._external:
                if self._external_up:
                    return
                self._start_external_locked()
                return
            if self.running:
                return
            if self.unix_socket:
                # A stale socket from a crashed run blocks bind: remove it.
                try:
                    Path(self.unix_socket).unlink(missing_ok=True)
                except OSError:  # noqa: BLE001
                    pass
            addr = (
                f"unix://{self.unix_socket}"
                if self.unix_socket
                else f"{self.host}:{self.port}"
            )
            cmd = [
                str(self.binary), "run", "--server",
                "--addr", addr,
                "--log-level", "error",
                str(self.policies_dir),
            ]
            log.info("starting OPA sidecar: %s (transport=%s)", addr, self.transport)
            try:
                self._proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.DEVNULL,
                )
            except OSError as exc:
                raise OpaUnavailable(f"cannot launch OPA sidecar: {exc}") from exc
            try:
                self._wait_ready()
            except Exception:
                self._terminate_locked()
                raise
            if self.unix_socket:
                self._http = None  # UDS uses http.client per call
            else:
                self._http = httpx.Client(
                    base_url=f"http://{self.host}:{self.port}",
                    timeout=self.request_timeout,
                    # Sidecar traffic is always local: never route it
                    # through an egress proxy (and this runtime's proxy
                    # env breaks httpx URL parsing outright).
                    trust_env=False,
                )

    def _start_external_locked(self) -> None:
        """Readiness probe for external mode (caller holds the lock).

        No subprocess is launched. On success a keep-alive client is
        created; on timeout raises OpaUnavailable (fail-closed). After
        the first success, per-decide liveness is the POST itself: any
        transport failure in decide() raises OpaUnavailable and the
        policy engine denies.

        GH #17: the pinned bundle is verified BEFORE the client is
        marked up — a misconfigured URL, a stale bundle after a bad
        rollout, or a redirected endpoint must not silently enforce the
        wrong policy. A periodic watchdog re-verifies afterwards.
        """
        url = self.external_url
        assert url is not None
        if not (url.startswith("http://") or url.startswith("https://")):
            raise OpaUnavailable(
                f"GATEWAY_OPA_URL must be an http(s) URL, got {url!r}"[:160]
            )
        log.info("using external OPA at %s (no sidecar subprocess)", url)
        deadline = time.monotonic() + self.startup_timeout
        last: Optional[str] = None
        # Sidecar traffic is always cluster-local: never route it
        # through an egress proxy (trust_env=False), same as the
        # sidecar path.
        with httpx.Client(timeout=2, trust_env=False) as probe:
            while time.monotonic() < deadline:
                try:
                    r = probe.get(f"{url}/health")
                    if 200 <= r.status_code < 300:
                        self._http = httpx.Client(
                            base_url=url,
                            timeout=self.request_timeout,
                            trust_env=False,
                        )
                        self._external_up = True
                        break
                    last = f"HTTP {r.status_code}"
                except Exception as exc:  # noqa: BLE001 — not ready yet
                    last = str(exc)[:200]
                time.sleep(0.5)
            else:
                raise OpaUnavailable(
                    f"external OPA at {url} not ready after "
                    f"{self.startup_timeout}s: {last}"
                )
        # GH #17: verify the pinned bundle before serving decisions.
        # A verification failure must not leave the client marked up:
        # reset _external_up so running/decide() stay fail-closed.
        try:
            self.verify_external_bundle()
        except OpaUnavailable:
            self._external_up = False
            if self._http is not None:
                try:
                    self._http.close()
                except Exception:  # noqa: BLE001 — best-effort
                    pass
                self._http = None
            raise
        self._start_bundle_watchdog_locked()

    @property
    def bundle_ok(self) -> bool:
        """Whether the external bundle last verified (GH #17).

        Always True in sidecar mode (the sidecar serves the local
        pinned bundle itself).
        """
        return self._bundle_ok

    def verify_external_bundle(self) -> str:
        """Verify the external OPA serves the pinned policy bundle.

        Fetches ``data.gateway.bundle.info`` from the external server
        and compares its fingerprint against the local policies/v1
        content fingerprint. Returns the verified fingerprint.

        Raises OpaUnavailable on any mismatch, missing document, or
        transport failure — the caller fails closed (deny), never
        serves decisions from an unverified bundle.
        """
        if not self._external:
            return bundle_fingerprint(self.policies_dir)
        url = self.external_url
        assert url is not None
        expected = bundle_fingerprint(self.policies_dir)
        try:
            with httpx.Client(timeout=self.request_timeout, trust_env=False) as cli:
                resp = cli.get(f"{url}{BUNDLE_INFO_PATH}")
        except Exception as exc:  # noqa: BLE001 — any transport failure is fail-closed
            raise OpaUnavailable(
                f"OPA bundle verification failed: {exc}"
            ) from exc
        served: Optional[str] = None
        if 200 <= resp.status_code < 300:
            try:
                served = resp.json().get("result", {}).get("fingerprint")
            except ValueError:
                served = None
        if served != expected:
            raise OpaUnavailable(
                "OPA bundle fingerprint mismatch: external OPA at "
                f"{url} serves fingerprint {served!r}, pinned bundle is "
                f"{expected[:16]}… — refusing to serve decisions "
                "(stale bundle, misconfigured URL, or redirected endpoint)"
            )
        log.info(
            "external OPA bundle verified (fingerprint %s…)", expected[:16])
        self._bundle_ok = True
        return expected

    def _start_bundle_watchdog_locked(self) -> None:
        """Periodic bundle re-verification (GH #17; caller holds the lock).

        A daemon thread re-checks the fingerprint every
        GATEWAY_OPA_BUNDLE_CHECK_SECONDS (default 300; <=0 disables).
        On failure _bundle_ok flips False and decide() refuses to serve
        until the bundle verifies again; the flip is logged CRITICAL
        (the alert the deploy's log monitor keys on).
        """
        if self._bundle_watchdog is not None:
            return
        interval = self._bundle_check_seconds
        if interval <= 0:
            log.info("OPA bundle watchdog disabled (GATEWAY_OPA_BUNDLE_CHECK_SECONDS<=0)")
            return

        def _watch() -> None:
            while True:
                time.sleep(interval)
                if not self._external_up:
                    continue  # stopped; stay quiet
                try:
                    self.verify_external_bundle()
                except OpaUnavailable as exc:
                    if self._bundle_ok:
                        log.critical(
                            "OPA bundle verification FAILED: %s — refusing "
                            "further decisions until the pinned bundle "
                            "verifies again", exc,
                        )
                    self._bundle_ok = False
                except Exception:  # noqa: BLE001 — watchdog never dies loudly
                    log.exception("OPA bundle watchdog error")

        thread = threading.Thread(
            target=_watch, daemon=True, name="opa-bundle-watchdog")
        thread.start()
        self._bundle_watchdog = thread
        log.info(
            "OPA bundle watchdog started (re-verify every %.0fs)", interval)

    def _wait_ready(self) -> None:
        deadline = time.monotonic() + self.startup_timeout
        last: Optional[Exception] = None
        while time.monotonic() < deadline:
            if not self.running:
                err = ""
                try:
                    _, err_b = self._proc.communicate(timeout=1)  # type: ignore[union-attr]
                    err = (err_b or b"").decode(errors="replace")[-500:]
                except Exception:  # noqa: BLE001
                    pass
                raise OpaUnavailable(f"OPA sidecar exited during startup: {err}")
            try:
                if self._health_ok():
                    return
            except Exception as exc:  # noqa: BLE001 — not ready yet
                last = exc
            time.sleep(0.1)
        raise OpaUnavailable(f"OPA sidecar not ready after {self.startup_timeout}s: {last}")

    def _health_ok(self) -> bool:
        if self.unix_socket:
            conn = _UnixHTTPConnection(self.unix_socket, timeout=2)
            try:
                conn.request("GET", "/health")
                resp = conn.getresponse()
                return 200 <= resp.status < 300
            finally:
                conn.close()
        assert self._http is None  # TCP client created after readiness
        with httpx.Client(timeout=2, trust_env=False) as cli:
            r = cli.get(f"http://{self.host}:{self.port}/health")
            return 200 <= r.status_code < 300

    def stop(self) -> None:
        with self._lock:
            self._terminate_locked()

    def _terminate_locked(self) -> None:
        if self._http is not None:
            try:
                self._http.close()
            except Exception:  # noqa: BLE001
                pass
            self._http = None
        self._external_up = False
        proc, self._proc = self._proc, None
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        if self.unix_socket:
            try:
                Path(self.unix_socket).unlink(missing_ok=True)
            except OSError:  # noqa: BLE001
                pass

    def _ready(self) -> bool:
        """The sidecar is up AND reachable (socket file exists for UDS).

        ``running`` alone is not enough: a concurrent caller can
        observe the process while it is still starting, before the
        socket is created (M6 AC-11 race fix).
        """
        if not self.running:
            return False
        if self.unix_socket and not Path(self.unix_socket).exists():
            return False
        return True

    def ensure_running(self) -> None:
        """Start if needed; raise OpaUnavailable when it cannot run."""
        if self._ready():
            return
        # start() is idempotent under the lock and waits for
        # readiness, so concurrent callers serialize here and all see
        # a ready sidecar afterwards.
        self.start()
        if not self._ready():
            raise OpaUnavailable("OPA sidecar is not running")

    # -- decisions -----------------------------------------------------

    def decide(self, input_doc: dict[str, Any]) -> dict[str, Any]:
        """POST the input document; return the decision object.

        Raises OpaUnavailable on any transport, timeout, HTTP, or
        protocol failure, or when the decision is malformed — the
        caller fails closed (deny).

        GH #17: in external mode, also raises when the periodic bundle
        re-verification has failed — decisions are refused until the
        pinned bundle verifies again.
        """
        self.ensure_running()
        if self._external and not self._bundle_ok:
            raise OpaUnavailable(
                "external OPA bundle verification failed; refusing "
                "decisions until the pinned bundle verifies again"
            )
        payload = json.dumps({"input": input_doc}).encode()
        try:
            if self.unix_socket:
                status, body = self._post_uds(payload)
            else:
                status, body = self._post_tcp(payload)
        except OpaUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001 — any transport failure is fail-closed
            raise OpaUnavailable(f"OPA decide transport failure: {exc}") from exc
        if not 200 <= status < 300:
            raise OpaUnavailable(f"OPA decide HTTP {status}: {body[:200]!r}")
        try:
            result = json.loads(body).get("result")
        except (ValueError, AttributeError) as exc:
            raise OpaUnavailable(f"OPA decide malformed response: {exc}") from exc
        return self._validate_decision(result)

    def _post_tcp(self, payload: bytes) -> tuple[int, str]:
        assert self._http is not None
        try:
            r = self._http.post(
                DECISION_PATH,
                content=payload,
                headers={"Content-Type": "application/json"},
            )
            return r.status_code, r.text
        except httpx.TimeoutException as exc:
            raise OpaUnavailable(f"OPA decide timeout: {exc}") from exc
        except httpx.HTTPError as exc:
            raise OpaUnavailable(f"OPA decide HTTP error: {exc}") from exc

    def _post_uds(self, payload: bytes) -> tuple[int, str]:
        assert self.unix_socket is not None
        conn = _UnixHTTPConnection(self.unix_socket, timeout=self.request_timeout)
        try:
            conn.request(
                "POST", DECISION_PATH, body=payload,
                headers={"Content-Type": "application/json"},
            )
            resp = conn.getresponse()
            return resp.status, resp.read().decode(errors="replace")
        except (socket.timeout, TimeoutError) as exc:
            raise OpaUnavailable(f"OPA decide timeout (uds): {exc}") from exc
        except OSError as exc:
            raise OpaUnavailable(f"OPA decide socket error (uds): {exc}") from exc
        finally:
            conn.close()

    @staticmethod
    def _validate_decision(result: Any) -> dict[str, Any]:
        if not isinstance(result, dict):
            raise OpaUnavailable(f"OPA decision not an object: {result!r}"[:200])
        effect = result.get("effect")
        if effect not in EFFECTS:
            raise OpaUnavailable(f"OPA decision bad effect: {effect!r}"[:200])
        if "rule" not in result:
            raise OpaUnavailable("OPA decision missing 'rule'")
        return result

    # -- measurement ---------------------------------------------------

    def benchmark_transport(
        self, input_doc: dict[str, Any], calls: int = 200
    ) -> dict[str, float]:
        """p50/p95/p99 decision latency in ms (for transport choice)."""
        self.ensure_running()
        # Warmup (JIT, connection setup).
        for _ in range(10):
            self.decide(input_doc)
        samples: list[float] = []
        for _ in range(calls):
            t0 = time.perf_counter()
            self.decide(input_doc)
            samples.append((time.perf_counter() - t0) * 1000.0)
        samples.sort()
        def pct(p: float) -> float:
            return samples[min(len(samples) - 1, int(p * len(samples)))]
        return {"p50": pct(0.50), "p95": pct(0.95), "p99": pct(0.99), "n": float(calls)}
