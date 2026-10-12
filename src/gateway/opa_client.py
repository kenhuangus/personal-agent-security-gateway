"""OPA sidecar client (ontology -> intent -> OPEN POLICY).

Supervised ``opa run --server`` process management plus a keep-alive
decision client. The sidecar is STATELESS: every input document carries
the rules, the intent, and the ontology snapshot, so a restart loses
nothing and no per-version data sync is needed.

Transports: TCP keep-alive (127.0.0.1) or Unix-domain socket. The UDS
transport is the default: the spike measured ~2.3 ms of the sidecar
p50 in OPA's HTTP layer, and the UDS path avoids TCP loopback
overhead (see ``benchmark_transport`` and docs/build-log.md).

Fail-closed (03 §7): ANY sidecar failure — unreachable, timeout,
non-2xx, malformed decision — raises :class:`OpaUnavailable`. The
policy engine catches it and denies (the pinned default-deny), never
passes through.
"""

from __future__ import annotations

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
OPA_VERSION = "1.8.0"

#: Decision endpoint (the contract in policies/v1/authz.rego).
DECISION_PATH = "/v1/data/gateway/authz/decision"

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
    ) -> None:
        self.binary = resolve_binary(binary)
        self.policies_dir = Path(policies_dir) if policies_dir else default_policies_dir()
        self.host = host
        self.port = port
        # UDS is the default transport (measured faster; see build log).
        # An explicit unix_socket=None + host/port keeps TCP available.
        self._want_uds = unix_socket != ""
        if unix_socket is None and self._want_uds:
            self.unix_socket: Optional[str] = str(
                Path(tempfile.gettempdir())
                / f"gateway-opa-{os.getpid()}-{uuid.uuid4().hex[:8]}.sock"
            )
        else:
            self.unix_socket = unix_socket
        self.startup_timeout = startup_timeout
        self.request_timeout = request_timeout
        self._proc: Optional[subprocess.Popen] = None
        self._lock = threading.Lock()
        self._http: Optional[httpx.Client] = None

    # -- lifecycle ----------------------------------------------------

    @property
    def transport(self) -> str:
        return "uds" if self.unix_socket else "tcp"

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def start(self) -> None:
        """Launch the sidecar (idempotent). Raises OpaUnavailable."""
        with self._lock:
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
        """
        self.ensure_running()
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
