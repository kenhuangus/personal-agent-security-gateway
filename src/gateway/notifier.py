"""Exempt system-notification path: email-to-Ken on new approval requests.

02 §2.8 step 5; 03 §5; 03 §6 T13. This path is DELIBERATELY outside the
policy-gated ``email.send`` connector (M3 does not wait for M4):

- Authentication: the bootstrap deploy-time secret from the PLATFORM
  SECRET STORE via ``NotifierSecretProvider`` (NOT the M4 vault, which
  holds connector credentials only). Every read is audit-logged
  (FR-024); max age 90 days (03 §5).
- Content limits: messages are built from a FIXED FIELD ALLOWLIST —
  agent name, tool name, timestamp, console link ONLY. There is no
  free-text passthrough of tool arguments: no PII, no argument values
  ever reach the message (T13).
- Failure semantics: a bounced/delayed/unconfigured notification falls
  back to the in-console queue — the request is always visible there.
  The 15-minute approval window runs from request creation regardless
  of notification delivery.
- Rate limits: volume is bounded by the per-agent pending-approval cap
  (default 5); a per-agent notification cooldown (default 5 min,
  tunable) blunts attention-DoS (T13).
"""

from __future__ import annotations

import datetime as dt
import logging
import smtplib
import threading
from dataclasses import dataclass, field
from email.message import EmailMessage
from typing import Any, Callable, Optional, Protocol

from .audit import AuditLog
from .config import Settings
from .models import as_utc
from .vault.notifier_secret import NotifierSecretProvider

log = logging.getLogger(__name__)

# Max bootstrap-secret age in days (03 §5: rotation via the platform
# secret store on a documented schedule).
MAX_SECRET_AGE_DAYS = 90


class NotifierError(Exception):
    """The notification could not be delivered (bounce, delay, config)."""


class NotifierNotConfigured(NotifierError):
    """No sending service / recipient configured: in-console fallback."""


class NotifierTransport(Protocol):
    """Pluggable sending service (chosen at deploy; 02 §2.8 step 5)."""

    def send(self, *, to: str, subject: str, body: str) -> None:
        """Deliver one message. Raise NotifierError on bounce/delay."""
        ...


class MockNotifierTransport:
    """In-memory transport for tests. Set ``fail=True`` to simulate a
    bounce/delayed notification (→ in-console fallback)."""

    def __init__(self) -> None:
        self.sent: list[dict[str, str]] = []
        self.fail = False
        self._lock = threading.Lock()

    def send(self, *, to: str, subject: str, body: str) -> None:
        if self.fail:
            raise NotifierError("mock transport: simulated bounce")
        with self._lock:
            self.sent.append({"to": to, "subject": subject, "body": body})


class SmtpNotifierTransport:
    """Real sending service over SMTP (stdlib only, no new deps).

    The bootstrap secret is used as the SMTP password when ``password``
    is not given explicitly.
    """

    def __init__(
        self,
        host: str,
        port: int = 587,
        username: str = "",
        password: str = "",
        sender: str = "",
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.sender = sender or username

    def send(self, *, to: str, subject: str, body: str) -> None:
        msg = EmailMessage()
        msg["From"] = self.sender
        msg["To"] = to
        msg["Subject"] = subject
        msg.set_content(body)
        try:
            with smtplib.SMTP(self.host, self.port, timeout=15) as smtp:
                smtp.starttls()
                if self.username:
                    smtp.login(self.username, self.password)
                smtp.send_message(msg)
        except (smtplib.SMTPException, OSError) as exc:
            raise NotifierError(f"smtp send failed: {exc}") from exc


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


@dataclass
class NotifyResult:
    delivered: bool
    # "sent" | "cooldown" | "fallback" | "secret_expired"
    outcome: str
    detail: str = ""


class Notifier:
    """Builds allowlist-only messages and delivers them.

    ``secret_provider`` reads the bootstrap secret (audit-logged);
    ``transport`` is the deploy-chosen sending service (or
    ``MockNotifierTransport`` in tests). ``console_base_url`` builds the
    console link; empty → relative path.
    """

    def __init__(
        self,
        secret_provider: NotifierSecretProvider,
        audit: AuditLog,
        settings: Settings,
        transport: Optional[NotifierTransport],
        console_base_url: str = "",
        clock: Callable[[], dt.datetime] | None = None,
    ) -> None:
        self._secrets = secret_provider
        self._audit = audit
        self._settings = settings
        self._transport = transport
        self._console_base_url = (console_base_url or settings.console_base_url).rstrip("/")
        self._clock = clock or _utcnow
        # Per-agent last-notification timestamps (attention-DoS cooldown).
        self._last_sent: dict[str, dt.datetime] = {}
        self._lock = threading.Lock()

    # -- message construction (fixed allowlist ONLY) --------------------

    def build_message(
        self,
        *,
        agent_name: str,
        tool_name: str,
        approval_id: str,
        created_at: dt.datetime,
    ) -> tuple[str, str]:
        """(subject, body) from the fixed field allowlist.

        Agent name, tool name, timestamp, console link ONLY. Tool
        arguments are NEVER interpolated here (T13) — not even
        redacted ones.
        """
        ts = as_utc(created_at) or created_at
        link = f"{self._console_base_url}/approvals/{approval_id}" if self._console_base_url else f"/approvals/{approval_id}"
        subject = f"[gateway] Approval requested: {tool_name} by {agent_name}"
        body = (
            f"Agent: {agent_name}\n"
            f"Tool: {tool_name}\n"
            f"Requested at: {ts.isoformat()}\n"
            f"Review: {link}\n"
        )
        return subject, body

    def _secret_age_ok(self) -> tuple[bool, str]:
        """Enforce the 90-day max bootstrap-secret age (03 §5).

        GH #16: fail closed. An unset or unparseable
        GATEWAY_NOTIFIER_SECRET_ISSUED_AT used to PASS vacuously
        ("secret age unknown") — a deploy that never set the timestamp
        got no rotation enforcement at all, with only a detail string
        noting it. Now an unknown age refuses to send, unless the
        explicit documented escape hatch
        GATEWAY_NOTIFIER_ALLOW_UNKNOWN_SECRET_AGE=1 is set.
        """
        raw = self._settings.notifier_secret_issued_at.strip()
        unknown_ok = self._settings.notifier_allow_unknown_secret_age
        if not raw:
            if unknown_ok:
                return True, (
                    "secret age unknown (GATEWAY_NOTIFIER_SECRET_ISSUED_AT "
                    "unset; escape hatch GATEWAY_NOTIFIER_ALLOW_UNKNOWN_SECRET_AGE=1 set)"
                )
            return False, (
                "GATEWAY_NOTIFIER_SECRET_ISSUED_AT is unset: refusing to "
                "send (90-day rotation cannot be enforced). Set the "
                "timestamp or GATEWAY_NOTIFIER_ALLOW_UNKNOWN_SECRET_AGE=1."
            )
        try:
            issued = dt.datetime.fromisoformat(raw)
        except ValueError:
            if unknown_ok:
                return True, (
                    f"unparseable GATEWAY_NOTIFIER_SECRET_ISSUED_AT {raw!r} "
                    "(escape hatch set)"
                )
            return False, (
                f"unparseable GATEWAY_NOTIFIER_SECRET_ISSUED_AT {raw!r}: "
                "refusing to send. Fix the timestamp or set "
                "GATEWAY_NOTIFIER_ALLOW_UNKNOWN_SECRET_AGE=1."
            )
        if issued.tzinfo is None:
            issued = issued.replace(tzinfo=dt.timezone.utc)
        age_days = (self._clock() - issued).days
        if age_days > MAX_SECRET_AGE_DAYS:
            return False, f"bootstrap secret age {age_days}d exceeds {MAX_SECRET_AGE_DAYS}d max"
        return True, f"secret age {age_days}d"

    def _cooldown_ok(self, agent_id: str) -> tuple[bool, str]:
        """Check the per-agent notification cooldown (GH #13: no stamp).

        Stamping used to happen here, BEFORE delivery was attempted —
        a failed send burned the 5-minute cooldown and a subsequent
        genuine approval request notified nobody. The stamp now happens
        in ``_stamp_cooldown``, called only after successful delivery.
        """
        window = dt.timedelta(minutes=self._settings.notifier_cooldown_minutes)
        now = self._clock()
        with self._lock:
            last = self._last_sent.get(agent_id)
            if last is not None and now - last < window:
                remaining = window - (now - last)
                return False, f"per-agent cooldown: {remaining} remaining"
            return True, ""

    def _stamp_cooldown(self, agent_id: str) -> None:
        """Record a successful delivery for the per-agent cooldown."""
        with self._lock:
            self._last_sent[agent_id] = self._clock()

    # -- delivery ------------------------------------------------------

    def notify_new_request(
        self,
        *,
        agent_id: str,
        agent_name: str,
        tool_name: str,
        approval_id: str,
        created_at: dt.datetime,
    ) -> NotifyResult:
        """Fire the email-to-Ken notification for one approval request.

        Never raises: every failure mode returns a NotifyResult with
        outcome "fallback" and is audit-logged. The approval request
        itself is always visible in the console queue.
        """
        try:
            return self._notify_inner(
                agent_id=agent_id, agent_name=agent_name,
                tool_name=tool_name, approval_id=approval_id,
                created_at=created_at,
            )
        except Exception as exc:  # noqa: BLE001 — GH #13: "never raises"
            # Last-resort guard: even the audit appends below can fail
            # (audit-DB outage). Log server-side and degrade to the
            # in-console queue rather than propagating out of
            # ApprovalStage.run with no error envelope and no audit row.
            log.exception(
                "notify_new_request failed unexpectedly (approval_id=%s)",
                approval_id,
            )
            return NotifyResult(
                delivered=False, outcome="fallback",
                detail=f"notifier internal error: {type(exc).__name__}",
            )

    def _notify_inner(
        self,
        *,
        agent_id: str,
        agent_name: str,
        tool_name: str,
        approval_id: str,
        created_at: dt.datetime,
    ) -> NotifyResult:
        ok, detail = self._cooldown_ok(agent_id)
        if not ok:
            return NotifyResult(delivered=False, outcome="cooldown", detail=detail)

        age_ok, age_detail = self._secret_age_ok()
        if not age_ok:
            self._audit.append(
                agent_id="system",
                tool="notifier.send",
                decision="error",
                redacted_args={"approval_request_id": approval_id, "outcome": "secret_expired", "detail": age_detail},
            )
            return NotifyResult(delivered=False, outcome="secret_expired", detail=age_detail)

        if self._transport is None or not self._settings.notifier_recipient:
            self._audit.append(
                agent_id="system",
                tool="notifier.send",
                decision="allowed",
                redacted_args={
                    "approval_request_id": approval_id,
                    "outcome": "fallback",
                    "detail": "no sending service/recipient configured; in-console queue is the delivery path",
                },
            )
            return NotifyResult(delivered=False, outcome="fallback",
                                detail="notifier not configured; in-console queue")

        subject, body = self.build_message(
            agent_name=agent_name, tool_name=tool_name,
            approval_id=approval_id, created_at=created_at,
        )
        try:
            # The bootstrap secret authenticates the sending service
            # (e.g. SMTP password). Read is audit-logged (FR-024); the
            # value never appears in logs or the message.
            secret = self._secrets.read(purpose="approval-notify")
            transport = self._transport
            if isinstance(transport, SmtpNotifierTransport) and not transport.password:
                transport.password = secret
            transport.send(to=self._settings.notifier_recipient, subject=subject, body=body)
        except Exception as exc:  # noqa: BLE001 — GH #13: never raises
            # GH #13: the old handler only caught (NotifierError,
            # VaultError), but self._secrets.read() or a deploy-chosen
            # custom transport's send() can raise anything (OSError,
            # KeyError, TimeoutError) — and the call site in
            # approvals._create_request ignores the return value with no
            # guard, so the exception used to propagate out of
            # Pipeline.run with no envelope and no audit row. The secret
            # VALUE never appears here (only type/message).
            log.warning(
                "notifier send failed (approval_id=%s): %s: %s",
                approval_id, type(exc).__name__, exc,
            )
            # A missing bootstrap secret is a configuration failure, not a
            # send failure: degrade to the in-console queue (the approval
            # request itself was already created).
            self._audit.append(
                agent_id="system",
                tool="notifier.send",
                decision="error",
                redacted_args={"approval_request_id": approval_id, "outcome": "fallback",
                               "detail": f"{type(exc).__name__}: {exc}"[:200]},
            )
            return NotifyResult(delivered=False, outcome="fallback", detail=f"{type(exc).__name__}: {exc}"[:200])
        # NOTE (GH #13): no cooldown stamp on the failure path above — a
        # failed send must not burn the per-agent cooldown; the next
        # genuine approval request still notifies.

        # GH #13: the cooldown is stamped only after SUCCESSFUL delivery.
        self._stamp_cooldown(agent_id)
        self._audit.append(
            agent_id="system",
            tool="notifier.send",
            decision="allowed",
            redacted_args={"approval_request_id": approval_id, "outcome": "sent",
                           "detail": age_detail},
        )
        return NotifyResult(delivered=True, outcome="sent", detail=age_detail)


def build_notifier(
    settings: Settings,
    audit: AuditLog,
    transport: Optional[NotifierTransport] = None,
    clock: Callable[[], dt.datetime] | None = None,
) -> Notifier:
    """Assemble the notifier. ``transport=None`` → in-console fallback
    mode (no secret read, no email)."""
    provider = NotifierSecretProvider(settings, audit)
    if transport is None and settings.notifier_smtp_host:
        transport = SmtpNotifierTransport(
            host=settings.notifier_smtp_host,
            port=settings.notifier_smtp_port,
            username=settings.notifier_smtp_user,
            sender=settings.notifier_smtp_user,
        )
    return Notifier(provider, audit, settings, transport, clock=clock)
