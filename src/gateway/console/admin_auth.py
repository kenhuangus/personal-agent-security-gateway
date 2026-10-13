"""Admin authentication for the console (FR-036, FR-039, FR-040; 02 §2.6).

- Password + TOTP (pyotp) for MVP (00 §7 param 6; 02 DQ-5 decided).
- First-run setup: if no AdminUser row exists the console exposes
  /setup, which creates the admin (password + TOTP secret with QR
  provisioning). /setup disappears once an admin exists.
- Login is rate-limited with lockout and exponential backoff
  (FR-040): 5 consecutive failures from one IP trigger a per-IP
  lockout whose duration doubles per lockout (1, 2, 4, … minutes,
  capped at 60). INDEPENDENTLY, 15 total consecutive failures from
  ANY source IPs lock the ACCOUNT for 30 minutes, so rotating IPs
  cannot buy unlimited guesses (issue #4). Lockout state is persisted
  on AdminUser (failed_logins, locked_until) so a restart does not
  clear it; per-IP backoff is additionally kept in-process by
  LoginGuard. Both counters reset on successful login.
- EVERY login attempt — success or failure — emits an audit event
  (FR-039): agent_id="admin", tool="admin.login",
  decision="allowed"/"denied", reason="ok" | "invalid_password" |
  "invalid_totp" | "locked_out" | "no_such_admin".
- Sessions: an HMAC-signed cookie (``gw_admin``) carrying
  ``admin_id|expiry_ts``; the signing secret derives from
  Settings.hmac_key when configured, else a per-process random key
  (restart invalidates sessions — documented).

The vault/TOTP secrets never leave this module's write path; the
login form never echoes the password.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import secrets
import threading
from typing import Any, Callable, Optional

import bcrypt
import pyotp
import qrcode

from ..audit import AuditLog
from ..config import Settings
from ..models import AdminUser, as_utc

SESSION_COOKIE = "gw_admin"
ADMIN_ID = "admin_ken"  # single admin = Ken (02 §3.3); admin_id seam kept

_LOCKOUT_BASE_MINUTES = 1
_LOCKOUT_CAP_MINUTES = 60
_FAILURES_BEFORE_LOCKOUT = 5
# Account-level lockout (issue #4): total consecutive failures across
# ALL source IPs before the account itself locks. Sane default 15;
# flag for Ken if he wants a different threshold or duration.
_ACCOUNT_FAILURES_BEFORE_LOCKOUT = 15
_ACCOUNT_LOCKOUT_MINUTES = 30


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("ascii")


def check_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("ascii"))
    except Exception:  # noqa: BLE001 — malformed hash must fail closed
        return False


def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_provisioning_uri(secret: str, account: str = "ken@gateway") -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(name=account, issuer_name="Agent Security Gateway")


def totp_qr_data_uri(secret: str) -> str:
    """PNG QR data-URI for the otpauth:// URI (shown once at setup)."""
    uri = totp_provisioning_uri(secret)
    img = qrcode.make(uri)
    import io as _io

    buf = _io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("ascii")


def verify_totp(secret: str, code: str) -> bool:
    try:
        return pyotp.TOTP(secret).verify(code, valid_window=1)
    except Exception:  # noqa: BLE001 — fail closed
        return False


class LoginGuard:
    """Per-IP in-process login attempt tracking (FR-040).

    Complements the persisted AdminUser.locked_until (which survives
    restarts); this guard adds per-client-IP backoff within the
    process.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # ip -> {"failures": int, "lockouts": int, "locked_until": datetime}
        self._state: dict[str, dict[str, Any]] = {}

    def check(self, ip: str) -> Optional[dt.timedelta]:
        """Return the remaining lockout, or None when login may proceed."""
        with self._lock:
            entry = self._state.get(ip)
            if not entry:
                return None
            locked_until = entry.get("locked_until")
            if locked_until is not None and _utcnow() < locked_until:
                return locked_until - _utcnow()
            if locked_until is not None:
                entry["locked_until"] = None
            return None

    def record_failure(self, ip: str) -> Optional[dt.timedelta]:
        """Record a failure; returns the new lockout if one started."""
        with self._lock:
            entry = self._state.setdefault(
                ip, {"failures": 0, "lockouts": 0, "locked_until": None}
            )
            entry["failures"] += 1
            if entry["failures"] >= _FAILURES_BEFORE_LOCKOUT:
                entry["lockouts"] += 1
                minutes = min(
                    _LOCKOUT_BASE_MINUTES * (2 ** (entry["lockouts"] - 1)),
                    _LOCKOUT_CAP_MINUTES,
                )
                entry["locked_until"] = _utcnow() + dt.timedelta(minutes=minutes)
                entry["failures"] = 0
                return dt.timedelta(minutes=minutes)
            return None

    def record_success(self, ip: str) -> None:
        with self._lock:
            self._state.pop(ip, None)


class AdminAuth:
    """Password + TOTP admin auth with sessions and audit (FR-036/039/040)."""

    def __init__(
        self,
        settings: Settings,
        audit_session_factory: Callable[[], Any],
        session_secret: Optional[bytes] = None,
        session_ttl_minutes: int = 12 * 60,
    ) -> None:
        self.settings = settings
        self.audit_session_factory = audit_session_factory
        key = session_secret or (
            settings.hmac_key.encode("utf-8")
            if settings.hmac_key
            else secrets.token_bytes(32)
        )
        self._session_secret = key
        self._ttl = dt.timedelta(minutes=session_ttl_minutes)
        self.guard = LoginGuard()

    # -- admin user ---------------------------------------------------

    def admin_exists(self, db: Any) -> bool:
        return db.get(AdminUser, ADMIN_ID) is not None

    def setup_admin(self, db: Any, password: str, totp_secret: Optional[str] = None) -> str:
        """Create the admin (setup only). Returns the TOTP secret.

        Raises ValueError when an admin already exists (setup is
        one-shot) or the password is too weak.
        """
        if self.admin_exists(db):
            raise ValueError("admin already provisioned")
        if len(password) < 12:
            raise ValueError("password must be at least 12 characters")
        secret = totp_secret or new_totp_secret()
        db.add(
            AdminUser(
                id=ADMIN_ID,
                password_hash=hash_password(password),
                totp_secret=secret,
            )
        )
        db.commit()
        with self.audit_session_factory() as audit_db:
            AuditLog(audit_db).append(
                agent_id="admin",
                tool="admin.setup",
                decision="allowed",
                redacted_args={"admin_id": ADMIN_ID},
            )
        return secret

    # -- sessions ------------------------------------------------------

    def _sign(self, payload: bytes) -> str:
        sig = hmac.new(self._session_secret, payload, hashlib.sha256).hexdigest()
        return base64.urlsafe_b64encode(payload + b"." + sig.encode("ascii")).decode("ascii")

    def _unsign(self, token: str) -> Optional[str]:
        try:
            raw = base64.urlsafe_b64decode(token.encode("ascii"))
            payload, sig = raw.rsplit(b".", 1)
            expect = hmac.new(self._session_secret, payload, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expect.encode("ascii"), sig):
                return None
            admin_id, exp = payload.decode("utf-8").rsplit("|", 1)
            if _utcnow().timestamp() > float(exp):
                return None
            return admin_id
        except Exception:  # noqa: BLE001 — any parse failure = no session
            return None

    def issue_session(self) -> tuple[str, dt.datetime]:
        exp = _utcnow() + self._ttl
        payload = f"{ADMIN_ID}|{exp.timestamp()}".encode("utf-8")
        return self._sign(payload), exp

    def verify_session(self, cookie_value: Optional[str]) -> Optional[str]:
        if not cookie_value:
            return None
        return self._unsign(cookie_value)

    def set_session_cookie(self, response: Any, token: str) -> None:
        # Issue #5: Secure flag on the admin session cookie, governed by
        # the console_cookie_secure setting (default true; disable only
        # for local HTTP development).
        response.set_cookie(
            SESSION_COOKIE,
            token,
            samesite="strict",
            httponly=True,
            secure=self.settings.console_cookie_secure,
            path="/",
        )

    def clear_session_cookie(self, response: Any) -> None:
        response.delete_cookie(SESSION_COOKIE, path="/")

    # -- login ----------------------------------------------------------

    def login(
        self,
        db: Any,
        password: str,
        totp_code: str,
        client_ip: str,
    ) -> tuple[bool, str]:
        """Attempt login. Returns (ok, reason).

        reason: ok | locked_out | invalid_password | invalid_totp |
        no_such_admin. Every attempt is audit-logged (FR-039) and the
        per-IP guard applies exponential-backoff lockout (FR-040).
        """
        remaining = self.guard.check(client_ip)
        if remaining is not None:
            self._audit_login("denied", "locked_out", client_ip)
            return False, "locked_out"
        user = db.get(AdminUser, ADMIN_ID)
        if user is None:
            self._audit_login("denied", "no_such_admin", client_ip)
            return False, "no_such_admin"
        # as_utc: SQLite returns naive datetimes for the
        # DateTime(timezone=True) column; without normalization this
        # comparison raises TypeError (issue #4 — the account-lockout
        # path reaches it from any IP).
        if user.locked_until is not None and _utcnow() < as_utc(user.locked_until):
            self.guard.record_failure(client_ip)
            self._audit_login("denied", "locked_out", client_ip)
            return False, "locked_out"
        if not check_password(password, user.password_hash):
            self._on_failure(db, user, client_ip, "invalid_password")
            return False, "invalid_password"
        if user.totp_secret and not verify_totp(user.totp_secret, totp_code.strip()):
            self._on_failure(db, user, client_ip, "invalid_totp")
            return False, "invalid_totp"
        self.guard.record_success(client_ip)
        user.failed_logins = 0
        user.locked_until = None
        db.commit()
        self._audit_login("allowed", "ok", client_ip)
        return True, "ok"

    def _on_failure(self, db: Any, user: AdminUser, client_ip: str, reason: str) -> None:
        ip_lockout = self.guard.record_failure(client_ip)
        user.failed_logins = (user.failed_logins or 0) + 1
        lock_until: Optional[dt.datetime] = None
        if ip_lockout is not None:
            lock_until = _utcnow() + ip_lockout
        if user.failed_logins >= _ACCOUNT_FAILURES_BEFORE_LOCKOUT:
            # Account-level lockout (issue #4): N total consecutive
            # failures regardless of source IP — IP rotation cannot
            # evade this. Kept alongside (not instead of) the per-IP
            # guard; the longer of the two wins.
            account_until = _utcnow() + dt.timedelta(
                minutes=_ACCOUNT_LOCKOUT_MINUTES
            )
            lock_until = (
                account_until
                if lock_until is None
                else max(lock_until, account_until)
            )
        if lock_until is not None:
            # Extend only — never shorten a live lockout.
            current = as_utc(user.locked_until)
            if current is None or lock_until > current:
                user.locked_until = lock_until
        db.commit()
        self._audit_login("denied", reason, client_ip)

    def _audit_login(self, decision: str, reason: str, client_ip: str) -> None:
        with self.audit_session_factory() as audit_db:
            AuditLog(audit_db).append(
                agent_id="admin",
                tool="admin.login",
                decision=decision,
                reason=reason,
                redacted_args={"client": "console"},
            )

    def reset_totp(self, db: Any) -> tuple[str, str]:
        """Re-issue the TOTP secret (admin action; audit-logged).

        Returns (secret, qr_data_uri). The new secret is shown once.
        """
        user = db.get(AdminUser, ADMIN_ID)
        if user is None:
            raise ValueError("no admin provisioned")
        secret = new_totp_secret()
        user.totp_secret = secret
        db.commit()
        with self.audit_session_factory() as audit_db:
            AuditLog(audit_db).append(
                agent_id="admin",
                tool="admin.totp_reset",
                decision="allowed",
                redacted_args={"admin_id": ADMIN_ID},
            )
        return secret, totp_qr_data_uri(secret)
