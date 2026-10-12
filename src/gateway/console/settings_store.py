"""Console-editable settings layer (M6, Vault & Settings page).

Env vars remain the base Settings values; the ``config_settings``
table holds the console-editable override layer for a whitelisted set
of keys. Every change is audit-logged as an admin action (FR-041).

The gateway process applies overrides at boot via
``effective_settings``; the console pages display the effective
values.
"""

from __future__ import annotations

import datetime as dt
from typing import Any, Callable, Optional

from ..config import Settings
from ..models import ConfigSetting

# Whitelisted console-editable keys -> (Settings field, display label,
# value kind). Kinds: "int" or "float".
EDITABLE_SETTINGS: dict[str, tuple[str, str, str]] = {
    "session_token_minutes": ("session_token_minutes", "Agent session token lifetime (minutes)", "int"),
    "derived_token_minutes": ("derived_token_minutes", "Derived per-call token lifetime (minutes)", "int"),
    "approval_window_minutes": ("approval_window_minutes", "Approval window (minutes)", "int"),
    "grant_ttl_minutes": ("grant_ttl_minutes", "One-time grant TTL (minutes)", "int"),
    "rate_limit_per_minute": ("rate_limit_per_minute", "Rate limit: calls/minute per agent", "int"),
    "rate_limit_per_day": ("rate_limit_per_day", "Rate limit: calls/day per agent", "int"),
    "approval_queue_cap": ("approval_queue_cap", "Pending-approval cap per agent", "int"),
    "audit_retention_days": ("audit_retention_days", "Audit retention (days)", "int"),
}


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class SettingsStore:
    """Read/write the console-editable override layer."""

    def __init__(self, db: Any, audit_session_factory: Optional[Callable[[], Any]] = None) -> None:
        self.db = db
        self.audit_session_factory = audit_session_factory

    def get_overrides(self) -> dict[str, Any]:
        rows = self.db.query(ConfigSetting).all()
        return {r.key: (r.value or {}).get("value") for r in rows}

    def get(self, key: str) -> Any:
        if key not in EDITABLE_SETTINGS:
            raise KeyError(f"not console-editable: {key!r}")
        row = self.db.get(ConfigSetting, key)
        return (row.value or {}).get("value") if row is not None else None

    def set(self, key: str, value: Any, admin_id: str = "admin_ken") -> Any:
        """Set an override; raises ValueError on unknown key or bad value."""
        if key not in EDITABLE_SETTINGS:
            raise ValueError(f"not console-editable: {key!r}")
        field, label, kind = EDITABLE_SETTINGS[key]
        try:
            parsed = int(value) if kind == "int" else float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{label}: not a number: {value!r}") from exc
        if parsed <= 0:
            raise ValueError(f"{label}: must be positive")
        row = self.db.get(ConfigSetting, key)
        if row is None:
            row = ConfigSetting(key=key, value={"value": parsed})
            self.db.add(row)
        else:
            row.value = {"value": parsed}
            row.updated_at = _utcnow()
        row.updated_by = admin_id
        self.db.commit()
        if self.audit_session_factory is not None:
            from ..audit import AuditLog

            with self.audit_session_factory() as audit_db:
                AuditLog(audit_db).append(
                    agent_id="admin",
                    tool="settings.update",
                    decision="allowed",
                    redacted_args={"key": key, "value": parsed},
                )
        return parsed

    def reset(self, key: str) -> None:
        row = self.db.get(ConfigSetting, key)
        if row is not None:
            self.db.delete(row)
            self.db.commit()


def effective_settings(settings: Settings, db: Any) -> Settings:
    """Return a Settings copy with console overrides applied.

    The gateway process calls this at boot so Vault & Settings edits
    take effect without env changes. Non-overridden fields keep their
    env/config-file values.
    """
    import dataclasses

    overrides = SettingsStore(db).get_overrides()
    changes: dict[str, Any] = {}
    for key, (field, _label, kind) in EDITABLE_SETTINGS.items():
        if key in overrides and overrides[key] is not None:
            raw = overrides[key]
            changes[field] = int(raw) if kind == "int" else float(raw)
    if not changes:
        return settings
    return dataclasses.replace(settings, **changes)
