"""Admin console package (M6): nine pages + admin auth + CSRF.

- ``create_console_app`` — the FastAPI factory (console/app.py).
- ``ApprovalConsoleDeps`` — wiring for the approvals routes (M3).
- ``AdminAuth`` / ``LoginGuard`` — password + TOTP admin auth (M6).
- ``HealthMonitor`` — connector health checks every 5 min (M6).
- ``SettingsStore`` / ``effective_settings`` — console-editable
  settings overrides (M6).
"""

from .admin_auth import ADMIN_ID, AdminAuth, LoginGuard
from .app import create_console_app
from .approvals import ApprovalConsoleDeps
from .health import HealthMonitor
from .settings_store import EDITABLE_SETTINGS, SettingsStore, effective_settings

__all__ = [
    "create_console_app",
    "ApprovalConsoleDeps",
    "ADMIN_ID",
    "AdminAuth",
    "LoginGuard",
    "HealthMonitor",
    "SettingsStore",
    "EDITABLE_SETTINGS",
    "effective_settings",
]
