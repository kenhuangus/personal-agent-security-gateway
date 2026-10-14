"""Environment-based settings for the Personal Agent Security Gateway.

Sources every value from the environment (optionally via a ``.env``
file loaded by the launcher). No secrets are defined here; secret
VALUES come only from the process environment or the platform secret
store — never from source.

Relevant docs: 00 §7 (reviewer's 20 parameters), 01 FR-014/FR-028,
03 §5 (storage). Timed values below are the reviewed defaults from
00 §7; "design target" numbers follow the docs' convention of being
design targets, not promises.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return int(raw)


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return float(raw)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    """All gateway configuration. Read once at process startup."""

    # --- storage (03 §5: three separate SQLite files, WAL mode) ---
    config_db_path: str = field(default_factory=lambda: _env("GATEWAY_CONFIG_DB", "data/config.db"))
    audit_db_path: str = field(default_factory=lambda: _env("GATEWAY_AUDIT_DB", "data/audit.db"))
    # M4 vault: encrypted secrets file, separate from config/audit (03 §5).
    vault_db_path: str = field(default_factory=lambda: _env("GATEWAY_VAULT_DB", "data/vault.db"))

    # --- token lifetimes (00 §7 param 1–2; 03 §2.2) ---
    # Agent-facing session credential lifetime.
    session_token_minutes: int = field(default_factory=lambda: _env_int("GATEWAY_SESSION_TTL_MIN", 60))
    # Per-call derived upstream token lifetime (FR-012b).
    derived_token_minutes: int = field(default_factory=lambda: _env_int("GATEWAY_DERIVED_TTL_MIN", 5))
    # Fallback bearer (Fix A conditional fallback): max age in days,
    # mandatory rotation, console-visible age indicator (00 §7 param 1).
    fallback_bearer_max_days: int = field(default_factory=lambda: _env_int("GATEWAY_FALLBACK_BEARER_MAX_DAYS", 90))

    # --- approval windows (00 §7 param 3) ---
    approval_window_minutes: int = field(default_factory=lambda: _env_int("GATEWAY_APPROVAL_WINDOW_MIN", 15))
    destructive_approval_window_minutes: int = field(
        default_factory=lambda: _env_int("GATEWAY_DESTRUCTIVE_APPROVAL_WINDOW_MIN", 5)
    )
    # One-time grant TTL: how long the agent has to re-invoke after
    # approval (00 §7 param 21).
    grant_ttl_minutes: int = field(default_factory=lambda: _env_int("GATEWAY_GRANT_TTL_MIN", 30))

    # --- pipeline execution deadline (GH #9) ---
    # Overall bound on one pipeline.execute() call. A hung connector
    # handler (infinite loop, blocking I/O without its own timeout)
    # ties up the caller indefinitely; expiry maps to upstream_failure
    # through the unknown-outcome gate (retries stay blocked until the
    # console resolves them). 0 or negative disables the deadline.
    pipeline_timeout_seconds: float = field(
        default_factory=lambda: _env_float("GATEWAY_PIPELINE_TIMEOUT_S", 120.0)
    )

    # --- rate limits (00 §7 param 4; FR-028) ---
    rate_limit_per_minute: int = field(default_factory=lambda: _env_int("GATEWAY_RATE_PER_MIN", 60))
    rate_limit_per_day: int = field(default_factory=lambda: _env_int("GATEWAY_RATE_PER_DAY", 1000))
    # Per-agent cap on concurrent pending approvals (FR-028, MF-9).
    approval_queue_cap: int = field(default_factory=lambda: _env_int("GATEWAY_APPROVAL_CAP", 5))

    # --- cooldowns (02 §2.8 step 3/10; FR-PAA09-003) ---
    refusal_cooldown_hours: int = field(default_factory=lambda: _env_int("GATEWAY_REFUSAL_COOLDOWN_H", 24))
    denial_streak_threshold: int = field(default_factory=lambda: _env_int("GATEWAY_DENIAL_STREAK_N", 3))
    denial_streak_window_hours: int = field(default_factory=lambda: _env_int("GATEWAY_DENIAL_STREAK_H", 24))

    # --- audit retention (00 §7 param 5; NFR-DATA-002) ---
    audit_retention_days: int = field(default_factory=lambda: _env_int("GATEWAY_AUDIT_RETENTION_DAYS", 90))
    # Dead-letter file for audit rows whose commit failed persistently
    # (GH #18): JSONL, replayable with scripts/replay_audit_dead_letter.py.
    audit_dead_letter_path: str = field(
        default_factory=lambda: _env("GATEWAY_AUDIT_DEAD_LETTER", "data/audit-dead-letter.jsonl")
    )

    # --- approval_status polling budget (02 §2.5: own budget) ---
    approval_status_polls_per_minute: int = field(
        default_factory=lambda: _env_int("GATEWAY_APPROVAL_POLL_PER_MIN", 60)
    )

    # --- secrets (values from env / platform secret store ONLY) ---
    # HMAC-SHA256 key for canonical-argument hashing (02 §2.8 step 3/4;
    # 03 §5: lives in the platform secret store, never the config DB).
    # Base64- or hex-encoded. M1: raw string used directly; the rotation
    # seam (key-id tagging) lives in hmac_util.
    hmac_key: str = field(default_factory=lambda: _env("GATEWAY_HMAC_KEY", ""), repr=False)
    hmac_key_id: str = field(default_factory=lambda: _env("GATEWAY_HMAC_KEY_ID", "k1"))
    # Dedicated exempt system-notification bootstrap secret (02 §2.8 step 5;
    # MAJOR-3; NFR-SEC-002 scope note). Held in the platform secret store
    # (Fly secrets / GCP Secret Manager); NOT the M4 vault.
    notifier_secret: str = field(default_factory=lambda: _env("GATEWAY_NOTIFIER_SECRET", ""), repr=False)
    # ISO-8601 timestamp of when the notifier bootstrap secret was
    # issued/rotated (deploy-time bookkeeping). The notifier refuses to
    # send when the secret is older than 90 days (03 §5; T13).
    notifier_secret_issued_at: str = field(
        default_factory=lambda: _env("GATEWAY_NOTIFIER_SECRET_ISSUED_AT", "")
    )
    # Escape hatch for the 90-day rotation enforcement (GH #16): when
    # True, an UNSET or unparseable GATEWAY_NOTIFIER_SECRET_ISSUED_AT
    # only warns instead of refusing to send. Default False (fail
    # closed): a deploy that never sets the timestamp gets no rotation
    # enforcement bypass.
    notifier_allow_unknown_secret_age: bool = field(
        default_factory=lambda: _env_bool("GATEWAY_NOTIFIER_ALLOW_UNKNOWN_SECRET_AGE", False)
    )
    # Recipient of the email-to-Ken approval notifications (Ken's address,
    # chosen at deploy). Empty = no email transport configured → the
    # in-console queue is the delivery path (documented fallback).
    notifier_recipient: str = field(default_factory=lambda: _env("GATEWAY_NOTIFIER_TO", ""))
    # Optional SMTP sending service for the notifier (stdlib smtplib;
    # the bootstrap secret is the SMTP password when set). Empty host =
    # unconfigured → in-console fallback.
    notifier_smtp_host: str = field(default_factory=lambda: _env("GATEWAY_NOTIFIER_SMTP_HOST", ""))
    notifier_smtp_port: int = field(default_factory=lambda: _env_int("GATEWAY_NOTIFIER_SMTP_PORT", 587))
    notifier_smtp_user: str = field(default_factory=lambda: _env("GATEWAY_NOTIFIER_SMTP_USER", ""))
    # Per-agent notification cooldown (minutes) blunting attention-DoS
    # (03 §6 T13). A new approval request inside the cooldown still
    # appears in the console queue; only the email is skipped.
    notifier_cooldown_minutes: int = field(
        default_factory=lambda: _env_int("GATEWAY_NOTIFIER_COOLDOWN_MIN", 5)
    )
    # Base URL of the admin console, used to build the console link in
    # notifier messages (fixed allowlist field). Empty → relative path.
    console_base_url: str = field(default_factory=lambda: _env("GATEWAY_CONSOLE_URL", ""))
    # Admin session cookie Secure flag (issue #5): when true the
    # ``gw_admin`` cookie is only sent over HTTPS. Default true;
    # set GATEWAY_CONSOLE_COOKIE_SECURE=0 for local HTTP development.
    # Never disable in production.
    console_cookie_secure: bool = field(
        default_factory=lambda: _env_bool("GATEWAY_CONSOLE_COOKIE_SECURE", True)
    )

    # --- admin bootstrap (M6 console; values seeded by operator) ---
    admin_password_hash: str = field(default_factory=lambda: _env("GATEWAY_ADMIN_PASSWORD_HASH", ""), repr=False)
    admin_totp_secret: str = field(default_factory=lambda: _env("GATEWAY_ADMIN_TOTP_SECRET", ""), repr=False)

    # --- server ---
    host: str = field(default_factory=lambda: _env("GATEWAY_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: _env_int("GATEWAY_PORT", 8000))

    # --- console display ---
    # 00 §7 param 15: UTC in storage, Ken's local timezone in display.
    display_tz: str = field(default_factory=lambda: _env("GATEWAY_DISPLAY_TZ", "America/New_York"))

    # --- judge decision backends (JUDGE build; OPT-IN) ---
    # "none" (default) = DisabledBackend: no judge calls, AC-11 latency
    # budget untouched. "kev" = local Kev-4B /v1/systemone server (or
    # OpenRouter via KEV_API_KEY). "jev" = TypeSafe hosted Jev API.
    judge_backend: str = field(default_factory=lambda: _env("GATEWAY_JUDGE_BACKEND", "none"))
    judge_kev_url: str = field(
        default_factory=lambda: _env("GATEWAY_JUDGE_KEV_URL", "http://127.0.0.1:8009")
    )
    judge_jev_url: str = field(default_factory=lambda: _env("GATEWAY_JUDGE_JEV_URL", ""))
    judge_jev_api_key: str = field(
        default_factory=lambda: _env("GATEWAY_JUDGE_JEV_API_KEY", ""), repr=False
    )
    # --- judge escalation (ESCALATION build; OPT-IN, default OFF) ---
    # "none" (default) = no escalation backend: low-confidence primary
    # answers return low_confidence=True → the caller maps it to the
    # deterministic ask path. "jev" = TypeSafe hosted Jev as the
    # escalation backend. "llm" = bring-your-own escalation model over
    # an OpenAI-compatible chat-completions endpoint (validated target:
    # meta-models/Muse-Glimmer-30B via Ollama/vLLM/SGLang). The
    # PRIMARY stays Kev; the LLM is escalation-only, exactly as the
    # cascade was designed.
    judge_escalation: str = field(
        default_factory=lambda: _env("GATEWAY_JUDGE_ESCALATION", "none")
    )
    judge_llm_escalation_url: str = field(
        default_factory=lambda: _env(
            "GATEWAY_LLM_ESCALATION_URL", "http://127.0.0.1:11434"
        )
    )
    judge_llm_escalation_model: str = field(
        default_factory=lambda: _env(
            "GATEWAY_LLM_ESCALATION_MODEL", "meta-models/Muse-Glimmer-30B"
        )
    )
    judge_llm_escalation_api_key: str = field(
        default_factory=lambda: _env("GATEWAY_LLM_ESCALATION_API_KEY", ""),
        repr=False,
    )
    # Per-decide timeout (seconds); consumed at the decide() call site,
    # not by the factory — the cascade passes settings.judge_timeout_s.
    judge_timeout_s: float = field(
        default_factory=lambda: float(_env("GATEWAY_JUDGE_TIMEOUT_S", "2.0"))
    )
    # --- judge pipeline hooks (advisory; default OFF) ---
    # GATEWAY_JUDGE_ENABLED=1 lets the pipeline INSTALL the judge hooks
    # (inspection second-opinion, intent risk step-up, counterparty
    # signals). Default 0: the deterministic path is byte-identical.
    # (Separate from GATEWAY_JUDGE_BACKEND: enabling the hooks with the
    # "none" backend just yields JudgeUnavailable → deterministic
    # fallback everywhere.)
    judge_enabled: bool = field(
        default_factory=lambda: bool(_env_int("GATEWAY_JUDGE_ENABLED", 0))
    )
    # When the hooks are enabled, the inspection hook fires only when
    # the deterministic scanner already flagged suspicion (pre-filter
    # gate). GATEWAY_JUDGE_ALWAYS_ON=1 consults the judge on every
    # tool output instead. Default 0.
    judge_always_on: bool = field(
        default_factory=lambda: bool(_env_int("GATEWAY_JUDGE_ALWAYS_ON", 0))
    )

    def validate(self) -> list[str]:
        """Return a list of config problems. Empty = OK."""
        problems: list[str] = []
        if not self.hmac_key:
            problems.append(
                "GATEWAY_HMAC_KEY is empty: argument hashing (approval dedupe, "
                "evidence subset) needs a gateway-held key from the platform secret store."
            )
        if self.session_token_minutes <= 0:
            problems.append("GATEWAY_SESSION_TTL_MIN must be > 0")
        if self.derived_token_minutes <= 0:
            problems.append("GATEWAY_DERIVED_TTL_MIN must be > 0")
        if self.approval_queue_cap <= 0:
            problems.append("GATEWAY_APPROVAL_CAP must be > 0")
        if self.judge_backend.strip().lower() not in ("none", "kev", "jev"):
            problems.append(
                f"GATEWAY_JUDGE_BACKEND={self.judge_backend!r} is not one of "
                "none|kev|jev"
            )
        if self.judge_escalation.strip().lower() not in ("none", "jev", "llm"):
            problems.append(
                f"GATEWAY_JUDGE_ESCALATION={self.judge_escalation!r} is not one of "
                "none|jev|llm"
            )
        if self.judge_timeout_s <= 0:
            problems.append("GATEWAY_JUDGE_TIMEOUT_S must be > 0")
        return problems


def load_settings() -> Settings:
    return Settings()
