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

import logging
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
    # --- TLS posture (GH #19) ---
    # Fix A requires per-agent secrets "over TLS". The gateway itself
    # speaks plain HTTP; production deployments MUST terminate TLS in
    # front of it (reverse proxy / platform ingress) and set this so
    # the startup check knows the traffic is protected.
    tls_terminated: bool = field(
        default_factory=lambda: bool(_env_int("GATEWAY_TLS_TERMINATED", 0))
    )
    # Escape hatch for plaintext-on-LAN testing. Refusing to start is
    # the default; this opts back into a LOUD warning instead. Never
    # enable in production.
    allow_plaintext_nonloopback: bool = field(
        default_factory=lambda: bool(_env_int("GATEWAY_ALLOW_PLAINTEXT_NONLOOPBACK", 0))
    )

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
    # Kev model id sent to the /v1/systemone endpoint (GH #33). The
    # client is model-agnostic (any checkpoint speaking the TypeSafe
    # contract works); this is the config knob for promotion. Default is
    # the production recommendation kev-4b (mirrors
    # gateway.judge.kev.DEFAULT_MODEL; kept as a literal here to avoid a
    # config -> judge import cycle). Local dev serves kev-0.8b on the
    # same URL — override this to match when the local server runs the
    # smaller checkpoint.
    judge_kev_model: str = field(
        default_factory=lambda: _env("GATEWAY_JUDGE_KEV_MODEL", "jaredpalmer/kev-4b")
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
    # Judge-backend supervision (GH #31): how many minutes of continuous
    # unreachability before the CRITICAL readiness alert fires.
    judge_alert_after_minutes: float = field(
        default_factory=lambda: float(_env("GATEWAY_JUDGE_ALERT_AFTER_MINUTES", "5"))
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

    # --- Pillar 1: finance-grade gateway (MVP m001/m002; all default-off) ---
    # Master switch for the money pack (MoneyStage, payment.* tools).
    # Off = the gateway behaves exactly as before.
    money_enabled: bool = field(
        default_factory=lambda: bool(_env_int("GATEWAY_MONEY_ENABLED", 0))
    )
    # Event interception mode: "off" | "monitor" | "enforce" (§4, ext).
    event_interception: str = field(
        default_factory=lambda: _env("GATEWAY_EVENT_INTERCEPTION", "off")
    )
    # Webhook HMAC timestamp acceptance window (seconds, §4.3).
    webhook_nonce_window_s: int = field(
        default_factory=lambda: _env_int("GATEWAY_WEBHOOK_NONCE_WINDOW_S", 600)
    )
    # Money-ledger retention horizon in days (aligned with audit).
    money_ledger_retention_days: int = field(
        default_factory=lambda: _env_int("GATEWAY_MONEY_LEDGER_RETENTION_DAYS", 90)
    )
    # Console default for checkpoint_every_days on new mandates (§3).
    checkpoint_default_days: int = field(
        default_factory=lambda: _env_int("GATEWAY_CHECKPOINT_DEFAULT_DAYS", 14)
    )
    # Staging dir for large compliance exports (§6).
    compliance_export_dir: str = field(
        default_factory=lambda: _env("GATEWAY_COMPLIANCE_EXPORT_DIR", "data/exports")
    )
    # Force dry_run=True on all payment.initiate calls (demo safety).
    money_dry_run: bool = field(
        default_factory=lambda: bool(_env_int("GATEWAY_MONEY_DRY_RUN", 0))
    )

    # --- Pillar 2: AI security agents (all default-off) ---
    # Master switch; the agents-runner refuses to start when 0.
    agents_enabled: bool = field(
        default_factory=lambda: bool(_env_int("GATEWAY_AGENTS_ENABLED", 0))
    )
    agents_runner_poll_s: int = field(
        default_factory=lambda: _env_int("GATEWAY_AGENTS_RUNNER_POLL_S", 15)
    )
    # Sandbox tools (red-team targets): sandbox.echo,
    # sandbox.payment_initiate, sandbox.event_receive.
    sandbox_tools: bool = field(
        default_factory=lambda: bool(_env_int("GATEWAY_SANDBOX_TOOLS", 0))
    )
    # Per-agent Fix-A credentials (raw secrets; env/secret-store ONLY —
    # never written to disk/DB/logs).
    agent_redteam_credential: str = field(
        default_factory=lambda: _env("GATEWAY_AGENT_REDATEAM_CREDENTIAL", ""), repr=False
    )
    agent_redteam_credential_id: str = field(
        default_factory=lambda: _env("GATEWAY_AGENT_REDATEAM_CREDENTIAL_ID", "")
    )
    agent_sentinel_credential: str = field(
        default_factory=lambda: _env("GATEWAY_AGENT_SENTINEL_CREDENTIAL", ""), repr=False
    )
    agent_sentinel_credential_id: str = field(
        default_factory=lambda: _env("GATEWAY_AGENT_SENTINEL_CREDENTIAL_ID", "")
    )
    agent_policy_assistant_credential: str = field(
        default_factory=lambda: _env("GATEWAY_AGENT_POLICY_ASSISTANT_CREDENTIAL", ""),
        repr=False,
    )
    agent_policy_assistant_credential_id: str = field(
        default_factory=lambda: _env("GATEWAY_AGENT_POLICY_ASSISTANT_CREDENTIAL_ID", "")
    )
    agent_incident_credential: str = field(
        default_factory=lambda: _env("GATEWAY_AGENT_INCIDENT_CREDENTIAL", ""), repr=False
    )
    agent_incident_credential_id: str = field(
        default_factory=lambda: _env("GATEWAY_AGENT_INCIDENT_CREDENTIAL_ID", "")
    )
    # Red-team schedule + rate limits.
    redteam_schedule: str = field(
        default_factory=lambda: _env("GATEWAY_REDATEAM_SCHEDULE", "0 2 * * *")
    )
    redteam_tz: str = field(
        default_factory=lambda: _env("GATEWAY_REDATEAM_TZ", "America/New_York")
    )
    redteam_max_attempts_hour: int = field(
        default_factory=lambda: _env_int("GATEWAY_REDATEAM_MAX_ATTEMPTS_HOUR", 60)
    )
    redteam_max_attempts_day: int = field(
        default_factory=lambda: _env_int("GATEWAY_REDATEAM_MAX_ATTEMPTS_DAY", 500)
    )
    redteam_max_concurrency: int = field(
        default_factory=lambda: _env_int("GATEWAY_REDATEAM_MAX_CONCURRENCY", 2)
    )
    redteam_issue_threshold: str = field(
        default_factory=lambda: _env("GATEWAY_REDATEAM_ISSUE_THRESHOLD", "medium")
    )
    redteam_daily_issue_cap: int = field(
        default_factory=lambda: _env_int("GATEWAY_REDATEAM_DAILY_ISSUE_CAP", 10)
    )
    # Issue-store backend: "file" (MVP) | "github" (unimplemented →
    # fail-closed startup config error).
    codehost_issues_backend: str = field(
        default_factory=lambda: _env("GATEWAY_CODEHOST_ISSUES_BACKEND", "file")
    )
    codehost_issues_dir: str = field(
        default_factory=lambda: _env("GATEWAY_CODEHOST_ISSUES_DIR", "data/issues")
    )
    codehost_issues_repo: str = field(
        default_factory=lambda: _env("GATEWAY_CODEHOST_ISSUES_REPO", "")
    )
    # Sentinel (extension).
    sentinel_interval_s: int = field(
        default_factory=lambda: _env_int("GATEWAY_SENTINEL_INTERVAL_S", 120)
    )
    sentinel_probing_n: int = field(
        default_factory=lambda: _env_int("GATEWAY_SENTINEL_PROBING_N", 10)
    )
    sentinel_probing_m_min: int = field(
        default_factory=lambda: _env_int("GATEWAY_SENTINEL_PROBING_M_MIN", 15)
    )
    sentinel_cooldown_h: int = field(
        default_factory=lambda: _env_int("GATEWAY_SENTINEL_COOLDOWN_H", 1)
    )
    sentinel_notify_severity: str = field(
        default_factory=lambda: _env("GATEWAY_SENTINEL_NOTIFY_SEVERITY", "high")
    )
    sentinel_renotify_max: int = field(
        default_factory=lambda: _env_int("GATEWAY_SENTINEL_RENOTIFY_MAX", 3)
    )
    sentinel_renotify_interval_h: int = field(
        default_factory=lambda: _env_int("GATEWAY_SENTINEL_RENOTIFY_INTERVAL_H", 4)
    )
    # Optional OpenAI-compatible LLM for drafting/summaries (never
    # load-bearing; unset → deterministic-only).
    agents_llm_url: str = field(
        default_factory=lambda: _env("GATEWAY_AGENTS_LLM_URL", "")
    )
    agents_llm_model: str = field(
        default_factory=lambda: _env("GATEWAY_AGENTS_LLM_MODEL", "")
    )
    agents_llm_api_key: str = field(
        default_factory=lambda: _env("GATEWAY_AGENTS_LLM_API_KEY", ""), repr=False
    )
    # Missed-heartbeat thresholds (counts).
    agents_heartbeat_missed_amber: int = field(
        default_factory=lambda: _env_int("GATEWAY_AGENTS_HEARTBEAT_MISSED_AMBER", 2)
    )
    agents_heartbeat_missed_red: int = field(
        default_factory=lambda: _env_int("GATEWAY_AGENTS_HEARTBEAT_MISSED_RED", 5)
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
        if self.judge_alert_after_minutes < 0:
            problems.append("GATEWAY_JUDGE_ALERT_AFTER_MINUTES must be >= 0")
        if self.event_interception not in ("off", "monitor", "enforce"):
            problems.append(
                f"GATEWAY_EVENT_INTERCEPTION={self.event_interception!r} is not one of "
                "off|monitor|enforce"
            )
        if self.money_ledger_retention_days <= 0:
            problems.append("GATEWAY_MONEY_LEDGER_RETENTION_DAYS must be > 0")
        if self.webhook_nonce_window_s <= 0:
            problems.append("GATEWAY_WEBHOOK_NONCE_WINDOW_S must be > 0")
        if self.codehost_issues_backend.strip().lower() not in ("file", "github"):
            problems.append(
                f"GATEWAY_CODEHOST_ISSUES_BACKEND={self.codehost_issues_backend!r} "
                "is not one of file|github"
            )
        if self.redteam_issue_threshold.strip().lower() not in (
            "low", "medium", "high", "critical"
        ):
            problems.append(
                "GATEWAY_REDATEAM_ISSUE_THRESHOLD must be one of "
                "low|medium|high|critical"
            )
        if self.sentinel_notify_severity.strip().lower() not in ("high", "medium"):
            problems.append(
                "GATEWAY_SENTINEL_NOTIFY_SEVERITY must be one of high|medium"
            )
        return problems


# ---------------------------------------------------------------------
# TLS posture (GH #19)
# ---------------------------------------------------------------------

#: Hosts that never leave the machine: binding one of these needs no
#: TLS-terminating proxy.
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


def is_loopback_host(host: str) -> bool:
    """True when *host* is a loopback bind (no network exposure)."""
    return host.strip().lower() in _LOOPBACK_HOSTS


def check_tls_posture(host: str, settings: "Settings") -> None:
    """Fail closed when binding a non-loopback address without TLS.

    Fix A requires per-agent secrets "over TLS". The gateway serves
    plain HTTP itself, so a non-loopback bind is only safe behind a
    TLS-terminating proxy (``GATEWAY_TLS_TERMINATED=1``). Without it,
    refuse to start — unless the explicit escape hatch
    ``GATEWAY_ALLOW_PLAINTEXT_NONLOOPBACK=1`` is set, which downgrades
    to a loud warning (LAN testing only, never production).

    Raises:
        RuntimeError: non-loopback bind with no TLS termination and no
            escape hatch.
    """
    if is_loopback_host(host):
        return
    if settings.tls_terminated:
        return
    if settings.allow_plaintext_nonloopback:
        logging.getLogger(__name__).warning(
            "TLS POSTURE: binding non-loopback address %r with no TLS "
            "termination (GATEWAY_ALLOW_PLAINTEXT_NONLOOPBACK=1) — per-agent "
            "secrets cross the network in cleartext. Never use in production.",
            host,
        )
        return
    raise RuntimeError(
        f"refusing to bind non-loopback address {host!r} with no TLS "
        "termination: per-agent secrets would cross the network in "
        "cleartext (Fix A requires TLS). Set GATEWAY_TLS_TERMINATED=1 "
        "when a TLS-terminating proxy is in front of the gateway, or "
        "GATEWAY_ALLOW_PLAINTEXT_NONLOOPBACK=1 for LAN testing only."
    )


def load_settings() -> Settings:
    return Settings()
