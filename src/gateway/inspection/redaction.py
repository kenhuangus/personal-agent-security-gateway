"""PII + code-artifact redaction (M5; FR-027; FR-PAA02-001; NFR-DATA-001).

Catalog (00 §7 param 13): email / phone (intl shapes) / SSN-shaped /
account-IBAN-shaped / API-key-shaped patterns, plus the code-artifact
class — verification codes, OTPs, password-reset links. Replacements
are full ``[redacted:type]`` tokens; no last-4 hints.

The catalog lives in the CONFIG DB (``RedactionPattern`` rows) and is
console-editable from day one via ``RedactionCatalog`` CRUD (M6 wires
the UI to these methods). ``RedactionCatalog`` also works session-less
(in-memory over the seeded defaults) for unit tests.

Redaction runs BEFORE agent delivery (on tool outputs, in
``InspectOutputStage``) AND BEFORE the audit write (on call arguments,
via ``redact_ctx_for_audit`` — the pipeline's pre-audit hook covers
every path, including calls halted before output inspection).
Redaction events are audit-logged. ``invalid_input`` and every other
error path never echo values — only field names.
"""

from __future__ import annotations

import copy
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import RedactionPattern
from .validation import walk_strings

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------
# Seeded default catalog
# ---------------------------------------------------------------------
# Each entry: name, description, regex, token, category, secret_group,
# priority. Scope defaults to tools=["*"], agents=["*"].


@dataclass(frozen=True)
class _SeedPattern:
    name: str
    description: str
    regex: str
    token: str
    category: str  # "pii" | "code_artifact"
    secret_group: int = 0
    priority: int = 20


DEFAULT_PATTERNS: tuple[_SeedPattern, ...] = (
    # -- code artifacts first (FR-PAA02-001; more specific) -------------
    _SeedPattern(
        name="verification_code",
        description="Verification / confirmation codes (keeps the label, redacts the digits).",
        regex=r"(?i)(verification code|security code|confirmation code|your code)[^:\d]{0,12}:?\s*(\d{4,8})",
        token="[redacted:verification_code]",
        category="code_artifact",
        secret_group=2,
        priority=10,
    ),
    _SeedPattern(
        name="otp",
        description="One-time passwords (keeps the label, redacts the digits).",
        regex=r"(?i)\botp\b[^:\d]{0,12}:?\s*#?(\d{4,8})",
        token="[redacted:otp]",
        category="code_artifact",
        secret_group=1,
        priority=10,
    ),
    _SeedPattern(
        name="reset_link",
        description="Password-reset / verify-email / magic-link URLs.",
        regex=(
            r"https?://\S*(?:password[-_]?reset|reset[-_]?password|verify[-_]?email"
            r"|magic[-_]?link|forgot[-_]?password|account[-_]?recovery)\S*"
            r"|https?://\S+[?&](?:token|code|key)=[A-Za-z0-9._~%-]+"
        ),
        token="[redacted:reset_link]",
        category="code_artifact",
        secret_group=0,
        priority=10,
    ),
    # -- PII ------------------------------------------------------------
    _SeedPattern(
        name="email",
        description="Email addresses.",
        regex=r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        token="[redacted:email]",
        category="pii",
        priority=20,
    ),
    _SeedPattern(
        name="phone_intl",
        description="International phone numbers (+country …).",
        regex=r"\+\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}",
        token="[redacted:phone]",
        category="pii",
        priority=20,
    ),
    _SeedPattern(
        name="phone_domestic",
        description="Domestic phone numbers with separators (never bare digit runs).",
        regex=r"(?<!\d)(?:\(\d{3}\)|\d{3})[-.\s]\d{3}[-.\s]\d{4}(?!\d)",
        token="[redacted:phone]",
        category="pii",
        priority=20,
    ),
    _SeedPattern(
        name="ssn",
        description="US Social-Security-shaped numbers (###-##-####).",
        regex=r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)",
        token="[redacted:ssn]",
        category="pii",
        priority=20,
    ),
    _SeedPattern(
        name="iban",
        description="IBAN-shaped account numbers.",
        regex=r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b",
        token="[redacted:account]",
        category="pii",
        priority=20,
    ),
    _SeedPattern(
        name="api_key",
        description="API-key-shaped strings (sk-…, AKIA…, xox…-, ghp_…, gsk_…).",
        regex=r"\b(?:sk-[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|ghp_[A-Za-z0-9]{20,}|gsk_[A-Za-z0-9]{20,})\b",
        token="[redacted:api_key]",
        category="pii",
        priority=20,
    ),
    _SeedPattern(
        name="secret_assignment",
        description="Labeled secrets (api_key=…, client_secret: …); redacts the value only.",
        regex=r"(?i)\b(api[_-]?key|client[_-]?secret|password)\s*[:=]\s*[\"']?([A-Za-z0-9_\-./+]{12,})[\"']?",
        token="[redacted:secret]",
        category="pii",
        secret_group=2,
        priority=20,
    ),
)


# ---------------------------------------------------------------------
# Catalog: CRUD over the config DB (console-editable from day one)
# ---------------------------------------------------------------------

@dataclass
class CompiledPattern:
    name: str
    token: str
    category: str
    secret_group: int
    priority: int
    tools: list[str]
    agents: list[str]
    rx: re.Pattern = field(repr=False)
    enabled: bool = True

    def applies_to(self, tool: str, agent_id: str) -> bool:
        tool_ok = "*" in self.tools or tool in self.tools
        agent_ok = "*" in self.agents or agent_id in self.agents
        return tool_ok and agent_ok


class RedactionCatalog:
    """Console-editable redaction catalog (00 §7 param 13).

    ``db`` is the config-DB session; when ``None`` the catalog runs
    purely in-memory over the seeded defaults (unit-test mode — edits
    are not persisted).
    """

    def __init__(self, db: Optional[Session] = None) -> None:
        self.db = db
        self._memory: list[CompiledPattern] = []  # session-less overlay
        self._seeded = False
        # GH #11: compiled-catalog cache. _catalog_version bumps on
        # every mutation (add/delete/toggle/update); _compiled_cache is
        # (version, compiled) and _last_good is the last successfully
        # compiled set — the config-DB-outage fallback.
        self._catalog_version = 0
        self._compiled_cache: Optional[tuple[int, list[CompiledPattern]]] = None
        self._last_good: list[CompiledPattern] = []

    def _bump_version(self) -> None:
        """Invalidate the compiled cache after a catalog mutation."""
        self._catalog_version += 1
        self._compiled_cache = None

    # -- seeding --------------------------------------------------------

    def ensure_seeded(self) -> None:
        """Insert the default patterns once (idempotent)."""
        if self._seeded:
            return
        self._seeded = True
        if self.db is None:
            self._memory = [_compile_seed(p) for p in DEFAULT_PATTERNS]
            return
        existing = {
            row.name for row in self.db.execute(select(RedactionPattern)).scalars()
        }
        for seed in DEFAULT_PATTERNS:
            if seed.name in existing:
                continue
            self.db.add(
                RedactionPattern(
                    name=seed.name,
                    description=seed.description,
                    regex=seed.regex,
                    token=seed.token,
                    category=seed.category,
                    secret_group=seed.secret_group,
                    priority=seed.priority,
                    tools=["*"],
                    agents=["*"],
                    enabled=True,
                )
            )
        self.db.commit()

    # -- CRUD (the surface M6's console edits) ---------------------------

    def list_patterns(self, enabled_only: bool = False) -> list[dict[str, Any]]:
        """List catalog rows as plain dicts (console read model)."""
        self.ensure_seeded()
        rows = self._rows()
        if enabled_only:
            rows = [r for r in rows if r["enabled"]]
        return rows

    def get_pattern(self, name: str) -> Optional[dict[str, Any]]:
        for row in self._rows():
            if row["name"] == name:
                return row
        return None

    def add_pattern(
        self,
        name: str,
        regex: str,
        token: str,
        category: str = "pii",
        description: str = "",
        secret_group: int = 0,
        priority: int = 20,
        tools: Optional[list[str]] = None,
        agents: Optional[list[str]] = None,
        enabled: bool = True,
    ) -> dict[str, Any]:
        """Add a pattern. Raises ValueError on bad regex / bad category."""
        try:
            re.compile(regex)  # validate now, not at scan time
        except re.error as exc:
            raise ValueError(f"invalid regex for pattern {name!r}: {exc}") from exc
        if category not in ("pii", "code_artifact"):
            raise ValueError(f"unknown category {category!r}")
        if self.get_pattern(name) is not None:
            raise ValueError(f"pattern {name!r} already exists")
        row = {
            "name": name, "description": description, "regex": regex,
            "token": token, "category": category, "secret_group": secret_group,
            "priority": priority, "tools": tools or ["*"],
            "agents": agents or ["*"], "enabled": enabled,
        }
        if self.db is None:
            self._memory.append(_compile_row(row))
        else:
            self.db.add(RedactionPattern(**row))
            self.db.commit()
        self._bump_version()
        return row

    def set_enabled(self, name: str, enabled: bool) -> dict[str, Any]:
        row = self._require(name)
        row["enabled"] = enabled
        self._persist_row(row)
        return row

    def update_pattern(self, name: str, **changes: Any) -> dict[str, Any]:
        """Update mutable fields (regex, token, tools, agents, …).

        ``name`` itself is immutable. A changed regex is recompiled
        immediately so a bad pattern fails here, not at scan time.
        """
        row = self._require(name)
        if "name" in changes:
            raise ValueError("pattern name is immutable; delete + re-add instead")
        if "regex" in changes:
            try:
                re.compile(changes["regex"])
            except re.error as exc:
                raise ValueError(
                    f"invalid regex for pattern {name!r}: {exc}") from exc
        if "category" in changes and changes["category"] not in ("pii", "code_artifact"):
            raise ValueError(f"unknown category {changes['category']!r}")
        row.update(changes)
        self._persist_row(row)
        return row

    def delete_pattern(self, name: str) -> None:
        self._require(name)
        if self.db is None:
            self._memory = [p for p in self._memory if p.name != name]
        else:
            row = self.db.execute(
                select(RedactionPattern).where(RedactionPattern.name == name)
            ).scalar_one()
            self.db.delete(row)
            self.db.commit()
        self._bump_version()

    # -- compiled view for the hot path ----------------------------------

    def active_patterns(self, tool: str, agent_id: str) -> list[CompiledPattern]:
        """Enabled patterns in priority order, scoped to (tool, agent).

        GH #11: the hot path must not depend on the config DB. The
        compiled set is cached in-process (invalidated on console
        edits); when the DB is unreachable ``ensure_seeded``/``_rows``
        failures fall back to the last-known-good compiled set instead
        of raising (which the old code turned into a full outage via
        ``injected_output_blocked``).
        """
        try:
            self.ensure_seeded()
        except Exception:  # noqa: BLE001 — config-DB blip: degrade, don't deny
            log.warning(
                "redaction catalog seed check failed; using cached/seed patterns",
                exc_info=True,
            )
        compiled = self._compiled()
        return sorted(
            [p for p in compiled if p.applies_to(tool, agent_id)],
            key=lambda p: (p.priority, p.name),
        )

    # -- internals ---------------------------------------------------------

    def _rows(self) -> list[dict[str, Any]]:
        self.ensure_seeded()
        if self.db is None:
            return [_row_of(p) for p in self._memory]
        return [
            {
                "name": r.name, "description": r.description, "regex": r.regex,
                "token": r.token, "category": r.category,
                "secret_group": r.secret_group, "priority": r.priority,
                "tools": list(r.tools or ["*"]), "agents": list(r.agents or ["*"]),
                "enabled": r.enabled,
            }
            for r in self.db.execute(select(RedactionPattern)).scalars()
        ]

    def _compiled(self) -> list[CompiledPattern]:
        cached = self._compiled_cache
        if cached is not None and cached[0] == self._catalog_version:
            return cached[1]
        try:
            if self.db is None:
                fresh = [p for p in self._memory if p.enabled]
            else:
                fresh = [
                    _compile_row(r)
                    for r in self._rows() if r["enabled"]
                ]
        except Exception:  # noqa: BLE001 — GH #11: config-DB outage
            if self._last_good:
                log.warning(
                    "redaction catalog DB read failed; falling back to "
                    "last-known-good compiled set (%d patterns)",
                    len(self._last_good), exc_info=True,
                )
                return self._last_good
            # No cache yet (first boot with the DB down): the seeded
            # defaults are compiled from code, no DB needed.
            log.warning(
                "redaction catalog DB read failed with no cached set; "
                "using seed defaults", exc_info=True,
            )
            return [_compile_seed(p) for p in DEFAULT_PATTERNS]
        self._last_good = fresh
        self._compiled_cache = (self._catalog_version, fresh)
        return fresh

    def _require(self, name: str) -> dict[str, Any]:
        row = self.get_pattern(name)
        if row is None:
            raise ValueError(f"unknown redaction pattern {name!r}")
        return row

    def _persist_row(self, row: dict[str, Any]) -> None:
        if self.db is None:
            self._memory = [
                _replace_enabled(_compile_row(row), row["enabled"])
                if p.name == row["name"] else p
                for p in self._memory
            ]
            self._bump_version()
            return
        db_row = self.db.execute(
            select(RedactionPattern).where(RedactionPattern.name == row["name"])
        ).scalar_one()
        for key in ("description", "regex", "token", "category", "secret_group",
                    "priority", "tools", "agents", "enabled"):
            setattr(db_row, key, row[key])
        self.db.commit()
        self._bump_version()


def _compile_seed(seed: _SeedPattern) -> CompiledPattern:
    return CompiledPattern(
        name=seed.name, token=seed.token, category=seed.category,
        secret_group=seed.secret_group, priority=seed.priority,
        tools=["*"], agents=["*"], rx=re.compile(seed.regex),
    )


def _compile_row(row: dict[str, Any]) -> CompiledPattern:
    return CompiledPattern(
        name=row["name"], token=row["token"], category=row["category"],
        secret_group=row["secret_group"], priority=row["priority"],
        tools=list(row.get("tools") or ["*"]),
        agents=list(row.get("agents") or ["*"]),
        rx=re.compile(row["regex"]),
        enabled=row.get("enabled", True),
    )


def _replace_enabled(pattern: CompiledPattern, enabled: bool) -> CompiledPattern:
    pattern.enabled = enabled
    return pattern


def _row_of(pattern: CompiledPattern) -> dict[str, Any]:
    return {
        "name": pattern.name, "description": "", "regex": pattern.rx.pattern,
        "token": pattern.token, "category": pattern.category,
        "secret_group": pattern.secret_group, "priority": pattern.priority,
        "tools": list(pattern.tools), "agents": list(pattern.agents),
        "enabled": pattern.enabled,
    }


# ---------------------------------------------------------------------
# Redaction application
# ---------------------------------------------------------------------

@dataclass
class RedactionEvent:
    pattern: str      # pattern name, e.g. "phone_domestic"
    token: str        # replacement token, e.g. "[redacted:phone]"
    field: str        # top-level field path (never the matched value)
    count: int = 1


#: GH #15: redaction byte budget — the same DoS class as the injection
#: scanner (attacker-influenced, unbounded outputs on the hot path).
#: Fields are redacted up to MAX_REDACT_BYTES_PER_FIELD chars; the
#: call redacts at most MAX_REDACT_BYTES_TOTAL chars overall. Text past
#: the budget is NOT delivered unredacted: it is replaced with
#: TRUNCATED_TOKEN (fail-closed for PII — the PII guarantee
#: (NFR-DATA-001) outranks output completeness), and a synthetic
#: RedactionEvent (pattern "_truncated") records it for the audit log.
MAX_REDACT_BYTES_PER_FIELD = 64 * 1024  # 64 KiB
MAX_REDACT_BYTES_TOTAL = 512 * 1024  # 512 KiB
TRUNCATED_TOKEN = "[redacted:truncated]"


def redact_text(
    text: str, patterns: list[CompiledPattern]
) -> tuple[str, list[RedactionEvent]]:
    """Apply patterns to one string. Returns (new_text, events)."""
    events: list[RedactionEvent] = []
    for pattern in patterns:
        def _replace(match: re.Match, _p: CompiledPattern = pattern) -> str:
            return _p.token

        if pattern.secret_group == 0:
            new_text, n = pattern.rx.subn(_replace, text)
        else:
            new_text, n = _sub_group(pattern.rx, _replace, text, pattern.secret_group)
        if n:
            events.append(RedactionEvent(
                pattern=pattern.name, token=pattern.token, field="", count=n))
            text = new_text
    return text, events


def _sub_group(
    rx: re.Pattern, repl_fn: Any, text: str, group: int
) -> tuple[str, int]:
    """Substitute only capture *group*'s span, keeping surrounding text."""
    out: list[str] = []
    last = 0
    n = 0
    for match in rx.finditer(text):
        try:
            start, end = match.span(group)
        except IndexError:
            continue
        if start < 0:
            continue
        out.append(text[last:start])
        out.append(repl_fn(match))
        last = end
        n += 1
    out.append(text[last:])
    return "".join(out), n


def redact_value(
    value: Any,
    catalog: RedactionCatalog,
    tool: str,
    agent_id: str,
    *,
    max_bytes_per_field: int = MAX_REDACT_BYTES_PER_FIELD,
    max_bytes_total: int = MAX_REDACT_BYTES_TOTAL,
) -> tuple[Any, list[RedactionEvent]]:
    """Recursively redact strings in a JSON-like value.

    Returns (redacted_value, events). Event ``field`` is the top-level
    field path — matched secrets never appear in events.

    GH #15: byte budget. Each string field is redacted up to
    ``max_bytes_per_field`` chars; the call redacts at most
    ``max_bytes_total`` chars. Text beyond the budget is replaced with
    ``[redacted:truncated]`` (never delivered unredacted) and reported
    as a ``_truncated`` event.
    """
    patterns = catalog.active_patterns(tool, agent_id)
    if not patterns:
        return value, []

    collected: list[RedactionEvent] = []
    budget = [max_bytes_total]  # mutable cell for the closure

    def _redact(node: Any, path: tuple) -> Any:
        if isinstance(node, str):
            top = str(path[0]) if path else "result"
            allowance = min(max_bytes_per_field, budget[0])
            if allowance <= 0:
                collected.append(RedactionEvent(
                    pattern="_truncated", token=TRUNCATED_TOKEN,
                    field=top, count=1))
                return TRUNCATED_TOKEN
            if len(node) > allowance:
                head = node[:allowance]
                new_head, events = redact_text(head, patterns)
                for event in events:
                    event.field = top
                    collected.append(event)
                collected.append(RedactionEvent(
                    pattern="_truncated", token=TRUNCATED_TOKEN,
                    field=top, count=1))
                budget[0] -= allowance
                return new_head + TRUNCATED_TOKEN
            new_text, events = redact_text(node, patterns)
            for event in events:
                event.field = top
                collected.append(event)
            budget[0] -= len(node)
            return new_text
        if isinstance(node, dict):
            return {k: _redact(v, path + (str(k),)) for k, v in node.items()}
        if isinstance(node, list):
            return [_redact(v, path + (i,)) for i, v in enumerate(node)]
        if isinstance(node, tuple):
            return tuple(_redact(v, path + (i,)) for i, v in enumerate(node))
        return node

    return _redact(value, ()), collected


def redact_ctx_for_audit(
    ctx: Any, catalog: RedactionCatalog, audit: Any = None
) -> None:
    """Redact call arguments BEFORE the audit write (NFR-DATA-001).

    Runs on every pipeline path (the pipeline calls this as its
    pre-audit hook, including for calls halted before output
    inspection). Rebinds ``ctx.args`` to the redacted copy; fires an
    audit event row only when at least one replacement happened.
    """
    catalog.ensure_seeded()
    redacted, events = redact_value(
        ctx.args, catalog, tool=ctx.tool, agent_id=ctx.agent_id)
    if not events:
        return
    ctx.args = redacted
    if audit is not None:
        fields = sorted({e.field for e in events})
        audit.append(
            agent_id=ctx.agent_id,
            tool="inspection.redaction",
            decision="allowed",
            request_id=ctx.request_id,
            reason="pii_redacted",
            redacted_args={
                "scope": "args",
                "fields": fields,
                "patterns": sorted({e.pattern for e in events}),
                "replacements": sum(e.count for e in events),
            },
        )
