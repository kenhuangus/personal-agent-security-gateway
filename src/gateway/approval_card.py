"""Approval card data model (02 §4.4; Fix B, MF-6).

Sections: mandate purpose + remaining duration; consequence summary
BEFORE free text; term sheet (PAA06); counterparty evidence (PAA05:
recipient, claim source, delta vs recorded record, urgency/relationship
flags — agent assertions rendered untrusted, never evidence);
incentives (PAA09, no urgency language); audience + content preview
(PAA07 — the approval binds audience-hash + content-hash); cap state
("3 of 5"); expiry countdown.

INERT-RENDERING CONTRACT (MF-6):
- Every argument block renders as preformatted monospace text.
- NO rich rendering, NO clickable links: ``render_inert_html`` escapes
  everything and never emits <a> tags (URLs render as plain text).
- A static "untrusted content" label marks every argument block.
- Code-like secrets (verification codes, OTPs, API-key-shaped strings)
  are redacted even in the evidence preview (FR-PAA02-001) — recipient,
  amount/currency, and audience stay cleartext.
- Because the preview is redacted but replay sends the RAW body, the
  evidence carries ``preview_redacted`` / ``preview_redacted_count``
  (set when redaction changed the preview), and the card renders a
  prominent warning for the raw-body tools (``email.send`` /
  ``code.pr.open``): "preview redacted N secrets — raw body will be
  sent verbatim". The approver must never mistake the redacted
  preview for the bytes that execute (WYSIWYE).
- No urgency language appears anywhere on the card (FR-PAA09-001):
  urgency PHRASES from the trigger content are reported as detected
  FLAGS, never repeated as calls to action.

Urgency/relationship/sponsor detection here is PROVISIONAL (M3):
pattern-based so the card can carry the FR-PAA05-003/FR-PAA09-001
sections. The M5 inspection pipeline owns the hardened detectors
(false-urgency flagging FR-PAA09-002, code-artifact redaction
FR-PAA02-001); when it lands, the card consumes its flags instead of
these patterns.
"""

from __future__ import annotations

import datetime as dt
import html
import re
from typing import Any, Optional

from .hmac_util import HmacKeyRing, canonical_json
from .models import as_utc


def format_cents(amount_cents: int) -> str:
    """Render integer cents as $48,000.00 — never via floats."""
    sign = "-" if amount_cents < 0 else ""
    dollars, rem = divmod(abs(int(amount_cents)), 100)
    return f"{sign}${dollars:,}.{rem:02d}"


def build_money_evidence(
    tool: str, args: dict[str, Any], money: dict[str, Any]
) -> dict[str, Any]:
    """Evidence subset for ``payment.*`` (Pillar 1 §1.7).

    Consequence summary first ("Pay $48,000.00 to IRS (verified payee,
    14 prior payments)" — amount rendered from integer cents, never
    floats); term sheet (mandate scope, remaining daily/monthly
    budget, velocity usage); counterparty evidence (verification
    state, verified-by/at, details snapshot — last-4 only, delta vs
    snapshot); quorum header; drift note (extension sets it via
    money["drift_notes"]); judge advisory (flags only).
    """
    args = args or {}
    money = money or {}
    card = money.get("money_card") or {}
    amount_cents = int(args.get("amount_cents") or 0)
    payee_key = str(args.get("payee_key") or "")
    cp = dict(card.get("counterparty") or {})
    label = cp.get("label") or payee_key
    verification = cp.get("verification_state") or "unlisted"
    prior = card.get("prior_payments")
    prior_text = f", {prior} prior payment{'s' if prior != 1 else ''}" if prior else ""
    new_flag = "new counterparty" if money.get("new_counterparty") else ""
    quorum_required = money.get("quorum_required") or 1
    consequence = (
        f"Pay {format_cents(amount_cents)} to {label} "
        f"({verification} payee{prior_text})"
    ).strip()
    if tool == "payment.cancel":
        consequence = (
            f"Cancel payment {args.get('payment_id')!r} "
            "(reversal; always requires approval)"
        )
    terms: dict[str, Any] = {
        "payee": label,
        "payee_key": payee_key,
        "amount": format_cents(amount_cents),
        "currency": args.get("currency") or "USD",
        "fees": None,
        "dates": None,
        "recurring": None,
        "cancellation": None,
        "remaining_daily_budget": card.get("remaining_daily"),
        "remaining_monthly_budget": card.get("remaining_monthly"),
        "velocity": card.get("velocity_used"),
        "quorum": (
            f"{quorum_required} of {quorum_required} distinct approvers"
            if quorum_required > 1 else "single approver"
        ),
        "new_counterparty": new_flag or None,
        "memo": redact_code_like_secrets(str(args.get("memo") or "")) or None,
        "dry_run": bool(args.get("dry_run", False)),
        "note": "synthetic dollars only — the gateway never custodies funds",
    }
    return {
        "tool": tool,
        "consequence": consequence,
        "terms": terms,
        # The money pack's allowlist snapshot (last-4 details only) —
        # richer than the generic counterparty snapshot, so the card
        # renders it directly.
        "counterparty": {
            "key": payee_key,
            "listed": cp.get("listed", False),
            "label": label,
            "verification_state": verification,
            "verified_by": cp.get("verified_by"),
            "verified_at": cp.get("verified_at"),
            "details_snapshot": cp.get("details_snapshot") or {},
            "record_version": cp.get("record_version"),
            "is_new": money.get("new_counterparty", False),
            "claim_source": "not provided in MVP",
        },
        "quorum": {
            "required": quorum_required,
            "progress": None,  # filled at render time from apr.approvals
        },
        "drift_notes": money.get("drift_notes"),
        "money_rule_id": money.get("money_rule_id"),
        # execute-on-approval is disabled for payment.* (the replay
        # path refuses without a builder): money calls use the agent
        # re-invoke path only.
        "replay_args": None,
    }

# ---------------------------------------------------------------------
# Code-like secret redaction (FR-PAA02-001) — provisional M3 patterns.
# ---------------------------------------------------------------------

_CODE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # 6-8 digit verification codes / OTPs (labeled or bare).
    ("code", re.compile(r"(?i)\b(?:verification\s*code|otp|one[\s-]?time\s*(?:pass)?code|2fa\s*code)\b\s*[:=]?\s*([0-9]{4,8})\b")),
    ("code", re.compile(r"\b[0-9]{6,8}\b")),
    # API-key-shaped strings: long base64-ish tokens, sk-/ghp-/xox- prefixes.
    ("api_key", re.compile(r"\b(?:sk|ghp|gho|xox[pbar]|AIza)[-_A-Za-z0-9]{16,}\b")),
    ("api_key", re.compile(r"\b[A-Za-z0-9+/]{32,}={0,2}\b")),
)

_BARE_CODE_RE = re.compile(r"\b[0-9]{6,8}\b")


def redact_code_like_secrets_with_count(text: str) -> tuple[str, int]:
    """Redact verification codes, OTPs, API-key-shaped strings.

    Returns ``(redacted_text, replacement_count)``. The count is the
    number of redaction substitutions applied — the ``preview_redacted``
    signal is derived from it (count > 0 means the preview differs
    from the raw bytes that replay will send).
    """
    if not text:
        return text, 0
    redacted = text
    total = 0
    for label, pattern in _CODE_PATTERNS:
        redacted, n = pattern.subn(f"[redacted:{label}]", redacted)
        total += n
    return redacted, total


def redact_code_like_secrets(text: str) -> str:
    """Redact verification codes, OTPs, API-key-shaped strings.

    Used for the evidence-subset rendered preview AND the
    execute-on-approval result summary. Recipient/payee,
    amount/currency, and audience are NOT redacted here.
    """
    return redact_code_like_secrets_with_count(text)[0]


#: Tools whose execute-on-approval replay sends the raw body verbatim
#: (``replay_args["body"]``), while the card shows only the redacted
#: ``body_preview``. These are the tools that MUST carry the
#: preview-redacted warning on the card (WYSIWYE).
RAW_BODY_TOOLS: frozenset[str] = frozenset({"email.send", "code.pr.open"})


# ---------------------------------------------------------------------
# Provisional flag detectors (M3; M5 hardens in the inspection pipeline)
# ---------------------------------------------------------------------

_URGENCY_RES = (
    re.compile(r"\b(urgent|urgently|asap|a\.s\.a\.p\.|immediately|right away|act now|"
               r"time[- ]sensitive|expires? soon|limited time|last chance|final notice|"
               r"respond (within|in \d+)|deadline (today|tonight))\b", re.IGNORECASE),
)
_RELATIONSHIP_RES = (
    re.compile(r"\b(as (your|the) (boss|manager|ceo|supervisor)|your (wife|husband|partner|"
               r"colleague|assistant) (asked|said|told)|trust me|between us|do not tell|"
               r"keep this (confidential|private|between us))\b", re.IGNORECASE),
)
_SPONSOR_RES = (
    re.compile(r"\b(sponsored|promotion(al)?|affiliate (link|code)|use (my|this) code|"
               r"referral (link|code|bonus)|paid placement|ad\s*[:#])\b", re.IGNORECASE),
)


def detect_urgency_flags(text: str) -> list[str]:
    """False-urgency patterns in trigger content (FR-PAA09-002, M3 patterns)."""
    return sorted({m.group(0) for rx in _URGENCY_RES for m in rx.finditer(text or "")})


def detect_relationship_claims(text: str) -> list[str]:
    """Deceptive relationship-claim language (FR-PAA05-003, M3 patterns)."""
    return sorted({m.group(0) for rx in _RELATIONSHIP_RES for m in rx.finditer(text or "")})


def detect_sponsor_signals(text: str) -> list[str]:
    """Sponsor/placement signals for the incentives section (FR-PAA09-001)."""
    return sorted({m.group(0) for rx in _SPONSOR_RES for m in rx.finditer(text or "")})


# ---------------------------------------------------------------------
# Evidence subset (02 §2.8 step 4): per-tool builders.
#
# Each builder returns a dict that is BOTH the card's evidence AND
# replay-complete for the execute-on-approval fallback (MF-11): the
# server-side replay rebuilds the call args from this subset alone, so
# what Ken sees on the card is exactly what executes (WYSIWYE).
#
# HASH-BINDING INVARIANT (issue #3): `content_hash` is computed over
# EXACTLY the `replay_args` dict that will execute — the single source
# of truth. The hash therefore binds the bytes that execute (and can
# be recomputed at replay time), never bytes that never run.
# Redaction applies to display previews (`body_preview`,
# `*_preview`) ONLY — never to `replay_args`. Because the preview
# then differs from what executes, each builder also records
# `preview_redacted` / `preview_redacted_count` so the card can warn
# the approver that the raw body will be sent verbatim (WYSIWYE).
# ---------------------------------------------------------------------

def _audience_hash(parts: Any, ring: HmacKeyRing) -> str:
    return ring.digest({"audience": parts})


def _content_hash(parts: Any, ring: HmacKeyRing) -> str:
    return ring.digest({"content": parts})


def build_evidence_subset(
    tool: str, args: dict[str, Any], ring: HmacKeyRing,
    money: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Build the approver-visible evidence subset for *tool*.

    Cleartext is LIMITED to recipient/payee, amount/currency, audience,
    and the rendered preview (with code-like secrets redacted). The
    ``replay_args`` entry carries the structured args the
    execute-on-approval fallback replays server-side, and
    ``content_hash`` is computed over exactly that dict (issue #3).

    ``money`` (Pillar 1): the money stage's evidence inputs for
    ``payment.*`` tools (money_state/money_card/new_counterparty/
    quorum_required from the threshold ladder).
    """
    args = args or {}
    if tool.startswith("payment."):
        return build_money_evidence(tool, args, money or {})
    if tool == "email.send":
        to = list(args.get("to") or [])
        cc = list(args.get("cc") or [])
        bcc = list(args.get("bcc") or [])
        subject = str(args.get("subject") or "")
        body = str(args.get("body") or "")
        audience = {"to": to, "cc": cc, "bcc": bcc}
        replay_args = {
            "to": to, "cc": cc, "bcc": bcc,
            "subject": subject, "body": body,
        }
        body_preview, n_redacted = redact_code_like_secrets_with_count(body)
        return {
            "tool": tool,
            "audience": audience,
            "recipients": to + cc + bcc,
            "subject": subject,
            "body_preview": body_preview,
            "preview_redacted": n_redacted > 0,
            "preview_redacted_count": n_redacted,
            "audience_hash": _audience_hash(audience, ring),
            "content_hash": _content_hash(replay_args, ring),
            "terms": {
                "payee": to[0] if to else None,
                "amount": None, "currency": None, "fees": None,
                "dates": None, "recurring": None, "cancellation": None,
                "note": "not applicable to email.send",
            },
            "consequence": (
                f"Send email to {len(to)} recipient(s)"
                + (f" (+{len(cc)} cc, +{len(bcc)} bcc)" if cc or bcc else "")
                + f". Subject: {subject[:80]!r}."
            ),
            "replay_args": replay_args,
        }
    if tool == "email.settings.write":
        section = str(args.get("section") or "")
        settings_val = args.get("settings") or {}
        preview, n_redacted = redact_code_like_secrets_with_count(
            canonical_json(settings_val))
        replay_args = {"section": section, "settings": settings_val}
        return {
            "tool": tool,
            "section": section,
            "settings_preview": preview,
            "preview_redacted": n_redacted > 0,
            "preview_redacted_count": n_redacted,
            "content_hash": _content_hash(replay_args, ring),
            "terms": {"payee": None, "amount": None, "currency": None, "fees": None,
                      "dates": None, "recurring": None, "cancellation": None,
                      "note": "recovery-affecting settings change (FR-PAA02-002/003)"},
            "consequence": f"Change mailbox settings section {section!r} (recovery-affecting).",
            "replay_args": replay_args,
        }
    if tool == "calendar.delete":
        event_id = str(args.get("event_id") or "")
        replay_args = {"event_id": event_id}
        return {
            "tool": tool,
            "event_id": event_id,
            "preview_redacted": False,
            "preview_redacted_count": 0,
            "content_hash": _content_hash(replay_args, ring),
            "terms": {"payee": None, "amount": None, "currency": None, "fees": None,
                      "dates": None, "recurring": None, "cancellation": None,
                      "note": "destructive: no undo at the service"},
            "consequence": f"Delete calendar event {event_id!r} (destructive; no undo).",
            "replay_args": replay_args,
        }
    if tool == "calendar.create":
        attendees = list(args.get("attendees") or [])
        title = str(args.get("title") or "")
        replay_args = {k: args.get(k) for k in
                       ("title", "start", "end", "attendees", "description", "location", "calendar_id")
                       if args.get(k) is not None}
        description_preview, n_redacted = redact_code_like_secrets_with_count(
            str(args.get("description") or ""))
        return {
            "tool": tool,
            "audience": {"attendees": attendees},
            "title": title,
            "start": args.get("start"), "end": args.get("end"),
            "description_preview": description_preview,
            "preview_redacted": n_redacted > 0,
            "preview_redacted_count": n_redacted,
            "audience_hash": _audience_hash({"attendees": attendees}, ring),
            "content_hash": _content_hash(replay_args, ring),
            "terms": {"payee": None, "amount": None, "currency": None, "fees": None,
                      "dates": {"start": args.get("start"), "end": args.get("end")},
                      "recurring": None, "cancellation": None, "note": None},
            "consequence": f"Create event {title!r} with {len(attendees)} attendee(s).",
            "replay_args": replay_args,
        }
    if tool == "code.pr.open":
        body = str(args.get("body") or "")
        replay_args = {k: args.get(k) for k in ("repo", "title", "head", "base")
                       if args.get(k) is not None}
        replay_args["body"] = body
        body_preview, n_redacted = redact_code_like_secrets_with_count(body)
        return {
            "tool": tool,
            "repo": args.get("repo"),
            "title": args.get("title"),
            "head": args.get("head"), "base": args.get("base"),
            "body_preview": body_preview,
            "preview_redacted": n_redacted > 0,
            "preview_redacted_count": n_redacted,
            "content_hash": _content_hash(replay_args, ring),
            "terms": {"payee": args.get("repo"), "amount": None, "currency": None, "fees": None,
                      "dates": None, "recurring": None, "cancellation": None,
                      "note": "public write action on the code host"},
            "consequence": f"Open pull request {args.get('title')!r} on {args.get('repo')}.",
            "replay_args": replay_args,
        }
    # Generic fallback for any other sensitive tool: audience unknown,
    # content = redacted canonical args. Replay is NOT supported for
    # tools without a dedicated builder (execute-on-approval refuses).
    preview, n_redacted = redact_code_like_secrets_with_count(canonical_json(args))
    return {
        "tool": tool,
        "content_hash": _content_hash(args, ring),
        "body_preview": preview,
        "preview_redacted": n_redacted > 0,
        "preview_redacted_count": n_redacted,
        "terms": {"payee": None, "amount": None, "currency": None, "fees": None,
                  "dates": None, "recurring": None, "cancellation": None,
                  "note": "no dedicated evidence builder for this tool"},
        "consequence": f"Sensitive call to {tool} (no dedicated evidence builder).",
        "replay_args": None,  # execute-on-approval refuses without a builder
    }


def build_replay_args(evidence: dict[str, Any]) -> dict[str, Any]:
    """Rebuild the call args for execute-on-approval (MF-11, WYSIWYE).

    Raises ValueError when the tool has no dedicated evidence builder:
    the fallback refuses to guess rather than replay something Ken did
    not see on the card.
    """
    replay = (evidence or {}).get("replay_args")
    if not replay:
        raise ValueError(
            f"execute-on-approval refused for {evidence.get('tool')}: "
            "no replay-complete evidence builder for this tool"
        )
    return dict(replay)


# ---------------------------------------------------------------------
# Card assembly (02 §4.4)
# ---------------------------------------------------------------------

def _format_countdown(expires_at: dt.datetime, now: dt.datetime) -> str:
    remaining = (as_utc(expires_at) or expires_at) - now
    total = int(remaining.total_seconds())
    if total <= 0:
        return "expired"
    minutes, seconds = divmod(total, 60)
    if minutes >= 60:
        hours, minutes = divmod(minutes, 60)
        return f"{hours}h {minutes}m remaining"
    return f"{minutes}m {seconds:02d}s remaining"


def build_card(
    approval: Any,  # ApprovalRequest
    *,
    agent_display_name: str,
    mandate: Any | None,  # Mandate | None
    cap_used: int,
    cap_total: int,
    recorded_criteria: dict[str, Any] | None,
    destructive: bool,
    now: dt.datetime,
) -> dict[str, Any]:
    """Assemble the full card sections per 02 §4.4.

    ``approval.evidence_subset`` must already contain the counterparty
    snapshot under ``evidence_subset["counterparty"]`` (written at
    creation time).
    """
    evidence = approval.evidence_subset or {}
    preview_text = evidence.get("body_preview") or evidence.get("settings_preview") or ""
    # WYSIWYE redaction signal: prefer the stored evidence signal;
    # legacy evidence (created before the signal existed) is
    # recomputed from the replay body, which still holds the raw
    # bytes. The signal must never be inferred from the redacted
    # preview itself — the preview alone cannot tell what it hid.
    preview_redacted = evidence.get("preview_redacted")
    preview_redacted_count = evidence.get("preview_redacted_count") or 0
    if preview_redacted is None:
        if approval.tool in RAW_BODY_TOOLS:
            raw_body = str((evidence.get("replay_args") or {}).get("body") or "")
            _, preview_redacted_count = redact_code_like_secrets_with_count(raw_body)
            preview_redacted = preview_redacted_count > 0
        else:
            preview_redacted = False
            preview_redacted_count = 0
    else:
        preview_redacted = bool(preview_redacted)
        try:
            preview_redacted_count = int(preview_redacted_count)
        except (TypeError, ValueError):
            preview_redacted_count = 0
    trigger_text = f"{evidence.get('subject') or ''}\n{preview_text}"
    mandate_remaining = None
    if mandate is not None and mandate.expires_at is not None:
        mandate_remaining = _format_countdown(mandate.expires_at, now)
    # Pillar 1 §2: quorum header for the card.
    quorum_required = getattr(approval, "quorum_required", 1) or 1
    slots = list(getattr(approval, "approvals", None) or [])
    quorum = None
    if quorum_required > 1:
        quorum = {
            "required": quorum_required,
            "progress": f"{len(slots)} / {quorum_required} approvals",
            "header": f"Needs {quorum_required} of {quorum_required} distinct approvers.",
            "slots": [
                {
                    "approver_index": s.get("approver_index"),
                    "admin_id": s.get("admin_id"),
                    "decided_at": s.get("decided_at"),
                    "auth_method": s.get("auth_method"),
                }
                for s in slots
            ],
            "awaiting": quorum_required - len(slots),
            # The evidence is frozen at request creation: the hash lets
            # the approver verify they signed exactly this context.
            "evidence_frozen": bool(getattr(approval, "evidence_hash", None)),
            "evidence_hash": getattr(approval, "evidence_hash", None),
            # Delegation chain (no-self-approval on delegated mandates).
            "delegated": (
                getattr(mandate, "parent_mandate_id", None) is not None
                if mandate is not None else False
            ),
            "delegated_by": getattr(mandate, "created_by", None) if mandate else None,
        }
    card = {
        "approval_request_id": approval.id,
        "agent": {"id": approval.agent_id, "display_name": agent_display_name},
        "tool": approval.tool,
        "requested_at": (as_utc(approval.created_at) or approval.created_at).isoformat(),
        "expires_at": (as_utc(approval.expires_at) or approval.expires_at).isoformat(),
        "expiry_countdown": _format_countdown(approval.expires_at, now),
        "destructive": destructive,
        "quorum": quorum,
        "mandate": {
            "id": approval.mandate_id,
            "purpose": getattr(mandate, "purpose", None),
            "remaining": mandate_remaining or "no expiry",
        },
        # Consequence summary BEFORE any free text (MF-6).
        "consequence": evidence.get("consequence", ""),
        "terms": evidence.get("terms", {}),
        "counterparty": evidence.get("counterparty", {}),
        # Judge advisory risk assessment (stored on the record by
        # approvals._create_request when the judge scored the call).
        # None for records created without the judge; the card then
        # omits the section (rendered only when present).
        "judge_risk": evidence.get("judge_risk"),
        "urgency_flags": detect_urgency_flags(trigger_text),
        "relationship_claims": detect_relationship_claims(trigger_text),
        "incentives": {
            "sponsor_signals": detect_sponsor_signals(trigger_text),
            "recorded_criteria": recorded_criteria,
            "trigger_source": "not provided in MVP",
            "note": "Spending limits are not a substitute for counterparty verification (FR-PAA05-004).",
        },
        "audience": evidence.get("audience", {}),
        "audience_hash": evidence.get("audience_hash"),
        "content_hash": evidence.get("content_hash"),
        "content_preview": preview_text,
        # True when redaction changed the preview: the card shows
        # redacted text but replay sends the raw body verbatim.
        "preview_redacted": preview_redacted,
        "preview_redacted_count": preview_redacted_count,
        "subject": evidence.get("subject"),
        "cap": {"used": cap_used, "total": cap_total,
                "label": f"{cap_used} of {cap_total} pending approvals used"},
        "policy_version": approval.policy_version,
        "untrusted_content_label": True,
        # Pillar 1 §3.5 (extension): drift signals that forced step-up.
        "drift_notes": evidence.get("drift_notes"),
    }
    return card


def render_inert_html(card: dict[str, Any]) -> str:
    """Render the card as INERT html: escaped, preformatted, no links.

    Every argument block is wrapped in <pre> with a static
    "untrusted content" badge. URLs render as plain text — this
    renderer never emits <a> tags.

    For the raw-body tools (``RAW_BODY_TOOLS``) whose preview was
    redacted, a prominent warning section is rendered immediately
    after the consequence: the preview hides secret(s), but approval
    sends the original unredacted body verbatim.
    """
    def pre(text: str) -> str:
        return (
            '<div class="untrusted">⚠ untrusted content — arguments render as inert text</div>'
            f"<pre class=\"args\">{html.escape(text or '')}</pre>"
        )

    def section(title: str, inner: str) -> str:
        return f"<h3>{html.escape(title)}</h3>\n{inner}"

    parts: list[str] = []
    m = card["mandate"]
    parts.append(section("Mandate", pre(
        f"purpose: {m['purpose']}\nremaining: {m['remaining']}")))
    # Pillar 1 §2: quorum header (approvals.html renders the same data
    # in the queue; the inert card carries the frozen-evidence note).
    quorum = card.get("quorum")
    if quorum:
        q_lines = [
            quorum["header"],
            f"Progress: {quorum['progress']}",
        ]
        for s in quorum["slots"]:
            q_lines.append(
                f"approver {s['approver_index']}: {s['admin_id']} "
                f"at {s['decided_at']} ({s['auth_method']})"
            )
        for _ in range(quorum["awaiting"]):
            q_lines.append("awaiting approver…")
        if quorum["evidence_frozen"]:
            q_lines.append(
                "Evidence frozen at request creation "
                f"(hash {str(quorum['evidence_hash'])[:16]}…): "
                "a mandate withdrawal, material policy change, or "
                "counterparty-record change expires this request "
                "instead of letting it be signed stale."
            )
        if quorum["delegated"]:
            q_lines.append(
                f"Delegated mandate (chain: {quorum['delegated_by']} → "
                "agent): the delegator cannot be an approver."
            )
        parts.append(section("Quorum", pre("\n".join(q_lines))))
    parts.append(section("Consequence", pre(card["consequence"])))
    # WYSIWYE warning: the approver sees the redacted preview, but
    # replay sends the raw body verbatim. Surface this BEFORE the
    # preview so approval is never granted on the mistaken belief
    # that the redacted text is what executes. Only for the
    # raw-body tools — other tools never replay a redacted body.
    if card.get("tool") in RAW_BODY_TOOLS and card.get("preview_redacted"):
        try:
            _count = int(card.get("preview_redacted_count") or 0)
        except (TypeError, ValueError):
            _count = 0
        if _count > 0:
            _headline = (
                f"preview redacted {_count} secrets — "
                "raw body will be sent verbatim"
            )
        else:
            _headline = "preview redacted secrets — raw body will be sent verbatim"
        parts.append(section("⚠ WARNING — preview redacted", pre(
            f"⚠ WARNING: {_headline}\n"
            "The preview below hides secret(s) that redaction removed. "
            "Approving sends the ORIGINAL unredacted body exactly as the "
            "agent submitted it — including the hidden secret(s). "
            "Do not approve unless the full raw body is safe to send."
        )))
    terms = card.get("terms") or {}
    parts.append(section("Term sheet (PAA06)", pre("\n".join(
        f"{k}: {v if v is not None else '—'}" for k, v in terms.items()))))
    cp = card.get("counterparty") or {}
    cp_lines = [f"key: {cp.get('key')}", f"known: {cp.get('known')}",
                f"new payee: {cp.get('is_new')}"]
    # Pillar 1 money evidence: allowlist snapshot (last-4 details only).
    if cp.get("verification_state"):
        cp_lines.append(f"verification: {cp.get('verification_state')}")
    if cp.get("verified_by"):
        cp_lines.append(
            f"verified by {cp.get('verified_by')} at {cp.get('verified_at')}")
    if cp.get("details_snapshot"):
        cp_lines.append(f"details (last-4 only): {cp['details_snapshot']}")
    if cp.get("record_version"):
        cp_lines.append(f"allowlist record version: {cp.get('record_version')}")
    if card.get("drift_notes"):
        cp_lines.append(f"drift (step-up reason): {card['drift_notes']}")
    if cp.get("delta"):
        cp_lines.append(f"delta vs recorded record: {cp['delta']}")
    if card.get("urgency_flags"):
        cp_lines.append(f"detected urgency language (flag, not instruction): {card['urgency_flags']}")
    if card.get("relationship_claims"):
        cp_lines.append(f"detected relationship claims (untrusted): {card['relationship_claims']}")
    if cp.get("judge_signals"):
        cp_lines.append(f"judge counterparty signals (advisory): {cp['judge_signals']}")
    parts.append(section("Counterparty evidence (PAA05)", pre("\n".join(cp_lines))))
    if card.get("judge_risk"):
        jr = card["judge_risk"]
        parts.append(section("Judge risk assessment (advisory)", pre(
            f"level: {jr.get('level')}\n"
            f"score: {jr.get('score')}\n"
            f"summary: {jr.get('summary')}\n"
            f"escalated: {jr.get('escalated')}\n"
            "Advisory only: this assessment added friction (step-up) "
            "but never overrides a policy decision.")))
    inc = card.get("incentives") or {}
    parts.append(section("Incentives (PAA09)", pre(
        f"sponsor/placement signals: {inc.get('sponsor_signals') or 'none detected'}\n"
        f"recorded criteria: {inc.get('recorded_criteria') or 'none recorded'}\n"
        f"trigger source: {inc.get('trigger_source')}\n"
        f"{inc.get('note', '')}")))
    audience = card.get("audience") or {}
    parts.append(section("Audience + content preview (PAA07)", pre(
        f"audience: {audience}\n"
        f"audience-hash: {card.get('audience_hash')}\n"
        f"content-hash: {card.get('content_hash')}\n"
        f"--- rendered message ---\n{card.get('content_preview', '')}")))
    cap = card["cap"]
    parts.append(
        f"<p><strong>Cap state:</strong> {html.escape(cap['label'])}"
        f" &nbsp;|&nbsp; <strong>Expires:</strong> {html.escape(card['expiry_countdown'])}</p>"
    )
    return "\n".join(parts)
