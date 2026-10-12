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


def redact_code_like_secrets(text: str) -> str:
    """Redact verification codes, OTPs, API-key-shaped strings.

    Used for the evidence-subset rendered preview AND the
    execute-on-approval result summary. Recipient/payee,
    amount/currency, and audience are NOT redacted here.
    """
    if not text:
        return text
    redacted = text
    for label, pattern in _CODE_PATTERNS:
        redacted = pattern.sub(f"[redacted:{label}]", redacted)
    return redacted


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
# ---------------------------------------------------------------------

def _audience_hash(parts: Any, ring: HmacKeyRing) -> str:
    return ring.digest({"audience": parts})


def _content_hash(parts: Any, ring: HmacKeyRing) -> str:
    return ring.digest({"content": parts})


def build_evidence_subset(tool: str, args: dict[str, Any], ring: HmacKeyRing) -> dict[str, Any]:
    """Build the approver-visible evidence subset for *tool*.

    Cleartext is LIMITED to recipient/payee, amount/currency, audience,
    and the rendered preview (with code-like secrets redacted). The
    ``replay_args`` entry carries the structured args the
    execute-on-approval fallback replays server-side.
    """
    args = args or {}
    if tool == "email.send":
        to = list(args.get("to") or [])
        cc = list(args.get("cc") or [])
        bcc = list(args.get("bcc") or [])
        subject = str(args.get("subject") or "")
        body = str(args.get("body") or "")
        audience = {"to": to, "cc": cc, "bcc": bcc}
        content = {"subject": subject, "body": body}
        return {
            "tool": tool,
            "audience": audience,
            "recipients": to + cc + bcc,
            "subject": subject,
            "body_preview": redact_code_like_secrets(body),
            "audience_hash": _audience_hash(audience, ring),
            "content_hash": _content_hash(content, ring),
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
            "replay_args": {
                "to": to, "cc": cc, "bcc": bcc,
                "subject": subject, "body": redact_code_like_secrets(body),
            },
        }
    if tool == "email.settings.write":
        section = str(args.get("section") or "")
        settings_val = args.get("settings") or {}
        preview = redact_code_like_secrets(canonical_json(settings_val))
        return {
            "tool": tool,
            "section": section,
            "settings_preview": preview,
            "content_hash": _content_hash({"section": section, "settings": settings_val}, ring),
            "terms": {"payee": None, "amount": None, "currency": None, "fees": None,
                      "dates": None, "recurring": None, "cancellation": None,
                      "note": "recovery-affecting settings change (FR-PAA02-002/003)"},
            "consequence": f"Change mailbox settings section {section!r} (recovery-affecting).",
            "replay_args": {"section": section, "settings": settings_val},
        }
    if tool == "calendar.delete":
        event_id = str(args.get("event_id") or "")
        return {
            "tool": tool,
            "event_id": event_id,
            "content_hash": _content_hash({"event_id": event_id}, ring),
            "terms": {"payee": None, "amount": None, "currency": None, "fees": None,
                      "dates": None, "recurring": None, "cancellation": None,
                      "note": "destructive: no undo at the service"},
            "consequence": f"Delete calendar event {event_id!r} (destructive; no undo).",
            "replay_args": {"event_id": event_id},
        }
    if tool == "calendar.create":
        attendees = list(args.get("attendees") or [])
        title = str(args.get("title") or "")
        return {
            "tool": tool,
            "audience": {"attendees": attendees},
            "title": title,
            "start": args.get("start"), "end": args.get("end"),
            "description_preview": redact_code_like_secrets(str(args.get("description") or "")),
            "audience_hash": _audience_hash({"attendees": attendees}, ring),
            "content_hash": _content_hash(
                {"title": title, "start": args.get("start"), "end": args.get("end")}, ring),
            "terms": {"payee": None, "amount": None, "currency": None, "fees": None,
                      "dates": {"start": args.get("start"), "end": args.get("end")},
                      "recurring": None, "cancellation": None, "note": None},
            "consequence": f"Create event {title!r} with {len(attendees)} attendee(s).",
            "replay_args": {k: args.get(k) for k in
                            ("title", "start", "end", "attendees", "description", "location", "calendar_id")
                            if args.get(k) is not None},
        }
    if tool == "code.pr.open":
        body = str(args.get("body") or "")
        return {
            "tool": tool,
            "repo": args.get("repo"),
            "title": args.get("title"),
            "head": args.get("head"), "base": args.get("base"),
            "body_preview": redact_code_like_secrets(body),
            "content_hash": _content_hash(
                {"repo": args.get("repo"), "title": args.get("title"),
                 "head": args.get("head"), "base": args.get("base"), "body": body}, ring),
            "terms": {"payee": args.get("repo"), "amount": None, "currency": None, "fees": None,
                      "dates": None, "recurring": None, "cancellation": None,
                      "note": "public write action on the code host"},
            "consequence": f"Open pull request {args.get('title')!r} on {args.get('repo')}.",
            "replay_args": {k: args.get(k) for k in ("repo", "title", "head", "base")
                            if args.get(k) is not None} | {"body": redact_code_like_secrets(body)},
        }
    # Generic fallback for any other sensitive tool: audience unknown,
    # content = redacted canonical args. Replay is NOT supported for
    # tools without a dedicated builder (execute-on-approval refuses).
    preview = redact_code_like_secrets(canonical_json(args))
    return {
        "tool": tool,
        "content_hash": _content_hash(args, ring),
        "body_preview": preview,
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
    trigger_text = f"{evidence.get('subject') or ''}\n{preview_text}"
    mandate_remaining = None
    if mandate is not None and mandate.expires_at is not None:
        mandate_remaining = _format_countdown(mandate.expires_at, now)
    return {
        "approval_request_id": approval.id,
        "agent": {"id": approval.agent_id, "display_name": agent_display_name},
        "tool": approval.tool,
        "requested_at": (as_utc(approval.created_at) or approval.created_at).isoformat(),
        "expires_at": (as_utc(approval.expires_at) or approval.expires_at).isoformat(),
        "expiry_countdown": _format_countdown(approval.expires_at, now),
        "destructive": destructive,
        "mandate": {
            "id": approval.mandate_id,
            "purpose": getattr(mandate, "purpose", None),
            "remaining": mandate_remaining or "no expiry",
        },
        # Consequence summary BEFORE any free text (MF-6).
        "consequence": evidence.get("consequence", ""),
        "terms": evidence.get("terms", {}),
        "counterparty": evidence.get("counterparty", {}),
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
        "subject": evidence.get("subject"),
        "cap": {"used": cap_used, "total": cap_total,
                "label": f"{cap_used} of {cap_total} pending approvals used"},
        "policy_version": approval.policy_version,
        "untrusted_content_label": True,
    }


def render_inert_html(card: dict[str, Any]) -> str:
    """Render the card as INERT html: escaped, preformatted, no links.

    Every argument block is wrapped in <pre> with a static
    "untrusted content" badge. URLs render as plain text — this
    renderer never emits <a> tags.
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
    parts.append(section("Consequence", pre(card["consequence"])))
    terms = card.get("terms") or {}
    parts.append(section("Term sheet (PAA06)", pre("\n".join(
        f"{k}: {v if v is not None else '—'}" for k, v in terms.items()))))
    cp = card.get("counterparty") or {}
    cp_lines = [f"key: {cp.get('key')}", f"known: {cp.get('known')}",
                f"new payee: {cp.get('is_new')}"]
    if cp.get("delta"):
        cp_lines.append(f"delta vs recorded record: {cp['delta']}")
    if card.get("urgency_flags"):
        cp_lines.append(f"detected urgency language (flag, not instruction): {card['urgency_flags']}")
    if card.get("relationship_claims"):
        cp_lines.append(f"detected relationship claims (untrusted): {card['relationship_claims']}")
    parts.append(section("Counterparty evidence (PAA05)", pre("\n".join(cp_lines))))
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
