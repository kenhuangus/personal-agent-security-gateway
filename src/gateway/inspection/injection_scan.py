"""Pattern-based prompt-injection scanner over tool OUTPUTS (M5; FR-026).

Classes covered:
- instruction override ("ignore previous instructions", "new instructions:", …);
- delimiter smuggling (``<<SYS>>``, ``[SYSTEM]``, ``### Instruction``,
  fenced system blocks, ``<|im_start|>system``);
- role-play / jailbreak markers ("do anything now", "jailbreak",
  "pretend you are", "developer mode", …);
- encoded-payload hints: long base64 blobs in text fields that decode
  cleanly (unexpected binary-ish content in a text field);
- tool-output "system instruction" impersonation ("system: …",
  "confidential system prompt", "[admin override]").

On a hit the caller blocks or redacts per the per-tool
``injection_action`` policy hook ("block" default). EVERY detection is
emitted to the audit log (AC-06) — the stage handles that; this module
only reports findings.

Residuals (accepted for MVP per 00 §8 risk 4):
- novel phrasings that no pattern matches are MISSED;
- semantic / intent-based detection (LLM judge) is explicitly out of
  MVP (00 §3) — this scanner is syntactic only;
- base64 detection is heuristic: short blobs and blobs in fields that
  legitimately carry encoded content are not flagged, and a blob that
  does not decode cleanly is ignored.

Findings never echo matched text: only pattern ids, classes, and field
paths leave this module (the matched payload stays out of logs).
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from typing import Any

from .validation import walk_strings

# ---------------------------------------------------------------------
# Pattern catalog: (pattern_id, category, compiled regex)
# ---------------------------------------------------------------------

_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    # -- instruction override -------------------------------------------
    ("ignore_previous_instructions", "instruction_override", re.compile(
        r"(?i)\bignore\s+(all\s+|any\s+)?(previous|prior|above)\s+instructions?\b")),
    ("disregard_instructions", "instruction_override", re.compile(
        r"(?i)\bdisregard\s+(all\s+)?(previous|prior)\s+instructions?\b")),
    ("forget_instructions", "instruction_override", re.compile(
        r"(?i)\bforget\s+(your|all|everything).{0,20}instructions?\b")),
    ("override_safety", "instruction_override", re.compile(
        r"(?i)\boverride\s+your\s+(safety|system|core)\s+(instructions?|directives?|rules?)\b")),
    ("new_instructions", "instruction_override", re.compile(
        r"(?i)\bnew\s+(system\s+)?instructions?\s*:")),
    ("updated_directives", "instruction_override", re.compile(
        r"(?i)\bupdated\s+directives?\b")),
    # -- delimiter smuggling ---------------------------------------------
    ("sys_delimiter", "delimiter_smuggling", re.compile(
        r"<<\s*SYS\s*>>|\[\s*SYSTEM\s*\]|###\s*(system|instruction)\b",
        re.IGNORECASE)),
    ("fenced_system_block", "delimiter_smuggling", re.compile(
        r"```\s*(system|instruction)\b", re.IGNORECASE)),
    ("im_start_system", "delimiter_smuggling", re.compile(
        r"<\|im_start\|>\s*system|<\|system\|>", re.IGNORECASE)),
    # -- role-play / jailbreak --------------------------------------------
    ("do_anything_now", "roleplay_jailbreak", re.compile(
        r"(?i)\bdo\s+anything\s+now\b")),
    ("jailbreak_keyword", "roleplay_jailbreak", re.compile(
        r"(?i)\bjailbreak\b")),
    ("pretend_you_are", "roleplay_jailbreak", re.compile(
        r"(?i)\bpretend\s+(you\s+are|to\s+be)\b")),
    ("roleplay_as", "roleplay_jailbreak", re.compile(
        r"(?i)\broleplay\s+as\b")),
    ("unfiltered_mode", "roleplay_jailbreak", re.compile(
        r"(?i)\b(unfiltered|developer|god)\s+mode\b")),
    # -- system-instruction impersonation ----------------------------------
    ("system_prefix", "system_impersonation", re.compile(
        r"(?im)^\s*system\s*:")),
    ("confidential_system_prompt", "system_impersonation", re.compile(
        r"(?i)\bconfidential\s+system\s+(instruction|prompt)\b")),
    ("admin_override", "system_impersonation", re.compile(
        r"(?i)\[\s*admin(istrator)?\s+override\s*\]")),
    ("must_now_comply", "system_impersonation", re.compile(
        r"(?i)\bas\s+an?\s+(ai|language\s+model|assistant),?\s+(you|i)\s+must\s+now\b")),
]

# Base64-blob heuristic (encoded-payload hints).
_B64_BLOB = re.compile(r"[A-Za-z0-9+/]{100,}={0,2}")
_B64_MIN_DECODE_BYTES = 48


@dataclass
class InjectionFinding:
    pattern_id: str
    category: str
    field: str  # dotted path into the result, e.g. "messages[2].body"
    spans: list[tuple[int, int]] = field(default_factory=list)


@dataclass
class ScanResult:
    findings: list[InjectionFinding] = field(default_factory=list)

    @property
    def hit(self) -> bool:
        return bool(self.findings)

    @property
    def pattern_ids(self) -> list[str]:
        return sorted({f.pattern_id for f in self.findings})


def _field_path(path: tuple) -> str:
    parts: list[str] = []
    for el in path:
        if isinstance(el, int):
            parts.append(f"[{el}]")
        else:
            if parts:
                parts.append(".")
            parts.append(str(el))
    return "".join(parts)


def _b64_spans(text: str) -> list[tuple[int, int]]:
    """Spans of base64 blobs that decode cleanly (encoded-payload hint)."""
    spans: list[tuple[int, int]] = []
    for match in _B64_BLOB.finditer(text):
        blob = match.group(0)
        try:
            # validate=True rejects non-alphabet chars; length is sane.
            decoded = base64.b64decode(blob, validate=True)
        except (binascii.Error, ValueError):
            continue
        if len(decoded) >= _B64_MIN_DECODE_BYTES:
            spans.append(match.span())
    return spans


def scan_output(result: Any, tool: str = "") -> ScanResult:  # noqa: ARG001
    """Scan a tool OUTPUT for prompt-injection patterns.

    Pure function: no I/O, no policy lookup. Returns findings; the
    caller (InspectOutputStage) decides block vs redact and logs.
    """
    findings: list[InjectionFinding] = []
    for path, text in walk_strings(result):
        field_path = _field_path(path) or "result"
        for pattern_id, category, rx in _PATTERNS:
            spans = [m.span() for m in rx.finditer(text)]
            if spans:
                findings.append(
                    InjectionFinding(
                        pattern_id=pattern_id,
                        category=category,
                        field=field_path,
                        spans=spans,
                    )
                )
        b64 = _b64_spans(text)
        if b64:
            findings.append(
                InjectionFinding(
                    pattern_id="encoded_payload_blob",
                    category="encoded_payload",
                    field=field_path,
                    spans=b64,
                )
            )
    return ScanResult(findings=findings)


def redact_findings(result: Any, scan: ScanResult) -> Any:
    """Return a copy of *result* with matched injection spans redacted.

    Spans are applied per field from the end so offsets stay valid.
    The replacement is a fixed token — matched payload never appears
    in the redacted output.
    """
    by_field: dict[str, list[tuple[int, int]]] = {}
    for finding in scan.findings:
        by_field.setdefault(finding.field, []).extend(finding.spans)

    def _redact(value: Any, path: tuple) -> Any:
        if isinstance(value, str):
            key = _field_path(path) or "result"
            spans = sorted(by_field.get(key, []), reverse=True)
            for start, end in spans:
                value = value[:start] + "[redacted:injection]" + value[end:]
            return value
        if isinstance(value, dict):
            return {k: _redact(v, path + (str(k),)) for k, v in value.items()}
        if isinstance(value, list):
            return [_redact(v, path + (i,)) for i, v in enumerate(value)]
        if isinstance(value, tuple):
            return tuple(_redact(v, path + (i,)) for i, v in enumerate(value))
        return value

    return _redact(result, ())
