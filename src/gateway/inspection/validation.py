"""Hardened input validation (M5; FR-025; 00 §4 M5; 02 §2.3).

Extends the M2 minimal validator (JSON Schema draft 2020-12 subset)
with:

- strict ``format`` validators: RFC 3339 ``date-time`` (a bare date
  like ``2026-10-14`` is rejected — it is not a date-time) and a
  stricter ``email`` shape;
- ``additionalProperties: false`` rejection where the tool schema opts
  in (native JSON Schema; this module only guarantees the checker
  honors it);
- canonicalization before hashing: recursive key sorting plus
  integral-float normalization (``1.0`` → ``1``) applied in place, so
  immaterial diffs do not change the HMAC argument hash. The actual
  hashing still goes through ``hmac_util.canonical_json`` (sort_keys),
  so this is belt-and-braces, consistent on every pipeline pass;
- injection-oriented constraints: control characters (C0 except
  tab/LF/CR, plus DEL) are rejected in string fields;
- per-tool stricter patterns where the schema declares them: the
  standard JSON Schema ``pattern`` keyword is honored (native); tools
  opt in by declaring ``pattern`` on string fields.

Every failure names the offending FIELD only — never its value
(``invalid_input`` per 02 §2.7 / 04 NH-2).
"""

from __future__ import annotations

import datetime as dt
import json
import re
from typing import Any, Optional

from jsonschema import FormatChecker, SchemaError, ValidationError
from jsonschema import validate as jsonschema_validate


# ---------------------------------------------------------------------
# Strict format checkers
# ---------------------------------------------------------------------

_RFC3339_DATETIME = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$"
)
_STRICT_EMAIL = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


def _is_rfc3339_datetime(value: str) -> bool:
    if not isinstance(value, str) or not _RFC3339_DATETIME.match(value):
        return False
    try:
        # Semantic check: month/day ranges, leap years, hour bounds.
        dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def _is_strict_email(value: str) -> bool:
    return isinstance(value, str) and bool(_STRICT_EMAIL.match(value))


STRICT_FORMAT_CHECKER = FormatChecker()


@STRICT_FORMAT_CHECKER.checks("date-time")
def _check_date_time(value: Any) -> bool:  # noqa: ANN001
    # Non-strings are not this format's business (type errors are
    # reported by the "type" keyword); only validate strings strictly.
    if not isinstance(value, str):
        return True
    return _is_rfc3339_datetime(value)


@STRICT_FORMAT_CHECKER.checks("email")
def _check_email(value: Any) -> bool:  # noqa: ANN001
    if not isinstance(value, str):
        return True
    return _is_strict_email(value)


# ---------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------

def validate_against_schema(schema: dict[str, Any], args: Any) -> Optional[str]:
    """Validate *args* against *schema*.

    Returns the offending field name on failure, ``None`` on success.
    Field naming follows the pipeline's ``_validation_field`` rule:
    the top-level path element, never the value.

    GH #14: total — a ``SchemaError`` (a bad TOOL schema, a server
    bug) is also a validation failure, never an unhandled crash. The
    offending "field" is ``"arguments"`` then; the schema problem is
    logged server-side by the caller.
    """
    try:
        jsonschema_validate(
            instance=args,
            schema=schema,
            format_checker=STRICT_FORMAT_CHECKER,
        )
    except ValidationError as exc:
        return _field_name(exc)
    except SchemaError:
        return "arguments"
    return None


# ---------------------------------------------------------------------
# Ingress bounds: JSON depth + serialized size (GH #14)
# ---------------------------------------------------------------------
# The walkers (walk_strings, canonicalize_args, the redaction walkers,
# the injection scanner) are recursive over agent-supplied JSON, and
# JSON parses fine at any depth. A deeply nested payload would raise
# RecursionError out of ValidateInputsStage — before the terminal audit
# stage, so with no error envelope and no audit row. Enforce these
# bounds FIRST, iteratively (no recursion), and reject with
# invalid_input.

#: Maximum nesting depth of agent-supplied arguments.
MAX_JSON_DEPTH = 32

#: Maximum serialized size of agent-supplied arguments (bytes).
MAX_ARGS_BYTES = 256 * 1024  # 256 KiB


def json_depth(value: Any) -> int:
    """Nesting depth of a JSON-like value (iterative; never recurses)."""
    depth = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        node, level = stack.pop()
        if level > depth:
            depth = level
        if isinstance(node, dict):
            stack.extend((v, level + 1) for v in node.values())
        elif isinstance(node, (list, tuple)):
            stack.extend((v, level + 1) for v in node)
    return depth


def check_json_limits(args: Any) -> Optional[str]:
    """Return a violation description when *args* exceed ingress bounds.

    None when the payload is within bounds. The description names the
    bound, never argument values.
    """
    depth = json_depth(args)
    if depth > MAX_JSON_DEPTH:
        return f"arguments exceed max JSON depth {MAX_JSON_DEPTH} (depth {depth})"
    try:
        size = len(json.dumps(args, separators=(",", ":"), default=str).encode("utf-8"))
    except (TypeError, ValueError):
        # Not JSON-serializable at all: invalid input, not a crash.
        return "arguments are not JSON-serializable"
    if size > MAX_ARGS_BYTES:
        return f"arguments exceed max size {MAX_ARGS_BYTES} bytes ({size} bytes)"
    return None


def _field_name(exc: ValidationError) -> str:
    path = list(exc.absolute_path)
    if path:
        return str(path[0])
    if exc.validator == "required":
        match = re.search(r"'([^']+)' is a required property", exc.message)
        if match:
            return match.group(1)
    return "arguments"


# ---------------------------------------------------------------------
# Injection-oriented constraints: control characters
# ---------------------------------------------------------------------

# C0 controls except HT/LF/CR, plus DEL. (C1 controls U+0080–U+009F are
# left alone: they can appear in legitimate non-ASCII text.)
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def walk_strings(value: Any, path: tuple = ()):  # noqa: ANN001, ANN202
    """Yield (path, string) for every string in a JSON-like value."""
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from walk_strings(item, path + (str(key),))
    elif isinstance(value, (list, tuple)):
        for i, item in enumerate(value):
            yield from walk_strings(item, path + (i,))


def find_control_chars(args: Any) -> Optional[str]:
    """Return the top-level field containing a control character, else None."""
    for path, text in walk_strings(args):
        if _CONTROL_CHARS.search(text):
            return str(path[0]) if path else "arguments"
    return None


# ---------------------------------------------------------------------
# Canonicalization before hashing
# ---------------------------------------------------------------------

def canonicalize_args(args: Any) -> Any:
    """Canonical form of JSON-like args (stable key order for hashing).

    - dict keys sorted recursively (JSON object order is insignificant);
    - integral floats normalized to int (``1.0`` → ``1``), because
      ``canonical_json`` renders them differently while they are
      semantically identical.

    String content is NOT touched: no unicode normalization, no
    trimming — argument hashing must not alter values, only order.
    """
    if isinstance(args, dict):
        return {
            key: canonicalize_args(value)
            for key, value in sorted(args.items(), key=lambda kv: str(kv[0]))
        }
    if isinstance(args, list):
        return [canonicalize_args(item) for item in args]
    if isinstance(args, tuple):
        return tuple(canonicalize_args(item) for item in args)
    if isinstance(args, float) and args.is_integer():
        return int(args)
    return args
