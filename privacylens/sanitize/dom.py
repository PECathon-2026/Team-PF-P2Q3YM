"""DOM field sanitization helpers used by the snapshot sanitizer."""
import re

from ..detect.patterns import scan_text
from ..contracts import Element
from .text import sanitize_text


def _placeholder(kind, raw_value, rules, tokenizer=None):
    return tokenizer.tokenize(raw_value, kind) if tokenizer is not None else f"[REDACTED:{kind}]"


def _redact_string(value, rules, force_kind=None, known_values=(), tokenizer=None):
    if not isinstance(value, str) or not value:
        return value, []
    findings = scan_text(value)
    chosen = [f for f in findings if f.kind in rules.block_types]
    if force_kind in rules.block_types and value.strip():
        return _placeholder(force_kind, value, rules, tokenizer), findings
    cleaned = sanitize_text(value, chosen, tokenizer)
    for raw, kind in sorted(known_values, key=lambda pair: len(pair[0]), reverse=True):
        if not raw or kind not in rules.block_types:
            continue
        replacement = _placeholder(kind, raw, rules, tokenizer)
        cleaned = re.sub(re.escape(raw), lambda _m, repl=replacement: repl, cleaned, flags=re.I)
    return cleaned, findings


def sanitize_element(element: Element, index: int, forced_kind: str | None, rules, known_values=(), max_text_chars=80, tokenizer=None):
    attrs = dict(element.attributes or {})
    raw_value = str(attrs.get("value", ""))
    filled = bool(raw_value.strip() or element.text.strip())
    sanitized_text, found = _redact_string(
        element.text, rules, forced_kind if element.tag.lower() != "input" else None, known_values, tokenizer
    )
    safe_attrs = {}
    for key, raw in attrs.items():
        key = str(key).lower()
        if key.startswith("data-"):
            continue
        if isinstance(raw, str):
            force = forced_kind if key == "value" and filled else None
            clean, extra = _redact_string(raw, rules, force, known_values, tokenizer)
            safe_attrs[key] = clean
            found.extend(extra)
        else:
            safe_attrs[key] = raw
    safe_attrs["enabled"] = ("disabled" not in attrs or attrs.get("disabled") is False)
    safe_attrs["visible"] = bool(element.metadata.get("visible", "hidden" not in attrs))
    safe_attrs["filled"] = filled
    for field_name in ("label", "title", "alt", "aria-label"):
        if field_name in attrs and isinstance(attrs[field_name], str):
            clean, extra = _redact_string(attrs[field_name], rules, known_values=known_values, tokenizer=tokenizer)
            safe_attrs[field_name] = clean
            found.extend(extra)
    def truncate(value):
        if isinstance(value, str) and not value.startswith("[REDACTED:"):
            return value[:max_text_chars]
        return value
    sanitized_text = truncate(sanitized_text)
    for key, value in tuple(safe_attrs.items()):
        if key not in ("id", "role", "selector", "vault_ref"):
            safe_attrs[key] = truncate(value)
    return Element(
        tag=element.tag,
        text=sanitized_text,
        attributes=safe_attrs,
        selector=element.selector,
        bounds=element.bounds,
        metadata={"enabled": safe_attrs["enabled"], "visible": safe_attrs["visible"], "filled": filled},
    ), found
