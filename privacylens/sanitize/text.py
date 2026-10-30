"""Span-based text redaction that never preserves fragments of a finding."""
import re
from ..contracts import Finding


def sanitize_text(text: str, findings, tokenizer=None) -> str:
    if not isinstance(text, str) or not text:
        return text
    spans = []
    for finding in findings:
        if isinstance(finding, dict):
            start, end, kind = finding.get("start"), finding.get("end"), finding.get("kind", "SENSITIVE")
        else:
            metadata = getattr(finding, "metadata", {})
            start, end, kind = metadata.get("start"), metadata.get("end"), finding.kind
        if isinstance(start, int) and isinstance(end, int) and 0 <= start < end <= len(text):
            spans.append((start, end, str(kind)))
    spans.sort()
    merged = []
    for start, end, kind in spans:
        if merged and start < merged[-1][1]:
            old_start, old_end, old_kind = merged[-1]
            merged[-1] = (old_start, max(old_end, end), old_kind if old_kind == kind else "SENSITIVE")
        else:
            merged.append((start, end, kind))
    result = text
    for start, end, kind in reversed(merged):
        token = tokenizer.tokenize(text[start:end], kind) if tokenizer is not None else f"[REDACTED:{kind}]"
        result = result[:start] + token + result[end:]
    return result


def _redact_findings(text):
    from ..detect.patterns import scan_text
    return sanitize_text(text, scan_text(text))
