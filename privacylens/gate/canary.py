"""Canary registry that reports matched labels only."""
import base64
import re
from urllib.parse import quote, quote_plus

_ZERO_WIDTH = "\u200b\u200c\u200d\ufeff"


def value_variants(value: str) -> set[str]:
    if not isinstance(value, str) or not value:
        return set()
    raw = value
    normalized = "".join(c for c in raw if c not in _ZERO_WIDTH and c not in " -\t\r\n").casefold()
    encoded = raw.encode("utf-8")
    b64 = base64.b64encode(encoded).decode("ascii")
    b64url = base64.urlsafe_b64encode(encoded).decode("ascii")
    digits = re.sub(r"\D", "", raw)
    variants = {raw, normalized, quote(raw, safe=""), quote_plus(raw, safe=""), encoded.hex(), encoded.hex().upper()}
    variants.update((b64, b64.rstrip("="), b64url, b64url.rstrip("=")))
    # One to five digit substrings collide with routine metadata, prices, and IDs.
    # Keep exact/encoded variants for those values but only emit a digits-only
    # canonical form when it carries enough entropy to be a useful canary.
    if len(digits) >= 6:
        variants.add(digits)
    return {item for item in variants if item}


def _contains_variant(payload_bytes: bytes, value: str) -> bool:
    variants = value_variants(value)
    payload_text = payload_bytes.decode("utf-8", errors="ignore")
    payload_normalized = "".join(c for c in payload_text if c not in _ZERO_WIDTH and c not in " -\t\r\n").casefold()
    for variant in variants:
        normalized = "".join(c for c in variant if c not in _ZERO_WIDTH and c not in " -\t\r\n").casefold()
        if variant.encode("utf-8") in payload_bytes or (normalized and normalized in payload_normalized):
            return True
    return False


class CanaryRegistry:
    def __init__(self):
        self._canaries = []

    def register(self, value: str, label: str):
        if not isinstance(value, str) or not value:
            raise ValueError("canary value must be a non-empty string")
        if not isinstance(label, str) or not label:
            raise ValueError("canary label must be a non-empty string")
        self._canaries.append((value, label))

    def variants(self, value: str) -> set[str]:
        return value_variants(value)

    def find(self, payload_bytes: bytes) -> list[str]:
        matched = []
        for value, label in self._canaries:
            if _contains_variant(payload_bytes, value):
                matched.append(label)
        return sorted(set(matched))

    def __repr__(self):
        return f"CanaryRegistry(labels={[label for _, label in self._canaries]!r})"
