"""Process-local vault with a local policy check; it is not cryptography."""
from urllib.parse import urlsplit

from ..detect.structural import classify_element


class VaultError(Exception):
    """Raised when a reference is missing or injection policy rejects it."""


def _origin(value):
    try:
        parts = urlsplit(str(value))
        scheme = parts.scheme.casefold()
        host = (parts.hostname or "").casefold()
        if not scheme or parts.username is not None or parts.password is not None:
            return None
        port = parts.port
        if port is None:
            port = {"http": 80, "https": 443}.get(scheme)
        return scheme, host, port
    except (ValueError, TypeError):
        return None


def _enabled(element):
    attrs = dict(getattr(element, "attributes", {}) or {})
    metadata = dict(getattr(element, "metadata", {}) or {})
    if "disabled" in attrs and attrs.get("disabled") is not False:
        return False
    if str(attrs.get("aria-disabled", "")).casefold() == "true":
        return False
    if "enabled" in metadata:
        return bool(metadata["enabled"])
    if "enabled" in attrs:
        return str(attrs["enabled"]).casefold() not in ("false", "0", "no", "")
    return "disabled" not in attrs


def _visible(element):
    attrs = dict(getattr(element, "attributes", {}) or {})
    metadata = dict(getattr(element, "metadata", {}) or {})
    if ("hidden" in attrs and attrs.get("hidden") is not False) or str(attrs.get("aria-hidden", "")).casefold() == "true":
        return False
    if "visible" in metadata:
        return bool(metadata["visible"])
    if "visible" in attrs:
        return str(attrs["visible"]).casefold() not in ("false", "0", "no", "")
    return "hidden" not in attrs


class Vault:
    def __init__(self):
        self.__entries = {}
        self.__counters = {}
        self.__tokenizer = None

    def session_tokenizer(self, rules):
        if self.__tokenizer is None:
            from .tokens import SessionTokenizer
            self.__tokenizer = SessionTokenizer(rules)
        return self.__tokenizer

    def add(self, value: str, kind: str, origins, max_uses=None, needs_approval=True) -> str:
        if not isinstance(value, str) or not value:
            raise VaultError("vault values must be non-empty strings")
        if max_uses is not None and (not isinstance(max_uses, int) or max_uses < 0):
            raise VaultError("max_uses must be a non-negative integer or None")
        origin_values = (origins,) if isinstance(origins, str) else tuple(origins)
        normalized_origins = frozenset(origin for origin in (_origin(item) for item in origin_values) if origin is not None)
        if not normalized_origins or len(normalized_origins) != len(set(_origin(item) for item in origin_values)):
            raise VaultError("at least one valid origin is required")
        kind = str(kind).upper()
        index = self.__counters.get(kind, 0) + 1
        self.__counters[kind] = index
        ref = f"VAULT://{kind.lower()}_{index}"
        self.__entries[ref] = {
            "value": value,
            "kind": kind,
            "origins": normalized_origins,
            "max_uses": max_uses,
            "uses": 0,
            "needs_approval": bool(needs_approval),
            "approved": not bool(needs_approval),
        }
        return ref

    def approve(self, ref: str) -> None:
        entry = self.__entry(ref)
        entry["approved"] = True

    def __entry(self, ref):
        try:
            return self.__entries[ref]
        except (KeyError, TypeError):
            raise VaultError("unknown vault reference") from None

    def verify_injection_safety(self, ref, element, current_url) -> tuple[bool, str]:
        """Check local field, origin, visibility, approval and use-count policy."""
        try:
            entry = self.__entry(ref)
            kind = entry["kind"]
            attrs = dict(getattr(element, "attributes", {}) or {})
            # A card number may only be restored into an explicitly typed card-number field.
            if kind == "CARD":
                if getattr(element, "tag", "").casefold() == "textarea":
                    return False, "card_not_allowed_in_textarea"
                if str(attrs.get("autocomplete", "")).casefold() != "cc-number" or getattr(element, "tag", "").casefold() != "input":
                    return False, "card_requires_cc_number_field"
                role = str(attrs.get("role", "")).casefold()
                if str(attrs.get("type", "")).casefold() == "search":
                    return False, "card_not_allowed_in_search_or_chat_field"
                hint = " ".join(str(attrs.get(k, "")) for k in ("name", "id", "label", "aria-label", "placeholder", "role")).casefold()
                if role == "searchbox" or any(word in hint for word in ("chat", "message", "search", "prompt")):
                    return False, "card_not_allowed_in_search_or_chat_field"
            field_kind = classify_element(element)
            if field_kind != kind:
                return False, "field_kind_mismatch"
            if _origin(current_url) not in entry["origins"]:
                return False, "origin_mismatch"
            if not _visible(element):
                return False, "element_not_visible"
            if not _enabled(element):
                return False, "element_not_enabled"
            if entry["max_uses"] is not None and entry["uses"] >= entry["max_uses"]:
                return False, "max_uses_exceeded"
            if entry["needs_approval"] and not entry["approved"]:
                return False, "approval_required"
            return True, "allowed_by_local_policy"
        except Exception:
            return False, "policy_check_failed"

    def get(self, ref, element, url) -> str:
        allowed, reason = self.verify_injection_safety(ref, element, url)
        if not allowed:
            raise VaultError(reason)
        entry = self.__entry(ref)
        entry["uses"] += 1
        return entry["value"]

    def values(self):
        """Internal gate iterator; callers must never render or persist its values."""
        return iter(entry["value"] for entry in self.__entries.values())

    def __repr__(self):
        return f"Vault(entries={len(self.__entries)})"

    __str__ = __repr__

    def __reduce__(self):
        raise TypeError("Vault cannot be pickled")

    def __getstate__(self):
        raise TypeError("Vault cannot be serialized")
