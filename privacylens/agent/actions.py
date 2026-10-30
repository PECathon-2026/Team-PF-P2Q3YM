"""Strict model-action parsing and local policy validation."""
import json
import re
from urllib.parse import urlsplit

from ..contracts import Action
from ..detect.patterns import scan_text
from ..gate.canary import _contains_variant

ALLOWED = {"click", "type", "select", "scroll", "navigate", "wait", "ask_user", "done"}
_REF = re.compile(r"^VAULT://[a-z][a-z0-9]*_\d+$", re.I)
_SHADOW = re.compile(r"\[REDACTED:[A-Z_]+(?::[A-Z_]+|#\d+(?:\|[^\]]+)?)?\]", re.I)


def parse_action(raw: str) -> Action:
    try:
        data = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("malformed action JSON") from exc
    if not isinstance(data, dict) or set(data) - {"action", "target", "text", "secret_ref", "reason"}:
        raise ValueError("action must be an object with only supported keys")
    kind = data.get("action")
    if not isinstance(kind, str) or kind not in ALLOWED:
        raise ValueError("unsupported action")
    target = data.get("target", "")
    text = data.get("text")
    ref = data.get("secret_ref")
    reason = data.get("reason", "")
    if not all(isinstance(v, str) for v in (target, reason)):
        raise ValueError("target and reason must be strings")
    if text is not None and not isinstance(text, str): raise ValueError("text must be a string")
    if text is not None and len(text) > 200: raise ValueError("text exceeds 200 characters")
    if text is not None and ref is not None: raise ValueError("text and secret_ref are mutually exclusive")
    if ref is not None and (not isinstance(ref, str) or not _REF.fullmatch(ref)): raise ValueError("invalid secret_ref")
    # Keep the model's free-form reason out of reports and history; it is untrusted text.
    return Action(kind=kind, target=target, value=text, metadata={"secret_ref": ref})


def _origin(url):
    try:
        p = urlsplit(url)
        if not p.scheme or not p.hostname or p.username is not None or p.password is not None: return None
        port = p.port
        if port is None: port = {"http": 80, "https": 443}.get(p.scheme)
        return p.scheme.lower(), p.hostname.lower(), port
    except (ValueError, AttributeError): return None


def _allowed_origin(url, rules):
    wanted = _origin(url)
    for allowed in rules.allowed_origins:
        # An origin entry may omit its default port; normalize exact tuple equality.
        if wanted is not None and wanted == _origin(allowed): return True
        if allowed == "file://" and urlsplit(url).scheme == "file": return True
    return False


def validate(action, snapshot, vault, rules, current_url):
    if action.kind not in ALLOWED: return False, "action_not_allowed", False
    needs_approval = False
    element = next((e for e in snapshot.elements
                    if action.target in (e.attributes.get("id"), e.selector, e.attributes.get("data-pl-id"))), None)
    if action.kind in {"click", "type", "select"}:
        if element is None: return False, "unknown_target", False
        attrs = dict(element.attributes or {})
        meta = dict(element.metadata or {})
        if meta.get("hidden") or ("hidden" in attrs and attrs.get("hidden") is not False) or str(attrs.get("visible", "true")).lower() == "false": return False, "target_hidden", False
        if "disabled" in attrs or str(attrs.get("enabled", "true")).lower() == "false": return False, "target_disabled", False
    if action.kind == "ask_user" and action.target and element is None: return False, "unknown_target", False
    if action.kind == "navigate":
        if not _allowed_origin(action.value or "", rules): return False, "navigation_origin_not_allowed", False
    if action.kind == "type" and action.value:
        if scan_text(action.value): return False, "typed_text_sensitive", False
        if _SHADOW.search(action.value): return False, "typed_text_contains_shadow_token", False
        if vault and any(value and _contains_variant(action.value.encode("utf-8"), value) for value in vault.values()): return False, "typed_text_contains_canary", False
    ref = action.metadata.get("secret_ref")
    if ref:
        if action.kind != "type": return False, "secret_ref_requires_type_action", False
        if element is None: return False, "unknown_target", False
        if vault is None: return False, "secret_vault_unavailable", False
        ok, reason = vault.verify_injection_safety(ref, element, current_url)
        if not ok and reason != "approval_required": return False, reason, False
        needs_approval = True
    if action.kind == "click" and element is not None:
        attrs = dict(element.attributes or {})
        label = " ".join([element.text, *(str(attrs.get(k, "")) for k in ("aria-label", "value", "title", "role"))]).casefold()
        triggers = ("pay", "submit", "place order", "buy", "confirm", "delete", "send", "rotate", "revoke", "generate token")
        needs_approval = needs_approval or any(word in label for word in triggers) or attrs.get("type", "").casefold() == "submit"
        if attrs.get("type", "").casefold() == "submit" or (attrs.get("form") and "submit" in label): needs_approval = True
    if action.kind == "scroll" and action.target and element is None: return False, "unknown_target", False
    return True, "allowed", needs_approval
