"""DOM-like structural field classification and content scanning."""
import re
from ..contracts import Element, Finding
from .patterns import scan_text

_SENSITIVE = re.compile(r"password|passwd|passcode|card|credit|debit|cvv|cvc|expiry|expir|otp|one.?time|verification|email|phone|mobile|tel|aadhaar|pan|account|secret|token|api.?key|upi|ifsc|address|street|postal|zip|given.?name|family.?name|first.?name|last.?name|full.?name", re.I)


def classify_element(el: Element) -> str | None:
    """Return a structural sensitivity kind without inspecting/logging field values."""
    attrs = dict(el.attributes or {})
    hint = {k: v for k, v in attrs.items() if k in ("type", "name", "id", "autocomplete", "aria-label", "label", "placeholder", "role")}
    hints = " ".join(str(v) for v in hint.values()).lower()
    name_hint = " ".join(str(attrs.get(k, "")) for k in ("name", "id", "label", "aria-label", "placeholder", "role"))
    auto = str(attrs.get("autocomplete", "")).lower()
    typ = str(attrs.get("type", "")).lower()
    tag = el.tag.lower()
    role = str(attrs.get("role", "")).lower()
    if typ == "password" or "password" in hints: return "PASSWORD"
    if auto == "cc-number" or re.search(r"card|credit|debit", hints): return "CARD"
    if auto == "cc-csc" or re.search(r"cvv|cvc", hints): return "CVV"
    if auto == "cc-exp" or re.search(r"expiry|expir", hints): return "EXPIRY"
    if auto == "one-time-code" or re.search(r"otp|one.?time|verification.?code", hints): return "OTP"
    if auto == "email" or "email" in hints: return "EMAIL"
    if auto == "tel" or re.search(r"phone|mobile|telephone|tel", hints): return "PHONE"
    if auto in ("name", "given-name", "family-name") or re.search(r"given.?name|family.?name|first.?name|last.?name|full.?name|contact.?name|(?:^|[\s_-])name(?:$|[\s_-])", name_hint, re.I): return "NAME"
    if auto in ("street-address", "address-line1", "postal-code") or re.search(r"address|street|postal|zip.?code", name_hint, re.I): return "ADDRESS"
    if re.search(r"aadhaar", hints): return "AADHAAR"
    if re.search(r"\bpan\b", hints): return "PAN"
    if re.search(r"api.?key|secret|token|webhook|bearer", hints): return "SECRET"
    if re.search(r"upi|ifsc|account", hints): return "OTHER"
    if tag in ("textarea",) or role in ("searchbox", "textbox") and re.search(r"chat|message|search|prompt", hints):
        return None
    return None


def scan_elements(elements: list[Element]) -> list[Finding]:
    findings = []
    for index, el in enumerate(elements):
        attrs = dict(el.attributes or {})
        eid = attrs.get("id", el.selector or f"element-{index}")
        bbox = el.bounds
        hint = {k: v for k, v in attrs.items() if k in ("type", "name", "id", "autocomplete", "aria-label", "label", "placeholder")}
        kind = classify_element(el)
        if kind:
            findings.append(Finding(kind=kind, value="", confidence=.9, source="structure", metadata={"element_id": eid, "bbox": bbox}))
            if kind == "PASSWORD":
                findings.append(Finding(kind="SECRET", value="", confidence=.9, source="structure", metadata={"element_id": eid, "bbox": bbox, "alias_of": "PASSWORD"}))
        values = [("text", el.text), ("value", attrs.get("value", "")), ("label", attrs.get("label", ""))]
        for key, value in attrs.items():
            if key in ("href", "title", "alt") or key.startswith("data-"): values.append((key, value))
        for source, value in values:
            if not value: continue
            for f in scan_text(str(value), hint):
                md = dict(f.metadata); md.update(element_id=eid, bbox=bbox, attribute=source)
                findings.append(Finding(f.kind, f.value, f.confidence, "structure", md))
    # Four neighboring single-digit-group input fields are common split card controls.
    inputs = [(i,e) for i,e in enumerate(elements) if e.tag.lower() == "input" and
              str(e.attributes.get("maxlength", "")) == "4" and
              re.search(r"card|number|cc", " ".join(str(v) for v in e.attributes.values()), re.I)]
    for n in range(max(0, len(inputs)-3)):
        group = inputs[n:n+4]
        if len(group) == 4 and all(group[j][0] + 1 == group[j+1][0] for j in range(3)):
            for idx, el in group:
                eid = el.attributes.get("id", el.selector or f"element-{idx}")
                findings.append(Finding("CARD", "", .95, "structure", {"element_id": eid, "bbox": el.bounds, "split_card": True}))
    unique = {}
    for f in findings:
        key=(f.kind,f.metadata.get("element_id"),f.value,f.metadata.get("start"),f.metadata.get("attribute"))
        unique[key]=f
    return list(unique.values())
