"""Text PII detection with zero-width normalization and original span mapping."""
import ipaddress
import re
import unicodedata
from .validators import luhn_validate, pan_validate, shannon_entropy, verhoeff_validate
from ..contracts import Finding

_ZW = "\u200b\u200c\u200d\ufeff"
_EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
_PHONE = re.compile(r"(?<!\w)(?:\+91[ -]?)?(?:0[ -]?)?[6-9](?:[ -]?\d){9}(?!\w)")
_DIGITS = re.compile(r"(?<!\d)(?:\d[ -]?){11,18}\d(?!\d)")
_IP = re.compile(r"(?<![\w:])(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{2,39})(?![\w:])")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
_TOKENS = [re.compile(p) for p in (r"\bAKIA[0-9A-Z]{16}\b", r"\bgh[pousr]_[A-Za-z0-9]{20,}\b", r"\bsk-[A-Za-z0-9_-]{16,}\b", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")]
_GENERIC = re.compile(r"\b[A-Za-z0-9_+/=-]{20,}\b")

def _normalized(text):
    chars, positions = [], []
    for i, ch in enumerate(text):
        if ch not in _ZW:
            for normalized_char in unicodedata.normalize("NFKC", ch):
                chars.append(normalized_char); positions.append(i)
    return "".join(chars), positions

def _near_hint(text, start, end, field_hint):
    neighborhood = text[max(0, start - 40):min(len(text), end + 40)].lower()
    hint = " ".join(str(v) for v in (field_hint or {}).values()).lower()
    return bool(re.search(r"otp|one.?time|code|verification|verify|pin", neighborhood + " " + hint))

def _expiry_context(text, start, end, field_hint):
    neighborhood = text[max(0, start - 40):min(len(text), end + 40)].lower()
    hint = " ".join(str(v) for v in (field_hint or {}).values()).lower()
    text_match = re.search(r"\b(?:exp|expiry)\b|\bvalid\s+(?:thru|till)\b", neighborhood)
    hint_match = re.search(r"(?:^|[^a-z])(?:exp|expiry)(?:$|[^a-z])", hint)
    return bool(text_match or hint_match)

def scan_text(text: str, field_hint: dict | None = None) -> list[Finding]:
    if not isinstance(text, str) or not text: return []
    norm, pos = _normalized(text)
    out = []
    def add(kind, match, confidence=0.9):
        a, b = match.span()
        orig_a = pos[a] if a < len(pos) else len(text)
        orig_b = pos[b - 1] + 1 if b and b - 1 < len(pos) else orig_a
        value = text[orig_a:orig_b]
        out.append(Finding(kind=kind, value=value, confidence=confidence, source="text", metadata={"start": orig_a, "end": orig_b}))
    for m in _EMAIL.finditer(norm): add("EMAIL", m, .99)
    for m in re.finditer(r"(?i)\bmailto:([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})\b", norm):
        add("EMAIL", _OffsetMatch(norm, m.start(1), m.end(1)), .99)
    for m in _PHONE.finditer(norm): add("PHONE", m, .98)
    for m in _DIGITS.finditer(norm):
        digits = re.sub(r"\D", "", m.group())
        if len(digits) == 12 and verhoeff_validate(digits): add("AADHAAR", m, .99)
        elif luhn_validate(digits): add("CARD", m, .99)
    for m in re.finditer(r"(?<![A-Z0-9])[A-Z]{3}[PCHFATBLJG][A-Z][0-9]{4}[A-Z](?![A-Z0-9])", norm):
        if pan_validate(m.group()): add("PAN", m, .99)
    for m in re.finditer(r"(?i)\b(?:otp|one.?time.?password|verification.?code|security.?code|pin)\b", norm):
        for digits in re.finditer(r"(?<!\d)\d{4,8}(?!\d)", norm[max(0,m.start()-40):m.end()+40]):
            start = max(0,m.start()-40) + digits.start(); end = max(0,m.start()-40) + digits.end()
            mm = re.match(r"\d+", norm[start:end]); add("OTP", mm and _OffsetMatch(norm, start, end) or m, .95)
    # Field hints can establish OTP context even if the nearby text does not.
    if field_hint and _near_hint("", 0, 0, field_hint):
        for m in re.finditer(r"(?<!\d)\d{4,8}(?!\d)", norm): add("OTP", m, .92)
    for pat in _TOKENS:
        for m in pat.finditer(norm): add("SECRET", m, .99)
    for m in _JWT.finditer(norm): add("SECRET", m, .99)
    for m in re.finditer(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", norm): add("SECRET", m, .99)
    for m in _GENERIC.finditer(norm):
        hint_text = " ".join(str(v) for v in (field_hint or {}).values())
        context = (norm[max(0,m.start()-40):m.end()+40] + " " + hint_text).lower()
        if shannon_entropy(m.group()) >= 4.2 and re.search(r"key|token|secret|webhook|bearer", context): add("SECRET", m, .9)
    for m in _IP.finditer(norm):
        try:
            ip = ipaddress.ip_address(m.group())
            preceding = norm[max(0, m.start() - 12):m.start()]
            version_context = re.search(r"(?<![a-z])(?:version|release|build|ver)\s*$", preceding, re.I) or re.search(r"v$", preceding, re.I)
            if str(ip) not in ("127.0.0.1", "::1") and not version_context: add("IP", m, .95)
        except ValueError: pass
    for m in re.finditer(r"(?i)\b(?:cvv|cvc|security code)\D{0,8}(\d{3,4})\b", norm): add("CVV", _OffsetMatch(norm,m.start(1),m.end(1)), .97)
    for m in re.finditer(r"(?<![\d/\-])(?:0[1-9]|1[0-2])\s*[/\-]\s*(?:\d{2}|\d{4})(?![\d/\-])", norm):
        if _expiry_context(norm, m.start(), m.end(), field_hint): add("EXPIRY", m, .9)
    for m in re.finditer(r"(?i)\b[A-Z]{4}0[A-Z0-9]{6}\b", norm): add("OTHER", m, .95) # IFSC
    for m in re.finditer(r"(?i)\b[A-Z0-9._-]{2,256}@[A-Z][A-Z0-9-]{1,63}(?![A-Z0-9.-])", norm):
        add("OTHER", m, .85) # UPI-like identifier (provider handles commonly have no dot)
    # Stable deduplication for overlapping regexes.
    unique = {}
    for f in out: unique[(f.kind, f.metadata.get("start"), f.metadata.get("end"))] = f
    return sorted(unique.values(), key=lambda f: (f.metadata["start"], f.metadata["end"], f.kind))

class _OffsetMatch:
    def __init__(self, string, start, end): self.string, self._start, self._end = string, start, end
    def span(self, group=0): return self._start, self._end
