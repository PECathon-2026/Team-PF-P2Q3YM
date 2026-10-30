"""Per-session, in-memory shadow tokens for redacted values."""
import re
import unicodedata

_TRAIT_DENY = {"PASSWORD", "OTP", "SECRET", "AADHAAR", "PAN", "CVV"}
_PUBLIC_MAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com",
    "proton.me", "protonmail.com", "live.com", "aol.com",
}


class SessionTokenizer:
    def __init__(self, rules=None):
        self._rules = rules
        self._tokens = {}
        self._counters = {}

    @staticmethod
    def _normalize(value, kind):
        text = unicodedata.normalize("NFKC", str(value))
        kind = str(kind).upper()
        if kind in {"CARD", "PHONE", "AADHAAR"}:
            digits = re.sub(r"\D", "", text)
            if kind == "PHONE":
                if len(digits) == 12 and digits.startswith("91"):
                    digits = digits[2:]
                elif len(digits) == 11 and digits.startswith("0"):
                    digits = digits[1:]
            return digits or text.casefold()
        if kind == "EMAIL":
            return text.casefold()
        return text.casefold()

    @staticmethod
    def _network(value):
        digits = re.sub(r"\D", "", unicodedata.normalize("NFKC", str(value)))
        if digits.startswith("4"): return "VISA"
        if digits.startswith(("34", "37")): return "AMEX"
        if digits.startswith(("51", "52", "53", "54", "55")) or (len(digits) >= 4 and 2221 <= int(digits[:4]) <= 2720): return "MASTERCARD"
        if digits.startswith(("60", "65")): return "RUPAY"
        return None

    def _trait(self, value, kind):
        options = getattr(self._rules, "keep_context", {}) or {}
        requested = options.get(kind)
        if kind in _TRAIT_DENY or not requested:
            return None
        if kind == "CARD" and requested in ("network", "brand"):
            network = self._network(value)
            return f"network={network}" if network else None
        if kind == "EMAIL" and requested in ("domain", "domain_class", "email_domain"):
            domain = str(value).rsplit("@", 1)[-1].casefold()
            category = "public" if domain in _PUBLIC_MAIL_DOMAINS else "other"
            return f"domain_class={category}"
        return None

    def tokenize(self, value: str, kind: str) -> str:
        kind = str(kind).upper()
        normalized = self._normalize(value, kind)
        if not normalized:
            raise ValueError("cannot tokenize an empty value")
        key = (kind, normalized)
        if key not in self._tokens:
            index = self._counters.get(kind, 0) + 1
            self._counters[kind] = index
            self._tokens[key] = index
        index = self._tokens[key]
        trait = self._trait(value, kind)
        suffix = f"|{trait}" if trait else ""
        return f"[REDACTED:{kind}#{index}{suffix}]"

    def token_for(self, value: str, kind: str) -> str:
        return self.tokenize(value, kind)

    def __repr__(self):
        return f"SessionTokenizer(token_count={len(self._tokens)})"

    def __reduce__(self):
        raise TypeError("SessionTokenizer cannot be pickled")

    def __getstate__(self):
        raise TypeError("SessionTokenizer cannot be serialized")
