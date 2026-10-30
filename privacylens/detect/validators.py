"""Dependency-free validators and deterministic synthetic value generators."""
import re
import math
from collections import Counter

_D = (
    (0,1,2,3,4,5,6,7,8,9),(1,2,3,4,0,6,7,8,9,5),(2,3,4,0,1,7,8,9,5,6),
    (3,4,0,1,2,8,9,5,6,7),(4,0,1,2,3,9,5,6,7,8),(5,9,8,7,6,0,4,3,2,1),
    (6,5,9,8,7,1,0,4,3,2),(7,6,5,9,8,2,1,0,4,3),(8,7,6,5,9,3,2,1,0,4),
    (9,8,7,6,5,4,3,2,1,0),
)
_P = (
    (0,1,2,3,4,5,6,7,8,9),(1,5,7,6,2,8,3,0,9,4),(5,8,0,3,7,9,6,1,4,2),
    (8,9,1,6,0,4,3,5,2,7),(9,4,5,3,1,2,6,8,7,0),(4,2,8,6,5,7,3,9,0,1),
    (2,7,9,3,8,0,6,4,1,5),(7,0,4,6,9,1,3,2,5,8),
)
_INV = (0,4,3,2,1,5,6,7,8,9)

def verhoeff_validate(num_str: str) -> bool:
    if not isinstance(num_str, str) or not re.fullmatch(r"[0-9]{12}", num_str) or num_str[0] not in "23456789":
        return False
    c = 0
    for i, digit in enumerate(reversed(num_str)):
        c = _D[c][_P[i % 8][int(digit)]]
    return c == 0

def verhoeff_generate(prefix_11: str) -> str:
    if not re.fullmatch(r"[0-9]{11}", prefix_11) or prefix_11[0] not in "23456789":
        raise ValueError("prefix must be 11 digits and start from 2 through 9")
    for check in "0123456789":
        candidate = prefix_11 + check
        c = 0
        for i, digit in enumerate(reversed(candidate)):
            c = _D[c][_P[i % 8][int(digit)]]
        if c == 0:
            return candidate
    raise AssertionError("No Verhoeff checksum found")

def _iin_ok(value: str) -> bool:
    if value.startswith("4"): return True
    if len(value) >= 2 and value[:2] in ("34", "37", "60", "65"): return True
    if len(value) >= 2 and 51 <= int(value[:2]) <= 55: return True
    return len(value) >= 4 and 2221 <= int(value[:4]) <= 2720

def luhn_validate(num_str: str) -> bool:
    if not isinstance(num_str, str) or not re.fullmatch(r"[0-9]{12,19}", num_str) or not _iin_ok(num_str):
        return False
    total = 0
    for i, c in enumerate(reversed(num_str)):
        n = int(c)
        if i % 2:
            n *= 2
            if n > 9: n -= 9
        total += n
    return total % 10 == 0

def luhn_generate(prefix: str, length: int = 16) -> str:
    if not isinstance(prefix, str) or not prefix.isdigit() or not 12 <= length <= 19 or len(prefix) >= length or not _iin_ok(prefix):
        raise ValueError("prefix must be numeric with a supported IIN and shorter than a 12-19 digit length")
    body = prefix + "0" * (length - len(prefix) - 1)
    for check in "0123456789":
        if luhn_validate(body + check):
            return body + check
    raise AssertionError("No Luhn checksum found")

def pan_validate(pan_str: str) -> bool:
    return isinstance(pan_str, str) and re.fullmatch(r"[A-Z]{3}[PCHFATBLJG][A-Z][0-9]{4}[A-Z]", pan_str) is not None

def shannon_entropy(s: str) -> float:
    if not s: return 0.0
    counts = Counter(s)
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in counts.values())
