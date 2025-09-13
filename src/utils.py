import math
import re
from typing import Dict

LOWER = re.compile(r"[a-z]")
UPPER = re.compile(r"[A-Z]")
DIGIT = re.compile(r"\d")
SYMBOL = re.compile(r"[^A-Za-z0-9]")

COMMON_PATTERNS = [
    re.compile(r"password", re.IGNORECASE),
    re.compile(r"qwerty", re.IGNORECASE),
    re.compile(r"12345"),
    re.compile(r"letmein", re.IGNORECASE),
    re.compile(r"iloveyou", re.IGNORECASE),
]

def charset_size(pw: str) -> int:
    size = 0
    size += 26 if LOWER.search(pw) else 0
    size += 26 if UPPER.search(pw) else 0
    size += 10 if DIGIT.search(pw) else 0
    # conservative symbol set ~33 common ASCII specials
    size += 33 if SYMBOL.search(pw) else 0
    return max(size, 1)

def entropy_bits(pw: str) -> float:
    """Approx entropy (bits) assuming uniform over detected charset."""
    r = charset_size(pw)
    return len(pw) * math.log2(r)

def pattern_flags(pw: str) -> Dict[str, bool]:
    return {
        "has_lower": bool(LOWER.search(pw)),
        "has_upper": bool(UPPER.search(pw)),
        "has_digit": bool(DIGIT.search(pw)),
        "has_symbol": bool(SYMBOL.search(pw)),
        "has_common_pattern": any(rx.search(pw) for rx in COMMON_PATTERNS),
        "has_repeats": bool(re.search(r"(.)\1{2,}", pw)),  # aaa, 111
        "has_sequence": bool(
            re.search(
                r"0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef|defg",
                pw.lower(),
            )
        ),
    }
