from dataclasses import dataclass
from typing import Dict
from .utils import entropy_bits, pattern_flags


@dataclass
class AuditResult:
    password: str
    length: int
    entropy: float
    flags: Dict[str, bool]
    hibp_breaches: int | None  # None if skipped/offline
    verdict: str
    score: int  # 0..100


MIN_LEN = 12
TARGET_ENTROPY = 60.0  # bits


def score_password(pw: str, hibp_hits: int | None) -> AuditResult:
    flags = pattern_flags(pw)
    ent = entropy_bits(pw)
    length = len(pw)

    score = 0

    # length (max 30)
    if length >= MIN_LEN:
        score += 20 + min(10, length - MIN_LEN)
    else:
        score += max(0, (length / MIN_LEN) * 20)

    # diversity (max 30)
    diversity = sum(
        [flags["has_lower"], flags["has_upper"], flags["has_digit"], flags["has_symbol"]]
    )
    score += diversity * 7  # 0..28

    # entropy (max 30)
    score += min(30, int(ent / 2))  # rough mapping 0..30

    # penalties
    if flags["has_common_pattern"]:
        score -= 40
    if flags["has_repeats"]:
        score -= 10
    if flags["has_sequence"]:
        score -= 10
    if hibp_hits and hibp_hits > 0:
        score -= 50

    score = max(0, min(100, score))

    if hibp_hits and hibp_hits > 0:
        verdict = "Compromised"
    elif length < MIN_LEN or diversity < 3 or ent < TARGET_ENTROPY:
        verdict = "Weak"
    elif score >= 80:
        verdict = "Strong"
    else:
        verdict = "Fair"

    return AuditResult(
        password=pw,
        length=length,
        entropy=ent,
        flags=flags,
        hibp_breaches=hibp_hits,
        verdict=verdict,
        score=score,
    )
