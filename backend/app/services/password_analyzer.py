"""
Deterministic password-strength analyser.

Rules applied (no external calls, no storage, no logging of the password):
  - Length scoring
  - Character-class diversity (upper, lower, digit, symbol)
  - Repeated characters / runs
  - Sequential keyboard / alphabetic / numeric patterns
  - Common weak passwords blocklist
  - Entropy estimation based on pool size
"""

import math
import re
from dataclasses import dataclass, field

from backend.app.schemas.password import PasswordAnalysisResult

# ---------------------------------------------------------------------------
# Common weak passwords (top patterns — stored as hashed set in memory only)
# ---------------------------------------------------------------------------
_WEAK_PASSWORDS: frozenset[str] = frozenset({
    "password", "password1", "password123", "123456", "12345678", "123456789",
    "111111", "000000", "qwerty", "qwerty123", "abc123", "letmein", "welcome",
    "monkey", "dragon", "master", "iloveyou", "admin", "login", "pass",
    "passw0rd", "trustno1", "sunshine", "princess", "football", "shadow",
    "superman", "michael", "jessica", "charlie", "donald", "batman",
})

# Sequential keyboard rows (horizontal adjacency)
_KEYBOARD_ROWS = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "1234567890",
]

_MIN_SEQ_LEN = 3   # minimum run length to flag


@dataclass
class _Context:
    pwd: str
    lower: str = field(init=False)
    length: int = field(init=False)
    weaknesses: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    deductions: int = 0
    score: int = 0

    def __post_init__(self):
        self.lower = self.pwd.lower()
        self.length = len(self.pwd)


# ---------------------------------------------------------------------------
# Individual rule checks — each mutates ctx
# ---------------------------------------------------------------------------

def _check_length(ctx: _Context) -> int:
    """Return a length score (0-40)."""
    n = ctx.length
    if n < 8:
        ctx.weaknesses.append(f"Too short ({n} characters).")
        ctx.recommendations.append("Use at least 12 characters.")
        return max(0, n * 2)
    if n < 12:
        ctx.recommendations.append("Consider using 14+ characters for stronger security.")
        return 18
    if n < 16:
        return 26
    if n < 20:
        return 33
    return 40


def _check_diversity(ctx: _Context) -> int:
    """Return a diversity score (0-40)."""
    has_upper  = bool(re.search(r"[A-Z]", ctx.pwd))
    has_lower  = bool(re.search(r"[a-z]", ctx.pwd))
    has_digit  = bool(re.search(r"\d",    ctx.pwd))
    has_symbol = bool(re.search(r"[^A-Za-z0-9]", ctx.pwd))

    classes = sum([has_upper, has_lower, has_digit, has_symbol])

    if not has_upper:
        ctx.weaknesses.append("No uppercase letters.")
        ctx.recommendations.append("Add uppercase letters (A-Z).")
    if not has_lower:
        ctx.weaknesses.append("No lowercase letters.")
        ctx.recommendations.append("Add lowercase letters (a-z).")
    if not has_digit:
        ctx.weaknesses.append("No numbers.")
        ctx.recommendations.append("Include numbers (0-9).")
    if not has_symbol:
        ctx.recommendations.append("Adding symbols (!@#$…) significantly increases strength.")

    return {1: 8, 2: 18, 3: 30, 4: 40}.get(classes, 0)


def _check_repetition(ctx: _Context) -> int:
    """Return deductions for repeated characters/patterns (0-20)."""
    deduct = 0

    # Same character repeated 3+ times consecutively
    if re.search(r"(.)\1{2,}", ctx.pwd):
        ctx.weaknesses.append("Contains repeated characters (e.g. 'aaa').")
        ctx.recommendations.append("Avoid repeating the same character consecutively.")
        deduct += 10

    # Whole-string character frequency > 60 %  (e.g. "aaaaab")
    if ctx.length >= 4:
        from collections import Counter
        most_common_count = Counter(ctx.lower).most_common(1)[0][1]
        if most_common_count / ctx.length > 0.6:
            ctx.weaknesses.append("Character set is too uniform.")
            deduct += 10

    return deduct


def _check_sequences(ctx: _Context) -> int:
    """Return deductions for sequential patterns (0-20)."""
    deduct = 0
    lower = ctx.lower

    # Alphabetic sequences: abc, xyz
    for i in range(len(lower) - _MIN_SEQ_LEN + 1):
        chunk = lower[i:i + _MIN_SEQ_LEN]
        if all(ord(chunk[j + 1]) - ord(chunk[j]) == 1 for j in range(len(chunk) - 1)):
            ctx.weaknesses.append("Contains alphabetic sequence (e.g. 'abc').")
            ctx.recommendations.append("Avoid sequential characters like 'abc' or 'xyz'.")
            deduct += 10
            break

    # Numeric sequences: 123, 987
    digits_only = re.sub(r"\D", "", ctx.pwd)
    for i in range(len(digits_only) - _MIN_SEQ_LEN + 1):
        chunk = digits_only[i:i + _MIN_SEQ_LEN]
        diffs = [int(chunk[j+1]) - int(chunk[j]) for j in range(len(chunk)-1)]
        if len(set(diffs)) == 1 and diffs[0] in (1, -1):
            ctx.weaknesses.append("Contains numeric sequence (e.g. '123' or '987').")
            ctx.recommendations.append("Avoid sequential numbers like '123' or '321'.")
            deduct += 10
            break

    # Keyboard-row sequences
    for row in _KEYBOARD_ROWS:
        for i in range(len(row) - _MIN_SEQ_LEN + 1):
            seq = row[i:i + _MIN_SEQ_LEN]
            if seq in lower or seq[::-1] in lower:
                ctx.weaknesses.append(f"Contains keyboard sequence ('{seq}').")
                ctx.recommendations.append("Avoid keyboard patterns like 'qwerty' or '1234'.")
                deduct += 10
                break
        else:
            continue
        break

    return min(deduct, 20)


def _check_common(ctx: _Context) -> int:
    """Return deduction if password matches a known-weak pattern."""
    if ctx.lower in _WEAK_PASSWORDS:
        ctx.weaknesses.append("This is a commonly used password and will be cracked instantly.")
        ctx.recommendations.append("Choose a unique passphrase instead of a common password.")
        return 40
    # Weak password with digits appended: "password1", "admin2024"
    stripped = re.sub(r"\d+$", "", ctx.lower)
    if stripped in _WEAK_PASSWORDS:
        ctx.weaknesses.append("Common password with numbers appended is still very weak.")
        ctx.recommendations.append("Don't just append numbers to a common word.")
        return 20
    return 0


def _estimate_entropy(pwd: str) -> float:
    """Shannon-inspired entropy estimate based on character pool size."""
    pool = 0
    if re.search(r"[a-z]", pwd): pool += 26
    if re.search(r"[A-Z]", pwd): pool += 26
    if re.search(r"\d",    pwd): pool += 10
    if re.search(r"[^A-Za-z0-9]", pwd): pool += 32
    if pool == 0:
        return 0.0
    return round(len(pwd) * math.log2(pool), 2)


def _score_to_level(score: int) -> str:
    if score < 20: return "very_weak"
    if score < 40: return "weak"
    if score < 60: return "moderate"
    if score < 80: return "strong"
    return "very_strong"


def _character_stats(pwd: str) -> dict:
    """Return counts by class — never includes raw password content."""
    return {
        "length":         len(pwd),
        "uppercase":      sum(1 for c in pwd if c.isupper()),
        "lowercase":      sum(1 for c in pwd if c.islower()),
        "digits":         sum(1 for c in pwd if c.isdigit()),
        "symbols":        sum(1 for c in pwd if not c.isalnum()),
        "unique_chars":   len(set(pwd)),
    }


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def analyse(password: str) -> PasswordAnalysisResult:
    """
    Analyse *password* and return a structured result.

    The password is used only within this call stack and is never stored,
    logged, or forwarded to any external service.
    """
    ctx = _Context(pwd=password)

    length_score    = _check_length(ctx)
    diversity_score = _check_diversity(ctx)
    rep_deduct      = _check_repetition(ctx)
    seq_deduct      = _check_sequences(ctx)
    common_deduct   = _check_common(ctx)

    raw = length_score + diversity_score - rep_deduct - seq_deduct - common_deduct
    score = max(0, min(100, raw))

    # De-duplicate recommendations/weaknesses while preserving order
    seen_w: set[str] = set()
    seen_r: set[str] = set()
    weaknesses      = [w for w in ctx.weaknesses      if not (w in seen_w or seen_w.add(w))]
    recommendations = [r for r in ctx.recommendations if not (r in seen_r or seen_r.add(r))]

    return PasswordAnalysisResult(
        score=score,
        level=_score_to_level(score),
        entropy_bits=_estimate_entropy(password),
        weaknesses=weaknesses,
        recommendations=recommendations,
        character_stats=_character_stats(password),
    )
