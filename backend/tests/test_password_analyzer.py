"""
Tests for the deterministic password analyser.

Covers: very_weak, weak, moderate, strong passwords and specific rule checks.
No HTTP client needed — tests the service layer directly.
"""

import pytest
from backend.app.services.password_analyzer import analyse


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _result(pwd):
    return analyse(pwd)


# ---------------------------------------------------------------------------
# Very weak passwords
# ---------------------------------------------------------------------------

def test_common_password_is_very_weak():
    r = _result("password")
    assert r.level == "very_weak"
    assert r.score < 20
    assert any("commonly used" in w.lower() for w in r.weaknesses)


def test_short_password_is_very_weak():
    r = _result("abc")
    assert r.level == "very_weak"
    assert any("short" in w.lower() for w in r.weaknesses)


def test_all_digits_sequence_is_very_weak():
    r = _result("123456")
    assert r.score < 20


# ---------------------------------------------------------------------------
# Weak passwords
# ---------------------------------------------------------------------------

def test_common_with_numbers_is_weak():
    r = _result("password1")
    assert r.level in ("very_weak", "weak")
    assert r.score < 40


def test_repeated_chars_penalised():
    r = _result("aaaaabbb1")
    assert any("repeated" in w.lower() or "uniform" in w.lower() for w in r.weaknesses)


def test_keyboard_sequence_penalised():
    r = _result("qwerty99A!")
    assert any("keyboard" in w.lower() for w in r.weaknesses)


# ---------------------------------------------------------------------------
# Moderate passwords
# ---------------------------------------------------------------------------

def test_moderate_password():
    # No sequences, mixed classes, medium length
    r = _result("Purple!Dog7")
    assert 40 <= r.score < 80


def test_moderate_has_recommendations():
    r = _result("Purple!Dog7")
    assert len(r.recommendations) > 0


# ---------------------------------------------------------------------------
# Strong passwords
# ---------------------------------------------------------------------------

def test_strong_password():
    r = _result("Tr0ub4dor&3Horse")
    assert r.score >= 60
    assert r.level in ("strong", "very_strong")


def test_very_strong_password():
    # 20+ chars, all 4 classes, no patterns — hits very_strong
    r = _result("X7!kP#2mQz@9vLnR$wT!")
    assert r.score >= 80
    assert r.level == "very_strong"


# ---------------------------------------------------------------------------
# Result structure
# ---------------------------------------------------------------------------

def test_result_never_contains_password():
    pwd = "MySecret99!"
    r = _result(pwd)
    # The raw password must not appear in any returned field
    assert pwd not in str(r.weaknesses)
    assert pwd not in str(r.recommendations)
    assert pwd not in str(r.character_stats)


def test_score_bounds():
    for pwd in ["a", "123456", "Hello123!", "X7!kP#2mQz@9vLnR$wT"]:
        r = _result(pwd)
        assert 0 <= r.score <= 100


def test_entropy_positive():
    r = _result("SomePassword1!")
    assert r.entropy_bits > 0


def test_character_stats_keys():
    r = _result("Hello1!")
    for key in ("length", "uppercase", "lowercase", "digits", "symbols", "unique_chars"):
        assert key in r.character_stats


def test_character_stats_correct():
    r = _result("Aa1!")
    assert r.character_stats["uppercase"] == 1
    assert r.character_stats["lowercase"] == 1
    assert r.character_stats["digits"] == 1
    assert r.character_stats["symbols"] == 1
    assert r.character_stats["length"] == 4
