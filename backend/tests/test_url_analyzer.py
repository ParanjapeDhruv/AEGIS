"""
Unit tests for the deterministic URL analyser.
All tests run against the service layer directly — no HTTP, no DB.
"""

import pytest
from backend.app.services.url_analyzer import analyse_url


def _analyse(url):
    normalized, score, level, indicators, recs = analyse_url(url)
    indicator_names = [i.name for i in indicators]
    return normalized, score, level, indicator_names, recs


# ---------------------------------------------------------------------------
# Safe / clean URLs
# ---------------------------------------------------------------------------

def test_clean_https_url_is_safe():
    _, score, level, indicators, _ = _analyse("https://example.com/page")
    assert level in ("safe", "low")
    assert score < 20


def test_clean_url_no_indicators():
    _, _, _, indicators, _ = _analyse("https://example.com")
    assert indicators == []


# ---------------------------------------------------------------------------
# HTTP (no HTTPS)
# ---------------------------------------------------------------------------

def test_http_flagged():
    _, _, _, indicators, _ = _analyse("http://example.com")
    assert "No HTTPS" in indicators


# ---------------------------------------------------------------------------
# IP-based URLs
# ---------------------------------------------------------------------------

def test_ip_url_flagged_high():
    _, score, level, indicators, _ = _analyse("http://192.168.1.1/login")
    assert "IP-based URL" in indicators
    assert score >= 25
    assert level in ("medium", "high", "critical")


# ---------------------------------------------------------------------------
# Brand impersonation
# ---------------------------------------------------------------------------

def test_brand_impersonation_detected():
    _, score, level, indicators, _ = _analyse("https://paypal.com.verify-account.net/login")
    assert "Brand impersonation" in indicators
    assert score >= 25


def test_real_brand_domain_not_flagged():
    _, _, _, indicators, _ = _analyse("https://paypal.com/signin")
    assert "Brand impersonation" not in indicators


# ---------------------------------------------------------------------------
# Phishing keywords
# ---------------------------------------------------------------------------

def test_multiple_keywords_flagged():
    _, score, _, indicators, _ = _analyse("https://secure-login-verify.com/account/confirm/password")
    assert "Multiple phishing keywords" in indicators or "Phishing keyword" in indicators
    assert score > 10


# ---------------------------------------------------------------------------
# Risky TLD
# ---------------------------------------------------------------------------

def test_risky_tld_flagged():
    _, _, _, indicators, _ = _analyse("https://free-prize.tk/claim")
    assert "High-risk TLD" in indicators


def test_safe_tld_not_flagged():
    _, _, _, indicators, _ = _analyse("https://example.com/page")
    assert "High-risk TLD" not in indicators


# ---------------------------------------------------------------------------
# URL length
# ---------------------------------------------------------------------------

def test_very_long_url_flagged():
    long_path = "a" * 200
    _, score, _, indicators, _ = _analyse(f"https://example.com/{long_path}")
    assert any("URL" in i and "long" in i.lower() for i in indicators)
    assert score > 0


# ---------------------------------------------------------------------------
# Suspicious characters
# ---------------------------------------------------------------------------

def test_at_symbol_flagged():
    _, score, _, indicators, _ = _analyse("https://evil.com@legit.com/page")
    assert "@ symbol in URL" in indicators
    assert score >= 30


def test_punycode_flagged():
    _, _, _, indicators, _ = _analyse("https://xn--pypal-4ve.com/login")
    assert "Punycode domain" in indicators


# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------

def test_excessive_encoding_flagged():
    encoded_path = "%61%62%63%64%65%66%67%68" * 2
    _, _, _, indicators, _ = _analyse(f"https://example.com/{encoded_path}")
    assert "Excessive URL encoding" in indicators


# ---------------------------------------------------------------------------
# Open redirect
# ---------------------------------------------------------------------------

def test_redirect_param_flagged():
    _, _, _, indicators, _ = _analyse("https://example.com/go?redirect=http://evil.com")
    assert "Open redirect parameter" in indicators


# ---------------------------------------------------------------------------
# Subdomains
# ---------------------------------------------------------------------------

def test_excessive_subdomains_flagged():
    _, _, _, indicators, _ = _analyse("https://a.b.c.d.example.com/page")
    assert "Excessive subdomains" in indicators


# ---------------------------------------------------------------------------
# Result structure
# ---------------------------------------------------------------------------

def test_score_bounds():
    for url in [
        "https://example.com",
        "http://192.168.1.1/login",
        "https://paypal.com.phish.tk/verify/account/password/confirm",
    ]:
        _, score, _, _, _ = _analyse(url)
        assert 0 <= score <= 100


def test_recommendations_always_present():
    _, _, _, _, recs = _analyse("https://example.com")
    assert len(recs) >= 1


def test_normalized_url_returned():
    normalized, _, _, _, _ = _analyse("HTTPS://Example.COM/Path")
    assert normalized  # non-empty


def test_indicator_severity_valid():
    _, _, _, _, _ = _analyse("http://192.168.1.1/login?redirect=evil.com")
    # Get raw Indicator objects directly from the service
    from backend.app.services.url_analyzer import analyse_url
    _, _, _, indicators, _ = analyse_url("http://192.168.1.1/login?redirect=evil.com")
    valid = {"info", "low", "medium", "high"}
    for i in indicators:
        assert i.severity in valid
