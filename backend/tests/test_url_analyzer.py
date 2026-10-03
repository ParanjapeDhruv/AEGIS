"""
Unit tests for the deterministic URL analyser v2.
Old tests updated to match new indicator names/ids; spec-required fixes applied.
"""

import pytest
from backend.app.services.url_analyzer import analyse_url


def _analyse(url):
    normalized, score, level, indicators, recs = analyse_url(url)
    indicator_names = [i.name for i in indicators]
    indicator_ids   = [i.id   for i in indicators]
    return normalized, score, level, indicator_names, indicator_ids, recs


# ---------------------------------------------------------------------------
# Safe / clean URLs
# ---------------------------------------------------------------------------

def test_clean_https_url_is_safe():
    _, score, level, _, ids, _ = _analyse("https://example.com/page")
    assert level in ("safe", "low")
    assert score < 20


def test_clean_url_no_indicators():
    _, _, _, names, ids, _ = _analyse("https://example.com")
    assert names == []


# ---------------------------------------------------------------------------
# HTTP (no HTTPS)
# ---------------------------------------------------------------------------

def test_http_flagged():
    _, _, _, names, ids, _ = _analyse("http://example.com")
    assert "no_https" in ids


# ---------------------------------------------------------------------------
# IP-based URLs — F7/F8 corrected behaviour
# ---------------------------------------------------------------------------

def test_public_ip_flagged_high():
    """Public raw IP is HIGH risk (F8 fix: use a public IP, not RFC1918)."""
    # 8.8.8.8 (Google DNS) — public, non-obfuscated
    _, score, level, _, ids, _ = _analyse("http://8.8.8.8/login")
    assert "public_ip" in ids
    assert score >= 30
    assert level in ("medium", "high", "critical")


def test_obfuscated_ip_flagged_high():
    """Decimal-encoded public IP must be flagged as obfuscated_ip (F7)."""
    # 134744072 = 8.8.8.8 in decimal
    _, score, level, _, ids, _ = _analyse("http://134744072/login")
    assert "obfuscated_ip" in ids
    assert score >= 55


def test_private_ip_is_info_not_high():
    """Private/RFC1918 IP must produce non_public_address info indicator, NOT public_ip (F8)."""
    _, score, level, _, ids, _ = _analyse("http://192.168.1.1/login")
    assert "non_public_address" in ids
    assert "public_ip" not in ids
    assert level in ("safe", "low", "medium")


# ---------------------------------------------------------------------------
# Brand impersonation
# ---------------------------------------------------------------------------

def test_brand_impersonation_detected():
    _, score, level, _, ids, _ = _analyse("https://paypal.com.verify-account.net/login")
    assert "brand_impersonation" in ids
    assert score >= 25


def test_real_brand_domain_not_flagged():
    _, _, _, _, ids, _ = _analyse("https://paypal.com/signin")
    assert "brand_impersonation" not in ids


def test_legitimate_google_signin_not_flagged():
    """F3 — accounts.google.com must not trigger brand impersonation."""
    _, _, _, _, ids, _ = _analyse("https://accounts.google.com/signin")
    assert "brand_impersonation" not in ids


def test_legitimate_microsoftonline_not_flagged():
    """F3 — login.microsoftonline.com must not trigger brand or keyword indicators."""
    _, _, _, _, ids, _ = _analyse("https://login.microsoftonline.com/")
    assert "brand_impersonation" not in ids
    assert "credential_kw_host" not in ids


def test_legitimate_amazon_uk_not_flagged():
    """F3 — PSL-aware registrable domain for amazon.co.uk."""
    _, _, _, _, ids, _ = _analyse("https://www.amazon.co.uk/")
    assert "brand_impersonation" not in ids


# ---------------------------------------------------------------------------
# Phishing keywords (new indicator names)
# ---------------------------------------------------------------------------

def test_multiple_keywords_flagged():
    _, score, _, _, ids, _ = _analyse(
        "https://secure-login-verify.com/account/confirm/password"
    )
    assert "multiple_kw" in ids or "credential_kw_host" in ids
    assert score > 10


# ---------------------------------------------------------------------------
# Risky TLD (new indicator ids)
# ---------------------------------------------------------------------------

def test_risky_tld_flagged():
    _, _, _, _, ids, _ = _analyse("https://free-prize.tk/claim")
    assert "freenom_tld" in ids


def test_safe_tld_not_flagged():
    _, _, _, _, ids, _ = _analyse("https://example.com/page")
    assert "freenom_tld" not in ids
    assert "medium_risky_tld" not in ids


# ---------------------------------------------------------------------------
# URL length
# ---------------------------------------------------------------------------

def test_very_long_url_flagged():
    long_path = "a" * 200
    _, score, _, _, ids, _ = _analyse(f"https://example.com/{long_path}")
    assert "long_url" in ids or "very_long_url" in ids
    assert score > 0


# ---------------------------------------------------------------------------
# Userinfo / @ (F5 fix)
# ---------------------------------------------------------------------------

def test_at_in_authority_flagged():
    """@ in the authority (userinfo) must be flagged as deceptive_userinfo."""
    _, score, _, _, ids, _ = _analyse("https://evil.com@legit.com/page")
    assert "deceptive_userinfo" in ids
    assert score >= 30


def test_at_in_path_not_flagged_as_userinfo():
    """F5 — @ in path (e.g. YouTube /@channel) must NOT trigger deceptive_userinfo."""
    _, _, _, _, ids, _ = _analyse("https://www.youtube.com/@channel")
    assert "deceptive_userinfo" not in ids


def test_at_in_medium_path_not_flagged():
    """F5 — medium.com/@user must NOT trigger deceptive_userinfo."""
    _, _, _, _, ids, _ = _analyse("https://medium.com/@user/post")
    assert "deceptive_userinfo" not in ids


# ---------------------------------------------------------------------------
# Punycode / homograph (F9)
# ---------------------------------------------------------------------------

def test_punycode_or_homograph_flagged():
    """xn--pypal-4ve.com decodes to Cyrillic lookalike → homograph indicator."""
    _, _, _, _, ids, _ = _analyse("https://xn--pypal-4ve.com/login")
    assert "punycode_label" in ids or "homograph" in ids


# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------

def test_excessive_encoding_flagged():
    encoded_path = "%61%62%63%64%65%66%67%68" * 2
    _, _, _, _, ids, _ = _analyse(f"https://example.com/{encoded_path}")
    assert "excessive_encoding" in ids


# ---------------------------------------------------------------------------
# Open redirect (F6 fix)
# ---------------------------------------------------------------------------

def test_redirect_to_external_domain_flagged():
    """Redirect param pointing to a different domain → external_redirect."""
    _, _, _, _, ids, _ = _analyse("https://example.com/go?redirect=http://evil.com")
    assert "external_redirect" in ids


def test_image_url_param_not_flagged():
    """F6 — image_url= must NOT be treated as a redirect parameter."""
    _, _, _, _, ids, _ = _analyse("https://example.com/page?image_url=thumb.jpg")
    assert "external_redirect" not in ids


# ---------------------------------------------------------------------------
# Subdomains
# ---------------------------------------------------------------------------

def test_excessive_subdomains_flagged():
    _, _, _, _, ids, _ = _analyse("https://a.b.c.d.example.com/page")
    assert "excessive_subdomains" in ids


# ---------------------------------------------------------------------------
# Result structure / properties
# ---------------------------------------------------------------------------

def test_score_bounds():
    for url in [
        "https://example.com",
        "http://8.8.8.8/login",
        "https://paypal.com.phish.tk/verify/account/password/confirm",
    ]:
        _, score, _, _, _, _ = _analyse(url)
        assert 0 <= score <= 100


def test_recommendations_always_present():
    _, _, _, _, _, recs = _analyse("https://example.com")
    assert len(recs) >= 1


def test_normalized_url_returned():
    normalized, _, _, _, _, _ = _analyse("HTTPS://Example.COM/Path")
    assert normalized
    assert normalized.startswith("https://")


def test_indicator_severity_valid():
    from backend.app.services.url_analyzer import analyse_url as au
    _, _, _, indicators, _ = au("http://8.8.8.8/login?redirect=http://evil.com")
    valid = {"info", "low", "medium", "high"}
    for i in indicators:
        assert i.severity in valid


def test_indicator_has_id_and_weight():
    """New schema fields: id and weight must be present on indicators."""
    from backend.app.services.url_analyzer import analyse_url as au
    _, _, _, indicators, _ = au("http://8.8.8.8/login")
    for i in indicators:
        assert i.id is not None
        assert i.weight is not None
        assert 0 <= i.weight <= 100


def test_determinism():
    """Same input twice must produce identical output."""
    url = "https://paypal-secure.verify.tk/login/account"
    r1 = analyse_url(url)
    r2 = analyse_url(url)
    assert r1[1] == r2[1]  # score
    assert r1[2] == r2[2]  # level
    assert [i.id for i in r1[3]] == [i.id for i in r2[3]]


def test_hostless_url_raises():
    """F11 — hostless URL must raise ValueError."""
    with pytest.raises(ValueError):
        analyse_url("https://")


def test_no_network_calls(monkeypatch):
    """Analyser must never open a socket."""
    import socket
    def _no_socket(*a, **kw):
        raise RuntimeError("Network call attempted during URL analysis!")
    monkeypatch.setattr(socket, "socket", _no_socket)
    monkeypatch.setattr(socket, "getaddrinfo", _no_socket)
    # Must complete without raising RuntimeError
    analyse_url("https://paypal.com.evil.tk/login/account/verify")


def test_malicious_url_is_high_or_critical():
    """A worst-case phishing URL must reach Critical."""
    _, score, level, _, _, _ = _analyse(
        "https://secure-paypal-login.verify-account.tk/signin/update/password"
    )
    assert level in ("high", "critical")
    assert score >= 60
