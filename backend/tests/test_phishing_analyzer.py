"""
Unit tests for the deterministic phishing email analyser.

All tests exercise pure-function logic — no database, no network, no Gemini.
"""
import socket

import pytest

from backend.app.services.phishing_analyzer import analyse_email


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _run(
    sender: str = "",
    reply_to: str = "",
    subject: str = "",
    body: str = "Test email body.",
    links: list[str] | None = None,
    attachments: list[str] | None = None,
) -> tuple[int, str, list[str], list[str]]:
    """Run analyse_email and return (score, level, indicator_ids, recommendations)."""
    score, level, indicators, recs = analyse_email(
        sender=sender,
        reply_to=reply_to,
        subject=subject,
        body=body,
        links=links or [],
        attachment_names=attachments or [],
    )
    return score, level, [i.id for i in indicators], recs


# ---------------------------------------------------------------------------
# Clean / legitimate emails
# ---------------------------------------------------------------------------

def test_clean_email_is_safe_or_low():
    score, level, ids, _ = _run(
        sender="newsletter@company.com",
        body="Hello, here is your monthly update.",
    )
    assert level in ("safe", "low"), f"Expected safe/low, got {level} (score={score})"


def test_no_indicators_on_minimal_body():
    _, _, ids, _ = _run(body="Hi John, see you tomorrow.")
    # Must not fire any high-severity indicators on benign text
    from backend.app.services.phishing_analyzer import analyse_email as ae
    _, _, inds, _ = ae("", "", "", "Hi John, see you tomorrow.", [], [])
    high = [i for i in inds if i.severity == "high"]
    assert high == [], f"Unexpected high indicators: {[i.id for i in high]}"


def test_recommendations_always_present():
    _, _, _, recs = _run(body="Hello team, the meeting is at 3pm.")
    assert len(recs) >= 1


# ---------------------------------------------------------------------------
# Sender / Reply-To mismatch
# ---------------------------------------------------------------------------

def test_sender_reply_mismatch_detected():
    _, _, ids, _ = _run(
        sender="ceo@company.com",
        reply_to="attacker@evil.com",
        body="Please review the attached document.",
    )
    assert "sender_reply_mismatch" in ids


def test_same_domain_no_mismatch():
    _, _, ids, _ = _run(
        sender="alice@company.com",
        reply_to="billing@company.com",
        body="Invoice attached.",
    )
    assert "sender_reply_mismatch" not in ids


def test_missing_reply_to_no_mismatch():
    _, _, ids, _ = _run(
        sender="support@paypal.com",
        reply_to="",
        body="Your account statement.",
    )
    assert "sender_reply_mismatch" not in ids


# ---------------------------------------------------------------------------
# Free email sender
# ---------------------------------------------------------------------------

def test_free_email_sender_flagged_at_info():
    _, _, ids, _ = _run(
        sender="user@gmail.com",
        body="Please click here to verify your account.",
    )
    assert "free_email_sender" in ids
    from backend.app.services.phishing_analyzer import analyse_email as ae
    _, _, inds, _ = ae("user@gmail.com", "", "", "Hello.", [], [])
    fe = next(i for i in inds if i.id == "free_email_sender")
    assert fe.severity == "info"


# ---------------------------------------------------------------------------
# Urgency language
# ---------------------------------------------------------------------------

def test_urgency_two_patterns_detected():
    _, _, ids, _ = _run(
        body="This is action required — your account will be suspended within 24 hours.",
    )
    assert "urgency_language" in ids


def test_single_urgency_term_not_flagged():
    """One urgency term alone should NOT trigger (threshold is >= 2 matches)."""
    _, _, ids, _ = _run(body="This is an urgent matter.")
    assert "urgency_language" not in ids


# ---------------------------------------------------------------------------
# Threat language
# ---------------------------------------------------------------------------

def test_threat_language_detected():
    _, _, ids, _ = _run(
        body="Failure to comply will result in legal action and your account will be banned.",
    )
    assert "threat_language" in ids


# ---------------------------------------------------------------------------
# Credential requests
# ---------------------------------------------------------------------------

def test_credential_request_detected():
    _, _, ids, _ = _run(
        body="Please enter your password to continue and confirm your payment details.",
    )
    assert "credential_request" in ids


def test_credential_request_raises_floor():
    score, _, ids, _ = _run(
        body="Please enter your password to verify your identity.",
    )
    assert "credential_request" in ids
    assert score >= 55, f"Expected score >= 55, got {score}"


# ---------------------------------------------------------------------------
# Payment requests
# ---------------------------------------------------------------------------

def test_payment_wire_transfer_detected():
    _, _, ids, _ = _run(body="Please initiate a wire transfer to account 1234567890.")
    assert "payment_request" in ids


def test_payment_gift_card_detected():
    _, _, ids, _ = _run(body="Send us an Amazon gift card worth $500.")
    assert "payment_request" in ids


def test_payment_bitcoin_detected():
    _, _, ids, _ = _run(body="Send the outstanding balance in bitcoin to the following address.")
    assert "payment_request" in ids


# ---------------------------------------------------------------------------
# Attachments
# ---------------------------------------------------------------------------

def test_executable_attachment_flagged():
    _, _, ids, _ = _run(body="See attached.", attachments=["invoice.exe"])
    assert "executable_attachment" in ids


def test_executable_attachment_raises_floor():
    score, _, ids, _ = _run(body="See attached.", attachments=["setup.bat"])
    assert "executable_attachment" in ids
    assert score >= 60, f"Expected score >= 60, got {score}"


def test_double_extension_attachment_flagged():
    _, _, ids, _ = _run(body="Please review.", attachments=["report.pdf.exe"])
    assert "executable_attachment" in ids


def test_macro_attachment_flagged():
    _, _, ids, _ = _run(body="Open this.", attachments=["document.docm"])
    assert "suspicious_attachment" in ids


def test_archive_attachment_flagged():
    _, _, ids, _ = _run(body="Extract and run.", attachments=["package.zip"])
    assert "suspicious_attachment" in ids


def test_clean_pdf_not_flagged():
    _, _, ids, _ = _run(body="Please find attached.", attachments=["invoice.pdf"])
    assert "executable_attachment" not in ids
    assert "suspicious_attachment" not in ids


# ---------------------------------------------------------------------------
# Suspicious links
# ---------------------------------------------------------------------------

def test_ip_address_link_flagged():
    _, _, ids, _ = _run(
        body="Click here.",
        links=["http://192.168.1.1/login"],
    )
    assert "suspicious_link" in ids


def test_risky_tld_link_flagged():
    _, _, ids, _ = _run(
        body="Verify now.",
        links=["https://free-offer.tk/claim"],
    )
    assert "suspicious_link" in ids


def test_url_shortener_link_flagged():
    _, _, ids, _ = _run(
        body="Click to confirm.",
        links=["https://bit.ly/abc123"],
    )
    assert "url_shortener_link" in ids


def test_excessive_links_flagged():
    links = [f"https://example.com/page{i}" for i in range(7)]
    _, _, ids, _ = _run(body="See below for details.", links=links)
    assert "excessive_links" in ids


# ---------------------------------------------------------------------------
# Impersonation
# ---------------------------------------------------------------------------

def test_impersonation_paypal_detected():
    _, _, ids, _ = _run(
        sender="support@gmail.com",
        subject="PayPal account suspended",
        body="Your PayPal account has been limited. Please verify.",
    )
    assert "impersonation_keyword" in ids


def test_legitimate_paypal_sender_not_impersonation():
    _, _, ids, _ = _run(
        sender="service@paypal.com",
        subject="Your PayPal receipt",
        body="Thank you for your payment through PayPal.",
    )
    assert "impersonation_keyword" not in ids


# ---------------------------------------------------------------------------
# Prize / lottery scam
# ---------------------------------------------------------------------------

def test_prize_scam_detected():
    _, _, ids, _ = _run(
        subject="Congratulations!",
        body="Congratulations you have won $1,000,000 in our lottery. Claim your prize now.",
    )
    assert "prize_scam" in ids


# ---------------------------------------------------------------------------
# Generic greeting
# ---------------------------------------------------------------------------

def test_generic_greeting_detected():
    _, _, ids, _ = _run(body="Dear customer, we need to verify your account details.")
    assert "generic_greeting" in ids


def test_named_greeting_not_flagged():
    _, _, ids, _ = _run(body="Dear John, please find the meeting notes attached.")
    assert "generic_greeting" not in ids


# ---------------------------------------------------------------------------
# Mismatched link text
# ---------------------------------------------------------------------------

def test_vague_cta_flagged():
    _, _, ids, _ = _run(
        body="Your account needs attention. Click here to verify.",
    )
    assert "mismatched_link_text" in ids


# ---------------------------------------------------------------------------
# Score / structure invariants
# ---------------------------------------------------------------------------

def test_risk_score_always_bounded():
    cases = [
        {"body": "Hi there."},
        {"sender": "ceo@company.com", "reply_to": "x@evil.com", "body": "Wire transfer required immediately."},
        {"body": "Enter your password", "attachments": ["virus.exe"]},
        {"subject": "You have won!", "body": "Congratulations you have won. Click here to claim your prize via wire transfer."},
    ]
    for kwargs in cases:
        attachments = kwargs.pop("attachments", None)
        score, _, _, _ = _run(**kwargs, attachments=attachments)
        assert 0 <= score <= 100, f"Score out of range: {score}"


def test_determinism():
    """Same input always produces the same output."""
    kwargs = dict(
        sender="support@gmail.com",
        reply_to="attacker@evil.com",
        subject="Urgent: Verify account",
        body="Dear customer, enter your password immediately or your account will be suspended.",
        links=["http://192.168.1.1/verify"],
        attachments=["invoice.exe"],
    )
    r1 = _run(**kwargs)
    r2 = _run(**kwargs)
    assert r1[0] == r2[0]   # score
    assert r1[1] == r2[1]   # level
    assert r1[2] == r2[2]   # indicator ids


def test_indicators_sorted_high_first():
    """When multiple indicators fire, highest severity must come first."""
    _, _, ids, _ = _run(
        sender="support@gmail.com",
        reply_to="evil@attacker.com",
        body="Dear customer, enter your password. Wire transfer required urgently — legal action will follow.",
        attachments=["malware.exe"],
    )
    from backend.app.services.phishing_analyzer import analyse_email as ae
    _, _, inds, _ = ae(
        "support@gmail.com", "evil@attacker.com", "",
        "Dear customer, enter your password. Wire transfer required urgently — legal action will follow.",
        [], ["malware.exe"],
    )
    sev_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    for i in range(len(inds) - 1):
        assert sev_order[inds[i].severity] <= sev_order[inds[i + 1].severity], (
            f"Indicator {inds[i].id} ({inds[i].severity}) should come before "
            f"{inds[i+1].id} ({inds[i+1].severity})"
        )


def test_no_network_io(monkeypatch):
    """The analyser must never open a network socket."""
    def _no_socket(*a, **kw):
        raise RuntimeError("Network call attempted during email analysis!")
    monkeypatch.setattr(socket, "socket", _no_socket)
    monkeypatch.setattr(socket, "getaddrinfo", _no_socket)
    # Must complete without raising RuntimeError
    _run(
        sender="attacker@gmail.com",
        reply_to="harvest@evil.com",
        subject="Your account is at risk",
        body="Dear customer, click here immediately. Enter your password to avoid suspension.",
        links=["https://paypa1.tk/login"],
        attachments=["invoice.exe"],
    )


def test_combined_phishing_email_is_high_or_critical():
    """A realistic multi-signal phishing email must reach high or critical."""
    score, level, ids, _ = _run(
        sender="security@gmail.com",
        reply_to="harvest@evil-domain.com",
        subject="URGENT: Your PayPal account will be suspended",
        body=(
            "Dear customer, action required — your account will be suspended within 24 hours. "
            "Please enter your password and billing information to confirm your identity. "
            "Failure to act will result in legal action. Wire transfer may be required."
        ),
        links=["https://paypa1.tk/verify/account/password"],
        attachments=["confirm.exe"],
    )
    assert level in ("high", "critical"), f"Expected high/critical, got {level} (score={score})"
    assert score >= 65, f"Expected score >= 65, got {score}"


def test_each_indicator_has_id_and_weight():
    """All indicators must have an id and a weight in range 0-100."""
    from backend.app.services.phishing_analyzer import analyse_email as ae
    _, _, inds, _ = ae(
        "bad@gmail.com", "evil@other.com",
        "Win a prize",
        "Dear customer, you have won. Click here to claim. Enter your password.",
        ["http://1.2.3.4/login"], ["virus.exe"],
    )
    for ind in inds:
        assert ind.id is not None
        assert ind.weight is not None
        assert 0 <= ind.weight <= 100
