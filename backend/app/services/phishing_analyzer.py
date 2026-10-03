"""
Deterministic phishing email analyser — v1.0-heuristic.

Design principles:
- Zero network I/O, fully deterministic.
- All email content (sender, subject, body, links, attachments) treated as untrusted.
- Attachments are never executed; links are never opened.
- Reuses URL-analysis domain-extraction logic via tldextract where possible.
- Gemini/AI is NOT used as the primary detection mechanism.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import tldextract as _tldextract

from backend.app.schemas.url_analysis import Indicator

ANALYSIS_VERSION = "1.0-heuristic"

# ---------------------------------------------------------------------------
# Indicator weights (noisy-OR — same pattern as url_analyzer)
# ---------------------------------------------------------------------------
_W: dict[str, float] = {
    "sender_reply_mismatch":  0.45,
    "free_email_sender":      0.10,
    "spoofed_display_name":   0.50,
    "suspicious_link":        0.40,
    "mismatched_link_text":   0.35,
    "url_shortener_link":     0.20,
    "urgency_language":       0.30,
    "threat_language":        0.40,
    "credential_request":     0.45,
    "payment_request":        0.40,
    "suspicious_attachment":  0.50,
    "executable_attachment":  0.65,
    "impersonation_keyword":  0.35,
    "excessive_links":        0.20,
    "html_obfuscation":       0.30,
    "lookalike_domain":       0.45,
    "prize_scam":             0.50,
    "generic_greeting":       0.10,
}

_LEVEL_CUTS = (
    (0,  "safe"),
    (20, "low"),
    (45, "medium"),
    (70, "high"),
    (101, "critical"),
)

_SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------
_FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "protonmail.com", "icloud.com", "mail.com", "yandex.com", "zoho.com",
    "yahoo.co.uk", "yahoo.co.in", "hotmail.co.uk", "live.com",
}

_IMPERSONATION_DISPLAY_KEYWORDS = {
    "paypal", "amazon", "microsoft", "google", "apple", "netflix",
    "facebook", "instagram", "twitter", "bank", "security", "support",
    "noreply", "no-reply", "admin", "helpdesk", "service", "verify",
    "account", "alert", "notification",
}

_URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "short.link", "rb.gy", "cutt.ly", "is.gd", "tiny.cc",
}

_RISKY_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work",
    "click", "download", "zip", "mov",
}

_CREDENTIAL_KW_URL = {
    "login", "signin", "verify", "account", "secure",
    "update", "confirm", "password", "credential",
}

# Brand → its legitimate domain(s)
_BRAND_DOMAINS: dict[str, set[str]] = {
    "paypal":       {"paypal.com"},
    "amazon":       {"amazon.com", "amazon.co.uk", "amazon.in"},
    "microsoft":    {"microsoft.com", "microsoftonline.com", "live.com"},
    "google":       {"google.com", "google.co.uk", "google.co.in"},
    "apple":        {"apple.com", "icloud.com"},
    "netflix":      {"netflix.com"},
    "facebook":     {"facebook.com", "fb.com"},
    "instagram":    {"instagram.com"},
    "twitter":      {"twitter.com", "x.com"},
    "linkedin":     {"linkedin.com"},
    "dropbox":      {"dropbox.com"},
    "adobe":        {"adobe.com"},
    "docusign":     {"docusign.com"},
    "fedex":        {"fedex.com"},
    "ups":          {"ups.com"},
    "dhl":          {"dhl.com"},
    "usps":         {"usps.com"},
    "irs":          {"irs.gov"},
    "bank of america": {"bankofamerica.com"},
    "wells fargo":  {"wellsfargo.com"},
    "chase":        {"chase.com"},
    "citibank":     {"citibank.com"},
    "hsbc":         {"hsbc.com", "hsbc.co.uk"},
}

_URGENCY_PATTERNS = [
    "urgent", "immediately", "act now", "action required",
    "expires today", "expires in 24", "expires in 48",
    "limited time", "time sensitive", "respond within",
    "your account will be", "your account has been",
    "will be suspended", "will be terminated", "will be closed",
    "24 hours", "48 hours", "within 24", "within 48",
]

_THREAT_PATTERNS = [
    "suspended", "terminated", "banned", "legal action", "law enforcement",
    "police", "arrest", "lawsuit", "prosecute", "account closed",
    "unauthorized access", "suspicious activity detected", "security breach",
    "hacked", "compromised",
]

_CREDENTIAL_PATTERNS = [
    "enter your password", "confirm your password", "verify your password",
    "enter your username", "login credentials", "enter your credit card",
    "enter your ssn", "social security", "date of birth", "mother's maiden",
    "security question", "pin number", "enter your pin",
    "update your payment", "billing information", "payment details",
]

_PAYMENT_PATTERNS = [
    "wire transfer", "western union", "moneygram", "gift card",
    "itunes card", "google play card", "amazon gift card",
    "bitcoin", "cryptocurrency", "send money", "transfer funds",
    "bank transfer", "routing number", "account number",
    "payment required", "pay now", "overdue invoice", "outstanding balance",
]

_PRIZE_PATTERNS = [
    "you have won", "you've won", "congratulations you",
    "winner selected", "claim your prize", "claim your reward",
    "free gift", "you are selected", "selected as winner",
    "lottery winner", "million dollar", "inheritance",
    "nigerian prince", "transfer funds to", "advance fee",
]

_GENERIC_GREETINGS = [
    "dear customer", "dear user", "dear member", "dear account holder",
    "dear valued customer", "hello customer", "greetings customer",
    "to whom it may concern", "dear sir", "dear madam",
]

_VAGUE_CTA = [
    "click here", "visit now", "go here", "click this link",
]

_EXECUTABLE_EXTS = {
    ".exe", ".bat", ".cmd", ".com", ".scr", ".pif",
    ".vbs", ".js", ".jar", ".ps1", ".wsf", ".hta",
}

_MACRO_EXTS = {".xlsm", ".xlsb", ".docm", ".dotm", ".pptm", ".potm"}
_ARCHIVE_EXTS = {".zip", ".rar", ".7z", ".iso", ".img"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _noisy_or(weights: list[float]) -> int:
    """Combine independent risk weights via noisy-OR. Returns 0-100."""
    if not weights:
        return 0
    prod = 1.0
    for w in weights:
        prod *= 1.0 - max(0.0, min(1.0, w))
    return round(100 * (1.0 - prod))


def _score_to_level(score: int) -> str:
    if score == 0:
        return "safe"
    if score < 20:
        return "low"
    if score < 45:
        return "medium"
    if score < 70:
        return "high"
    return "critical"


def _extract_email_domain(addr: str) -> str:
    """Extract the domain portion from an email address, ignoring display names."""
    addr = addr.strip()
    # "Display Name <user@domain.com>" → user@domain.com
    m = re.search(r"<([^>]+)>", addr)
    if m:
        addr = m.group(1).strip()
    if "@" in addr:
        return addr.split("@")[-1].strip().lower()
    return ""


def _extract_display_name(addr: str) -> str:
    """Return the display name portion, or empty string."""
    m = re.match(r"^([^<]+)<", addr)
    if m:
        return m.group(1).strip().strip('"\'')
    return ""


def _registrable_domain(url: str) -> str:
    """Extract registrable domain from a URL string. Returns '' on failure."""
    try:
        ext = _tldextract.extract(url)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
    except Exception:
        pass
    return ""


def _is_ip_host(url: str) -> bool:
    """Return True if the URL host is an IP address."""
    try:
        host = urlsplit(url).hostname or ""
        import ipaddress
        ipaddress.ip_address(host)
        return True
    except (ValueError, Exception):
        return False


def _damerau_levenshtein(s1: str, s2: str) -> int:
    """DL distance with early-exit at > 2."""
    if abs(len(s1) - len(s2)) > 2:
        return 3
    la, lb = len(s1), len(s2)
    dp = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        dp[i][0] = i
    for j in range(lb + 1):
        dp[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            dp[i][j] = min(
                dp[i - 1][j] + 1,
                dp[i][j - 1] + 1,
                dp[i - 1][j - 1] + cost,
            )
            if i > 1 and j > 1 and s1[i - 1] == s2[j - 2] and s1[i - 2] == s2[j - 1]:
                dp[i][j] = min(dp[i][j], dp[i - 2][j - 2] + cost)
    return dp[la][lb]


# ---------------------------------------------------------------------------
# Analysis context
# ---------------------------------------------------------------------------

@dataclass
class _Ctx:
    sender: str
    reply_to: str
    subject: str
    body: str
    links: list[str]
    attachment_names: list[str]

    indicators: list[Indicator] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    _weights: list[float] = field(default_factory=list)
    _ids: set[str] = field(default_factory=set)

    # Derived fields populated during init
    sender_domain: str = field(default="")
    reply_to_domain: str = field(default="")
    combined_text: str = field(default="")  # subject + body, lowercased

    def __post_init__(self) -> None:
        self.sender_domain = _extract_email_domain(self.sender)
        self.reply_to_domain = _extract_email_domain(self.reply_to)
        self.combined_text = (self.subject + " " + self.body).lower()

    def add(self, ind_id: str, name: str, detail: str, severity: str) -> None:
        if ind_id in self._ids:
            return
        self._ids.add(ind_id)
        w = _W.get(ind_id, 0.0)
        self._weights.append(w)
        self.indicators.append(Indicator(
            id=ind_id,
            name=name,
            detail=detail,
            severity=severity,
            weight=round(w * 100),
        ))

    def rec(self, text: str) -> None:
        if text not in self.recommendations:
            self.recommendations.append(text)


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def _check_sender_reply_mismatch(ctx: _Ctx) -> None:
    sd, rd = ctx.sender_domain, ctx.reply_to_domain
    if sd and rd and sd != rd:
        ctx.add(
            "sender_reply_mismatch",
            "Sender / Reply-To domain mismatch",
            f"Reply-To domain '{rd}' differs from sender domain '{sd}' — "
            "a common trick to harvest replies to an attacker-controlled inbox.",
            "high",
        )
        ctx.rec("Do not reply to this email — the reply goes to a different domain than the sender.")


def _check_free_email_sender(ctx: _Ctx) -> None:
    if ctx.sender_domain in _FREE_EMAIL_DOMAINS:
        ctx.add(
            "free_email_sender",
            "Free email provider used as sender",
            f"Sender uses '{ctx.sender_domain}', a free email provider. "
            "Legitimate businesses use their own corporate domain.",
            "info",
        )


def _check_spoofed_display_name(ctx: _Ctx) -> None:
    display = _extract_display_name(ctx.sender).lower()
    if not display:
        return
    toks = set(re.split(r"[^a-z0-9]", display))
    hits = toks & _IMPERSONATION_DISPLAY_KEYWORDS
    if hits and ctx.sender_domain in _FREE_EMAIL_DOMAINS:
        ctx.add(
            "spoofed_display_name",
            "Spoofed display name",
            f"Display name contains '{next(iter(hits))}' but sender uses free email "
            f"'{ctx.sender_domain}' — typical impersonation pattern.",
            "high",
        )
        ctx.rec("The sender's display name does not match their email domain — likely impersonation.")


def _check_suspicious_links(ctx: _Ctx) -> None:
    for raw_link in ctx.links:
        reasons: list[str] = []

        if _is_ip_host(raw_link):
            reasons.append("host is an IP address, not a domain name")

        try:
            ext = _tldextract.extract(raw_link)
            tld = (ext.suffix or "").split(".")[-1]
            subdomains = [s for s in (ext.subdomain or "").split(".") if s]

            if tld in _RISKY_TLDS:
                reasons.append(f"uses risky TLD .{tld}")

            if len(subdomains) >= 3:
                reasons.append(f"excessive subdomain depth ({len(subdomains)} levels)")

            # Credential keywords in the URL string
            url_lower = raw_link.lower()
            url_toks = set(re.split(r"[^a-z0-9]", url_lower))
            kw_hits = url_toks & _CREDENTIAL_KW_URL
            if kw_hits:
                reasons.append(f"credential keywords: {', '.join(sorted(kw_hits)[:3])}")

        except Exception:
            pass

        if reasons:
            ctx.add(
                "suspicious_link",
                "Suspicious link in email",
                f"Link '{raw_link[:80]}' shows suspicious characteristics: "
                + "; ".join(reasons) + ".",
                "high",
            )
            ctx.rec("Do not click any links in this email. Navigate to the official website directly.")
            return  # flag first match only


def _check_mismatched_link_text(ctx: _Ctx) -> None:
    body_lower = ctx.body.lower()
    for phrase in _VAGUE_CTA:
        if phrase in body_lower:
            ctx.add(
                "mismatched_link_text",
                "Generic / vague link label",
                f"Email uses generic link phrase ('{phrase}') that hides the true destination.",
                "medium",
            )
            ctx.rec("Generic link labels like 'click here' are a phishing red flag. Inspect the actual URL before clicking.")
            return


def _check_url_shorteners(ctx: _Ctx) -> None:
    for raw_link in ctx.links:
        try:
            host = urlsplit(raw_link).hostname or ""
            host = host.lower().lstrip("www.")
            if host in _URL_SHORTENERS:
                ctx.add(
                    "url_shortener_link",
                    "URL shortener link",
                    f"Email contains a link from '{host}' — the true destination is hidden.",
                    "medium",
                )
                ctx.rec("Expand the short URL using a preview tool before visiting.")
                return
        except Exception:
            pass


def _check_urgency(ctx: _Ctx) -> None:
    matches = [p for p in _URGENCY_PATTERNS if p in ctx.combined_text]
    if len(matches) >= 2:
        ctx.add(
            "urgency_language",
            "Urgency / pressure tactics",
            f"Email uses urgency language: {', '.join(repr(m) for m in matches[:3])}.",
            "medium",
        )
        ctx.rec("Ignore artificial urgency. Legitimate organisations do not threaten account closure via email.")


def _check_threats(ctx: _Ctx) -> None:
    matches = [p for p in _THREAT_PATTERNS if p in ctx.combined_text]
    if matches:
        ctx.add(
            "threat_language",
            "Threatening language",
            f"Email contains threats or alarming language: {', '.join(repr(m) for m in matches[:3])}.",
            "high",
        )
        ctx.rec("Threatening emails are a common social-engineering tactic. Verify through official channels before taking any action.")


def _check_credential_requests(ctx: _Ctx) -> None:
    body_lower = ctx.body.lower()
    matches = [p for p in _CREDENTIAL_PATTERNS if p in body_lower]
    if matches:
        ctx.add(
            "credential_request",
            "Credential / personal information request",
            "Email explicitly requests sensitive credentials or personal information.",
            "high",
        )
        ctx.rec("Do not enter passwords, personal details, or payment information in response to this email.")


def _check_payment_requests(ctx: _Ctx) -> None:
    body_lower = ctx.body.lower()
    matches = [p for p in _PAYMENT_PATTERNS if p in body_lower]
    if matches:
        ctx.add(
            "payment_request",
            "Payment / financial transfer request",
            f"Email requests financial transactions: {', '.join(repr(m) for m in matches[:3])}.",
            "high",
        )
        ctx.rec("Never send money, gift cards, or banking details in response to an unsolicited email.")


def _check_attachments(ctx: _Ctx) -> None:
    for name in ctx.attachment_names:
        name_lower = name.lower()
        # Double extension check (e.g. invoice.pdf.exe)
        parts = name_lower.split(".")
        ext = f".{parts[-1]}" if len(parts) > 1 else ""
        has_double = len(parts) > 2 and any(
            f".{parts[i]}" in _EXECUTABLE_EXTS | _MACRO_EXTS | {".pdf", ".doc", ".docx"}
            for i in range(len(parts) - 1)
        )

        if ext in _EXECUTABLE_EXTS or has_double:
            ctx.add(
                "executable_attachment",
                "Executable / double-extension attachment",
                f"Attachment '{name}' has a dangerous file type or double extension — "
                "never open or execute it.",
                "high",
            )
            ctx.rec("Do not open the attachment. Executable files and double-extension files are almost always malware.")
            return

        if ext in _MACRO_EXTS:
            ctx.add(
                "suspicious_attachment",
                "Macro-enabled Office attachment",
                f"Attachment '{name}' is a macro-enabled Office file — macros can execute malicious code.",
                "medium",
            )
            ctx.rec("Do not enable macros in Office documents from unknown senders.")
            return

        if ext in _ARCHIVE_EXTS:
            ctx.add(
                "suspicious_attachment",
                "Archive attachment",
                f"Attachment '{name}' is an archive file — verify its contents before extracting.",
                "medium",
            )
            ctx.rec("Scan archive attachments with antivirus before opening.")
            return


def _check_impersonation(ctx: _Ctx) -> None:
    """Brand name in subject/body opening but sender is not that brand's domain."""
    check_zone = (ctx.subject + " " + ctx.body[:500]).lower()
    for brand, legit_domains in _BRAND_DOMAINS.items():
        if brand not in check_zone:
            continue
        # Sender is on a legitimate domain for this brand → not impersonation
        if any(ctx.sender_domain.endswith(d) for d in legit_domains):
            continue
        ctx.add(
            "impersonation_keyword",
            "Brand impersonation",
            f"Email mentions '{brand}' but sender domain is '{ctx.sender_domain or '(unknown)'}' — "
            "likely impersonation.",
            "medium",
        )
        ctx.rec("Verify the sender is genuine by contacting the organisation through its official website.")
        return  # flag first match only


def _check_excessive_links(ctx: _Ctx) -> None:
    if len(ctx.links) > 5:
        ctx.add(
            "excessive_links",
            "Excessive number of links",
            f"Email contains {len(ctx.links)} links — phishing emails often pack many redirects.",
            "low",
        )


def _check_html_obfuscation(ctx: _Ctx) -> None:
    body = ctx.body
    # Zero-width characters
    if re.search(r"[\u200b\u200c\u200d\ufeff]", body):
        ctx.add(
            "html_obfuscation",
            "Text obfuscation (zero-width characters)",
            "Email contains invisible/zero-width characters — used to evade keyword filters.",
            "medium",
        )
        return
    # Significant percent-encoding in body
    pct_count = len(re.findall(r"%[0-9a-fA-F]{2}", body))
    if pct_count >= 5:
        ctx.add(
            "html_obfuscation",
            "Encoded / obfuscated content",
            f"Email body contains {pct_count} percent-encoded sequences — possible obfuscation.",
            "medium",
        )
        return
    # Long base64-like strings
    if re.search(r"[A-Za-z0-9+/]{60,}={0,2}", body):
        ctx.add(
            "html_obfuscation",
            "Base64 / encoded content",
            "Email contains long base64-like strings — content may be obfuscated.",
            "medium",
        )


def _check_lookalike_domain(ctx: _Ctx) -> None:
    brands_to_check = list(_BRAND_DOMAINS.keys())
    for raw_link in ctx.links:
        ext = _tldextract.extract(raw_link)
        domain_label = ext.domain or ""
        if not domain_label:
            continue
        for brand in brands_to_check:
            # Only compare single-word brand names to the domain label
            brand_word = brand.split()[0]
            if len(brand_word) < 4:
                continue
            if domain_label == brand_word:
                continue  # exact match → legitimate
            if _damerau_levenshtein(domain_label.lower(), brand_word.lower()) <= 1:
                reg = f"{ext.domain}.{ext.suffix}" if ext.suffix else domain_label
                ctx.add(
                    "lookalike_domain",
                    "Lookalike / typosquat domain in link",
                    f"Link domain '{reg}' closely resembles '{brand_word}' — possible typosquat.",
                    "high",
                )
                ctx.rec("A link in this email uses a domain that resembles a known brand — do not click it.")
                return


def _check_prize_scam(ctx: _Ctx) -> None:
    matches = [p for p in _PRIZE_PATTERNS if p in ctx.combined_text]
    if matches:
        ctx.add(
            "prize_scam",
            "Prize / lottery / advance-fee scam",
            f"Email contains prize or advance-fee scam language: "
            f"{', '.join(repr(m) for m in matches[:2])}.",
            "high",
        )
        ctx.rec("Prize or lottery emails requesting personal information or fees are scams.")


def _check_generic_greeting(ctx: _Ctx) -> None:
    opening = ctx.body[:200].lower()
    for phrase in _GENERIC_GREETINGS:
        if phrase in opening:
            ctx.add(
                "generic_greeting",
                "Generic greeting",
                f"Email uses generic greeting '{phrase}' — legitimate services address you by name.",
                "info",
            )
            return


def _apply_escalation_floors(ctx: _Ctx, raw_score: int) -> int:
    ids = ctx._ids
    score = raw_score
    if "credential_request" in ids or "payment_request" in ids:
        score = max(score, 55)
    if "executable_attachment" in ids:
        score = max(score, 60)
    if ("lookalike_domain" in ids or "spoofed_display_name" in ids) and "credential_request" in ids:
        score = max(score, 70)
    return score


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyse_email(
    sender: str,
    reply_to: str,
    subject: str,
    body: str,
    links: list[str],
    attachment_names: list[str],
) -> tuple[int, str, list[Indicator], list[str]]:
    """
    Analyse an email for phishing indicators deterministically.

    - No network I/O.
    - All inputs treated as untrusted.
    - Attachments are inspected by name/extension only — never executed.
    - Links are parsed structurally — never opened.

    Returns: (risk_score, risk_level, indicators, recommendations)
    """
    ctx = _Ctx(
        sender=sender,
        reply_to=reply_to,
        subject=subject,
        body=body,
        links=links,
        attachment_names=attachment_names,
    )

    _check_sender_reply_mismatch(ctx)
    _check_free_email_sender(ctx)
    _check_spoofed_display_name(ctx)
    _check_suspicious_links(ctx)
    _check_mismatched_link_text(ctx)
    _check_url_shorteners(ctx)
    _check_urgency(ctx)
    _check_threats(ctx)
    _check_credential_requests(ctx)
    _check_payment_requests(ctx)
    _check_attachments(ctx)
    _check_impersonation(ctx)
    _check_excessive_links(ctx)
    _check_html_obfuscation(ctx)
    _check_lookalike_domain(ctx)
    _check_prize_scam(ctx)
    _check_generic_greeting(ctx)

    raw_score = _noisy_or(ctx._weights)
    score = _apply_escalation_floors(ctx, raw_score)
    score = max(0, min(100, score))
    level = _score_to_level(score)

    # Sort: high first, then medium, low, info; ties broken by weight descending
    ctx.indicators.sort(
        key=lambda i: (_SEV_ORDER.get(i.severity, 9), -(i.weight or 0))
    )

    # Always add at least one recommendation
    if not ctx.recommendations:
        ctx.rec(
            "No significant phishing indicators detected. "
            "Always verify the sender domain matches the expected organisation before acting."
        )

    return score, level, ctx.indicators, ctx.recommendations
