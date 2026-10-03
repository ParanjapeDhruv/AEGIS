"""
Deterministic URL phishing/threat analyser.

Feature extraction + risk scoring — no external API calls, no ML, no Gemini.
HTTPS presence is noted but NEVER used as a safety signal on its own.
"""

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import unquote, urlparse

from backend.app.schemas.url_analysis import Indicator

# ---------------------------------------------------------------------------
# Reference data (all in-process, no network)
# ---------------------------------------------------------------------------

# High-risk TLDs frequently abused in phishing campaigns
_RISKY_TLDS: frozenset[str] = frozenset({
    ".tk", ".ml", ".ga", ".cf", ".gq",       # Freenom free TLDs
    ".xyz", ".top", ".click", ".link",
    ".online", ".site", ".info", ".biz",
    ".pw", ".cc", ".su", ".icu",
})

# Suspicious keywords commonly embedded in phishing URLs
_PHISHING_KEYWORDS: frozenset[str] = frozenset({
    "login", "signin", "sign-in", "account", "verify", "verification",
    "secure", "security", "update", "confirm", "bank", "paypal", "ebay",
    "amazon", "google", "microsoft", "apple", "facebook", "instagram",
    "support", "helpdesk", "password", "credential", "wallet",
    "crypto", "bitcoin", "urgent", "suspended", "limited", "unusual",
    "activity", "alert", "invoice", "payment", "refund",
})

# Brands frequently impersonated — if in subdomain/path but not registrable domain
_BRAND_NAMES: frozenset[str] = frozenset({
    "paypal", "amazon", "google", "microsoft", "apple", "facebook",
    "netflix", "instagram", "twitter", "linkedin", "dropbox",
    "chase", "wellsfargo", "bankofamerica", "citibank",
})

# Excessive subdomains threshold
_MAX_SAFE_SUBDOMAINS = 3


# ---------------------------------------------------------------------------
# Data container
# ---------------------------------------------------------------------------

@dataclass
class _Ctx:
    raw_url: str
    parsed:  object = field(init=False)
    indicators: list[Indicator] = field(default_factory=list)
    recommendations: list[str]  = field(default_factory=list)
    score: int = 0

    def __post_init__(self):
        self.parsed = urlparse(self.normalized)

    @property
    def normalized(self) -> str:
        """Lowercase scheme+host, preserve path/query, decode percent-encoding."""
        u = self.raw_url.strip()
        # Decode percent-encoding in the URL (but keep structure)
        decoded = unquote(u)
        # Re-parse to normalise
        p = urlparse(decoded)
        return p.geturl()

    def add(self, name: str, detail: str, severity: str, weight: int) -> None:
        self.indicators.append(Indicator(name=name, detail=detail, severity=severity))
        self.score += weight

    def rec(self, text: str) -> None:
        if text not in self.recommendations:
            self.recommendations.append(text)


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def _check_length(ctx: _Ctx) -> None:
    length = len(ctx.raw_url)
    if length > 100:
        ctx.add("Long URL", f"URL is {length} characters — long URLs are often used to hide the real destination.", "low", 5)
    if length > 150:
        ctx.add("Very long URL", f"URL is {length} characters — extremely long URLs are a common obfuscation technique.", "medium", 10)
        ctx.rec("Inspect the full URL carefully before clicking.")


def _check_scheme(ctx: _Ctx) -> None:
    # HTTPS is noted but NOT presented as a safety guarantee
    scheme = ctx.parsed.scheme.lower()
    if scheme == "http":
        ctx.add("No HTTPS", "Connection is unencrypted (HTTP). Data can be intercepted in transit.", "low", 8)
        ctx.rec("Prefer sites using HTTPS, though HTTPS alone does not guarantee safety.")


def _check_ip_host(ctx: _Ctx) -> None:
    host = ctx.parsed.hostname or ""
    # Strip port if present
    host = host.split(":")[0]
    try:
        ipaddress.ip_address(host)
        ctx.add("IP-based URL", f"Host is a raw IP address ({host}). Legitimate services almost always use domain names.", "high", 25)
        ctx.rec("Avoid clicking URLs that use a raw IP address instead of a domain name.")
    except ValueError:
        pass  # Normal domain — not an issue


def _check_subdomains(ctx: _Ctx) -> None:
    host = ctx.parsed.hostname or ""
    parts = host.split(".")
    # e.g. paypal.com = 2 parts, sub.paypal.com = 3, a.b.paypal.com = 4
    if len(parts) > _MAX_SAFE_SUBDOMAINS + 1:
        ctx.add(
            "Excessive subdomains",
            f"'{host}' has {len(parts) - 2} subdomain levels — often used to impersonate legitimate brands.",
            "medium", 15,
        )
        ctx.rec("Check the actual registrable domain (second-to-last + last label) carefully.")


def _check_brand_impersonation(ctx: _Ctx) -> None:
    host = ctx.parsed.hostname or ""
    parts = host.split(".")
    # Registrable domain = last two labels
    registrable = ".".join(parts[-2:]) if len(parts) >= 2 else host
    reg_base = parts[-2] if len(parts) >= 2 else host

    full_url_lower = ctx.normalized.lower()

    for brand in _BRAND_NAMES:
        if brand in full_url_lower:
            # Fine if the brand IS the registrable domain (e.g. paypal.com)
            if brand == reg_base:
                continue
            ctx.add(
                "Brand impersonation",
                f"'{brand}' appears in the URL but the registrable domain is '{registrable}', not '{brand}.com'.",
                "high", 25,
            )
            ctx.rec(f"Verify you are on the official {brand}.com domain before entering any credentials.")
            break  # one impersonation finding is enough


def _check_suspicious_keywords(ctx: _Ctx) -> None:
    path_query = (ctx.parsed.path + "?" + (ctx.parsed.query or "")).lower()
    host_lower = (ctx.parsed.hostname or "").lower()
    combined = host_lower + path_query

    found = [kw for kw in _PHISHING_KEYWORDS if kw in combined]
    if len(found) >= 3:
        ctx.add(
            "Multiple phishing keywords",
            f"URL contains {len(found)} high-risk keywords: {', '.join(found[:5])}.",
            "high", 20,
        )
        ctx.rec("URLs with multiple security-related keywords are a common phishing tactic.")
    elif len(found) >= 1:
        ctx.add(
            "Phishing keyword",
            f"URL contains sensitive keyword(s): {', '.join(found)}.",
            "medium", 10,
        )


def _check_tld(ctx: _Ctx) -> None:
    host = ctx.parsed.hostname or ""
    for tld in _RISKY_TLDS:
        if host.endswith(tld):
            ctx.add(
                "High-risk TLD",
                f"The domain uses '{tld}', a TLD commonly associated with free/throwaway domains used in phishing.",
                "medium", 15,
            )
            ctx.rec("Treat URLs on free TLDs with extra caution.")
            break


def _check_encoding(ctx: _Ctx) -> None:
    # Percent-encoding in host is a strong obfuscation signal
    raw_host = (urlparse(ctx.raw_url).hostname or "")
    if "%" in raw_host:
        ctx.add(
            "Encoded hostname",
            "The hostname contains percent-encoded characters — a common obfuscation technique.",
            "high", 25,
        )
        ctx.rec("Percent-encoded hostnames are used to bypass filters. Do not visit this URL.")

    # Count % sequences in the RAW URL path/query (before normalisation decodes them)
    raw_parsed = urlparse(ctx.raw_url)
    raw_path_query = raw_parsed.path + (raw_parsed.query or "")
    pct_count = raw_path_query.count("%")
    if pct_count >= 5:
        ctx.add(
            "Excessive URL encoding",
            f"{pct_count} percent-encoded sequences found in path/query — often used to hide malicious content.",
            "medium", 15,
        )

def _check_suspicious_chars(ctx: _Ctx) -> None:
    host = ctx.parsed.hostname or ""

    # @ in URL — everything before @ is ignored by browsers (user-info trick)
    if "@" in ctx.raw_url.split("?")[0]:
        ctx.add(
            "@ symbol in URL",
            "A '@' before the path causes browsers to ignore everything before it — classic phishing trick.",
            "high", 30,
        )
        ctx.rec("URLs containing '@' before the domain are almost always phishing attempts.")

    # Double slash in path (not the scheme //)
    path = ctx.parsed.path
    if "//" in path:
        ctx.add("Double slash in path", "Double slashes in the URL path can confuse parsers and hide the real destination.", "low", 5)

    # Homograph / punycode
    if host.startswith("xn--"):
        ctx.add(
            "Punycode domain",
            f"'{host}' is a punycode-encoded domain — may visually impersonate a well-known brand.",
            "high", 20,
        )
        ctx.rec("Check if this punycode domain visually resembles a trusted brand when decoded.")

    # Hyphen abuse: many hyphens in domain
    domain_part = host.split(".")[0] if "." in host else host
    if domain_part.count("-") >= 3:
        ctx.add(
            "Hyphen-heavy domain",
            f"'{host}' contains {domain_part.count('-')} hyphens — domains like 'secure-login-paypal-verify.com' are common phishing patterns.",
            "medium", 10,
        )


def _check_redirect_indicators(ctx: _Ctx) -> None:
    """Flag URL-redirect patterns in the query string (no network call)."""
    query = (ctx.parsed.query or "").lower()
    redirect_params = ["url=", "redirect=", "next=", "goto=", "return=", "returnurl=", "redir=", "forward="]
    for param in redirect_params:
        if param in query:
            ctx.add(
                "Open redirect parameter",
                f"Query string contains '{param}' — a potential open-redirect that could forward you to a malicious site.",
                "medium", 15,
            )
            ctx.rec("URLs with redirect parameters may chain you to a malicious destination.")
            break


# ---------------------------------------------------------------------------
# Score → level
# ---------------------------------------------------------------------------

def _score_to_level(score: int) -> str:
    if score <= 0:  return "safe"
    if score < 20:  return "low"
    if score < 45:  return "medium"
    if score < 70:  return "high"
    return "critical"


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def analyse_url(raw_url: str) -> tuple[str, int, str, list[Indicator], list[str]]:
    """
    Analyse *raw_url* deterministically.

    Returns (normalized_url, risk_score, risk_level, indicators, recommendations).
    No network calls are made. The URL is never stored here — persistence is
    handled by the API layer.
    """
    ctx = _Ctx(raw_url=raw_url)

    _check_scheme(ctx)
    _check_length(ctx)
    _check_ip_host(ctx)
    _check_subdomains(ctx)
    _check_brand_impersonation(ctx)
    _check_suspicious_keywords(ctx)
    _check_tld(ctx)
    _check_encoding(ctx)
    _check_suspicious_chars(ctx)
    _check_redirect_indicators(ctx)

    score = max(0, min(100, ctx.score))
    level = _score_to_level(score)

    # Default recommendation for all scans
    if not ctx.recommendations:
        ctx.rec("Always verify the domain matches the expected website before entering credentials.")

    return ctx.normalized, score, level, ctx.indicators, ctx.recommendations
