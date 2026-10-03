"""
Deterministic URL phishing/threat analyser — v2.1-heuristic.

Design: zero network I/O, fully deterministic, HTTPS never a safety signal.
v2.1 improvements (data-driven from PDB/Tranco eval):
  - Path-based signals for phishing infrastructure patterns
  - High-entropy path segments
  - OAuth redirect FP suppression
  - Expanded risky TLD list
  - credential_kw_path suppressed unless elevated score
"""
from __future__ import annotations

import ipaddress
import math
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlsplit, urlunsplit

import tldextract as _tldextract

from backend.app.schemas.url_analysis import Indicator
from backend.app.services.url_data.brands import (
    ALL_LEGITIMATE, BRANDS, CONFUSABLES, CREDENTIAL_KEYWORDS,
    FREENOM_TLDS, LIGHT_RISKY_TLDS, MEDIUM_RISKY_TLDS,
    OAUTH_PROVIDERS, PHISHING_PATH_PATTERNS, REDIRECT_PARAMS,
    RISKY_MULTI_TLDS, URL_SHORTENERS,
)

_TLD = _tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True
)

ANALYSIS_VERSION = "2.2-heuristic"

_W: dict[str, float] = {
    # Structural
    "no_https":               0.05,
    "long_url":               0.05,
    "very_long_url":          0.10,
    # Brand / identity
    "brand_impersonation":    0.50,
    "typosquat":              0.55,
    "homograph":              0.60,
    "brand_in_path":          0.05,
    # Keywords
    "credential_kw_host":     0.15,
    "credential_kw_path":     0.03,
    "multiple_kw":            0.25,
    # TLD
    "freenom_tld":            0.20,
    "medium_risky_tld":       0.12,
    "light_risky_tld":        0.08,
    # Host structure
    "excessive_subdomains":   0.15,
    "hyphen_heavy":           0.10,
    "punycode_label":         0.25,
    # IP
    "public_ip":              0.45,
    "obfuscated_ip":          0.60,
    "non_public_address":     0.08,
    # Deception
    "deceptive_userinfo":     0.60,
    "external_redirect":      0.30,
    # Encoding
    "encoded_hostname":       0.50,
    "double_encoding":        0.25,
    "excessive_encoding":     0.12,
    # Misc
    "shortener":              0.15,
    "nondefault_port":        0.10,
    "double_slash_path":      0.04,
    "high_entropy_label":     0.10,
    "control_chars":          0.30,
    "had_backslash":          0.20,
    # Path signals (new in v2.1)
    "path_cgi_bin":           0.25,
    "path_sitekey":           0.30,
    "path_wp_login":          0.20,
    "path_xmlrpc":            0.20,
    "path_admin_login":       0.15,
    "path_account_action":    0.20,
    "path_base64":            0.25,
    "path_secure_resource":   0.20,
    "path_script_query":      0.15,
    "path_update_credential": 0.35,
    "path_uuid":              0.08,
    "path_high_entropy":      0.18,
    # New in v2.2
    "path_cvv":               0.35,
    "numeric_domain":         0.20,
    "risky_multi_tld":        0.15,
}

_LEVEL_CUTS = ((1, "safe"), (20, "low"), (45, "medium"), (70, "high"), (101, "critical"))
_SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


@dataclass
class ParsedUrl:
    scheme: str
    userinfo: str
    host_ascii: str
    host_unicode: str
    port: int | None
    path: str
    query_pairs: list[tuple[str, str]]
    fragment: str
    had_backslash: bool
    had_control_chars: bool
    encoding_depth: int
    host_was_percent_encoded: bool
    raw_query: str


def _strip_control(s: str) -> tuple[str, bool]:
    cleaned = re.sub(r"[\x00-\x1f\x7f]", "", s)
    return cleaned, cleaned != s


def _percent_decode_depth(s: str) -> tuple[str, int]:
    from urllib.parse import unquote
    depth, current = 0, s
    for _ in range(3):
        decoded = unquote(current)
        if decoded == current:
            break
        current, depth = decoded, depth + 1
    return current, depth


def _apply_confusables(s: str) -> str:
    result = s
    for src, dst in CONFUSABLES.items():
        if len(src) > 1:
            result = result.replace(src, dst)
    return "".join(CONFUSABLES.get(ch, ch) for ch in result)


def parse_url(raw: str) -> ParsedUrl:
    """Parse raw URL carefully without global unquoting. Raises ValueError for no host."""
    s, had_control = _strip_control(raw.strip())
    had_backslash = False
    if re.match(r"^https?://", s, re.IGNORECASE):
        new_s = s.replace("\\", "/")
        had_backslash, s = new_s != s, new_s

    split = urlsplit(s)
    scheme = split.scheme.lower()
    raw_netloc = split.netloc
    host_was_pct = "%" in raw_netloc

    userinfo = ""
    netloc_noport = raw_netloc
    if "@" in raw_netloc:
        userinfo, _, netloc_noport = raw_netloc.rpartition("@")

    host_raw, port = netloc_noport, None
    if netloc_noport.startswith("["):
        bracket_end = netloc_noport.find("]")
        if bracket_end != -1:
            host_raw = netloc_noport[1:bracket_end]
            rest = netloc_noport[bracket_end + 1:]
            if rest.startswith(":") and rest[1:].isdigit():
                port = int(rest[1:])
    elif ":" in netloc_noport:
        h, _, p = netloc_noport.rpartition(":")
        if p.isdigit():
            host_raw, port = h, int(p)

    host_decoded, enc_depth = _percent_decode_depth(host_raw)
    host_lower = host_decoded.lower().rstrip(".")
    try:
        host_ascii = host_lower.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        host_ascii = host_lower

    if not host_ascii:
        raise ValueError(f"No valid host in URL: {raw!r}")

    raw_q = split.query or ""
    try:
        q_pairs = parse_qsl(raw_q, keep_blank_values=True)
    except Exception:
        q_pairs = []

    return ParsedUrl(
        scheme=scheme, userinfo=userinfo, host_ascii=host_ascii,
        host_unicode=host_lower, port=port, path=split.path,
        query_pairs=q_pairs, fragment=split.fragment,
        had_backslash=had_backslash, had_control_chars=had_control,
        encoding_depth=enc_depth, host_was_percent_encoded=host_was_pct,
        raw_query=raw_q,
    )


def _normalize_for_display(p: ParsedUrl) -> str:
    netloc = f"{p.host_ascii}:{p.port}" if p.port else p.host_ascii
    query = "&".join(f"{k}={v}" for k, v in p.query_pairs) if p.query_pairs else ""
    return urlunsplit((p.scheme, netloc, p.path, query, ""))


def redact_url_for_storage(raw_url: str) -> str:
    """URL for DB: query values redacted, userinfo/fragment dropped."""
    try:
        p = parse_url(raw_url)
    except ValueError:
        return raw_url[:2048]
    netloc = f"{p.host_ascii}:{p.port}" if p.port else p.host_ascii
    query = "&".join(f"{k}=REDACTED" for k, _ in p.query_pairs) if p.query_pairs else ""
    return urlunsplit((p.scheme, netloc, p.path, query, ""))


def _noisy_or(weights: list[float]) -> int:
    if not weights:
        return 0
    prod = 1.0
    for w in weights:
        prod *= (1.0 - max(0.0, min(1.0, w)))
    return round(100 * (1.0 - prod))


def _score_to_level(score: int) -> str:
    if score == 0:
        return "safe"
    for threshold, label in _LEVEL_CUTS:
        if score < threshold:
            return label
    return "critical"


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    return -sum((c / len(s)) * math.log2(c / len(s)) for c in freq.values())


@dataclass
class _Ctx:
    parsed: ParsedUrl
    ext: object
    indicators: list[Indicator] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    _weights: list[float] = field(default_factory=list)
    _ids: set[str] = field(default_factory=set)

    def add(self, ind_id: str, name: str, detail: str, severity: str) -> None:
        if ind_id in self._ids:
            return
        self._ids.add(ind_id)
        w = _W.get(ind_id, 0.0)
        self._weights.append(w)
        self.indicators.append(Indicator(
            id=ind_id, name=name, detail=detail,
            severity=severity, weight=round(w * 100),
        ))

    def rec(self, text: str) -> None:
        if text not in self.recommendations:
            self.recommendations.append(text)

    @property
    def registrable(self) -> str:
        return f"{self.ext.domain}.{self.ext.suffix}" if self.ext.domain and self.ext.suffix else self.parsed.host_ascii

    @property
    def host_tokens(self) -> list[str]:
        tokens: list[str] = []
        for label in self.parsed.host_ascii.split("."):
            tokens.extend(label.split("-"))
        return [t for t in tokens if t]


def _try_parse_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    if re.match(r"^0[xX][0-9a-fA-F]+$", host):
        try:
            return ipaddress.IPv4Address(int(host, 16))
        except Exception:
            pass
    if re.match(r"^\d+$", host):
        try:
            v = int(host)
            if 0 <= v <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(v)
        except Exception:
            pass
    if "." in host:
        parts = host.split(".")
        if len(parts) == 4:
            try:
                octets = []
                for p in parts:
                    if p.startswith(("0x", "0X")):
                        octets.append(int(p, 16))
                    elif p.startswith("0") and len(p) > 1:
                        octets.append(int(p, 8))
                    else:
                        octets.append(int(p))
                if all(0 <= o <= 255 for o in octets):
                    return ipaddress.IPv4Address(bytes(octets))
            except Exception:
                pass
    return None


def _check_control_backslash(ctx: _Ctx) -> None:
    if ctx.parsed.had_control_chars:
        ctx.add("control_chars", "Control characters in URL",
                "The URL contains ASCII control characters — a sign of obfuscation.", "high")
        ctx.rec("URLs with control characters are almost certainly malicious.")
    if ctx.parsed.had_backslash:
        ctx.add("had_backslash", "Backslash in URL authority",
                "Backslash before the host is treated as '/' by browsers but trips naive parsers.", "medium")


def _check_scheme(ctx: _Ctx) -> None:
    if ctx.parsed.scheme == "http":
        ctx.add("no_https", "No HTTPS",
                "Connection is unencrypted. Note: HTTPS alone does NOT prove legitimacy.", "low")
        ctx.rec("Prefer HTTPS, though HTTPS alone does not guarantee safety.")


def _check_length(ctx: _Ctx) -> None:
    raw_len = (len(ctx.parsed.scheme) + 3 + len(ctx.parsed.host_ascii)
               + (len(str(ctx.parsed.port)) + 1 if ctx.parsed.port else 0)
               + len(ctx.parsed.path) + len(ctx.parsed.raw_query))
    if raw_len > 150:
        ctx.add("very_long_url", "Very long URL",
                f"URL is {raw_len} characters — extremely long URLs often hide the real destination.", "low")
        ctx.rec("Inspect the full URL carefully before clicking.")
    elif raw_len > 100:
        ctx.add("long_url", "Long URL",
                f"URL is {raw_len} characters — longer than typical legitimate URLs.", "low")


def _check_ip_host(ctx: _Ctx) -> None:
    host = ctx.parsed.host_ascii
    ip = _try_parse_ip(host)
    if ip is None:
        return
    canonical = str(ip)
    is_obfuscated = canonical != host
    is_private = (ip.is_private or ip.is_loopback or ip.is_link_local
                  or ip.is_reserved or ip.is_multicast or ip.is_unspecified)
    if is_private:
        ctx.add("non_public_address", "Non-public IP address",
                f"Host is a non-public address ({canonical}) — a LAN device or loopback.", "info")
    elif is_obfuscated:
        ctx.add("obfuscated_ip", "Obfuscated IP address",
                f"Host '{host}' is an obfuscated form of {canonical}. Legitimate services use domain names.", "high")
        ctx.rec("Obfuscated IP addresses bypass URL filters. Treat as critical risk.")
    else:
        ctx.add("public_ip", "Raw public IP address",
                f"Host is a raw public IP ({canonical}). Legitimate services almost always use domain names.", "high")
        ctx.rec("Avoid clicking URLs that use a raw IP address.")


def _check_userinfo(ctx: _Ctx) -> None:
    ui = ctx.parsed.userinfo
    if not ui:
        return
    if "." in ui or "@" in ui:
        ctx.add("deceptive_userinfo", "Deceptive userinfo in URL",
                f"Userinfo '{ui[:40]}' before '@' makes the URL appear to be on a trusted domain, "
                f"but the browser navigates to '{ctx.parsed.host_ascii}'.", "high")
    else:
        ctx.add("deceptive_userinfo", "Userinfo in URL",
                f"The URL has userinfo before '@'. Browser navigates to '{ctx.parsed.host_ascii}'.", "high")
    ctx.rec("URLs with '@' in the authority should be treated with extreme caution.")


def _check_subdomains(ctx: _Ctx) -> None:
    sub = ctx.ext.subdomain
    if not sub:
        return
    labels = [s for s in sub.split(".") if s]
    if len(labels) >= 3:
        ctx.add("excessive_subdomains", "Excessive subdomains",
                f"'{ctx.parsed.host_ascii}' has {len(labels)} subdomain levels — often used to impersonate brands.",
                "medium")
        ctx.rec("Check the actual registrable domain carefully.")


def _damerau_levenshtein(s1: str, s2: str) -> int:
    if abs(len(s1) - len(s2)) > 2:
        return 3
    la, lb = len(s1), len(s2)
    dp = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1): dp[i][0] = i
    for j in range(lb + 1): dp[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if s1[i-1] == s2[j-1] else 1
            dp[i][j] = min(dp[i-1][j] + 1, dp[i][j-1] + 1, dp[i-1][j-1] + cost)
            if i > 1 and j > 1 and s1[i-1] == s2[j-2] and s1[i-2] == s2[j-1]:
                dp[i][j] = min(dp[i][j], dp[i-2][j-2] + cost)
    return dp[la][lb]


def _check_brand(ctx: _Ctx) -> None:
    reg = ctx.registrable
    reg_label = ctx.ext.domain or ""
    host_tok = set(ctx.host_tokens)
    path_lower = ctx.parsed.path.lower()

    for brand_label, legit_set in BRANDS.items():
        if reg in legit_set:
            continue
        # Whole-token brand match in host
        if brand_label in host_tok:
            ctx.add("brand_impersonation", "Brand impersonation",
                    f"'{brand_label}' appears as a host token but registrable domain is '{reg}', not a legitimate {brand_label} domain.",
                    "high")
            ctx.rec(f"Verify you are on the official {brand_label} domain before entering credentials.")
            return
        # Brand embedded in registrable label — whole token only
        folded_reg = _apply_confusables(reg_label.lower())
        reg_tokens = set(re.split(r"[^a-z0-9]", folded_reg))
        if brand_label in reg_tokens and brand_label != reg_label:
            ctx.add("brand_impersonation", "Brand impersonation",
                    f"Registrable domain '{reg}' embeds '{brand_label}' — common phishing pattern.",
                    "high")
            ctx.rec(f"Verify you are on the official {brand_label} domain before entering credentials.")
            return
        # Typosquat: DL <= 1 for brand >= 6 chars
        if len(brand_label) >= 6:
            folded = _apply_confusables(reg_label.lower())
            if _damerau_levenshtein(folded, brand_label) <= 1 and folded != brand_label:
                ctx.add("typosquat", "Possible typosquat",
                        f"Registrable domain '{reg}' closely resembles '{brand_label}'.",
                        "high")
                ctx.rec("Domain closely resembles a known brand. Verify carefully before entering credentials.")
                return
        # Brand only in path
        path_tokens = set(re.split(r"[^a-z0-9]", path_lower))
        if brand_label in path_tokens and "brand_in_path" not in ctx._ids:
            ctx.add("brand_in_path", "Brand name in URL path",
                    f"'{brand_label}' appears in the URL path — may be legitimate but verify the domain.",
                    "info")

    _check_homograph(ctx)


def _check_homograph(ctx: _Ctx) -> None:
    for label in ctx.parsed.host_ascii.split("."):
        if not label.startswith("xn--"):
            continue
        try:
            decoded = label.encode("ascii").decode("idna")
        except Exception:
            decoded = label
        scripts = {unicodedata.name(ch, "").split(" ")[0]
                   for ch in decoded if ch.isalpha()}
        scripts.discard("LATIN")
        scripts.discard("")
        if scripts:
            ctx.add("homograph", "Homograph / mixed-script domain",
                    f"Label '{label}' decodes to '{decoded}' with non-Latin characters ({', '.join(scripts)}).",
                    "high")
            ctx.rec("Non-Latin characters that mimic Latin letters are a homograph attack.")
        else:
            ctx.add("punycode_label", "Punycode domain label",
                    f"Label '{label}' is punycode-encoded — verify it does not resemble a trusted brand.",
                    "medium")
        break


def _check_keywords(ctx: _Ctx) -> None:
    """Token-based credential keyword detection. Suppressed for legitimate brand domains."""
    if ctx.registrable in ALL_LEGITIMATE:
        return

    def tok(s: str) -> set[str]:
        return {t for t in re.split(r"[^a-z0-9]", s.lower()) if t}

    host_kw = CREDENTIAL_KEYWORDS & tok(ctx.parsed.host_ascii)
    path_kw = CREDENTIAL_KEYWORDS & tok(ctx.parsed.path)
    total = host_kw | path_kw

    if len(total) >= 3:
        ctx.add("multiple_kw", "Multiple credential keywords",
                f"URL contains {len(total)} credential-related keywords: {', '.join(sorted(total)[:5])}.",
                "high")
        ctx.rec("Multiple security-related keywords in a URL are a strong phishing indicator.")
    elif host_kw:
        ctx.add("credential_kw_host", "Credential keyword in hostname",
                f"Credential keyword '{next(iter(host_kw))}' found in the hostname.",
                "medium")
    elif len(path_kw) >= 2:
        # Suppress path-only kw if no other signal — avoids FP on /login, /account etc.
        # Only add it when there's at least one other indicator already firing.
        if ctx._ids:
            ctx.add("credential_kw_path", "Credential keywords in path",
                    f"Credential keywords in path: {', '.join(sorted(path_kw)[:3])}.",
                    "low")


def _check_tld(ctx: _Ctx) -> None:
    suffix = ctx.ext.suffix or ""
    tld = suffix.split(".")[-1] if suffix else ""
    if tld in FREENOM_TLDS:
        ctx.add("freenom_tld", "High-risk free TLD",
                f"Domain uses '.{tld}', a Freenom free TLD widely abused for phishing.", "high")
        ctx.rec("Free TLDs (.tk, .ml, .ga, .cf, .gq) are heavily used in phishing. Treat with extreme caution.")
    elif tld in MEDIUM_RISKY_TLDS:
        ctx.add("medium_risky_tld", "Risky TLD",
                f"Domain uses '.{tld}', frequently associated with throwaway domains.", "medium")
    elif tld in LIGHT_RISKY_TLDS:
        ctx.add("light_risky_tld", "Elevated-risk TLD",
                f"Domain uses '.{tld}', with elevated misuse rates.", "low")


def _check_encoding(ctx: _Ctx) -> None:
    if ctx.parsed.host_was_percent_encoded:
        ctx.add("encoded_hostname", "Percent-encoded hostname",
                "Hostname contains percent-encoded characters — obfuscation to bypass URL filters.", "high")
        ctx.rec("Percent-encoded hostnames are used to bypass filters. Do not visit.")
    if ctx.parsed.encoding_depth >= 2:
        ctx.add("double_encoding", "Double URL encoding",
                f"URL is encoded {ctx.parsed.encoding_depth} times — double encoding evades scanners.", "medium")
    raw_pct = ctx.parsed.path.count("%") + ctx.parsed.raw_query.count("%")
    if raw_pct >= 5:
        ctx.add("excessive_encoding", "Excessive URL encoding",
                f"{raw_pct} percent-encoded sequences in path/query.", "medium")


def _check_port(ctx: _Ctx) -> None:
    if ctx.parsed.port is not None and ctx.parsed.port not in {80, 443, 8080, 8443}:
        ctx.add("nondefault_port", "Non-standard port",
                f"URL uses port {ctx.parsed.port} — legitimate sites rarely use non-standard ports.", "low")


def _check_shortener(ctx: _Ctx) -> None:
    if ctx.registrable in URL_SHORTENERS:
        ctx.add("shortener", "URL shortener",
                f"'{ctx.parsed.host_ascii}' is a URL shortener — the true destination is hidden.", "medium")
        ctx.rec("Expand the short URL using a preview tool before visiting.")


def _check_redirect(ctx: _Ctx) -> None:
    """Flag open-redirect params. Suppressed for OAuth flows."""
    # Suppress for known OAuth provider domains
    if ctx.registrable in OAUTH_PROVIDERS or ctx.parsed.host_ascii in OAUTH_PROVIDERS:
        return
    # Suppress when path contains /oauth2/ or /authorize — standard OAuth pattern
    # that legitimately carries redirect_uri on any provider
    if re.search(r"/(oauth2?|authorize|auth)/", ctx.parsed.path, re.IGNORECASE):
        return

    for key, value in ctx.parsed.query_pairs:
        if key.lower() not in REDIRECT_PARAMS:
            continue
        if not (value.startswith("http") or value.startswith("//")):
            continue
        try:
            ext_dest = _TLD(value)
            dest_reg = f"{ext_dest.domain}.{ext_dest.suffix}" if ext_dest.domain else ""
        except Exception:
            continue
        if dest_reg and dest_reg != ctx.registrable:
            ctx.add("external_redirect", "External redirect target",
                    f"Parameter '{key}' redirects to '{dest_reg}', a different domain.", "medium")
            ctx.rec("Redirect parameters pointing to external domains may chain you to a malicious site.")
            break


def _check_hyphens(ctx: _Ctx) -> None:
    reg_label = ctx.ext.domain or ""
    if reg_label.count("-") >= 2:
        ctx.add("hyphen_heavy", "Hyphen-heavy registrable domain",
                f"Registrable domain '{ctx.registrable}' has {reg_label.count('-')} hyphens.", "medium")


def _check_numeric_domain(ctx: _Ctx) -> None:
    """Pure numeric registrable domain (e.g. 2018337.com) — not used by legitimate sites."""
    reg_label = ctx.ext.domain or ""
    if reg_label.isdigit() and len(reg_label) >= 4:
        ctx.add("numeric_domain", "Numeric-only domain",
                f"Registrable domain '{ctx.registrable}' is entirely numeric — extremely unusual for legitimate sites.",
                "medium")


def _check_multi_tld(ctx: _Ctx) -> None:
    """Flag known-abused multi-label TLDs like .my.id."""
    suffix = ctx.ext.suffix or ""
    if suffix in RISKY_MULTI_TLDS:
        ctx.add("risky_multi_tld", "Risky multi-label TLD",
                f"Domain uses '.{suffix}', a free/abused multi-label TLD.",
                "medium")


def _check_double_slash(ctx: _Ctx) -> None:
    if "//" in ctx.parsed.path:
        ctx.add("double_slash_path", "Double slash in path",
                "Double slashes in the URL path can confuse parsers.", "low")


def _check_entropy(ctx: _Ctx) -> None:
    """Flag high-entropy domain labels (DGA-like). Minimum 14 chars to avoid hyphenated legit domains."""
    for label in ctx.parsed.host_ascii.split("."):
        if len(label) < 14:
            continue
        if _shannon_entropy(label) > 3.8:
            ctx.add("high_entropy_label", "High-entropy domain label",
                    f"Label '{label}' looks randomly generated (entropy {_shannon_entropy(label):.1f}).", "low")
            break


def _check_path_signals(ctx: _Ctx) -> None:
    """
    Match path against known phishing infrastructure patterns.
    These catch phishing URLs that use normal domains but characteristic paths
    (cgi-bin, sitekey.php, base64 blobs, credential-update paths, etc.).
    """
    path = ctx.parsed.path
    for pattern, ind_id, display_name in PHISHING_PATH_PATTERNS:
        if re.search(pattern, path, re.IGNORECASE):
            severity = "high" if _W.get(ind_id, 0) >= 0.25 else "medium"
            ctx.add(ind_id, display_name,
                    f"Path matches phishing infrastructure pattern: '{pattern}'.",
                    severity)


def _check_path_entropy(ctx: _Ctx) -> None:
    """
    Flag high-entropy path segments — random-looking paths like
    /CRbbRVJmfPVTtQZPzqSKZJGqHQVFhqkHm/ are characteristic of phishing kits
    that embed tokens or session IDs to track victims.
    Legitimate sites use readable paths or short tokens.
    """
    # Split on / and check each segment
    for segment in ctx.parsed.path.split("/"):
        if len(segment) < 16:
            continue
        # Skip known-safe patterns: hex hashes (git SHAs), numeric IDs
        if re.match(r"^[0-9a-f]{16,64}$", segment, re.IGNORECASE):
            continue
        if _shannon_entropy(segment) > 3.8:
            ctx.add("path_high_entropy", "High-entropy path segment",
                    f"Path segment '{segment[:40]}' appears randomly generated — "
                    "phishing kits often embed tracking tokens in URLs.",
                    "medium")
            ctx.rec("Random-looking path segments are used by phishing kits to track victims.")
            break


def _apply_escalation_floors(ctx: _Ctx, raw_score: int) -> int:
    ids = ctx._ids
    score = raw_score
    if "deceptive_userinfo" in ids:
        score = max(score, 55)
    if "obfuscated_ip" in ids:
        score = max(score, 55)
    brand_hit = ids & {"brand_impersonation", "typosquat", "homograph"}
    kw_hit = ids & {"credential_kw_host", "credential_kw_path", "multiple_kw"}
    if brand_hit and kw_hit:
        score = max(score, 60)
    return score


def analyse_url(raw_url: str) -> tuple[str, int, str, list[Indicator], list[str]]:
    """
    Analyse *raw_url* deterministically. No network I/O.
    Returns (normalized_url, risk_score, risk_level, indicators, recommendations).
    Raises ValueError for no-host URLs (caller maps to HTTP 422).
    """
    parsed = parse_url(raw_url)
    ext = _TLD(parsed.host_ascii)
    ctx = _Ctx(parsed=parsed, ext=ext)

    _check_control_backslash(ctx)
    _check_scheme(ctx)
    _check_length(ctx)
    _check_ip_host(ctx)
    _check_userinfo(ctx)
    _check_subdomains(ctx)
    _check_brand(ctx)
    _check_keywords(ctx)
    _check_tld(ctx)
    _check_encoding(ctx)
    _check_port(ctx)
    _check_shortener(ctx)
    _check_redirect(ctx)
    _check_hyphens(ctx)
    _check_double_slash(ctx)
    _check_entropy(ctx)
    _check_path_signals(ctx)
    _check_path_entropy(ctx)
    _check_numeric_domain(ctx)
    _check_multi_tld(ctx)

    raw_score = _noisy_or(ctx._weights)
    score = _apply_escalation_floors(ctx, raw_score)
    score = max(0, min(100, score))
    level = _score_to_level(score)

    ctx.indicators.sort(key=lambda i: (_SEV_ORDER.get(i.severity, 9), -(i.weight or 0)))

    if not ctx.recommendations:
        ctx.rec("Always verify the registrable domain matches the expected website before entering credentials.")

    return _normalize_for_display(parsed), score, level, ctx.indicators, ctx.recommendations
