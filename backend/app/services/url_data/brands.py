"""
Brand legitimacy registry.

BRANDS maps a canonical brand label to the set of registrable domains
(label + PSL suffix, as returned by tldextract) that are genuinely owned
by that brand. A URL whose registrable domain is in this set must NOT
trigger a brand-impersonation indicator for that brand.
"""

BRANDS: dict[str, set[str]] = {
    "paypal":        {"paypal.com", "paypal.me", "paypalobjects.com"},
    "google":        {
        "google.com", "google.co.in", "google.co.uk", "google.de",
        "google.fr", "google.com.au", "google.ca", "google.co.jp",
        "googleapis.com", "gstatic.com", "youtube.com", "gmail.com",
        "googlevideo.com", "googleusercontent.com", "ggpht.com",
        "accounts.google.com",   # kept for hostname checks
        "google-analytics.com", "googletagmanager.com", "googlesyndication.com",
        "googledomains.com", "googleadservices.com", "googleoptimize.com",
        "2mdn.net", "doubleclick.net",
    },
    "microsoft":     {
        "microsoft.com", "microsoftonline.com", "live.com",
        "office.com", "outlook.com", "azure.com", "azurewebsites.net",
        "sharepoint.com", "windows.net", "msauth.net", "msftauth.net",
        "office365.com", "skype.com", "xbox.com",
        "trafficmanager.net", "office.net",
    },
    "amazon":        {
        "amazon.com", "amazon.in", "amazon.co.uk", "amazon.de",
        "amazon.fr", "amazon.co.jp", "amazon.ca", "amazon.com.au",
        "amazonaws.com", "aws.amazon.com", "cloudfront.net",
        "amazon.dev", "awsstatic.com",
    },
    "apple":         {
        "apple.com", "icloud.com", "itunes.com", "mzstatic.com",
        "apple-dns.net", "cdn-apple.com",
    },
    "facebook":      {"facebook.com", "fb.com", "meta.com", "instagram.com",
                      "whatsapp.com", "fbcdn.net"},
    "instagram":     {"instagram.com"},
    "netflix":       {"netflix.com", "nflxvideo.net", "nflximg.net"},
    "linkedin":      {"linkedin.com"},
    "dropbox":       {"dropbox.com", "dropboxusercontent.com"},
    "github":        {"github.com", "github.io", "githubusercontent.com", "githubassets.com"},
    "twitter":       {"twitter.com", "x.com", "t.co"},
    "whatsapp":      {"whatsapp.com", "whatsapp.net"},
    # Banks — US
    "chase":         {"chase.com", "jpmorgan.com"},
    "wellsfargo":    {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com", "bofa.com"},
    "citibank":      {"citibank.com", "citi.com"},
    # Banks — India
    "sbi":           {"sbi.co.in", "onlinesbi.com", "onlinesbi.sbi"},
    "hdfcbank":      {"hdfcbank.com", "hdfc.com"},
    "icicibank":     {"icicibank.com", "icici.com"},
    "axisbank":      {"axisbank.com"},
    "paytm":         {"paytm.com"},
    "phonepe":       {"phonepe.com"},
    "irctc":         {"irctc.co.in", "irctc.com"},
    "uidai":         {"uidai.gov.in"},
    "incometax":     {"incometaxindia.gov.in", "incometax.gov.in"},
    "ebay":          {"ebay.com", "ebay.co.uk", "ebay.de"},
    "americanexpress": {"americanexpress.com", "aexp.com"},
    "ups":           {"ups.com"},
    "fedex":         {"fedex.com"},
    "dhl":           {"dhl.com"},
    "usps":          {"usps.com"},
    "metamask":      {"metamask.io"},
    # Additional financial brands commonly phished
    "lloyds":        {"lloyds.com", "lloydsbank.com"},
    "barclays":      {"barclays.com", "barclaycard.co.uk"},
    "natwest":       {"natwest.com"},
    "santander":     {"santander.co.uk", "santander.com"},
    "hsbc":          {"hsbc.com", "hsbc.co.uk"},
    "halifax":       {"halifax.co.uk"},
    "commbank":      {"commbank.com.au"},
    "westpac":       {"westpac.com.au"},
    "anz":           {"anz.com", "anz.com.au"},
    "nab":           {"nab.com.au"},
}

# Flat set of ALL legitimate registrable domains for O(1) lookup
ALL_LEGITIMATE: frozenset[str] = frozenset(
    d for domains in BRANDS.values() for d in domains
)

# URL shorteners — destination is hidden
URL_SHORTENERS: frozenset[str] = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd",
    "ow.ly", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
    "tiny.cc", "lnkd.in", "db.tt", "qr.ae", "adf.ly",
    "bitly.com", "tr.im", "su.pr",
})

# Redirect parameter names (exact, case-insensitive)
REDIRECT_PARAMS: frozenset[str] = frozenset({
    "url", "uri", "redirect", "redirect_url", "redirect_uri",
    "next", "goto", "return", "returnurl", "return_to",
    "continue", "dest", "destination", "target", "rurl",
    "redir", "forward", "callback",
})

# Freenom TLDs (heaviest weight)
FREENOM_TLDS: frozenset[str] = frozenset({"tk", "ml", "ga", "cf", "gq"})

# Medium-weight risky TLDs — data-driven from PDB miss analysis
MEDIUM_RISKY_TLDS: frozenset[str] = frozenset({
    "xyz", "top", "click", "icu", "cc", "su", "pw", "zip", "mov",
    "cfd", "shop", "club", "live", "rocks", "cyou", "bar",
    "buzz", "fun", "rest", "uno", "vip", "cam", "monster",
})

# Light risky TLDs (many legitimate sites use these)
LIGHT_RISKY_TLDS: frozenset[str] = frozenset({
    "info", "biz", "online", "site", "link",
})

# Multi-label TLDs with elevated abuse (checked against full suffix)
RISKY_MULTI_TLDS: frozenset[str] = frozenset({
    "my.id", "web.id", "biz.id",
})

# Credential-related keywords (token-matched, never brand names)
CREDENTIAL_KEYWORDS: frozenset[str] = frozenset({
    "login", "signin", "sign-in", "account", "verify", "verification",
    "secure", "security", "update", "confirm", "password", "credential",
    "suspended", "limited", "unusual", "alert", "refund", "payment",
    "invoice", "wallet", "reset", "unlock", "activate", "authenticate",
})

# Confusable character map for typosquat detection
CONFUSABLES: dict[str, str] = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
    "6": "g", "7": "t", "8": "b", "9": "g",
    "rn": "m", "vv": "w",
    # Cyrillic lookalikes -> Latin
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "х": "x", "у": "y", "і": "i", "ј": "j", "ѕ": "s",
    # Greek lookalikes
    "α": "a", "ο": "o", "ρ": "p", "ν": "v",
}

# OAuth providers — suppress redirect FP for these registrable domains
OAUTH_PROVIDERS: frozenset[str] = frozenset({
    "accounts.google.com", "google.com", "microsoftonline.com",
    "microsoft.com", "facebook.com", "github.com", "linkedin.com",
    "twitter.com", "x.com", "apple.com", "amazon.com",
    "salesforce.com", "okta.com", "auth0.com", "ping.com",
})

# Phishing path patterns — regex fragments matched against decoded path
# Each fires a distinct indicator. Ordered by signal strength.
PHISHING_PATH_PATTERNS: list[tuple[str, str, str]] = [
    # (regex, indicator_id, display_name)
    (r"/cgi-bin/",                    "path_cgi_bin",    "CGI-bin path"),
    (r"login\.php",                   "path_sitekey",    "login.php in path"),
    (r"sitekey\.php",                 "path_sitekey",    "sitekey.php in path"),
    (r"/wp-admin/",                   "path_wp_login",   "WordPress admin path"),
    (r"/wp-login\.php",               "path_wp_login",   "WordPress login path"),
    (r"/xmlrpc\.php",                 "path_xmlrpc",     "xmlrpc.php in path"),
    (r"/admin/login",                 "path_admin_login","Admin login path"),
    (r"\b(deactivat\w*|suspend\w*|blocked|frozen|locked)\b", "path_account_action", "Account action keyword in path"),
    (r"[A-Za-z0-9+/]{30,}={0,2}$",   "path_base64",     "Base64-like string in path"),
    (r"/secure/(?:file|document|auth|banking)", "path_secure_resource", "Suspicious /secure/ resource"),
    (r"(\.php|\.asp|\.aspx|\.cfm)\?", "path_script_query", "Script extension with query"),
    (r"/(?:update|confirm|verify)/.*(?:password|credential|pin|ssn|dob|cvv)", "path_update_credential", "Credential update path"),
    (r"\bcvv\b",                      "path_cvv",        "CVV keyword in path"),
    (r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "path_uuid", "UUID in path"),
]
