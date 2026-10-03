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
    },
    "microsoft":     {
        "microsoft.com", "microsoftonline.com", "live.com",
        "office.com", "outlook.com", "azure.com", "azurewebsites.net",
        "sharepoint.com", "windows.net", "msauth.net", "msftauth.net",
        "office365.com", "skype.com", "xbox.com",
    },
    "amazon":        {
        "amazon.com", "amazon.in", "amazon.co.uk", "amazon.de",
        "amazon.fr", "amazon.co.jp", "amazon.ca", "amazon.com.au",
        "amazonaws.com", "aws.amazon.com", "cloudfront.net",
    },
    "apple":         {"apple.com", "icloud.com", "itunes.com", "mzstatic.com"},
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

# Medium-weight risky TLDs
MEDIUM_RISKY_TLDS: frozenset[str] = frozenset({
    "xyz", "top", "click", "icu", "cc", "su", "pw", "zip", "mov",
})

# Light risky TLDs (many legitimate sites use these)
LIGHT_RISKY_TLDS: frozenset[str] = frozenset({
    "info", "biz", "online", "site", "link",
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
