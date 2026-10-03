"""Quick regression check — run with: .venv/Scripts/python.exe scripts/quick_check.py"""
import sys
sys.path.insert(0, ".")
from backend.app.services.url_analyzer import analyse_url

# 8.8.8.8 = 134744072 decimal, 0x8080808 hex
cases = [
    ("https://example.com",                          None,                                  None,                  "clean safe"),
    ("https://paypal.com/signin",                    None,                                  "brand_impersonation", "real paypal"),
    ("https://accounts.google.com/signin",           None,                                  "brand_impersonation", "real google"),
    ("https://www.amazon.co.uk/",                    None,                                  "brand_impersonation", "real amazon uk"),
    ("https://login.microsoftonline.com/",           None,                                  "brand_impersonation", "real microsoft"),
    ("https://www.google.co.in/",                    None,                                  None,                  "real google india"),
    ("https://medium.com/@user/post",                None,                                  "deceptive_userinfo",  "medium @user in path"),
    ("https://www.youtube.com/@channel",             None,                                  "deceptive_userinfo",  "yt @channel"),
    ("https://github.com/apple/swift",               None,                                  "brand_impersonation", "github/apple path"),
    ("https://paypal.com%2F@evil.com/",              "deceptive_userinfo",                  None,                  "F1 deceptive userinfo"),
    ("http://134744072/login",                       "obfuscated_ip",                       None,                  "F7 decimal ip (8.8.8.8)"),
    ("http://0x8080808/login",                       "obfuscated_ip",                       None,                  "F7 hex ip (8.8.8.8)"),
    ("http://192.168.1.1/login",                     "non_public_address",                  "public_ip",           "F8 private ip"),
    ("https://paypa1.com/login",                     ["typosquat","brand_impersonation"],   None,                  "F9 digit-1"),
    ("https://paypal.com.evil.co.uk/login",          "brand_impersonation",                 None,                  "F10 brand in subdomain"),
    ("https://xn--pypal-4ve.com/login",              ["punycode_label","homograph"],        None,                  "F9 punycode/homograph"),
    ("https://example.com/go?redirect=http://evil.com", "external_redirect",                None,                  "F6 redirect"),
    ("https://example.com/go?image_url=x",           None,                                  "external_redirect",   "F6 no fp on image_url"),
    ("https://secure-paypal-login.verify-account.tk/signin/update/password",
                                                     "brand_impersonation",                 None,                  "malicious combo"),
    ("https://login.microsoftonline.com/",           None,                                  "credential_kw_host",  "F3 ms no keyword fp"),
]

ok = fail = 0
for url, must_have, must_not, note in cases:
    try:
        n, s, l, ind, _ = analyse_url(url)
        ids = [i.id for i in ind]
        problems = []
        if must_have:
            check = must_have if isinstance(must_have, list) else [must_have]
            if not any(m in ids for m in check):
                problems.append(f"MISSING any of {check}")
        if must_not and must_not in ids:
            problems.append(f"UNEXPECTED {must_not}")
        if problems:
            print(f"FAIL  {l:8} s={s:3} {problems} | {note}")
            fail += 1
        else:
            print(f"OK    {l:8} s={s:3} ids={ids[:4]} | {note}")
            ok += 1
    except Exception as e:
        print(f"ERR   {type(e).__name__}: {e} | {note}")
        fail += 1

print(f"\n{ok} passed, {fail} failed")
