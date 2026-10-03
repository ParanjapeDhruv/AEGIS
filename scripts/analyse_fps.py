"""Drill into FP categories to understand what's causing them."""
import sys
from collections import Counter
from pathlib import Path
sys.path.insert(0, ".")
from backend.app.services.url_analyzer import analyse_url

benign_hard = [l.strip() for l in Path("data/eval/benign_hard_tune.txt").read_text().splitlines() if l.strip()]

THRESHOLD = 10
fp_by_indicator: dict[str, list[str]] = {}
for url in benign_hard:
    try:
        _, score, _, ind, _ = analyse_url(url)
        if score >= THRESHOLD:
            ids = [i.id for i in ind]
            for iid in ids:
                fp_by_indicator.setdefault(iid, []).append(url)
    except ValueError:
        pass

print("=== FP BREAKDOWN ===")
for iid, urls in sorted(fp_by_indicator.items(), key=lambda x: -len(x[1])):
    print(f"\n{iid}: {len(urls)} FPs")
    for u in urls[:5]:
        print(f"  {u[:90]}")

# Specifically look at external_redirect FPs
print("\n\n=== EXTERNAL REDIRECT FPs (sample) ===")
for url in fp_by_indicator.get("external_redirect", [])[:20]:
    from urllib.parse import urlsplit, parse_qsl
    q = parse_qsl(urlsplit(url).query or "", keep_blank_values=True)
    redirect_pairs = [(k,v) for k,v in q if k.lower() in {"redirect","redirect_uri","next","return","callback","continue","dest","goto","url","uri"}]
    print(f"  params={redirect_pairs[:2]} | {url[:80]}")

# brand_impersonation FPs
print("\n\n=== BRAND IMPERSONATION FPs (sample) ===")
for url in fp_by_indicator.get("brand_impersonation", [])[:20]:
    print(f"  {url[:90]}")
