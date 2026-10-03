"""
Understand the theoretical recall ceiling:
what % of phishing URLs could EVER be caught by purely lexical/structural signals?
"""
import sys
from collections import Counter
from pathlib import Path
sys.path.insert(0, ".")
from backend.app.services.url_analyzer import analyse_url
import tldextract as tld
_TLD = tld.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)

phish = [l.strip() for l in Path("data/eval/phish_holdout.txt").read_text().splitlines() if l.strip()]

caught = missed_with_signal = missed_clean = 0
missed_clean_examples = []
missed_detail = Counter()

for url in phish:
    try:
        _, score, level, ind, _ = analyse_url(url)
        ids = [i.id for i in ind]
        if score >= 10:
            caught += 1
        else:
            ext = _TLD(url)
            # Categorise the miss
            if ids:
                missed_with_signal += 1
                for iid in ids: missed_detail[iid] += 1
            else:
                missed_clean += 1
                if len(missed_clean_examples) < 20:
                    missed_clean_examples.append((url, ext.suffix or "?"))
    except:
        pass

total = len(phish)
print(f"=== HOLDOUT RECALL CEILING ANALYSIS (n={total}) ===")
print(f"Caught (score>=10):  {caught:4} ({caught/total*100:.1f}%)")
print(f"Missed, has signal:  {missed_with_signal:4} ({missed_with_signal/total*100:.1f}%) — adjust threshold")
print(f"Missed, no signal:   {missed_clean:4} ({missed_clean/total*100:.1f}%) — structural ceiling")
print()
print("Signals on near-misses:")
for k,v in missed_detail.most_common(): print(f"  {k}: {v}")
print()
print("Sample clean misses (no indicator fires at all):")
for url, suffix in missed_clean_examples[:15]:
    print(f"  .{suffix:12} {url[:70]}")

# What TLDs are the clean misses on?
ext_c = Counter()
for url in phish:
    try:
        _, score, _, ind, _ = analyse_url(url)
        if score == 0:
            ext = _TLD(url)
            ext_c[ext.suffix or "?"] += 1
    except: pass
print("\nTLD distribution of score=0 phishing (holdout):")
for t, n in ext_c.most_common(12):
    print(f"  .{t}: {n}")
