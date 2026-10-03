"""Analyse false negatives and false positives from the tune set."""
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, ".")
from backend.app.services.url_analyzer import analyse_url

def load(p): return [l.strip() for l in Path(p).read_text().splitlines() if l.strip()]

phish  = load("data/eval/phish_tune.txt")
benign_easy = load("data/eval/benign_easy_tune.txt")
benign_hard = load("data/eval/benign_hard_tune.txt")

THRESHOLD = 10

# False negatives — phishing missed
fn = []
for url in phish:
    try:
        _, score, _, ind, _ = analyse_url(url)
        if score < THRESHOLD:
            fn.append((score, url, [i.id for i in ind]))
    except ValueError:
        fn.append((-1, url, ["INVALID"]))

fn.sort(key=lambda x: x[0])
print(f"\n=== FALSE NEGATIVES at threshold={THRESHOLD} ===")
print(f"Total: {len(fn)} / {len(phish)} phishing missed ({len(fn)/len(phish)*100:.1f}%)")
print("\nScore distribution of missed:")
dist = Counter(s // 5 * 5 for s,_,_ in fn if s >= 0)
for k in sorted(dist): print(f"  score {k:3}: {dist[k]}")

print("\nSample missed (score=0, no indicators):")
zero = [(s,u,ids) for s,u,ids in fn if s == 0]
print(f"  {len(zero)} URLs score exactly 0")
for s,u,ids in zero[:10]:
    print(f"  {u}")

import tldextract as tld
_TLD = tld.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)
print("\nTLD distribution of missed phishing:")
tld_c = Counter()
for _,u,_ in fn:
    ext = _TLD(u)
    tld_c[ext.suffix or "?"] += 1
for t,n in tld_c.most_common(15):
    print(f"  .{t}: {n}")

print("\nURL length distribution of missed:")
lc = Counter(len(u) // 50 * 50 for _,u,_ in fn)
for k in sorted(lc): print(f"  {k:4}-{k+49}: {lc[k]}")

# FP analysis — hard benign
print(f"\n=== FALSE POSITIVES (hard benign) at threshold={THRESHOLD} ===")
fp = []
for url in benign_hard:
    try:
        _, score, _, ind, _ = analyse_url(url)
        if score >= THRESHOLD:
            fp.append((score, url, [i.id for i in ind]))
    except ValueError:
        pass
fp_ids = Counter(iid for _,_,ids in fp for iid in ids)
print(f"Total FPs: {len(fp)} / {len(benign_hard)}")
print("Top FP indicators:")
for iid, n in fp_ids.most_common(10):
    print(f"  {iid}: {n}")

# What do score-0 phishing URLs look like?
print("\n=== REPRESENTATIVE SCORE-0 PHISHING ===")
for _,u,_ in zero[:20]:
    ext = _TLD(u)
    print(f"  reg={ext.domain}.{ext.suffix} | {u[:80]}")
