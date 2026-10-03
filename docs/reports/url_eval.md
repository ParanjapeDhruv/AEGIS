# AEGIS URL Analyser — Evaluation Report (v2.2-heuristic)

**Engine:** deterministic lexical/structural analysis, zero network I/O  
**Date:** generated from PDB + Tranco holdout sets  

> All numbers below are from the **holdout set** (never used for tuning).

---

## Holdout Results — Easy Benign (Tranco top domains)

| Phishing | Benign | Threshold | TP | FP | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|---|---|---|
| 1013 | 1599 | **10** | 516 | 53 | **0.907** | **0.509** | **0.652** | 0.033 |
| 1013 | 1599 | 15 | 379 | 24 | 0.940 | 0.374 | 0.535 | 0.015 |
| 1013 | 1599 | 20 | 281 | 18 | 0.940 | 0.277 | 0.428 | 0.011 |

## Holdout Results — Hard Benign (Tranco top domains + realistic login paths)

| Phishing | Benign | Threshold | TP | FP | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|---|---|---|
| 1013 | 1136 | **10** | 516 | 32 | **0.942** | **0.509** | **0.661** | 0.028 |
| 1013 | 1136 | 15 | 379 | 32 | 0.922 | 0.374 | 0.532 | 0.028 |
| 1013 | 1136 | 20 | 281 | 16 | 0.946 | 0.277 | 0.430 | 0.014 |

---

## Progress Across Versions (holdout, easy benign, t=10)

| Version | TP | FP | Precision | Recall | F1 |
|---|---|---|---|---|---|
| v2.0 (baseline) | 449 | 38 | 0.922 | 0.443 | 0.599 |
| v2.1 (+path signals, +TLDs, OAuth FP fix) | 516 | 53 | 0.907 | 0.509 | 0.652 |
| v2.2 (+login.php, +wp-admin, +CVV, +numeric domain, +multi-TLD, +banks) | **516** | **53** | **0.907** | **0.509** | **0.652** |

---

## Recall Ceiling Analysis

Of the **497 missed phishing URLs** (holdout, t=10):

- **~170 (34%)** score 5–9 — have weak signals (HTTP-only, light TLD). Lowering threshold to 5 would catch these but doubles FPR.
- **~327 (66%)** score 0 — **no lexical signals at all**. These use:
  - Normal `.com`/`.net` domains with no brand or risky TLD
  - Clean-looking short paths or single-segment paths
  - No encoding, no IP, no userinfo, no suspicious keywords

**These cannot be caught by URL-string analysis alone.** Catching them requires domain age, WHOIS, DNS reputation, page content analysis, or ML — all of which are out of scope for this deterministic offline module.

## Top False-Positive Indicators (hard benign, t=10)

| Indicator | Count | Root cause |
|---|---|---|
| brand_impersonation | ~32 | Infrastructure domains containing brand tokens (e.g. google-analytics.com paths on non-google hosts) |
| credential_kw_path | ~24 | Synthetic `/login`, `/account` paths on benign domains |

---

## Recommendation

**Use threshold = 10** in production. This gives:
- 90.7–94.2% precision (very few false alarms)
- 50.9% recall (catches ~half of real phishing via structural signals)
- Complement with: domain age lookup, VirusTotal integration, or ML scoring for the remaining 49%
