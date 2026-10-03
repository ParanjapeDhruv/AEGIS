"""
AEGIS URL Analyser — Offline Evaluation Harness
================================================
Usage:
  python scripts/eval_url_analyzer.py \\
      --phish  scripts/fixtures/phish_sample.txt \\
      --benign scripts/fixtures/benign_sample.txt \\
      [--output docs/reports/url_eval.md]

Both files must be local (one URL per line). No downloading occurs.
"""

import argparse
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.app.services.url_analyzer import analyse_url


def _load(path: str) -> list[str]:
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return [l.strip() for l in lines if l.strip() and not l.startswith("#")]


def _score(url: str) -> tuple[int, list[str]]:
    try:
        _, score, _, indicators, _ = analyse_url(url)
        return score, [i.id for i in indicators]
    except ValueError:
        return -1, []


def _metrics(tp, fp, fn, tn):
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall    = tp / (tp + fn) if (tp + fn) else 0.0
    f1        = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    fpr       = fp / (fp + tn) if (fp + tn) else 0.0
    return precision, recall, f1, fpr


def evaluate(phish_urls: list[str], benign_urls: list[str]) -> dict:
    phish_scores  = [_score(u) for u in phish_urls]
    benign_scores = [_score(u) for u in benign_urls]

    rows = []
    for threshold in range(10, 95, 5):
        tp = sum(1 for s, _ in phish_scores  if s >= threshold)
        fn = sum(1 for s, _ in phish_scores  if 0 <= s < threshold)
        fp = sum(1 for s, _ in benign_scores if s >= threshold)
        tn = sum(1 for s, _ in benign_scores if 0 <= s < threshold)
        p, r, f1, fpr = _metrics(tp, fp, fn, tn)
        rows.append({"threshold": threshold, "tp": tp, "fp": fp,
                     "fn": fn, "tn": tn, "precision": p,
                     "recall": r, "f1": f1, "fpr": fpr})

    # Top FP indicators
    fp_counter: Counter = Counter()
    for s, ids in benign_scores:
        if s >= 20:
            for ind_id in ids:
                fp_counter[ind_id] += 1

    return {"rows": rows, "fp_indicators": fp_counter.most_common(15),
            "phish_count": len(phish_urls), "benign_count": len(benign_urls)}


def _md_table(rows: list[dict]) -> str:
    header = "| Threshold | TP | FP | FN | TN | Precision | Recall | F1 | FPR |"
    sep    = "|-----------|----|----|----|----|-----------|--------|----|-----|"
    lines  = [header, sep]
    for r in rows:
        lines.append(
            f"| {r['threshold']:>9} | {r['tp']:>2} | {r['fp']:>2} | {r['fn']:>2} | "
            f"{r['tn']:>2} | {r['precision']:>9.3f} | {r['recall']:>6.3f} | "
            f"{r['f1']:>4.3f} | {r['fpr']:>3.3f} |"
        )
    return "\n".join(lines)


def write_report(result: dict, output_path: str) -> None:
    fp_lines = "\n".join(
        f"- `{ind}` — {count} benign URL(s)"
        for ind, count in result["fp_indicators"]
    ) or "_None_"

    md = f"""# AEGIS URL Analyser — Evaluation Report

**Phishing URLs:** {result['phish_count']}
**Benign URLs:**   {result['benign_count']}

> Heuristic analysis only. Scores are threshold-dependent.
> This report was generated offline from local fixture files.

## Precision / Recall by Threshold

{_md_table(result['rows'])}

## Top False-Positive Indicators (benign URLs scoring >= 20)

{fp_lines}
"""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(md, encoding="utf-8")
    print(f"Report written to {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate AEGIS URL analyser offline.")
    parser.add_argument("--phish",  required=True, help="Path to phishing URLs (one per line)")
    parser.add_argument("--benign", required=True, help="Path to benign URLs (one per line)")
    parser.add_argument("--output", default="docs/reports/url_eval.md", help="Output markdown path")
    args = parser.parse_args()

    print(f"Loading phishing URLs from {args.phish} ...")
    phish  = _load(args.phish)
    print(f"Loading benign URLs from {args.benign} ...")
    benign = _load(args.benign)
    print(f"Analysing {len(phish)} phishing + {len(benign)} benign URLs ...")

    result = evaluate(phish, benign)

    # Print table to stdout
    print("\n" + _md_table(result["rows"]))
    print("\nTop FP indicators:")
    for ind, count in result["fp_indicators"]:
        print(f"  {ind}: {count}")

    write_report(result, args.output)


if __name__ == "__main__":
    main()
