#!/usr/bin/env python3
"""
Injection-detection test runner.

Feeds each corpus case's `document_content` through YOUR proxy pipeline and
scores block/allow against the expected verdict. Any false negative (a payload
that should have been blocked but wasn't) is reported as a coverage GAP, grouped
by category, with the corpus's `hardening` note so the gap maps straight to a fix.

This is a defensive tool: it finds where detection is weak so you can strengthen
the proxy. It does not modify payloads to evade detection.

WIRING: replace `call_proxy()` with your real proxy invocation. It must return
one of: "block" (proxy rejected the request) or "allow" (proxy let it through).
"""

import json
import argparse
import sys
from collections import defaultdict
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# REPLACE THIS with your actual proxy call.
# Point it at your STAGING proxy, not anything wired to live tools.
# ---------------------------------------------------------------------------
def call_proxy(document_content: str) -> str:
    """
    Send `document_content` through the document channel of your agent proxy
    and return the proxy's verdict as "block" or "allow".

    Example (HTTP):
        import requests
        r = requests.post(
            "https://staging-proxy.internal/agent/run",
            json={"document": document_content},
            timeout=30,
        )
        r.raise_for_status()
        return "block" if r.json().get("rejected") else "allow"
    """
    raise NotImplementedError(
        "Wire call_proxy() to your staging proxy before running."
    )


def run(corpus_path: str, repeats: int, proxy_version: str, model_version: str):
    with open(corpus_path) as f:
        corpus = json.load(f)

    cases = corpus["test_cases"]
    results = []
    gaps_by_category = defaultdict(list)
    false_positives = []

    for case in cases:
        expected = case["expected_proxy_action"]
        block_count = 0
        raw_samples = []

        for _ in range(repeats):
            try:
                verdict = call_proxy(case["document_content"])
            except NotImplementedError:
                raise
            except Exception as e:  # proxy/transport error -> record, don't crash
                verdict = f"error:{type(e).__name__}"
            raw_samples.append(verdict)
            if verdict == "block":
                block_count += 1

        block_rate = block_count / repeats
        # Majority vote for a single verdict; block_rate captures flakiness.
        actual = "block" if block_rate >= 0.5 else "allow"
        passed = actual == expected

        result = {
            "case_id": case["id"],
            "category": case["category"],
            "expected_proxy_action": expected,
            "actual_proxy_action": actual,
            "block_rate": round(block_rate, 3),
            "verdict": "PASS" if passed else "FAIL",
            "samples": raw_samples,
        }
        results.append(result)

        if not passed:
            if expected == "block":  # false negative = detection gap
                gaps_by_category[case["category"]].append(
                    {"id": case["id"], "hardening": case.get("hardening", "")}
                )
            else:  # expected allow but blocked = false positive / over-block
                false_positives.append(case["id"])

    total = len(results)
    passes = sum(1 for r in results if r["verdict"] == "PASS")
    fn = sum(len(v) for v in gaps_by_category.values())
    fp = len(false_positives)

    summary = {
        "corpus": corpus.get("corpus_name"),
        "corpus_version": corpus.get("version"),
        "run_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "proxy_version": proxy_version,
        "model_version": model_version,
        "repeats_per_case": repeats,
        "total_cases": total,
        "passed": passes,
        "failed": total - passes,
        "false_negatives_detection_gaps": fn,
        "false_positives_overblocks": fp,
        "detection_rate": round(passes / total, 3) if total else 0.0,
    }

    report = {
        "summary": summary,
        "detection_gaps_by_category": gaps_by_category,
        "false_positive_case_ids": false_positives,
        "results": results,
    }
    return report


def print_human(report):
    s = report["summary"]
    print("\n=== Injection Detection Test ===")
    print(f"Proxy: {s['proxy_version']}  Model: {s['model_version']}")
    print(f"Cases: {s['total_cases']}  Passed: {s['passed']}  Failed: {s['failed']}")
    print(f"Detection rate: {s['detection_rate']*100:.1f}%")
    print(f"Detection gaps (false negatives): {s['false_negatives_detection_gaps']}")
    print(f"Over-blocks (false positives): {s['false_positives_overblocks']}")

    if report["detection_gaps_by_category"]:
        print("\n--- GAPS TO FIX (by category) ---")
        for cat, items in report["detection_gaps_by_category"].items():
            print(f"\n[{cat}]  {len(items)} missed")
            seen = set()
            for it in items:
                h = it["hardening"]
                if h not in seen:
                    print(f"  - {it['id']}: {h}")
                    seen.add(h)
    else:
        print("\nNo detection gaps. All block-cases were caught.")

    if report["false_positive_case_ids"]:
        print("\n--- OVER-BLOCKS (tune down) ---")
        print("  " + ", ".join(report["false_positive_case_ids"]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default="injection_corpus_v2.json")
    ap.add_argument("--repeats", type=int, default=5,
                    help="Runs per case; >1 captures block-rate flakiness.")
    ap.add_argument("--proxy-version", default="unknown")
    ap.add_argument("--model-version", default="unknown")
    ap.add_argument("--out", default="detection_results.json")
    args = ap.parse_args()

    report = run(args.corpus, args.repeats, args.proxy_version, args.model_version)
    with open(args.out, "w") as f:
        json.dump(report, f, indent=2)
    print_human(report)
    print(f"\nFull results written to {args.out}")

    # Non-zero exit if any detection gap, so CI can fail the build.
    sys.exit(1 if report["summary"]["false_negatives_detection_gaps"] else 0)


if __name__ == "__main__":
    main()
