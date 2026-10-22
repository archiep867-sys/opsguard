#!/usr/bin/env python3
"""Measure OpsGuard on a labelled set of commands: rules only vs Decider only vs combined.

Needs the local Decider for the model columns:
    strands-decider serve StrandsAgents/strands-decider-2B-qwen3.5-v1-2610 --port 8099
Run:  python eval/run_eval.py            (add --no-decider for the offline rules-only numbers)
Labels are a human judgement of how risky each command is; the dataset is small, so treat
the numbers as a sanity check, not a benchmark.
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from opsguard.decider_client import DeciderClient, DeciderInvalidResponse, DeciderUnavailable  # noqa: E402
from opsguard.decision_pipeline import decide  # noqa: E402
from opsguard.safety_engine import Decision, evaluate_command  # noqa: E402

LABELS = ["SAFE", "REVIEW", "BLOCK"]
SEVERITY = {"SAFE": 0, "REVIEW": 1, "BLOCK": 2}


def confusion(pairs: list[tuple[str, str]]) -> dict[str, dict[str, int]]:
    table = {a: {p: 0 for p in LABELS} for a in LABELS}
    for actual, predicted in pairs:
        table[actual][predicted] += 1
    return table


def mode_metrics(pairs: list[tuple[str, str]]) -> dict[str, object]:
    n = len(pairs)
    correct = sum(a == p for a, p in pairs)
    table = confusion(pairs)
    per_class = {}
    for label in LABELS:
        tp = table[label][label]
        predicted = sum(table[a][label] for a in LABELS)
        actual = sum(table[label].values())
        per_class[label] = {"precision": tp / predicted if predicted else None, "recall": tp / actual if actual else None}
    return {
        "n": n,
        "accuracy": correct / n if n else None,
        "unsafe_allow": sum(1 for a, p in pairs if a == "BLOCK" and p == "SAFE"),  # the critical failure
        "under_escalated": sum(1 for a, p in pairs if SEVERITY[p] < SEVERITY[a]),
        "over_cautious": sum(1 for a, p in pairs if SEVERITY[p] > SEVERITY[a]),
        "confusion": table,
        "per_class": per_class,
    }


def pct(value: float | None) -> str:
    return "-" if value is None else f"{value * 100:.1f}%"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(ROOT / "eval" / "commands.jsonl"))
    ap.add_argument("--out", default=str(ROOT / "eval" / "results"))
    ap.add_argument("--no-decider", action="store_true", help="rules only, no model calls")
    args = ap.parse_args()

    rows = [json.loads(line) for line in Path(args.data).read_text().splitlines() if line.strip()]
    client = DeciderClient()
    use_model = not args.no_decider
    if use_model and client.health() != "available":
        print("Decider is not reachable. Start it, or use --no-decider.", file=sys.stderr)
        return 2

    results, decider_latency, rule_latency = [], [], []
    for index, row in enumerate(rows, 1):
        command, label = row["command"], row["label"]
        started = time.perf_counter()
        deterministic = evaluate_command(command).decision.value
        rule_latency.append((time.perf_counter() - started) * 1000)
        record = {"command": command, "label": label, "rules": deterministic, "decider": None,
                  "decider_confidence": None, "combined": deterministic, "status": "rules-only"}
        if use_model:
            try:
                vote = client.classify(command)
                record.update(decider=vote.verdict.value, decider_confidence=round(vote.confidence, 4))
                decider_latency.append(vote.latency_ms if vote.latency_ms is not None else 0.0)
            except (DeciderUnavailable, DeciderInvalidResponse) as exc:
                record["status"] = f"decider-error: {type(exc).__name__}"
            pipeline = decide(command, client)
            record.update(combined=pipeline.final.decision.value, status=pipeline.decider_status)
        results.append(record)
        print(f"[{index}/{len(rows)}] {label:6} rules={record['rules']:6} decider={record['decider'] or '-':6} combined={record['combined']}", flush=True)

    summary: dict[str, object] = {"n": len(results), "rules": mode_metrics([(r["label"], r["rules"]) for r in results]),
                                  "combined": mode_metrics([(r["label"], r["combined"]) for r in results]),
                                  "median_rule_latency_ms": round(statistics.median(rule_latency), 4)}
    if use_model:
        scored = [r for r in results if r["decider"]]
        summary["decider_only"] = mode_metrics([(r["label"], r["decider"]) for r in scored])
        if decider_latency:
            ordered = sorted(decider_latency)
            summary["decider_latency_ms"] = {"median": round(statistics.median(ordered), 1), "p95": round(ordered[int(0.95 * (len(ordered) - 1))], 1)}
        buckets: dict[str, list[bool]] = {}
        for r in scored:
            c = r["decider_confidence"] or 0.0
            key = f"{int(min(c, 0.999) * 5) / 5:.1f}-{int(min(c, 0.999) * 5) / 5 + 0.2:.1f}"
            buckets.setdefault(key, []).append(r["decider"] == r["label"])
        summary["decider_calibration"] = {k: {"n": len(v), "accuracy": sum(v) / len(v)} for k, v in sorted(buckets.items())}

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "summary.json").write_text(json.dumps(summary, indent=2))
    with open(out / "predictions.csv", "w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(results[0]))
        writer.writeheader()
        writer.writerows(results)

    lines = ["| mode | accuracy | unsafe-allow (BLOCK shown as SAFE) | under-escalated | over-cautious |", "|---|---|---|---|---|"]
    for name in ("rules", "decider_only", "combined"):
        if name in summary:
            m = summary[name]
            lines.append(f"| {name} | {pct(m['accuracy'])} | {m['unsafe_allow']} | {m['under_escalated']} | {m['over_cautious']} |")
    if "decider_latency_ms" in summary:
        lines.append(f"\nDecider latency: median {summary['decider_latency_ms']['median']} ms, p95 {summary['decider_latency_ms']['p95']} ms. "
                     f"Rules: median {summary['median_rule_latency_ms']} ms.")
    (out / "summary.md").write_text("\n".join(lines) + "\n")
    print("\n" + "\n".join(lines))
    print(f"\nWrote {out}/summary.md, summary.json, predictions.csv")
    return 1 if summary["combined"]["unsafe_allow"] else 0


if __name__ == "__main__":
    sys.exit(main())
