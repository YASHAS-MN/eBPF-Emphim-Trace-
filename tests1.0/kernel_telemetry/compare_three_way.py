#!/usr/bin/env python3
"""compare_three_way.py — Three-Way Normalized Comparative Analyzer for EphimTrace

Strict comparative analyzer evaluating Architecture A vs Architecture B vs Architecture C
against the 6 owner-approved numerical acceptance targets recorded in
GitHub Issue #3, Issue #4, and BENCHMARK_SPEC.md.

Enforces:
1. Operation completeness derived from actual unique reconciled records.
2. Independent stage-wise event loss accounting.
3. Retention and reporting of all trial reports (never silently drops invalid trials).
4. Strict sample size requirements (N >= 5 valid runs per target).
5. Workload configuration matching between architectures.
6. Per-trial residual checks (preventing cancellation across trials).
7. Evaluation across Architecture A (baseline), Architecture B (async), and Architecture C (minimal-kernel).
"""

import argparse
import json
import math
import pathlib
import sys
from typing import Any, Dict, List, Optional

# Import normalized metrics aggregation from shared comparative analyzer
HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from compare_architectures import (
    aggregate_workload_metrics,
    compute_stats,
    load_suite_trials,
    parse_trial_report,
)
from compare_architectures import (
    evaluate_acceptance_targets as evaluate_pair_targets,
)


def evaluate_three_way_targets(
    aggs_a: Dict[str, Dict[str, Any]],
    aggs_b: Dict[str, Dict[str, Any]],
    aggs_c: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    """Evaluates the 6 numerical acceptance targets for Arch B vs Arch A and Arch C vs Arch A."""
    targets_b = evaluate_pair_targets(aggs_a, aggs_b)
    targets_c = evaluate_pair_targets(aggs_a, aggs_c)
    return {
        "architecture_b_vs_a": targets_b,
        "architecture_c_vs_a": targets_c,
    }


def print_three_way_report(
    aggs_a: Dict[str, Dict[str, Any]],
    aggs_b: Dict[str, Dict[str, Any]],
    aggs_c: Dict[str, Dict[str, Any]],
    targets: Dict[str, Any],
):
    """Prints comprehensive three-way comparative tables and target evaluations."""
    workloads = sorted(set(aggs_a.keys()) | set(aggs_b.keys()) | set(aggs_c.keys()))

    print("=" * 115)
    print(
        "EphimTrace Telemetry Architecture Comparative Evaluation: Arch A vs Arch B vs Arch C"
    )
    print("=" * 115)

    # 1. Completeness & Loss Accounting
    print(
        "\n[TABLE 1: VALIDATED CREATION-OPERATION COMPLETENESS & STAGE-WISE LOSS RECONCILIATION]"
    )
    print(
        f"{'Workload':<14} | {'Arch':<5} | {'Ops':<7} | {'Reconstructed':<13} | {'C_e2e (%)':<10} | {'Ring Loss':<9} | {'Queue Loss':<10} | {'Residual':<8}"
    )
    print("-" * 115)
    for wl in workloads:
        for arch_label, aggs in [("A", aggs_a), ("B", aggs_b), ("C", aggs_c)]:
            data = aggs.get(wl)
            if data and data.get("sample_size", 0) > 0:
                c = data["completeness_c_e2e"]["mean"] * 100.0
                r = data["ring_loss"]["mean"]
                q = data["queue_loss"]["mean"]
                res = data["residual"]["mean"]
                ops = int(round(data["ops_attempted"]["mean"]))
                rec = int(round(data["reconstructed"]["mean"]))
                tag = wl if arch_label == "A" else ""
                print(
                    f"{tag:<14} | {arch_label:<5} | {ops:<7} | {rec:<13} | {c:<10.2f} | {r:<9.0f} | {q:<10.0f} | {res:<8.0f}"
                )
        print("-" * 115)

    # 2. Throughput, Drain Latency & Memory Footprint
    print("\n[TABLE 2: THROUGHPUT, DRAIN LATENCY & MEMORY FOOTPRINT]")
    print(
        f"{'Workload':<14} | {'Arch':<5} | {'Offered Thru (op/s)':<20} | {'Useful Thru (op/s)':<20} | {'Drain Latency (ms)':<18} | {'Peak RSS (MiB)':<14}"
    )
    print("-" * 115)
    for wl in workloads:
        for arch_label, aggs in [("A", aggs_a), ("B", aggs_b), ("C", aggs_c)]:
            data = aggs.get(wl)
            if data and data.get("sample_size", 0) > 0:
                o = data["offered_throughput_ops_sec"]
                u = data["useful_throughput_ops_sec"]
                d = data["drain_latency_ms"]
                m = data["peak_rss_mib"]
                tag = wl if arch_label == "A" else ""
                print(
                    f"{tag:<14} | {arch_label:<5} | {o['mean']:>8.1f} ± {o['ci95']:<7.1f} | {u['mean']:>8.1f} ± {u['ci95']:<7.1f} | {d['mean']:>7.1f} ± {d['ci95']:<6.1f} | {m['mean']:>6.1f} (max {m['max']:.1f})"
                )
        print("-" * 115)

    # 3. CPU Resource Disaggregation
    print("\n[TABLE 3: DISAGGREGATED CPU COST ACCOUNTING (ACTIVE VS TOTAL)]")
    print(
        f"{'Workload':<14} | {'Arch':<5} | {'Active CPU / Op (µs)':<22} | {'Total CPU / Op (µs)':<22} | {'Active CPU / Reconstructed (µs)':<30}"
    )
    print("-" * 115)
    for wl in workloads:
        for arch_label, aggs in [("A", aggs_a), ("B", aggs_b), ("C", aggs_c)]:
            data = aggs.get(wl)
            if data and data.get("sample_size", 0) > 0:
                ca = data["cpu_cost_attempted_us"]
                tot = data.get("total_trial_cpu_cost_attempted_us", ca)
                cr = data["cpu_cost_reconstructed_us"]
                tag = wl if arch_label == "A" else ""
                print(
                    f"{tag:<14} | {arch_label:<5} | {ca['mean']:>8.2f} ± {ca['ci95']:<6.2f}     | {tot['mean']:>8.2f} ± {tot['ci95']:<6.2f}    | {cr['mean']:>11.2f} ± {cr['ci95']:<8.2f}"
                )
        print("-" * 115)

    # 4. Acceptance Target Evaluation
    print(
        "\n[NUMERICAL ACCEPTANCE TARGET EVALUATION: ARCHITECTURE C VS ARCHITECTURE A]"
    )
    all_pass_c = True
    targets_c = targets["architecture_c_vs_a"]
    for key, tgt in targets_c.items():
        status = "PASS" if tgt["pass"] else "FAIL"
        if not tgt["pass"]:
            all_pass_c = False
        print(f"  [{status}] {tgt['name']}")
        print(f"         Observed:  {tgt['metric']}")
        print(f"         Threshold: {tgt['threshold']}")

    print(
        "\n[NUMERICAL ACCEPTANCE TARGET EVALUATION: ARCHITECTURE B VS ARCHITECTURE A]"
    )
    all_pass_b = True
    targets_b = targets["architecture_b_vs_a"]
    for key, tgt in targets_b.items():
        status = "PASS" if tgt["pass"] else "FAIL"
        if not tgt["pass"]:
            all_pass_b = False
        print(f"  [{status}] {tgt['name']}")
        print(f"         Observed:  {tgt['metric']}")
        print(f"         Threshold: {tgt['threshold']}")

    # 5. Invalid Trial Summary (if any)
    all_invalid = []
    for arch, aggs in [("Arch A", aggs_a), ("Arch B", aggs_b), ("Arch C", aggs_c)]:
        for wl, agg in aggs.items():
            for inv in agg.get("invalid_trials", []):
                all_invalid.append((arch, wl, inv.get("name"), inv.get("error")))

    if all_invalid:
        print("\n[WARNING: INVALID TRIALS DETECTED IN EVIDENCE]")
        for arch, wl, name, err in all_invalid:
            print(f"  - [{arch}] {wl} / {name}: {err}")

    print("\n" + "=" * 115)
    overall_c = (
        "[PASS] Architecture C satisfies ALL numerical acceptance targets."
        if all_pass_c
        else "[FAIL] Architecture C DOES NOT satisfy all acceptance targets."
    )
    overall_b = (
        "[PASS] Architecture B satisfies ALL numerical acceptance targets."
        if all_pass_b
        else "[FAIL] Architecture B DOES NOT satisfy all acceptance targets."
    )
    print(f"OVERALL RESULT (Arch C): {overall_c}")
    print(f"OVERALL RESULT (Arch B): {overall_b}")
    print("=" * 115 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Three-way comparative analysis between Arch A, Arch B, and Arch C."
    )
    parser.add_argument(
        "--dir-a",
        required=True,
        type=pathlib.Path,
        help="Directory containing Arch A results",
    )
    parser.add_argument(
        "--dir-b",
        required=True,
        type=pathlib.Path,
        help="Directory containing Arch B results",
    )
    parser.add_argument(
        "--dir-c",
        required=True,
        type=pathlib.Path,
        help="Directory containing Arch C results",
    )
    parser.add_argument(
        "--json",
        type=pathlib.Path,
        help="Output path for three-way comparison summary JSON",
    )
    args = parser.parse_args()

    for p, label in [
        (args.dir_a, "Arch A"),
        (args.dir_b, "Arch B"),
        (args.dir_c, "Arch C"),
    ]:
        if not p.exists():
            parser.error(f"Directory for {label} does not exist: {p}")

    raw_a = load_suite_trials(args.dir_a)
    raw_b = load_suite_trials(args.dir_b)
    raw_c = load_suite_trials(args.dir_c)

    aggs_a = {wl: aggregate_workload_metrics(trials) for wl, trials in raw_a.items()}
    aggs_b = {wl: aggregate_workload_metrics(trials) for wl, trials in raw_b.items()}
    aggs_c = {wl: aggregate_workload_metrics(trials) for wl, trials in raw_c.items()}

    targets = evaluate_three_way_targets(aggs_a, aggs_b, aggs_c)
    print_three_way_report(aggs_a, aggs_b, aggs_c, targets)

    if args.json:
        summary = {
            "architecture_a": aggs_a,
            "architecture_b": aggs_b,
            "architecture_c": aggs_c,
            "acceptance_targets": targets,
            "all_targets_passed_c": all(
                t["pass"] for t in targets["architecture_c_vs_a"].values()
            ),
            "all_targets_passed_b": all(
                t["pass"] for t in targets["architecture_b_vs_a"].values()
            ),
        }
        args.json.write_text(json.dumps(summary, indent=2))
        print(f"Wrote comparison summary JSON to {args.json}")

    return 0 if all(t["pass"] for t in targets["architecture_c_vs_a"].values()) else 1


if __name__ == "__main__":
    sys.exit(main())
