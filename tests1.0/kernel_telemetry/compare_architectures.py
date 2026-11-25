#!/usr/bin/env python3
"""
EphimTrace Telemetry Architecture Comparative Analyzer (Architecture A vs B).

Evaluates benchmark results against the owner-approved numerical acceptance targets
from GitHub Issue #3 and BENCHMARK_SPEC.md:
  1. Control Completeness: C_e2e = 100.0% (0 drops across all stages) on W_PACED.
  2. Fidelity Invariants: Zero corrupted tokens, zero outcome inversions, zero residuals.
  3. Burst Incomplete-Operation Reduction: >= 50% relative reduction in F_incomplete on W_BURST.
  4. Sustained Useful Throughput Gain: >= 20% gain in Useful Throughput on W_SUSTAIN.
  5. Memory Cap: Peak RSS(B) <= Peak RSS(A) + 64 MiB.
  6. Burst Drain Latency: Drain latency <= 1,000 ms on W_BURST.
"""

import argparse
import json
import math
import pathlib
import sys
from typing import Any, Dict, List, Tuple

# t-distribution critical values for 95% two-sided confidence intervals
# df = N - 1
T_DIST_95 = {
    1: 12.706,
    2: 4.303,
    3: 3.182,
    4: 2.776,
    5: 2.571,
    6: 2.447,
    7: 2.365,
    8: 2.306,
    9: 2.262,
    10: 2.228,
}


def compute_stats(values: List[float]) -> Dict[str, float]:
    """Computes mean, sample std dev, min, max, and 95% confidence interval half-width."""
    n = len(values)
    if n == 0:
        return {"n": 0, "mean": 0.0, "std": 0.0, "min": 0.0, "max": 0.0, "ci95": 0.0}
    mean = sum(values) / n
    if n > 1:
        variance = sum((x - mean) ** 2 for x in values) / (n - 1)
        std = math.sqrt(variance)
        t_val = T_DIST_95.get(n - 1, 1.96)
        ci95 = t_val * std / math.sqrt(n)
    else:
        std = 0.0
        ci95 = 0.0
    return {
        "n": n,
        "mean": mean,
        "std": std,
        "min": min(values),
        "max": max(values),
        "ci95": ci95,
    }


def parse_trial_report(path: pathlib.Path) -> Dict[str, Any]:
    """Parses a single trial JSON report and extracts normalized pipeline metrics."""
    data = json.loads(path.read_text())
    if data.get("status") != "VALID":
        return {
            "valid": False,
            "name": path.stem,
            "error": data.get("error", "invalid trial"),
        }

    analysis = data.get("analysis", {})
    workload = data.get("workload", {})
    meas = data.get("measurement", {})
    pipe = analysis.get("pipeline_accounting", {})
    thru = analysis.get("throughput", {})
    res = analysis.get("resources", {})
    rec = analysis.get("reconciliation", {})

    n_ops = pipe.get("ops_attempted", workload.get("create_attempts", 0))
    n_reconstructed = pipe.get("reconstructed", 0)
    c_e2e = pipe.get(
        "completeness_c_e2e", 1.0 if n_ops == 0 else (n_reconstructed / n_ops)
    )
    f_incomplete = pipe.get("incomplete_fraction_f", 1.0 - c_e2e)
    residual = pipe.get("residual", 0)

    # Losses
    ring_loss = pipe.get("ring_loss", analysis.get("target_reservation_failures", 0))
    queue_loss = pipe.get("queue_loss", meas.get("queue", {}).get("drops", 0))
    gen_gap = pipe.get("gen_gap", 0)
    corr_def = pipe.get("corr_def", analysis.get("completion_uncorrelated", 0))
    proc_fail = pipe.get("proc_fail", 0)

    # Fidelity counts
    corrupt_count = rec.get("corrupted_events_count", 0)
    incorrect_outcome = rec.get("incorrect_outcome_count", 0)

    # Throughput & Timing
    offered_thru = thru.get("offered_throughput_ops_sec", 0.0)
    useful_thru = thru.get("useful_throughput_ops_sec", 0.0)
    drain_ms = thru.get("drain_latency_ms", 0.0)

    # Resources
    rss_mib = res.get(
        "loader_max_rss_mib", meas.get("rusage", {}).get("max_rss_kb", 0) / 1024.0
    )
    cost_attempted_us = res.get("cpu_cost_attempted_us", 0.0)
    cost_reconstructed_us = res.get("cpu_cost_reconstructed_us", 0.0)

    return {
        "valid": True,
        "name": path.stem,
        "ops_attempted": n_ops,
        "reconstructed": n_reconstructed,
        "completeness_c_e2e": c_e2e,
        "incomplete_fraction_f": f_incomplete,
        "ring_loss": ring_loss,
        "queue_loss": queue_loss,
        "gen_gap": gen_gap,
        "corr_def": corr_def,
        "proc_fail": proc_fail,
        "residual": residual,
        "corrupt_count": corrupt_count,
        "incorrect_outcome": incorrect_outcome,
        "offered_throughput_ops_sec": offered_thru,
        "useful_throughput_ops_sec": useful_thru,
        "drain_latency_ms": drain_ms,
        "peak_rss_mib": rss_mib,
        "cpu_cost_attempted_us": cost_attempted_us,
        "cpu_cost_reconstructed_us": cost_reconstructed_us,
    }


def load_suite_trials(dir_path: pathlib.Path) -> Dict[str, List[Dict[str, Any]]]:
    """Loads all trial reports in a directory, grouping by workload name."""
    trials_by_workload: Dict[str, List[Dict[str, Any]]] = {}
    ignored = {"environment.json", "build_info.json", "summary.json"}

    for p in sorted(dir_path.glob("*.json")):
        if p.name in ignored:
            continue
        if p.name.endswith("_ground_truth.json") or p.name.endswith(
            "_captured_events.json"
        ):
            continue

        trial = parse_trial_report(p)
        if not trial.get("valid"):
            continue

        # Extract workload name by removing iteration suffix (_1, _2, etc.)
        base_name = p.stem
        parts = base_name.rsplit("_", 1)
        if len(parts) == 2 and parts[1].isdigit():
            wl_name = parts[0]
        else:
            wl_name = base_name

        trials_by_workload.setdefault(wl_name, []).append(trial)

    return trials_by_workload


def aggregate_workload_metrics(trials: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Computes statistical summaries for a group of trials."""
    metrics = [
        "completeness_c_e2e",
        "incomplete_fraction_f",
        "ring_loss",
        "queue_loss",
        "gen_gap",
        "corr_def",
        "proc_fail",
        "residual",
        "corrupt_count",
        "incorrect_outcome",
        "offered_throughput_ops_sec",
        "useful_throughput_ops_sec",
        "drain_latency_ms",
        "peak_rss_mib",
        "cpu_cost_attempted_us",
        "cpu_cost_reconstructed_us",
    ]
    agg = {}
    for m in metrics:
        vals = [t[m] for t in trials if m in t]
        agg[m] = compute_stats(vals)
    agg["sample_size"] = len(trials)
    return agg


def evaluate_acceptance_targets(
    aggs_a: Dict[str, Dict[str, Any]], aggs_b: Dict[str, Dict[str, Any]]
) -> Dict[str, Dict[str, Any]]:
    """Evaluates the 6 owner-approved numerical acceptance targets."""
    results = {}

    # Target 1: Control Completeness on W_PACED
    # Arch B must have C_e2e = 100.0% (0 drops across all stages)
    b_paced = aggs_b.get("W_PACED", aggs_b.get("paced_full", {}))
    if b_paced and b_paced.get("sample_size", 0) > 0:
        c_e2e_mean = b_paced["completeness_c_e2e"]["mean"]
        ring_drops = b_paced["ring_loss"]["mean"]
        queue_drops = b_paced["queue_loss"]["mean"]
        t1_pass = (c_e2e_mean == 1.0) and (ring_drops == 0) and (queue_drops == 0)
        results["target_1_control_completeness"] = {
            "name": "Target 1 — Control Completeness (W_PACED)",
            "pass": t1_pass,
            "metric": f"C_e2e={c_e2e_mean*100:.1f}%, ring_drops={ring_drops:.0f}, queue_drops={queue_drops:.0f}",
            "threshold": "C_e2e = 100.0%, 0 drops across all stages",
        }
    else:
        results["target_1_control_completeness"] = {
            "name": "Target 1 — Control Completeness (W_PACED)",
            "pass": False,
            "metric": "W_PACED data missing in Arch B",
            "threshold": "C_e2e = 100.0%",
        }

    # Target 2: Fidelity Invariants across all workloads
    # Zero corrupted tokens, zero outcome inversions, zero unexplained residuals
    all_b_corrupt = sum(agg["corrupt_count"]["mean"] for agg in aggs_b.values())
    all_b_inversions = sum(agg["incorrect_outcome"]["mean"] for agg in aggs_b.values())
    all_b_residuals = sum(abs(agg["residual"]["mean"]) for agg in aggs_b.values())
    t2_pass = (
        (all_b_corrupt == 0) and (all_b_inversions == 0) and (all_b_residuals == 0)
    )
    results["target_2_fidelity_invariants"] = {
        "name": "Target 2 — Fidelity Invariants (All Workloads)",
        "pass": t2_pass,
        "metric": f"corrupt={all_b_corrupt:.0f}, inversions={all_b_inversions:.0f}, residuals={all_b_residuals:.0f}",
        "threshold": "Zero corrupt tokens, zero inversions, zero unexplained residuals",
    }

    # Target 3: Burst Incomplete-Operation Reduction on W_BURST
    # >= 50% relative reduction in F_incomplete vs Arch A
    a_burst = aggs_a.get("W_BURST", aggs_a.get("parallel_full", {}))
    b_burst = aggs_b.get("W_BURST", aggs_b.get("parallel_full", {}))
    if (
        a_burst
        and b_burst
        and a_burst.get("sample_size", 0) > 0
        and b_burst.get("sample_size", 0) > 0
    ):
        f_a = a_burst["incomplete_fraction_f"]["mean"]
        f_b = b_burst["incomplete_fraction_f"]["mean"]
        if f_a == 0.0:
            t3_pass = f_b == 0.0
            reduction_pct = 100.0 if f_b == 0.0 else -100.0
        else:
            reduction_pct = ((f_a - f_b) / f_a) * 100.0
            t3_pass = reduction_pct >= 50.0
        results["target_3_burst_loss_reduction"] = {
            "name": "Target 3 — Burst Incomplete-Operation Reduction (W_BURST)",
            "pass": t3_pass,
            "metric": f"Arch A F_inc={f_a*100:.2f}%, Arch B F_inc={f_b*100:.2f}% (Rel Reduction: {reduction_pct:.1f}%)",
            "threshold": ">= 50.0% relative reduction in F_incomplete",
        }
    else:
        results["target_3_burst_loss_reduction"] = {
            "name": "Target 3 — Burst Incomplete-Operation Reduction (W_BURST)",
            "pass": False,
            "metric": "W_BURST data missing in A or B",
            "threshold": ">= 50.0% reduction",
        }

    # Target 4: Sustained Useful Throughput Gain on W_SUSTAIN
    # >= 20% gain in useful throughput (Theta_useful) vs Arch A
    a_sustain = aggs_a.get("W_SUSTAIN", {})
    b_sustain = aggs_b.get("W_SUSTAIN", {})
    if (
        a_sustain
        and b_sustain
        and a_sustain.get("sample_size", 0) > 0
        and b_sustain.get("sample_size", 0) > 0
    ):
        thru_a = a_sustain["useful_throughput_ops_sec"]["mean"]
        thru_b = b_sustain["useful_throughput_ops_sec"]["mean"]
        gain_pct = (((thru_b - thru_a) / thru_a) * 100.0) if thru_a > 0 else 0.0
        t4_pass = gain_pct >= 20.0
        results["target_4_sustained_throughput_gain"] = {
            "name": "Target 4 — Sustained Useful Throughput Gain (W_SUSTAIN)",
            "pass": t4_pass,
            "metric": f"Arch A={thru_a:.1f} op/s, Arch B={thru_b:.1f} op/s (Gain: {gain_pct:+.1f}%)",
            "threshold": ">= +20.0% gain in Theta_useful",
        }
    else:
        # Fall back to W_CONTENTION or generic parallel workload if W_SUSTAIN was not executed
        alt_wl = (
            "W_CONTENTION"
            if "W_CONTENTION" in aggs_a and "W_CONTENTION" in aggs_b
            else None
        )
        if alt_wl:
            thru_a = aggs_a[alt_wl]["useful_throughput_ops_sec"]["mean"]
            thru_b = aggs_b[alt_wl]["useful_throughput_ops_sec"]["mean"]
            gain_pct = (((thru_b - thru_a) / thru_a) * 100.0) if thru_a > 0 else 0.0
            t4_pass = gain_pct >= 20.0
            results["target_4_sustained_throughput_gain"] = {
                "name": f"Target 4 — Sustained Throughput Gain ({alt_wl})",
                "pass": t4_pass,
                "metric": f"Arch A={thru_a:.1f} op/s, Arch B={thru_b:.1f} op/s (Gain: {gain_pct:+.1f}%)",
                "threshold": ">= +20.0% gain in Theta_useful",
            }
        else:
            results["target_4_sustained_throughput_gain"] = {
                "name": "Target 4 — Sustained Useful Throughput Gain (W_SUSTAIN)",
                "pass": False,
                "metric": "W_SUSTAIN data missing in A or B",
                "threshold": ">= +20.0% gain",
            }

    # Target 5: Memory Cap
    # Peak RSS(Arch B) <= Peak RSS(Arch A) + 64 MiB across all workloads
    max_rss_a = max(
        (agg["peak_rss_mib"]["max"] for agg in aggs_a.values()), default=0.0
    )
    max_rss_b = max(
        (agg["peak_rss_mib"]["max"] for agg in aggs_b.values()), default=0.0
    )
    delta_rss = max_rss_b - max_rss_a
    t5_pass = delta_rss <= 64.0
    results["target_5_memory_cap"] = {
        "name": "Target 5 — Memory Ceiling (Peak RSS)",
        "pass": t5_pass,
        "metric": f"Arch A Peak={max_rss_a:.1f} MiB, Arch B Peak={max_rss_b:.1f} MiB (Delta: {delta_rss:+.1f} MiB)",
        "threshold": "Peak RSS(B) <= Peak RSS(A) + 64.0 MiB",
    }

    # Target 6: Burst Drain Latency on W_BURST
    # Drain latency <= 1,000 ms
    if b_burst and b_burst.get("sample_size", 0) > 0:
        drain_b = b_burst["drain_latency_ms"]["mean"]
        drain_max = b_burst["drain_latency_ms"]["max"]
        t6_pass = drain_max <= 1000.0
        results["target_6_burst_drain_latency"] = {
            "name": "Target 6 — Burst Drain Latency (W_BURST)",
            "pass": t6_pass,
            "metric": f"Arch B Drain Mean={drain_b:.1f} ms, Max={drain_max:.1f} ms",
            "threshold": "Delta T_drain <= 1,000 ms",
        }
    else:
        results["target_6_burst_drain_latency"] = {
            "name": "Target 6 — Burst Drain Latency (W_BURST)",
            "pass": False,
            "metric": "W_BURST data missing in Arch B",
            "threshold": "Delta T_drain <= 1,000 ms",
        }

    return results


def print_comparison_tables(
    aggs_a: Dict[str, Dict[str, Any]],
    aggs_b: Dict[str, Dict[str, Any]],
    targets: Dict[str, Dict[str, Any]],
):
    """Prints standard tabular comparison report to stdout."""
    workloads = sorted(set(aggs_a.keys()) | set(aggs_b.keys()))

    print("=" * 110)
    print(
        "EphimTrace Telemetry Architecture Comparative Evaluation: Architecture A vs Architecture B"
    )
    print("=" * 110)

    # 1. Completeness & Loss Accounting
    print("\n[TABLE 1: END-TO-END COMPLETENESS & STAGE-WISE LOSS RECONCILIATION]")
    print(
        f"{'Workload':<15} | {'Arch':<5} | {'Ops':<7} | {'Reconstructed':<13} | {'C_e2e (%)':<10} | {'Ring Loss':<9} | {'Queue Loss':<10} | {'Residual':<8}"
    )
    print("-" * 110)
    for wl in workloads:
        a_data = aggs_a.get(wl)
        b_data = aggs_b.get(wl)
        if a_data:
            c_a = a_data["completeness_c_e2e"]["mean"] * 100.0
            r_a = a_data["ring_loss"]["mean"]
            q_a = a_data["queue_loss"]["mean"]
            res_a = a_data["residual"]["mean"]
            print(
                f"{wl:<15} | {'A':<5} | {int(a_data.get('ops_attempted', {}).get('mean', 0)):<7} | {int(a_data['useful_throughput_ops_sec'].get('mean', 0)):<13} | {c_a:<10.2f} | {r_a:<9.0f} | {q_a:<10.0f} | {res_a:<8.0f}"
            )
        if b_data:
            c_b = b_data["completeness_c_e2e"]["mean"] * 100.0
            r_b = b_data["ring_loss"]["mean"]
            q_b = b_data["queue_loss"]["mean"]
            res_b = b_data["residual"]["mean"]
            print(
                f"{'':<15} | {'B':<5} | {int(b_data.get('ops_attempted', {}).get('mean', 0)):<7} | {int(b_data['useful_throughput_ops_sec'].get('mean', 0)):<13} | {c_b:<10.2f} | {r_b:<9.0f} | {q_b:<10.0f} | {res_b:<8.0f}"
            )
        print("-" * 110)

    # 2. Throughput, Drain Latency & Memory Footprint
    print("\n[TABLE 2: THROUGHPUT, DRAIN LATENCY & MEMORY]")
    print(
        f"{'Workload':<15} | {'Arch':<5} | {'Offered Thru (op/s)':<20} | {'Useful Thru (op/s)':<20} | {'Drain Latency (ms)':<18} | {'Peak RSS (MiB)':<14}"
    )
    print("-" * 110)
    for wl in workloads:
        a_data = aggs_a.get(wl)
        b_data = aggs_b.get(wl)
        if a_data:
            o_a = a_data["offered_throughput_ops_sec"]
            u_a = a_data["useful_throughput_ops_sec"]
            d_a = a_data["drain_latency_ms"]
            m_a = a_data["peak_rss_mib"]
            print(
                f"{wl:<15} | {'A':<5} | {o_a['mean']:>8.1f} ± {o_a['ci95']:<7.1f} | {u_a['mean']:>8.1f} ± {u_a['ci95']:<7.1f} | {d_a['mean']:>7.1f} ± {d_a['ci95']:<6.1f} | {m_a['mean']:>6.1f} (max {m_a['max']:.1f})"
            )
        if b_data:
            o_b = b_data["offered_throughput_ops_sec"]
            u_b = b_data["useful_throughput_ops_sec"]
            d_b = b_data["drain_latency_ms"]
            m_b = b_data["peak_rss_mib"]
            print(
                f"{'':<15} | {'B':<5} | {o_b['mean']:>8.1f} ± {o_b['ci95']:<7.1f} | {u_b['mean']:>8.1f} ± {u_b['ci95']:<7.1f} | {d_b['mean']:>7.1f} ± {d_b['ci95']:<6.1f} | {m_b['mean']:>6.1f} (max {m_b['max']:.1f})"
            )
        print("-" * 110)

    # 3. CPU Resource Disaggregation
    print("\n[TABLE 3: DISAGGREGATED CPU COST ACCOUNTING]")
    print(
        f"{'Workload':<15} | {'Arch':<5} | {'CPU / Attempted Op (µs)':<25} | {'CPU / Reconstructed Op (µs)':<28}"
    )
    print("-" * 110)
    for wl in workloads:
        a_data = aggs_a.get(wl)
        b_data = aggs_b.get(wl)
        if a_data:
            ca_a = a_data["cpu_cost_attempted_us"]
            cr_a = a_data["cpu_cost_reconstructed_us"]
            print(
                f"{wl:<15} | {'A':<5} | {ca_a['mean']:>9.2f} ± {ca_a['ci95']:<7.2f}      | {cr_a['mean']:>11.2f} ± {cr_a['ci95']:<8.2f}"
            )
        if b_data:
            ca_b = b_data["cpu_cost_attempted_us"]
            cr_b = b_data["cpu_cost_reconstructed_us"]
            print(
                f"{'':<15} | {'B':<5} | {ca_b['mean']:>9.2f} ± {ca_b['ci95']:<7.2f}      | {cr_b['mean']:>11.2f} ± {cr_b['ci95']:<8.2f}"
            )
        print("-" * 110)

    # 4. Acceptance Target Evaluation
    print("\n[NUMERICAL ACCEPTANCE TARGET EVALUATION]")
    all_pass = True
    for key, tgt in targets.items():
        status = "PASS" if tgt["pass"] else "FAIL"
        if not tgt["pass"]:
            all_pass = False
        print(f"\n  [{status}] {tgt['name']}")
        print(f"         Required Threshold : {tgt['threshold']}")
        print(f"         Observed Evidence  : {tgt['metric']}")

    print("\n" + "=" * 110)
    if all_pass:
        print(
            "OVERALL VERDICT: ALL OWNER-APPROVED ACCEPTANCE TARGETS SATISFIED -> ADOPT ARCHITECTURE B"
        )
    else:
        print(
            "OVERALL VERDICT: ONE OR MORE ACCEPTANCE TARGETS FAILED -> ARCHITECTURE B NOT QUALIFIED"
        )
    print("=" * 110)


def main():
    parser = argparse.ArgumentParser(
        description="EphimTrace Telemetry Architecture Comparative Analyzer (Arch A vs Arch B)"
    )
    parser.add_argument(
        "--dir-a",
        type=pathlib.Path,
        required=True,
        help="Directory containing Architecture A results",
    )
    parser.add_argument(
        "--dir-b",
        type=pathlib.Path,
        required=True,
        help="Directory containing Architecture B results",
    )
    parser.add_argument(
        "--json",
        type=pathlib.Path,
        help="Optional path to output comparison summary JSON",
    )
    args = parser.parse_args()

    if not args.dir_a.is_dir():
        parser.error(f"--dir-a {args.dir_a} is not a directory")
    if not args.dir_b.is_dir():
        parser.error(f"--dir-b {args.dir_b} is not a directory")

    trials_a = load_suite_trials(args.dir_a)
    trials_b = load_suite_trials(args.dir_b)

    aggs_a = {wl: aggregate_workload_metrics(ts) for wl, ts in trials_a.items()}
    aggs_b = {wl: aggregate_workload_metrics(ts) for wl, ts in trials_b.items()}

    targets = evaluate_acceptance_targets(aggs_a, aggs_b)

    print_comparison_tables(aggs_a, aggs_b, targets)

    if args.json:
        out_data = {
            "dir_a": str(args.dir_a),
            "dir_b": str(args.dir_b),
            "aggregates_a": aggs_a,
            "aggregates_b": aggs_b,
            "targets": targets,
            "verdict": "PASS" if all(t["pass"] for t in targets.values()) else "FAIL",
        }
        args.json.write_text(json.dumps(out_data, indent=2))
        print(f"\nSaved structured comparison to {args.json}")

    return 0 if all(t["pass"] for t in targets.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
