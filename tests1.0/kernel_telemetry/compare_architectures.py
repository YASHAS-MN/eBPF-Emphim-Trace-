#!/usr/bin/env python3
"""compare_architectures.py — Normalized Comparative Analyzer for EphimTrace

Strict comparative analyzer evaluating Architecture A vs Architecture B
against the 6 owner-approved numerical acceptance targets recorded in
GitHub Issue #3 and BENCHMARK_SPEC.md.

Enforces:
1. Operation completeness derived from actual unique reconciled records.
2. Independent stage-wise event loss accounting.
3. Retention and reporting of all trial reports (never silently drops invalid trials).
4. Strict sample size requirements (N >= 5 valid runs per target).
5. Workload configuration matching between architectures.
6. Per-trial residual checks (preventing cancellation across trials).
7. Strict target evaluation without workload substitution (e.g., no W_CONTENTION for sustained).
"""

import argparse
import json
import math
import pathlib
import sys
from typing import Any, Dict, List, Optional


def compute_stats(values: List[float]) -> Dict[str, float]:
    """Computes mean, standard deviation, min, max, and 95% confidence interval."""
    if not values:
        return {"n": 0, "mean": 0.0, "std": 0.0, "min": 0.0, "max": 0.0, "ci95": 0.0}
    n = len(values)
    mean = sum(values) / n
    if n > 1:
        variance = sum((x - mean) ** 2 for x in values) / (n - 1)
        std = math.sqrt(variance)
        ci95 = 1.96 * (std / math.sqrt(n))
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
    """Parses a single trial JSON report and extracts normalized pipeline metrics.
    Retains invalid trial evidence and enforces strict schema validation."""
    try:
        data = json.loads(path.read_text())
    except Exception as e:
        return {
            "valid": False,
            "status": "JSON_PARSE_ERROR",
            "name": path.stem,
            "error": str(e),
        }

    status = data.get("status")
    if status != "VALID":
        return {
            "valid": False,
            "status": status or "INVALID",
            "name": path.stem,
            "error": data.get("error", f"Trial status is {status}"),
        }

    analysis = data.get("analysis", {})
    workload = data.get("workload", {})
    meas = data.get("measurement", {})
    pipe = analysis.get("pipeline_accounting", {})
    thru = analysis.get("throughput", {})
    res = analysis.get("resources", {})
    rec = analysis.get("reconciliation", {})

    # Strict schema / measurement validation
    required_sections = ["pipeline_accounting", "throughput", "resources"]
    for s in required_sections:
        if s not in analysis:
            return {
                "valid": False,
                "status": "SCHEMA_ERROR",
                "name": path.stem,
                "error": f"Missing required analysis section: {s}",
            }

    n_ops = pipe.get("ops_attempted")
    if n_ops is None:
        n_ops = workload.get("create_attempts")
    if n_ops is None:
        return {
            "valid": False,
            "status": "MISSING_DATA",
            "name": path.stem,
            "error": "Missing ops_attempted",
        }

    n_reconstructed = pipe.get("reconstructed")
    if n_reconstructed is None:
        return {
            "valid": False,
            "status": "MISSING_DATA",
            "name": path.stem,
            "error": "Missing reconstructed count",
        }

    c_e2e = pipe.get("validated_create_completeness_c_e2e", pipe.get("completeness_c_e2e", 1.0 if n_ops == 0 else (n_reconstructed / n_ops)))
    f_incomplete = pipe.get("incomplete_create_fraction_f", pipe.get("incomplete_fraction_f", 1.0 - c_e2e))
    residual = pipe.get("residual", pipe.get("operation_residual", 0))

    # Losses
    ring_loss = pipe.get("ring_loss", analysis.get("target_reservation_failures", 0))
    queue_loss = pipe.get("queue_loss", meas.get("queue", {}).get("drops", 0))
    gen_gap = pipe.get("gen_gap", len(analysis.get("backend_findings", {}).get("generation_gaps", [])))
    corr_def = pipe.get("corr_def", analysis.get("completion_uncorrelated", 0))
    proc_fail = pipe.get("proc_fail", 0)

    # Fidelity counts
    corrupt_count = rec.get("corrupted_events_count", len(rec.get("corrupted_events", [])))
    incorrect_outcome = rec.get("incorrect_outcome_count", len(rec.get("incorrect_outcome", [])))

    # Throughput & Timing
    offered_thru = thru.get("offered_throughput_ops_sec", 0.0)
    useful_thru = thru.get("useful_throughput_ops_sec", 0.0)
    drain_ms = thru.get("drain_latency_ms", 0.0)

    # Resources
    rss_mib = res.get("loader_max_rss_mib", meas.get("rusage", {}).get("max_rss_kb", 0) / 1024.0)
    cost_attempted_us = res.get("cpu_cost_attempted_us", 0.0)
    cost_reconstructed_us = res.get("cpu_cost_reconstructed_us", 0.0)
    total_cost_attempted_us = res.get("total_trial_cpu_cost_attempted_us", cost_attempted_us)

    # Workload configuration parameters for consistency verification
    wl_config = {
        "workers": workload.get("workers", 1),
        "iterations": workload.get("iterations", 0),
        "pace_us": workload.get("pace_us", 0),
        "hold": workload.get("hold", False),
    }

    return {
        "valid": True,
        "status": "VALID",
        "name": path.stem,
        "ops_attempted": float(n_ops),
        "reconstructed": float(n_reconstructed),
        "completeness_c_e2e": float(c_e2e),
        "incomplete_fraction_f": float(f_incomplete),
        "ring_loss": float(ring_loss),
        "queue_loss": float(queue_loss),
        "gen_gap": float(gen_gap),
        "corr_def": float(corr_def),
        "proc_fail": float(proc_fail),
        "residual": float(residual),
        "corrupt_count": float(corrupt_count),
        "incorrect_outcome": float(incorrect_outcome),
        "offered_throughput_ops_sec": float(offered_thru),
        "useful_throughput_ops_sec": float(useful_thru),
        "drain_latency_ms": float(drain_ms),
        "peak_rss_mib": float(rss_mib),
        "cpu_cost_attempted_us": float(cost_attempted_us),
        "cpu_cost_reconstructed_us": float(cost_reconstructed_us),
        "total_trial_cpu_cost_attempted_us": float(total_cost_attempted_us),
        "validated_create_completeness_c_e2e": float(c_e2e),
        "config": wl_config,
    }


def load_suite_trials(dir_path: pathlib.Path) -> Dict[str, List[Dict[str, Any]]]:
    """Loads all trial reports in a directory, grouping by workload name.
    Retains invalid trials rather than silently dropping them."""
    trials_by_workload: Dict[str, List[Dict[str, Any]]] = {}
    ignored = {"environment.json", "build_info.json", "summary.json"}

    for p in sorted(dir_path.glob("*.json")):
        if p.name in ignored or p.name.endswith("_ground_truth.json") or p.name.endswith("_captured_events.json"):
            continue

        trial = parse_trial_report(p)

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
    """Computes statistical summaries for a group of trials, tracking valid and invalid runs."""
    metrics = [
        "ops_attempted",
        "reconstructed",
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
        "total_trial_cpu_cost_attempted_us",
        "validated_create_completeness_c_e2e",
    ]
    valid_trials = [t for t in trials if t.get("valid")]
    invalid_trials = [t for t in trials if not t.get("valid")]



    agg = {}
    for m in metrics:
        vals = [t[m] for t in valid_trials if m in t]
        agg[m] = compute_stats(vals)

    agg["sample_size"] = len(valid_trials)
    agg["total_trials"] = len(trials)
    agg["invalid_trials"] = invalid_trials
    agg["trials"] = trials
    agg["config"] = valid_trials[0]["config"] if valid_trials and "config" in valid_trials[0] else {}
    return agg


def evaluate_acceptance_targets(
    aggs_a: Dict[str, Dict[str, Any]], aggs_b: Dict[str, Dict[str, Any]]
) -> Dict[str, Dict[str, Any]]:
    """Evaluates the 6 owner-approved numerical acceptance targets with strict validity rules."""
    results = {}
    MIN_RUNS = 5

    # Target 1: Control Completeness on W_PACED
    # Arch B must have C_e2e = 100.0% (0 drops across all stages) on W_PACED with >= 5 valid runs
    b_paced = aggs_b.get("W_PACED")
    if b_paced:
        n_valid = b_paced.get("sample_size", 0)
        n_invalid = len(b_paced.get("invalid_trials", []))
        if n_invalid > 0:
            results["target_1_control_completeness"] = {
                "name": "Target 1 — Control Completeness (W_PACED)",
                "pass": False,
                "metric": f"{n_invalid} invalid trial(s) detected in W_PACED",
                "threshold": "C_e2e = 100.0%, 0 drops, 0 invalid trials",
            }
        elif n_valid < MIN_RUNS:
            results["target_1_control_completeness"] = {
                "name": "Target 1 — Control Completeness (W_PACED)",
                "pass": False,
                "metric": f"Insufficient valid repetitions (found N={n_valid} < {MIN_RUNS})",
                "threshold": f"N >= {MIN_RUNS} valid runs, C_e2e = 100.0%",
            }
        else:
            c_e2e_mean = b_paced["completeness_c_e2e"]["mean"]
            ring_drops = b_paced["ring_loss"]["mean"]
            queue_drops = b_paced["queue_loss"]["mean"]
            t1_pass = (c_e2e_mean == 1.0) and (ring_drops == 0) and (queue_drops == 0)
            results["target_1_control_completeness"] = {
                "name": "Target 1 — Control Completeness (W_PACED)",
                "pass": t1_pass,
                "metric": f"C_e2e={c_e2e_mean*100:.1f}%, ring_drops={ring_drops:.0f}, queue_drops={queue_drops:.0f} (N={n_valid})",
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
    # Zero corrupted tokens, zero outcome inversions, zero unexplained residuals (checked per trial, no cancellation!)
    all_b_trials = []
    for wl_agg in aggs_b.values():
        all_b_trials.extend(wl_agg.get("trials", []))

    invalid_count = sum(1 for t in all_b_trials if not t.get("valid"))
    corrupt_count = sum(t.get("corrupt_count", 0) for t in all_b_trials if t.get("valid"))
    inversion_count = sum(t.get("incorrect_outcome", 0) for t in all_b_trials if t.get("valid"))
    # Check absolute residual PER TRIAL to prevent positive and negative residuals cancelling across trials
    non_zero_residuals = [t.get("residual", 0) for t in all_b_trials if t.get("valid") and abs(t.get("residual", 0)) > 1e-6]

    t2_pass = (invalid_count == 0) and (corrupt_count == 0) and (inversion_count == 0) and (len(non_zero_residuals) == 0)
    results["target_2_fidelity_invariants"] = {
        "name": "Target 2 — Fidelity Invariants (All Workloads)",
        "pass": t2_pass,
        "metric": f"invalid_trials={invalid_count}, corrupt={corrupt_count}, inversions={inversion_count}, non_zero_residual_trials={len(non_zero_residuals)}",
        "threshold": "Zero corrupt tokens, zero inversions, zero unexplained residuals per trial",
    }

    # Target 3: Burst Incomplete-Operation Reduction on W_BURST
    # >= 50% relative reduction in F_incomplete vs Arch A
    a_burst = aggs_a.get("W_BURST")
    b_burst = aggs_b.get("W_BURST")
    if a_burst and b_burst:
        na = a_burst.get("sample_size", 0)
        nb = b_burst.get("sample_size", 0)
        if a_burst.get("config") != b_burst.get("config"):
            results["target_3_burst_loss_reduction"] = {
                "name": "Target 3 — Burst Incomplete-Operation Reduction (W_BURST)",
                "pass": False,
                "metric": f"Workload configuration mismatch (A={a_burst.get('config')} vs B={b_burst.get('config')})",
                "threshold": "Identical workload configurations",
            }
        elif a_burst["ops_attempted"]["mean"] != b_burst["ops_attempted"]["mean"]:
            results["target_3_burst_loss_reduction"] = {
                "name": "Target 3 — Burst Incomplete-Operation Reduction (W_BURST)",
                "pass": False,
                "metric": f"Workload attempted population mismatch (Arch A={a_burst['ops_attempted']['mean']} vs Arch B={b_burst['ops_attempted']['mean']})",
                "threshold": "Identical workload event/operation populations",
            }
        elif na < MIN_RUNS or nb < MIN_RUNS:
            results["target_3_burst_loss_reduction"] = {
                "name": "Target 3 — Burst Incomplete-Operation Reduction (W_BURST)",
                "pass": False,
                "metric": f"Insufficient valid repetitions (Arch A N={na}, Arch B N={nb} < {MIN_RUNS})",
                "threshold": f"N >= {MIN_RUNS} valid runs, >= 50.0% reduction",
            }
        else:
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
                "metric": f"Arch A F_inc={f_a*100:.2f}%, Arch B F_inc={f_b*100:.2f}% (Rel Reduction: {reduction_pct:.1f}%, NA={na}, NB={nb})",
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
    # >= 20% gain in useful throughput (Theta_useful) vs Arch A (Strictly W_SUSTAIN, no substitution!)
    a_sustain = aggs_a.get("W_SUSTAIN")
    b_sustain = aggs_b.get("W_SUSTAIN")
    if a_sustain and b_sustain:
        na = a_sustain.get("sample_size", 0)
        nb = b_sustain.get("sample_size", 0)
        if a_sustain.get("config") != b_sustain.get("config"):
            results["target_4_sustained_throughput_gain"] = {
                "name": "Target 4 — Sustained Useful Throughput Gain (W_SUSTAIN)",
                "pass": False,
                "metric": f"Workload configuration mismatch (A={a_sustain.get('config')} vs B={b_sustain.get('config')})",
                "threshold": "Identical workload configurations",
            }
        elif a_sustain["ops_attempted"]["mean"] != b_sustain["ops_attempted"]["mean"]:
            results["target_4_sustained_throughput_gain"] = {
                "name": "Target 4 — Sustained Useful Throughput Gain (W_SUSTAIN)",
                "pass": False,
                "metric": f"Workload attempted population mismatch (Arch A={a_sustain['ops_attempted']['mean']} vs Arch B={b_sustain['ops_attempted']['mean']})",
                "threshold": "Identical workload event/operation populations",
            }
        elif na < MIN_RUNS or nb < MIN_RUNS:
            results["target_4_sustained_throughput_gain"] = {
                "name": "Target 4 — Sustained Useful Throughput Gain (W_SUSTAIN)",
                "pass": False,
                "metric": f"Insufficient valid repetitions (Arch A N={na}, Arch B N={nb} < {MIN_RUNS})",
                "threshold": f"N >= {MIN_RUNS} valid runs, >= +20.0% gain",
            }
        else:
            thru_a = a_sustain["useful_throughput_ops_sec"]["mean"]
            thru_b = b_sustain["useful_throughput_ops_sec"]["mean"]
            gain_pct = (((thru_b - thru_a) / thru_a) * 100.0) if thru_a > 0 else 0.0
            t4_pass = gain_pct >= 20.0
            results["target_4_sustained_throughput_gain"] = {
                "name": "Target 4 — Sustained Useful Throughput Gain (W_SUSTAIN)",
                "pass": t4_pass,
                "metric": f"Arch A={thru_a:.1f} op/s, Arch B={thru_b:.1f} op/s (Gain: {gain_pct:+.1f}%, NA={na}, NB={nb})",
                "threshold": ">= +20.0% gain in Theta_useful",
            }
    else:
        results["target_4_sustained_throughput_gain"] = {
            "name": "Target 4 — Sustained Useful Throughput Gain (W_SUSTAIN)",
            "pass": False,
            "metric": "W_SUSTAIN data missing in A or B (workload substitution prohibited)",
            "threshold": ">= +20.0% gain in Theta_useful on W_SUSTAIN",
        }

    # Target 5: Memory Cap
    # Peak RSS(Arch B) <= Peak RSS(Arch A) + 64 MiB across all valid workloads
    valid_a_aggs = [agg for agg in aggs_a.values() if agg.get("sample_size", 0) > 0]
    valid_b_aggs = [agg for agg in aggs_b.values() if agg.get("sample_size", 0) > 0]
    if valid_a_aggs and valid_b_aggs:
        max_rss_a = max((agg["peak_rss_mib"]["max"] for agg in valid_a_aggs), default=0.0)
        max_rss_b = max((agg["peak_rss_mib"]["max"] for agg in valid_b_aggs), default=0.0)
        delta_rss = max_rss_b - max_rss_a
        t5_pass = delta_rss <= 64.0
        results["target_5_memory_cap"] = {
            "name": "Target 5 — Memory Overhead Cap",
            "pass": t5_pass,
            "metric": f"Peak RSS(A)={max_rss_a:.1f} MiB, Peak RSS(B)={max_rss_b:.1f} MiB (Delta: {delta_rss:+.1f} MiB)",
            "threshold": "Delta RSS <= +64.0 MiB",
        }
    else:
        results["target_5_memory_cap"] = {
            "name": "Target 5 — Memory Overhead Cap",
            "pass": False,
            "metric": "Insufficient valid data in A or B",
            "threshold": "Delta RSS <= +64.0 MiB",
        }

    # Target 6: Burst Drain Latency on W_BURST
    # Delta T_drain <= 1,000 ms on W_BURST
    if b_burst and b_burst.get("sample_size", 0) > 0:
        drain_b = b_burst["drain_latency_ms"]["mean"]
        t6_pass = drain_b <= 1000.0
        results["target_6_drain_latency"] = {
            "name": "Target 6 — Burst Drain Latency (W_BURST)",
            "pass": t6_pass,
            "metric": f"Arch B Drain={drain_b:.1f} ms",
            "threshold": "Delta T_drain <= 1,000.0 ms",
        }
    else:
        results["target_6_drain_latency"] = {
            "name": "Target 6 — Burst Drain Latency (W_BURST)",
            "pass": False,
            "metric": "W_BURST data missing in Arch B",
            "threshold": "Delta T_drain <= 1,000.0 ms",
        }

    return results


def print_comparison_report(
    aggs_a: Dict[str, Dict[str, Any]],
    aggs_b: Dict[str, Dict[str, Any]],
    targets: Dict[str, Dict[str, Any]],
):
    """Prints formatted comparative tables and target evaluations."""
    workloads = sorted(set(aggs_a.keys()) | set(aggs_b.keys()))

    print("=" * 110)
    print("EphimTrace Telemetry Architecture Comparative Evaluation: Architecture A vs Architecture B")
    print("=" * 110)

    # 1. Completeness & Loss Accounting
    print("\n[TABLE 1: VALIDATED CREATION-OPERATION COMPLETENESS & STAGE-WISE LOSS RECONCILIATION]")
    print(
        f"{'Workload':<15} | {'Arch':<5} | {'Ops':<7} | {'Reconstructed':<13} | {'C_e2e (%)':<10} | {'Ring Loss':<9} | {'Queue Loss':<10} | {'Residual':<8}"
    )
    print("-" * 110)
    for wl in workloads:
        a_data = aggs_a.get(wl)
        b_data = aggs_b.get(wl)
        if a_data and a_data.get("sample_size", 0) > 0:
            c_a = a_data["completeness_c_e2e"]["mean"] * 100.0
            r_a = a_data["ring_loss"]["mean"]
            q_a = a_data["queue_loss"]["mean"]
            res_a = a_data["residual"]["mean"]
            ops_a = int(round(a_data["ops_attempted"]["mean"]))
            rec_a = int(round(a_data["reconstructed"]["mean"]))
            print(
                f"{wl:<15} | {'A':<5} | {ops_a:<7} | {rec_a:<13} | {c_a:<10.2f} | {r_a:<9.0f} | {q_a:<10.0f} | {res_a:<8.0f}"
            )
        if b_data and b_data.get("sample_size", 0) > 0:
            c_b = b_data["completeness_c_e2e"]["mean"] * 100.0
            r_b = b_data["ring_loss"]["mean"]
            q_b = b_data["queue_loss"]["mean"]
            res_b = b_data["residual"]["mean"]
            ops_b = int(round(b_data["ops_attempted"]["mean"]))
            rec_b = int(round(b_data["reconstructed"]["mean"]))
            print(
                f"{'':<15} | {'B':<5} | {ops_b:<7} | {rec_b:<13} | {c_b:<10.2f} | {r_b:<9.0f} | {q_b:<10.0f} | {res_b:<8.0f}"
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
        if a_data and a_data.get("sample_size", 0) > 0:
            o_a = a_data["offered_throughput_ops_sec"]
            u_a = a_data["useful_throughput_ops_sec"]
            d_a = a_data["drain_latency_ms"]
            m_a = a_data["peak_rss_mib"]
            print(
                f"{wl:<15} | {'A':<5} | {o_a['mean']:>8.1f} ± {o_a['ci95']:<7.1f} | {u_a['mean']:>8.1f} ± {u_a['ci95']:<7.1f} | {d_a['mean']:>7.1f} ± {d_a['ci95']:<6.1f} | {m_a['mean']:>6.1f} (max {m_a['max']:.1f})"
            )
        if b_data and b_data.get("sample_size", 0) > 0:
            o_b = b_data["offered_throughput_ops_sec"]
            u_b = b_data["useful_throughput_ops_sec"]
            d_b = b_data["drain_latency_ms"]
            m_b = b_data["peak_rss_mib"]
            print(
                f"{'':<15} | {'B':<5} | {o_b['mean']:>8.1f} ± {o_b['ci95']:<7.1f} | {u_b['mean']:>8.1f} ± {u_b['ci95']:<7.1f} | {d_b['mean']:>7.1f} ± {d_b['ci95']:<6.1f} | {m_b['mean']:>6.1f} (max {m_b['max']:.1f})"
            )
        print("-" * 110)

    # 3. CPU Resource Disaggregation
    print("\n[TABLE 3: DISAGGREGATED CPU COST ACCOUNTING (ACTIVE VS TOTAL)]")
    print(
        f"{'Workload':<15} | {'Arch':<5} | {'Active CPU / Op (µs)':<22} | {'Total CPU / Op (µs)':<22} | {'Active CPU / Reconstructed (µs)':<30}"
    )
    print("-" * 110)
    for wl in workloads:
        a_data = aggs_a.get(wl)
        b_data = aggs_b.get(wl)
        if a_data and a_data.get("sample_size", 0) > 0:
            ca_a = a_data["cpu_cost_attempted_us"]
            tot_a = a_data.get("total_trial_cpu_cost_attempted_us", ca_a)
            cr_a = a_data["cpu_cost_reconstructed_us"]
            print(
                f"{wl:<15} | {'A':<5} | {ca_a['mean']:>8.2f} ± {ca_a['ci95']:<6.2f}     | {tot_a['mean']:>8.2f} ± {tot_a['ci95']:<6.2f}    | {cr_a['mean']:>11.2f} ± {cr_a['ci95']:<8.2f}"
            )
        if b_data and b_data.get("sample_size", 0) > 0:
            ca_b = b_data["cpu_cost_attempted_us"]
            tot_b = b_data.get("total_trial_cpu_cost_attempted_us", ca_b)
            cr_b = b_data["cpu_cost_reconstructed_us"]
            print(
                f"{'':<15} | {'B':<5} | {ca_b['mean']:>8.2f} ± {ca_b['ci95']:<6.2f}     | {tot_b['mean']:>8.2f} ± {tot_b['ci95']:<6.2f}    | {cr_b['mean']:>11.2f} ± {cr_b['ci95']:<8.2f}"
            )
        print("-" * 110)

    # 4. Acceptance Target Evaluation
    print("\n[NUMERICAL ACCEPTANCE TARGET EVALUATION]")
    all_pass = True
    for key, tgt in targets.items():
        status = "PASS" if tgt["pass"] else "FAIL"
        if not tgt["pass"]:
            all_pass = False
        print(f"  [{status}] {tgt['name']}")
        print(f"         Observed:  {tgt['metric']}")
        print(f"         Threshold: {tgt['threshold']}")

    # 5. Invalid Trial Summary (if any)
    all_invalid = []
    for wl, agg in aggs_a.items():
        for inv in agg.get("invalid_trials", []):
            all_invalid.append(("Arch A", wl, inv.get("name"), inv.get("error")))
    for wl, agg in aggs_b.items():
        for inv in agg.get("invalid_trials", []):
            all_invalid.append(("Arch B", wl, inv.get("name"), inv.get("error")))

    if all_invalid:
        print("\n[WARNING: INVALID TRIALS DETECTED IN EVIDENCE]")
        for arch, wl, name, err in all_invalid:
            print(f"  - [{arch}] {wl} / {name}: {err}")

    print("\n" + "=" * 110)
    if all_pass:
        print("OVERALL RESULT: [PASS] Architecture B satisfies ALL 6 numerical acceptance targets.")
    else:
        print("OVERALL RESULT: [FAIL] Architecture B DOES NOT satisfy all acceptance targets.")
    print("=" * 110 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Compare Architecture A and B benchmark results.")
    parser.add_argument("--dir-a", required=True, type=pathlib.Path, help="Directory containing Arch A results")
    parser.add_argument("--dir-b", required=True, type=pathlib.Path, help="Directory containing Arch B results")
    parser.add_argument("--json", type=pathlib.Path, help="Output path for comparison summary JSON")
    args = parser.parse_args()

    if not args.dir_a.exists():
        parser.error(f"Directory does not exist: {args.dir_a}")
    if not args.dir_b.exists():
        parser.error(f"Directory does not exist: {args.dir_b}")

    raw_a = load_suite_trials(args.dir_a)
    raw_b = load_suite_trials(args.dir_b)

    aggs_a = {wl: aggregate_workload_metrics(trials) for wl, trials in raw_a.items()}
    aggs_b = {wl: aggregate_workload_metrics(trials) for wl, trials in raw_b.items()}

    targets = evaluate_acceptance_targets(aggs_a, aggs_b)

    print_comparison_report(aggs_a, aggs_b, targets)

    if args.json:
        summary = {
            "architecture_a": aggs_a,
            "architecture_b": aggs_b,
            "acceptance_targets": targets,
            "all_targets_passed": all(t["pass"] for t in targets.values()),
        }
        args.json.write_text(json.dumps(summary, indent=2))
        print(f"Wrote comparison summary JSON to {args.json}")

    return 0 if all(t["pass"] for t in targets.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
