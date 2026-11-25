#!/usr/bin/env python3
"""compare_persistent_evidence.py — Model M (Online) vs Model P (Deferred) Comparative Auditor

Compares persistent evidence experiment results between:
- Model M (Online): Receive -> Preserve original evidence -> Process -> Graph
- Model P (Deferred): Receive -> Preserve original evidence -> Complete -> Replay -> Graph

Audits:
1. Persisted evidence completeness (records_written / records_received)
2. Stage-wise evidence losses (ring, transport, persistence, sync, replay)
3. Evidence and reconstruction fidelity (framing/CRC32, outcome invariants)
4. Collection throughput (ops/sec)
5. Persistence drain latency (ms)
6. Replay duration (ms) and total time to graph (ms)
7. CPU, memory and storage consumption (bytes, bytes/op)
"""

import argparse
import glob
import json
import math
import pathlib
import sys

WORKLOADS = ["W_PACED", "W_BURST", "W_SUSTAIN", "W_CONTENTION", "W_REGISTRY"]


def stats(values):
    n = len(values)
    if n == 0:
        return {"n": 0, "mean": 0.0, "std": 0.0, "min": 0.0, "max": 0.0, "ci95": 0.0}
    mean = sum(values) / n
    if n > 1:
        variance = sum((x - mean) ** 2 for x in values) / (n - 1)
        std = math.sqrt(variance)
        ci95 = 1.96 * std / math.sqrt(n)
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


def parse_trial(filepath: pathlib.Path):
    with filepath.open("r") as f:
        d = json.load(f)

    analysis = d.get("analysis", {})
    pa = analysis.get("pipeline_accounting", {})
    thru = analysis.get("throughput", {})
    res = analysis.get("resources", {})
    rec = analysis.get("reconciliation", {})
    ev = analysis.get("evidence", {}) or d.get("measurement", {}).get("evidence", {})

    w_name = d.get("test", {}).get("name", filepath.stem)
    base_name = w_name.rsplit("_", 1)[0]

    return {
        "file": str(filepath),
        "name": w_name,
        "base_workload": base_name,
        "ops_attempted": pa.get("ops_attempted", 0),
        "reconstructed": pa.get("reconstructed", 0),
        "completeness_c_e2e": pa.get("completeness_c_e2e", 0.0),
        "incomplete_fraction_f": pa.get("incomplete_fraction_f", 0.0),
        "ring_loss": pa.get("ring_loss", 0),
        "transport_loss": pa.get("target_transport_loss", 0),
        "persisted_received": ev.get("records_received", 0),
        "persisted_written": ev.get("records_written", 0),
        "persisted_synced": ev.get("records_synced", 0),
        "persisted_replayed": ev.get("records_replayed", 0),
        "persistence_loss": ev.get("records_received", 0)
        - ev.get("records_written", 0),
        "sync_loss": ev.get("records_written", 0) - ev.get("records_synced", 0),
        "replay_loss": ev.get("records_synced", 0) - ev.get("records_replayed", 0),
        "persisted_completeness": (
            ev.get("records_written", 0) / ev.get("records_received", 1)
            if ev.get("records_received", 0) > 0
            else 1.0
        ),
        "write_errors": ev.get("write_errors", 0),
        "corrupt_records": ev.get("corrupt_records", 0),
        "seq_gaps": ev.get("seq_gaps", 0),
        "incomplete_records": ev.get("incomplete_records", 0),
        "storage_bytes": ev.get("storage_bytes", 0),
        "storage_per_op_bytes": (
            ev.get("storage_bytes", 0) / pa.get("ops_attempted", 1)
            if pa.get("ops_attempted", 0) > 0
            else 0.0
        ),
        "offered_throughput": thru.get("offered_throughput_ops_sec", 0.0),
        "useful_throughput": thru.get("useful_throughput_ops_sec", 0.0),
        "drain_latency_ms": thru.get("drain_latency_ms", 0.0),
        "persist_drain_latency_ms": ev.get("persist_drain_latency_ns", 0) / 1e6,
        "replay_duration_ms": ev.get("replay_duration_ns", 0) / 1e6,
        "total_time_to_graph_ms": ev.get("total_time_to_graph_ns", 0) / 1e6,
        "workload_cpu_us": res.get("workload_cpu_us", 0),
        "loader_active_cpu_us": res.get("loader_active_cpu_us", 0),
        "loader_total_cpu_us": res.get("loader_total_cpu_us", 0),
        "peak_rss_mib": res.get("loader_max_rss_mib", 0.0),
        "measurement_valid": analysis.get("measurement_valid", True),
        "telemetry_fidelity_valid": analysis.get("telemetry_fidelity_valid", True),
        "incorrect_outcomes": rec.get("incorrect_outcome_count", 0),
    }


def audit_results_dir(results_dir: pathlib.Path):
    dir_m = results_dir / "model_m"
    dir_p = results_dir / "model_p"

    if not dir_m.exists() or not dir_p.exists():
        sys.exit(
            f"Error: results directory must contain model_m/ and model_p/ subdirectories: {results_dir}"
        )

    files_m = sorted(glob.glob(str(dir_m / "*.json")))
    files_p = sorted(glob.glob(str(dir_p / "*.json")))

    trials_m = [
        parse_trial(pathlib.Path(f))
        for f in files_m
        if not f.endswith("_ground_truth.json")
        and not f.endswith("_captured_events.json")
    ]
    trials_p = [
        parse_trial(pathlib.Path(f))
        for f in files_p
        if not f.endswith("_ground_truth.json")
        and not f.endswith("_captured_events.json")
    ]

    by_wl_m = {}
    for t in trials_m:
        by_wl_m.setdefault(t["base_workload"], []).append(t)

    by_wl_p = {}
    for t in trials_p:
        by_wl_p.setdefault(t["base_workload"], []).append(t)

    all_wls = sorted(set(list(by_wl_m.keys()) + list(by_wl_p.keys())))

    print(
        "===================================================================================================="
    )
    print(
        "                      EphimTrace Persistent Evidence Audit: Model M vs Model P                       "
    )
    print(
        "===================================================================================================="
    )
    print(f"Results Directory: {results_dir}")
    print(f"Total Trials: {len(trials_m)} (Model M) | {len(trials_p)} (Model P)\n")

    summary_out = {"model_m": {}, "model_p": {}, "comparisons": {}}

    for wl in all_wls:
        tm = by_wl_m.get(wl, [])
        tp = by_wl_p.get(wl, [])

        sm_comp = stats([x["completeness_c_e2e"] * 100 for x in tm])
        sp_comp = stats([x["completeness_c_e2e"] * 100 for x in tp])

        sm_p_comp = stats([x["persisted_completeness"] * 100 for x in tm])
        sp_p_comp = stats([x["persisted_completeness"] * 100 for x in tp])

        sm_storage = stats([x["storage_bytes"] / 1024 for x in tm])  # KiB
        sp_storage = stats([x["storage_bytes"] / 1024 for x in tp])

        sm_persist_drain = stats([x["persist_drain_latency_ms"] for x in tm])
        sp_persist_drain = stats([x["persist_drain_latency_ms"] for x in tp])

        sp_replay = stats([x["replay_duration_ms"] for x in tp])

        sm_time_to_graph = stats([x["total_time_to_graph_ms"] for x in tm])
        sp_time_to_graph = stats([x["total_time_to_graph_ms"] for x in tp])

        sm_act_cpu = stats([x["loader_active_cpu_us"] / 1000 for x in tm])  # ms
        sp_act_cpu = stats([x["loader_active_cpu_us"] / 1000 for x in tp])

        sm_wkl_cpu = stats([x["workload_cpu_us"] / 1000 for x in tm])
        sp_wkl_cpu = stats([x["workload_cpu_us"] / 1000 for x in tp])

        sm_rss = stats([x["peak_rss_mib"] for x in tm])
        sp_rss = stats([x["peak_rss_mib"] for x in tp])

        print(
            f"----------------------------------------------------------------------------------------------------"
        )
        print(f"Workload: {wl} (N_M={len(tm)}, N_P={len(tp)})")
        print(
            f"----------------------------------------------------------------------------------------------------"
        )
        print(
            f"  Persisted Completeness:  Model M: {sm_p_comp['mean']:6.2f}% | Model P: {sp_p_comp['mean']:6.2f}%"
        )
        print(
            f"  E2E Graph Completeness:  Model M: {sm_comp['mean']:6.2f}% | Model P: {sp_comp['mean']:6.2f}%"
        )
        print(
            f"  Persistence Drain Lat:   Model M: {sm_persist_drain['mean']:8.2f} ms | Model P: {sp_persist_drain['mean']:8.2f} ms"
        )
        print(
            f"  Replay Duration:         Model M:     0.00 ms | Model P: {sp_replay['mean']:8.2f} ms"
        )
        print(
            f"  Total Time To Graph:     Model M: {sm_time_to_graph['mean']:8.2f} ms | Model P: {sp_time_to_graph['mean']:8.2f} ms"
        )
        print(
            f"  Storage Consumed:        Model M: {sm_storage['mean']:8.1f} KiB | Model P: {sp_storage['mean']:8.1f} KiB"
        )
        print(
            f"  Loader Active CPU:       Model M: {sm_act_cpu['mean']:8.2f} ms  | Model P: {sp_act_cpu['mean']:8.2f} ms"
        )
        print(
            f"  Producer Workload CPU:   Model M: {sm_wkl_cpu['mean']:8.2f} ms  | Model P: {sp_wkl_cpu['mean']:8.2f} ms"
        )
        print(
            f"  Peak RSS:                Model M: {sm_rss['mean']:8.2f} MiB | Model P: {sp_rss['mean']:8.2f} MiB"
        )

        # Fidelity checks
        m_corrupt = sum(x["corrupt_records"] for x in tm)
        p_corrupt = sum(x["corrupt_records"] for x in tp)
        m_incomplete = sum(x["incomplete_records"] for x in tm)
        p_incomplete = sum(x["incomplete_records"] for x in tp)
        m_errors = sum(x["write_errors"] for x in tm)
        p_errors = sum(x["write_errors"] for x in tp)
        print(
            f"  Integrity & Fidelity:    M (corrupt={m_corrupt}, trunc={m_incomplete}, errs={m_errors}) | P (corrupt={p_corrupt}, trunc={p_incomplete}, errs={p_errors})"
        )
        print()

        summary_out["comparisons"][wl] = {
            "model_m": {
                "completeness": sm_comp,
                "persisted_completeness": sm_p_comp,
                "time_to_graph_ms": sm_time_to_graph,
                "storage_kib": sm_storage,
                "active_cpu_ms": sm_act_cpu,
                "rss_mib": sm_rss,
            },
            "model_p": {
                "completeness": sp_comp,
                "persisted_completeness": sp_p_comp,
                "replay_ms": sp_replay,
                "time_to_graph_ms": sp_time_to_graph,
                "storage_kib": sp_storage,
                "active_cpu_ms": sp_act_cpu,
                "rss_mib": sp_rss,
            },
        }

    out_file = results_dir / "persist_comparison_summary.json"
    out_file.write_text(json.dumps(summary_out, indent=2))
    print(f"Comparative audit summary saved to: {out_file}")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Audit and compare Model M and Model P results."
    )
    parser.add_argument(
        "results_dir",
        type=pathlib.Path,
        help="Directory containing model_m/ and model_p/",
    )
    args = parser.parse_args()

    if not args.results_dir.exists():
        sys.exit(f"Error: directory does not exist: {args.results_dir}")

    audit_results_dir(args.results_dir)


if __name__ == "__main__":
    main()
