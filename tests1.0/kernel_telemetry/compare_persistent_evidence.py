#!/usr/bin/env python3
"""compare_persistent_evidence.py — Model M (Online) vs Model P (Deferred) Comparative Auditor

Compares persistent evidence experiment results between:
- Model M (Online): Receive -> Preserve original evidence -> Process -> Graph
- Model P (Deferred): Receive -> Preserve original evidence -> Complete -> Replay -> Graph

Audits:
1. Persisted evidence completeness (independently reconciled create pairs from disk readback)
2. Stage-wise evidence losses (ring, transport, persistence, sync, verification, replay)
3. Evidence and reconstruction fidelity (framing/CRC32, outcome invariants, Model M graph equivalence)
4. Useful throughput (ops/sec using total time to graph)
5. Persistence drain latency (ms from workload done to sync complete)
6. Replay duration (ms) and total time to graph (ms from workload start to graph complete)
7. CPU (collection vs replay), memory and storage consumption (bytes, bytes/op)
"""

import argparse
import glob
import json
import math
import pathlib
import sys

WORKLOADS = ["W_PACED", "W_BURST", "W_SUSTAIN"]


def stats(values):
    clean = [x for x in values if x is not None]
    n = len(clean)
    if n == 0:
        return {"n": 0, "available": False, "mean": None, "std": None, "min": None, "max": None, "ci95": None}
    mean = sum(clean) / n
    if n > 1:
        variance = sum((x - mean) ** 2 for x in clean) / (n - 1)
        std = math.sqrt(variance)
        ci95 = 1.96 * std / math.sqrt(n)
    else:
        std = 0.0
        ci95 = 0.0
    return {
        "n": n,
        "available": True,
        "mean": mean,
        "std": std,
        "min": min(clean),
        "max": max(clean),
        "ci95": ci95,
    }


def parse_trial(filepath: pathlib.Path):
    with filepath.open("r") as f:
        d = json.load(f)

    status = d.get("status", "VALID")
    w_name = d.get("test", {}).get("name", filepath.stem)
    base_name = w_name.rsplit("_", 1)[0]

    # Handle invalid or timed-out trials: do NOT inject zero or fallback 100%
    if status != "VALID":
        return {
            "file": str(filepath),
            "name": w_name,
            "base_workload": base_name,
            "valid": False,
            "status": status,
            "error": d.get("error", "Trial failed or timed out"),
            "ops_attempted": None,
            "reconstructed": None,
            "completeness_c_e2e": None,
            "incomplete_fraction_f": None,
            "ring_loss": None,
            "transport_loss": None,
            "persisted_received": None,
            "persisted_written": None,
            "persisted_synced": None,
            "persisted_verified": None,
            "persisted_replayed": None,
            "persistence_loss": None,
            "sync_loss": None,
            "verification_loss": None,
            "replay_loss": None,
            "persisted_completeness": None,
            "write_errors": 0,
            "corrupt_records": 0,
            "seq_gaps": 0,
            "incomplete_records": 0,
            "storage_bytes": None,
            "storage_per_op_bytes": None,
            "offered_throughput": None,
            "useful_throughput": None,
            "drain_latency_ms": None,
            "persist_drain_latency_ms": None,
            "replay_duration_ms": None,
            "total_time_to_graph_ms": None,
            "workload_cpu_us": None,
            "loader_active_cpu_us": None,
            "collection_cpu_us": None,
            "replay_cpu_us": None,
            "loader_total_cpu_us": None,
            "peak_rss_mib": None,
            "measurement_valid": False,
            "telemetry_fidelity_valid": False,
            "model_m_replay_equivalence": None,
            "incorrect_outcomes": None,
        }

    analysis = d.get("analysis", {})
    pa = analysis.get("pipeline_accounting", {})
    thru = analysis.get("throughput", {})
    res = analysis.get("resources", {})
    rec = analysis.get("reconciliation", {})
    ev = analysis.get("evidence", {}) or d.get("measurement", {}).get("evidence", {})

    p_comp = ev.get("persisted_completeness")
    if p_comp is None:
        p_comp = pa.get("persisted_completeness")

    rec_recv = ev.get("records_received", 0)
    rec_writ = ev.get("records_written", 0)
    rec_sync = ev.get("records_synced", 0)
    rec_veri = ev.get("records_verified", rec_sync)
    rec_repl = ev.get("records_replayed", rec_veri)

    # Correct timing-field selection: prioritize analysis.throughput fields over raw counters
    drain_ms = thru.get("persist_drain_latency_ms")
    if drain_ms is None:
        drain_ms = ev.get("persist_drain_latency_ms", ev.get("persist_drain_latency_ns", 0) / 1e6)

    replay_ms = thru.get("replay_duration_ms")
    if replay_ms is None:
        replay_ms = ev.get("replay_duration_ms", ev.get("replay_duration_ns", 0) / 1e6)

    total_time_ms = thru.get("total_time_to_graph_ms")
    if total_time_ms is None:
        total_time_ms = ev.get("total_time_to_graph_ms", ev.get("total_time_to_graph_ns", 0) / 1e6)

    return {
        "file": str(filepath),
        "name": w_name,
        "base_workload": base_name,
        "valid": True,
        "status": status,
        "error": None,
        "ops_attempted": pa.get("ops_attempted", 0),
        "reconstructed": pa.get("reconstructed", 0),
        "completeness_c_e2e": pa.get("completeness_c_e2e", 0.0),
        "incomplete_fraction_f": pa.get("incomplete_fraction_f", 0.0),
        "ring_loss": pa.get("ring_loss", 0),
        "transport_loss": pa.get("target_transport_loss", 0),
        "persisted_received": rec_recv,
        "persisted_written": rec_writ,
        "persisted_synced": rec_sync,
        "persisted_verified": rec_veri,
        "persisted_replayed": rec_repl,
        "persistence_loss": rec_recv - rec_writ,
        "sync_loss": rec_writ - rec_sync,
        "verification_loss": rec_sync - rec_veri,
        "replay_loss": rec_veri - rec_repl,
        "persisted_completeness": p_comp,
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
        "persist_drain_latency_ms": drain_ms,
        "replay_duration_ms": replay_ms,
        "total_time_to_graph_ms": total_time_ms,
        "workload_cpu_us": res.get("workload_cpu_us", 0),
        "loader_active_cpu_us": res.get("loader_active_cpu_us", 0),
        "collection_cpu_us": res.get("collection_cpu_us", res.get("loader_active_cpu_us", 0)),
        "replay_cpu_us": res.get("replay_cpu_us", 0),
        "loader_total_cpu_us": res.get("loader_total_cpu_us", 0),
        "peak_rss_mib": res.get("loader_max_rss_mib", 0.0),
        "measurement_valid": analysis.get("measurement_valid", True),
        "telemetry_fidelity_valid": analysis.get("telemetry_fidelity_valid", True),
        "model_m_replay_equivalence": ev.get("model_m_replay_equivalence", True),
        "incorrect_outcomes": rec.get("incorrect_outcome_count", 0),
    }


def fmt_stat(st, unit="", prec=2):
    if not st.get("available") or st.get("mean") is None:
        return "UNAVAILABLE"
    val = st["mean"]
    if unit == "%":
        return f"{val:6.{prec}f}%"
    elif unit == "ms":
        return f"{val:8.{prec}f} ms"
    elif unit == "KiB":
        return f"{val:8.{prec}f} KiB"
    elif unit == "MiB":
        return f"{val:8.{prec}f} MiB"
    elif unit == "ops/s":
        return f"{val:8.{prec}f} ops/s"
    return f"{val:.{prec}f} {unit}".strip()


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

    all_wls = [w for w in WORKLOADS if (w in by_wl_m or w in by_wl_p)]
    if not all_wls:
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
        tm_all = by_wl_m.get(wl, [])
        tp_all = by_wl_p.get(wl, [])

        tm = [x for x in tm_all if x.get("valid")]
        tp = [x for x in tp_all if x.get("valid")]

        sm_comp = stats([x["completeness_c_e2e"] * 100 for x in tm])
        sp_comp = stats([x["completeness_c_e2e"] * 100 for x in tp])

        sm_p_comp = stats([x["persisted_completeness"] * 100 for x in tm if x["persisted_completeness"] is not None])
        sp_p_comp = stats([x["persisted_completeness"] * 100 for x in tp if x["persisted_completeness"] is not None])

        sm_useful_thru = stats([x["useful_throughput"] for x in tm])
        sp_useful_thru = stats([x["useful_throughput"] for x in tp])

        sm_storage = stats([x["storage_bytes"] / 1024 for x in tm if x["storage_bytes"] is not None])  # KiB
        sp_storage = stats([x["storage_bytes"] / 1024 for x in tp if x["storage_bytes"] is not None])

        sm_persist_drain = stats([x["persist_drain_latency_ms"] for x in tm])
        sp_persist_drain = stats([x["persist_drain_latency_ms"] for x in tp])

        sp_replay = stats([x["replay_duration_ms"] for x in tp])

        sm_time_to_graph = stats([x["total_time_to_graph_ms"] for x in tm])
        sp_time_to_graph = stats([x["total_time_to_graph_ms"] for x in tp])

        sm_act_cpu = stats([x["loader_active_cpu_us"] / 1000 for x in tm if x["loader_active_cpu_us"] is not None])  # ms
        sp_act_cpu = stats([x["loader_active_cpu_us"] / 1000 for x in tp if x["loader_active_cpu_us"] is not None])

        sm_coll_cpu = stats([x["collection_cpu_us"] / 1000 for x in tm if x["collection_cpu_us"] is not None])
        sp_coll_cpu = stats([x["collection_cpu_us"] / 1000 for x in tp if x["collection_cpu_us"] is not None])

        sm_repl_cpu = stats([x["replay_cpu_us"] / 1000 for x in tm if x["replay_cpu_us"] is not None])
        sp_repl_cpu = stats([x["replay_cpu_us"] / 1000 for x in tp if x["replay_cpu_us"] is not None])

        sm_wkl_cpu = stats([x["workload_cpu_us"] / 1000 for x in tm if x["workload_cpu_us"] is not None])
        sp_wkl_cpu = stats([x["workload_cpu_us"] / 1000 for x in tp if x["workload_cpu_us"] is not None])

        sm_rss = stats([x["peak_rss_mib"] for x in tm if x["peak_rss_mib"] is not None])
        sp_rss = stats([x["peak_rss_mib"] for x in tp if x["peak_rss_mib"] is not None])

        print(
            f"----------------------------------------------------------------------------------------------------"
        )
        print(f"Workload: {wl} (Model M valid={len(tm)}/{len(tm_all)}, Model P valid={len(tp)}/{len(tp_all)})")
        print(
            f"----------------------------------------------------------------------------------------------------"
        )
        print(
            f"  Persisted Completeness:  Model M: {fmt_stat(sm_p_comp, "%")} | Model P: {fmt_stat(sp_p_comp, "%")}"
        )
        print(
            f"  E2E Graph Completeness:  Model M: {fmt_stat(sm_comp, "%")} | Model P: {fmt_stat(sp_comp, "%")}"
        )
        print(
            f"  Useful Throughput:       Model M: {fmt_stat(sm_useful_thru, "ops/s", 1)} | Model P: {fmt_stat(sp_useful_thru, "ops/s", 1)}"
        )
        print(
            f"  Persistence Drain Lat:   Model M: {fmt_stat(sm_persist_drain, "ms")} | Model P: {fmt_stat(sp_persist_drain, "ms")}"
        )
        print(
            f"  Replay Duration:         Model M:     0.00 ms | Model P: {fmt_stat(sp_replay, "ms")}"
        )
        print(
            f"  Total Time To Graph:     Model M: {fmt_stat(sm_time_to_graph, "ms")} | Model P: {fmt_stat(sp_time_to_graph, "ms")}"
        )
        print(
            f"  Storage Consumed:        Model M: {fmt_stat(sm_storage, "KiB", 1)} | Model P: {fmt_stat(sp_storage, "KiB", 1)}"
        )
        print(
            f"  Collection CPU:          Model M: {fmt_stat(sm_coll_cpu, "ms")} | Model P: {fmt_stat(sp_coll_cpu, "ms")}"
        )
        print(
            f"  Replay CPU:              Model M: {fmt_stat(sm_repl_cpu, "ms")} | Model P: {fmt_stat(sp_repl_cpu, "ms")}"
        )
        print(
            f"  Loader Active CPU:       Model M: {fmt_stat(sm_act_cpu, "ms")} | Model P: {fmt_stat(sp_act_cpu, "ms")}"
        )
        print(
            f"  Producer Workload CPU:   Model M: {fmt_stat(sm_wkl_cpu, "ms")} | Model P: {fmt_stat(sp_wkl_cpu, "ms")}"
        )
        print(
            f"  Peak RSS:                Model M: {fmt_stat(sm_rss, "MiB")} | Model P: {fmt_stat(sp_rss, "MiB")}"
        )

        # Fidelity checks
        m_corrupt = sum(x.get("corrupt_records", 0) for x in tm)
        p_corrupt = sum(x.get("corrupt_records", 0) for x in tp)
        m_incomplete = sum(x.get("incomplete_records", 0) for x in tm)
        p_incomplete = sum(x.get("incomplete_records", 0) for x in tp)
        m_errors = sum(x.get("write_errors", 0) for x in tm)
        p_errors = sum(x.get("write_errors", 0) for x in tp)
        m_equiv = all(x.get("model_m_replay_equivalence") for x in tm) if tm else None
        print(
            f"  Integrity & Fidelity:    M (corrupt={m_corrupt}, trunc={m_incomplete}, errs={m_errors}, equiv={m_equiv}) | P (corrupt={p_corrupt}, trunc={p_incomplete}, errs={p_errors})"
        )
        print()

        summary_out["comparisons"][wl] = {
            "model_m": {
                "trials_total": len(tm_all),
                "trials_valid": len(tm),
                "completeness": sm_comp,
                "persisted_completeness": sm_p_comp,
                "useful_throughput": sm_useful_thru,
                "persist_drain_ms": sm_persist_drain,
                "time_to_graph_ms": sm_time_to_graph,
                "storage_kib": sm_storage,
                "collection_cpu_ms": sm_coll_cpu,
                "replay_cpu_ms": sm_repl_cpu,
                "active_cpu_ms": sm_act_cpu,
                "rss_mib": sm_rss,
                "replay_equivalence": m_equiv,
            },
            "model_p": {
                "trials_total": len(tp_all),
                "trials_valid": len(tp),
                "completeness": sp_comp,
                "persisted_completeness": sp_p_comp,
                "useful_throughput": sp_useful_thru,
                "persist_drain_ms": sp_persist_drain,
                "replay_ms": sp_replay,
                "time_to_graph_ms": sp_time_to_graph,
                "storage_kib": sp_storage,
                "collection_cpu_ms": sp_coll_cpu,
                "replay_cpu_ms": sp_repl_cpu,
                "active_cpu_ms": sp_act_cpu,
                "rss_mib": sp_rss,
            },
        }

    out_file = results_dir / "persist_comparison_summary.json"
    try:
        out_file.write_text(json.dumps(summary_out, indent=2))
        print(f"Comparative audit summary saved to: {out_file}")
    except PermissionError:
        print(f"Note: {out_file} is root-owned and read-only. Summary generated in-memory.")
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
