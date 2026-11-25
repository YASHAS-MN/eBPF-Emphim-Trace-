#!/usr/bin/env python3
"""test_persistent_evidence.py — Deterministic Validation Suite for Issue #7

Validates:
1. Binary wire format, header, framing and CRC32 checksums.
2. Model M replay equivalence: saved evidence bit-for-bit reproduces the online graph.
3. Model P deferred pipeline: collection-only persistence, followed by replay graph construction.
4. Storage failure, truncation, sequence gap and bit-flip corruption handling.
5. Stage-wise loss accounting, persistence drain latency, and total time to graph metrics.
6. Comparative auditor report generation.
"""

import json
import os
import pathlib
import struct
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]

# Ensure local test framework is importable
sys.path.insert(0, str(HERE))
import compare_persistent_evidence
import runner


def test_c_unit_tests():
    print("[TEST 1/5] Executing C deterministic unit tests...")
    # 1. test_evidence_writer
    cmd1 = [
        "gcc",
        "-O2",
        "-Wall",
        "-Wextra",
        "-I",
        "src/user",
        str(HERE / "test_evidence_writer.c"),
        "-o",
        str(ROOT / "build" / "test_evidence_writer"),
    ]
    subprocess.run(cmd1, cwd=ROOT, check=True)
    res1 = subprocess.run(
        [str(ROOT / "build" / "test_evidence_writer")],
        check=True,
        capture_output=True,
        text=True,
    )
    print(res1.stdout.strip())

    # 2. test_replay_equivalence
    cmd2 = [
        "gcc",
        "-O2",
        "-Wall",
        "-Wextra",
        "-I",
        "src/user",
        str(HERE / "test_replay_equivalence.c"),
        str(ROOT / "build" / "telemetry_lab" / "provenance.diag.c"),
        "-o",
        str(ROOT / "build" / "test_replay_equivalence"),
    ]
    subprocess.run(cmd2, cwd=ROOT, check=True)
    res2 = subprocess.run(
        [str(ROOT / "build" / "test_replay_equivalence")],
        check=True,
        capture_output=True,
        text=True,
    )
    print(res2.stdout.strip())
    print("  -> C unit tests passed successfully!\n")


def test_synthetic_reconciliation():
    print(
        "[TEST 2/5] Testing telemetry lab persistence reconciliation & stage-wise loss accounting..."
    )

    # Create synthetic measurement data for Model M
    d_m = {
        "pid": 1234,
        "invalid": 0,
        "unknown_type": 0,
        "captured_count": 20,
        "captured_overflow": 0,
        "events": [
            {"scope": 1, "type": 2, "attempted": 10, "reserve_failed": 0, "submitted": 10, "received": 10},
            {"scope": 1, "type": 12, "attempted": 10, "reserve_failed": 0, "submitted": 10, "received": 10},
            {"scope": 1, "type": 15, "attempted": 10, "reserve_failed": 0, "submitted": 10, "received": 10},
            {"scope": 1, "type": 16, "attempted": 0, "reserve_failed": 0, "submitted": 0, "received": 0},
            {"scope": 1, "type": 17, "attempted": 0, "reserve_failed": 0, "submitted": 0, "received": 0},
        ],
        "target_counters": [0] * 128,
        "captured_events": [],
        "evidence": {
            "mode": "M",
            "path": "/tmp/test_m.evid",
            "records_received": 20,
            "records_written": 20,
            "records_synced": 20,
            "records_replayed": 20,
            "write_errors": 0,
            "corrupt_records": 0,
            "seq_gaps": 0,
            "incomplete_records": 0,
            "storage_bytes": 13920,
            "flush_count": 1,
            "sync_duration_ns": 150000,
            "persist_drain_latency_ns": 800000,
            "replay_duration_ns": 0,
            "total_time_to_graph_ns": 800000,
        },
        "map_mutations": [],
        "rusage": {
            "user_cpu_us": 5000,
            "sys_cpu_us": 10000,
            "active_user_cpu_us": 5000,
            "active_sys_cpu_us": 10000,
            "total_user_cpu_us": 8000,
            "total_sys_cpu_us": 12000,
            "max_rss_kb": 18000,
        },
        "timing": {
            "workload_start_ns": 1000000,
            "workload_done_ns": 1010000000,
            "workload_duration_sec": 1.0,
            "total_duration_sec": 1.01,
        },
    }

    d_m["target_counters"][60] = 10
    d_m["target_counters"][70] = 10
    d_m["target_counters"][71] = 10

    w_truth = {
        "status": "VALID",
        "execution_failures": 0,
        "calls": 10,
        "creates": 10,
        "writes": 0,
        "closes": 0,
        "failures": 0,
        "create_attempts": 10,
        "create_successes": 10,
        "create_failures": 0,
        "start_ts_ns": 1000000000,
        "done_ts_ns": 1010000000,
        "user_cpu_us": 5000,
        "sys_cpu_us": 10000,
        "records": [
            {
                "op_id": i,
                "name": f"test_{i}",
                "pid": 1234,
                "tid": 1234,
                "ret": 3,
                "errno": 0,
                "success": 1,
            }
            for i in range(10)
        ],
    }

    # Add matching captured events
    for i in range(10):
        d_m["captured_events"].append(
            {
                "type": 2,
                "pid": 1234,
                "tid": 1234,
                "ret": 0,
                "fd": -1,
                "op": 0,
                "token": 0,
                "inode": 100 + i,
                "dev": 1,
                "entry_ts": 1000 + i,
                "ts": 1000 + i,
                "p": 2,
                "name": f"test_{i}",
            }
        )
        d_m["captured_events"].append(
            {
                "type": 12,
                "pid": 1234,
                "tid": 1234,
                "ret": 3,
                "fd": 3,
                "op": 2,
                "token": 500 + i,
                "inode": 100 + i,
                "dev": 1,
                "entry_ts": 1000 + i,
                "ts": 1500 + i,
                "p": 1,
                "name": f"test_{i}",
            }
        )

    analysis_m = runner.analyse(d_m, w_truth, d_m["timing"])
    assert analysis_m["measurement_valid"] is True
    assert analysis_m["telemetry_complete"] is True
    assert analysis_m["telemetry_fidelity_valid"] is True

    pa = analysis_m["pipeline_accounting"]
    assert pa["persisted_received"] == 20
    assert pa["persisted_written"] == 20
    assert pa["persisted_synced"] == 20
    assert pa["persistence_loss"] == 0
    assert pa["sync_loss"] == 0
    assert pa["persisted_completeness"] == 1.0

    thru = analysis_m["throughput"]
    assert thru["persist_drain_latency_ms"] == 0.8
    assert thru["storage_bytes"] == 13920
    assert thru["storage_per_op_bytes"] == 1392.0

    print("  -> Model M reconciliation & metrics verified!\n")


def test_model_p_deferred_pipeline():
    print(
        "[TEST 3/5] Testing Model P deferred pipeline metrics & fidelity check on corruption..."
    )

    # Model P with 1 write error and 1 corrupt record
    d_p = {
        "pid": 5678,
        "invalid": 0,
        "unknown_type": 0,
        "captured_count": 2,
        "captured_overflow": 0,
        "events": [
            {"scope": 1, "type": 2, "attempted": 1, "reserve_failed": 0, "submitted": 1, "received": 1},
            {"scope": 1, "type": 12, "attempted": 1, "reserve_failed": 0, "submitted": 1, "received": 1},
            {"scope": 1, "type": 15, "attempted": 1, "reserve_failed": 0, "submitted": 1, "received": 1},
            {"scope": 1, "type": 16, "attempted": 0, "reserve_failed": 0, "submitted": 0, "received": 0},
            {"scope": 1, "type": 17, "attempted": 0, "reserve_failed": 0, "submitted": 0, "received": 0},
        ],
        "target_counters": [0] * 128,
        "captured_events": [
            {
                "type": 2,
                "pid": 5678,
                "tid": 5678,
                "ret": 0,
                "fd": -1,
                "op": 0,
                "token": 0,
                "inode": 10,
                "dev": 1,
                "entry_ts": 100,
                "ts": 100,
                "p": 2,
                "name": "f0",
            },
            {
                "type": 12,
                "pid": 5678,
                "tid": 5678,
                "ret": 3,
                "fd": 3,
                "op": 2,
                "token": 99,
                "inode": 10,
                "dev": 1,
                "entry_ts": 100,
                "ts": 150,
                "p": 1,
                "name": "f0",
            },
        ],
        "evidence": {
            "mode": "P",
            "path": "/tmp/test_p.evid",
            "records_received": 10,
            "records_written": 9,
            "records_synced": 9,
            "records_replayed": 8,
            "write_errors": 1,
            "corrupt_records": 1,
            "seq_gaps": 0,
            "incomplete_records": 0,
            "storage_bytes": 6264,
            "flush_count": 2,
            "sync_duration_ns": 200000,
            "persist_drain_latency_ns": 1200000,
            "replay_duration_ns": 4500000,
            "total_time_to_graph_ns": 5700000,
        },
        "map_mutations": [],
        "rusage": {
            "user_cpu_us": 2000,
            "sys_cpu_us": 4000,
            "active_user_cpu_us": 2000,
            "active_sys_cpu_us": 4000,
            "total_user_cpu_us": 3000,
            "total_sys_cpu_us": 5000,
            "max_rss_kb": 18000,
        },
        "timing": {
            "workload_start_ns": 1000000,
            "workload_done_ns": 1005000000,
            "workload_duration_sec": 0.5,
            "total_duration_sec": 0.51,
        },
    }

    d_p["target_counters"][60] = 1
    d_p["target_counters"][70] = 1
    d_p["target_counters"][71] = 1

    w_truth = {
        "status": "VALID",
        "execution_failures": 0,
        "calls": 1,
        "creates": 1,
        "writes": 0,
        "closes": 0,
        "failures": 0,
        "create_attempts": 1,
        "create_successes": 1,
        "create_failures": 0,
        "start_ts_ns": 1000000000,
        "done_ts_ns": 1005000000,
        "user_cpu_us": 2000,
        "sys_cpu_us": 4000,
        "records": [
            {
                "op_id": 0,
                "name": "f0",
                "pid": 5678,
                "tid": 5678,
                "ret": 3,
                "errno": 0,
                "success": 1,
            }
        ],
    }

    analysis_p = runner.analyse(d_p, w_truth, d_p["timing"])
    # Fidelity should fail because corrupt_records == 1 and write_errors == 1!
    assert (
        analysis_p["telemetry_fidelity_valid"] is False
    ), "Fidelity must be False when corrupt_records or write_errors occur"
    pa = analysis_p["pipeline_accounting"]
    assert pa["persisted_received"] == 10
    assert pa["persisted_written"] == 9
    assert pa["persistence_loss"] == 1
    assert pa["replay_loss"] == 1  # 9 synced - 8 replayed = 1 replay loss

    thru = analysis_p["throughput"]
    assert thru["persist_drain_latency_ms"] == 1.2
    assert thru["replay_duration_ms"] == 4.5
    assert thru["total_time_to_graph_ms"] == 5.7

    print("  -> Model P deferred pipeline metrics & fidelity enforcement verified!\n")


def test_comparative_auditor():
    print(
        "[TEST 4/5] Testing comparative auditor with synthetic Model M and Model P trial sets..."
    )

    test_dir = pathlib.Path("/tmp/test_persist_auditor")
    out_m = test_dir / "model_m"
    out_p = test_dir / "model_p"
    out_m.mkdir(parents=True, exist_ok=True)
    out_p.mkdir(parents=True, exist_ok=True)

    def write_sample_trial(dir_path, name, mode, drain_ms, replay_ms):
        sample = {
            "test": {"name": name},
            "workload": {"create_attempts": 100, "records": []},
            "measurement": {},
            "analysis": {
                "measurement_valid": True,
                "telemetry_fidelity_valid": True,
                "pipeline_accounting": {
                    "ops_attempted": 100,
                    "reconstructed": 100,
                    "completeness_c_e2e": 1.0,
                    "incomplete_fraction_f": 0.0,
                    "ring_loss": 0,
                    "target_transport_loss": 0,
                },
                "throughput": {
                    "offered_throughput_ops_sec": 5000.0,
                    "useful_throughput_ops_sec": 4800.0,
                    "drain_latency_ms": drain_ms,
                },
                "resources": {
                    "workload_cpu_us": 25000,
                    "loader_active_cpu_us": 150000,
                    "loader_total_cpu_us": 180000,
                    "loader_max_rss_mib": 18.5,
                },
                "reconciliation": {"incorrect_outcome_count": 0},
                "evidence": {
                    "mode": mode,
                    "records_received": 200,
                    "records_written": 200,
                    "records_synced": 200,
                    "records_replayed": 200,
                    "write_errors": 0,
                    "corrupt_records": 0,
                    "seq_gaps": 0,
                    "incomplete_records": 0,
                    "storage_bytes": 139200,
                    "persist_drain_latency_ns": int(drain_ms * 1e6),
                    "replay_duration_ns": int(replay_ms * 1e6),
                    "total_time_to_graph_ns": int((drain_ms + replay_ms) * 1e6),
                },
            },
        }
        (dir_path / f"{name}.json").write_text(json.dumps(sample, indent=2))

    for w_name in ["W_PACED_1", "W_BURST_1", "W_SUSTAIN_1"]:
        write_sample_trial(out_m, w_name, "M", drain_ms=1.5, replay_ms=0.0)
        write_sample_trial(out_p, w_name, "P", drain_ms=0.8, replay_ms=12.0)

    rc = compare_persistent_evidence.audit_results_dir(test_dir)
    assert rc == 0
    summary_file = test_dir / "persist_comparison_summary.json"
    assert summary_file.exists()
    summary = json.loads(summary_file.read_text())
    assert "W_PACED" in summary["comparisons"]
    assert "W_BURST" in summary["comparisons"]
    assert "W_SUSTAIN" in summary["comparisons"]

    print("  -> Comparative auditor report generated and validated!\n")


def test_build_artifacts():
    print("[TEST 5/5] Testing runner.py build artifact verification...")
    runner.build()
    build_info = json.loads((ROOT / "build" / "telemetry_lab" / "build_info.json").read_text())
    assert "bpf_sha256" in build_info
    assert "loader_sha256" in build_info
    assert (ROOT / "build" / "telemetry_lab" / "loader.diag").exists()
    assert (ROOT / "build" / "telemetry_lab" / "monitor.diag.bpf.o").exists()
    assert (ROOT / "build" / "telemetry_lab" / "workload").exists()
    print("  -> Diagnostic build artifacts verified!\n")


if __name__ == "__main__":
    print("======================================================================")
    print("      Running Issue #7 Persistent Evidence Test Suite                 ")
    print("======================================================================\n")
    test_c_unit_tests()
    test_synthetic_reconciliation()
    test_model_p_deferred_pipeline()
    test_comparative_auditor()
    test_build_artifacts()
    print("======================================================================")
    print("      ALL PERSISTENT EVIDENCE TESTS PASSED SUCCESSFULLY!             ")
    print("======================================================================")
