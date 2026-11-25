#!/usr/bin/env python3
"""
Unit and integration test suite for the benchmark measurement infrastructure.
Validates:
1. Workload extended metrics (timestamps, rusage, duration).
2. Unique reconciled operation completeness in runner.analyse().
3. Independent stage-wise event loss accounting and conservation laws.
4. Adversarial measurement scenarios (multiple event losses per operation).
5. Strict comparative analyzer rules (invalid trials, sample size, config mismatch, residual cancellation).
"""

import copy
import json
import os
import pathlib
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))

from compare_architectures import (
    aggregate_workload_metrics,
    compute_stats,
    evaluate_acceptance_targets,
    parse_trial_report,
)
from runner import analyse, reconcile_events


def test_workload_binary_extended_metrics():
    """Verify that compiling and running workload.c produces the required timing and rusage fields."""
    print("\n[TEST 1] Verifying workload binary extended metrics...")
    build_dir = ROOT / "build" / "telemetry_lab"
    build_dir.mkdir(parents=True, exist_ok=True)
    workload_bin = build_dir / "workload"

    # Recompile workload
    cmd = [
        "gcc",
        "-O2",
        "-Wall",
        "-Wextra",
        "-pthread",
        str(HERE / "workload.c"),
        "-o",
        str(workload_bin),
    ]
    res = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    assert res.returncode == 0, f"Compilation failed:\n{res.stderr}"

    # Run quick workload
    with tempfile.NamedTemporaryFile(suffix=".json") as tf:
        env = dict(os.environ, EPHIM_GROUND_TRUTH_FILE=tf.name)
        p = subprocess.Popen(
            [str(workload_bin), "50", "2", "0", "0"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        line = p.stdout.readline().strip()
        assert line == "WORKLOAD_READY", f"Expected WORKLOAD_READY, got: {line}"
        p.stdin.write("\n")
        p.stdin.flush()
        out_line = p.stdout.readline().strip()
        p.stdin.write("\n")
        p.stdin.flush()
        p.wait(timeout=5)
        assert p.returncode == 0, f"Workload exited with code {p.returncode}"

        data = json.loads(out_line)
        assert data.get("status") == "VALID"
        assert data.get("create_attempts") == 100
        assert data.get("create_successes") == 100
        assert data.get("create_failures") == 0
        assert data.get("seconds", 0.0) > 0.0
        assert data.get("start_ts_ns", 0) > 0
        assert data.get("done_ts_ns", 0) >= data.get("start_ts_ns", 0)
        assert "user_cpu_us" in data
        assert "sys_cpu_us" in data
        print(
            "  [PASS] Workload correctly emitted monotonic timestamps and process rusage"
        )


def test_unique_operation_reconciliation_and_stage_conservation():
    """Verify operation completeness derived from unique reconciled records and independent stage conservation."""
    print(
        "\n[TEST 2] Verifying unique operation completeness and stage conservation..."
    )

    mock_workload = {
        "status": "VALID",
        "calls": 1000,
        "creates": 1000,
        "writes": 1000,
        "closes": 1000,
        "failures": 0,
        "create_attempts": 1000,
        "create_successes": 1000,
        "create_failures": 0,
        "start_ts_ns": 1000000000,
        "done_ts_ns": 1500000000,  # 0.5s duration -> 2000 ops/s offered
        "user_cpu_us": 25000,
        "sys_cpu_us": 35000,
        "records": [
            {
                "op_id": i + 1,
                "name": f"mem_{i}",
                "pid": 100,
                "tid": 101,
                "ret": 3 + i,
                "errno": 0,
                "success": 1,
            }
            for i in range(1000)
        ],
    }

    # Case A: Loss-free baseline (Architecture A control)
    mock_diag_clean = {
        "pid": 100,
        "invalid": 0,
        "unknown_type": 0,
        "captured_count": 2000,
        "captured_overflow": 0,
        "events": [
            {"scope": 1, "type": 2, "attempted": 1000, "reserve_failed": 0, "submitted": 1000, "received": 1000},
            {"scope": 1, "type": 12, "attempted": 1000, "reserve_failed": 0, "submitted": 1000, "received": 1000},
            {"scope": 1, "type": 15, "attempted": 1000, "reserve_failed": 0, "submitted": 1000, "received": 1000},
            {"scope": 1, "type": 16, "attempted": 1000, "reserve_failed": 0, "submitted": 1000, "received": 1000},
            {"scope": 1, "type": 17, "attempted": 1000, "reserve_failed": 0, "submitted": 1000, "received": 1000},
        ],
        "target_counters": [0] * 128,
        "captured_events": [
            {
                "type": 2,
                "pid": 100,
                "tid": 101,
                "name": f"mem_{i}",
                "ret": 0,
                "fd": -1,
                "op": 0,
                "token": 0,
                "p": 2,
            }
            for i in range(1000)
        ]
        + [
            {
                "type": 12,
                "pid": 100,
                "tid": 101,
                "name": f"mem_{i}",
                "ret": 3 + i,
                "fd": 3 + i,
                "op": 2,
                "token": 500 + i,
                "p": 1,
            }
            for i in range(1000)
        ],
        "p": {
            "available": True,
            "success": 1000,
            "filtered": 1000,
            "correlation_deficiency": 0,
            "edge_suppressed": 0,
            "failed": 0,
        },
        "timing": {
            "first_event_proc_ts_ns": 1005000000,
            "last_event_proc_ts_ns": 1550000000,
        },
        "rusage": {"user_cpu_us": 40000, "sys_cpu_us": 60000, "max_rss_kb": 32768},
    }
    mock_diag_clean["target_counters"][60] = 1000
    mock_diag_clean["target_counters"][70] = 1000
    mock_diag_clean["target_counters"][71] = 1000

    timing = {
        "workload_duration_sec": 0.5,
        "drain_latency_sec": 0.05,
        "total_duration_sec": 0.55,
    }

    res = analyse(mock_diag_clean, mock_workload, timing=timing)
    assert res["measurement_valid"]
    assert res["telemetry_complete"]
    assert res["telemetry_fidelity_valid"]

    p = res["pipeline_accounting"]
    assert p["ops_attempted"] == 1000
    assert p["reconstructed"] == 1000
    assert p["incomplete"] == 0
    assert p["operation_residual"] == 0
    assert p["ring_loss"] == 0
    assert p["queue_loss"] == 0
    assert p["residual"] == 0
    assert p["completeness_c_e2e"] == 1.0

    print(
        "  [PASS] Unique operation completeness derived directly from verified records"
    )


def test_adversarial_multiple_event_loss_per_operation():
    """Verify that multiple lost events belonging to one operation do not double-count operation loss."""
    print("\n[TEST 3] Verifying adversarial multi-event loss per operation...")

    mock_workload = {
        "status": "VALID",
        "calls": 10,
        "creates": 10,
        "writes": 10,
        "closes": 10,
        "failures": 0,
        "create_attempts": 10,
        "create_successes": 10,
        "create_failures": 0,
        "start_ts_ns": 1000000000,
        "done_ts_ns": 1100000000,
        "records": [
            {
                "op_id": i + 1,
                "name": f"adv_{i}",
                "pid": 200,
                "tid": 201,
                "ret": 3 + i,
                "errno": 0,
                "success": 1,
            }
            for i in range(10)
        ],
    }

    # Simulate adversarial event losses:
    # Op 0: fully intact (type 2 + type 12)
    # Op 1: missing create (type 12 only) -> 1 event drop
    # Op 2: missing complete (type 2 only) -> 1 event drop
    # Op 3: BOTH create and complete lost! -> 2 event drops from SINGLE operation!
    # Op 4: token corrupted on enter (token != 0)
    # Op 5: incorrect outcome on complete (ret mismatch)
    # Ops 6..9: fully intact
    captured_events = [
        # Type 2 (create)
        {
            "type": 2,
            "pid": 200,
            "tid": 201,
            "name": "adv_0",
            "ret": 0,
            "fd": -1,
            "op": 0,
            "token": 0,
            "p": 2,
        },
        # Op 1 missing type 2
        {
            "type": 2,
            "pid": 200,
            "tid": 201,
            "name": "adv_2",
            "ret": 0,
            "fd": -1,
            "op": 0,
            "token": 0,
            "p": 2,
        },
        # Op 3 missing type 2
        {
            "type": 2,
            "pid": 200,
            "tid": 201,
            "name": "adv_4",
            "ret": 0,
            "fd": -1,
            "op": 0,
            "token": 99999,
            "p": 1,
        },  # Corrupted token!
        {
            "type": 2,
            "pid": 200,
            "tid": 201,
            "name": "adv_5",
            "ret": 0,
            "fd": -1,
            "op": 0,
            "token": 0,
            "p": 2,
        },
        {
            "type": 2,
            "pid": 200,
            "tid": 201,
            "name": "adv_6",
            "ret": 0,
            "fd": -1,
            "op": 0,
            "token": 0,
            "p": 2,
        },
        {
            "type": 2,
            "pid": 200,
            "tid": 201,
            "name": "adv_7",
            "ret": 0,
            "fd": -1,
            "op": 0,
            "token": 0,
            "p": 2,
        },
        {
            "type": 2,
            "pid": 200,
            "tid": 201,
            "name": "adv_8",
            "ret": 0,
            "fd": -1,
            "op": 0,
            "token": 0,
            "p": 2,
        },
        {
            "type": 2,
            "pid": 200,
            "tid": 201,
            "name": "adv_9",
            "ret": 0,
            "fd": -1,
            "op": 0,
            "token": 0,
            "p": 2,
        },
        # Type 12 (complete)
        {
            "type": 12,
            "pid": 200,
            "tid": 201,
            "name": "adv_0",
            "ret": 3,
            "fd": 3,
            "op": 2,
            "token": 100,
            "p": 1,
        },
        {
            "type": 12,
            "pid": 200,
            "tid": 201,
            "name": "adv_1",
            "ret": 4,
            "fd": 4,
            "op": 2,
            "token": 101,
            "p": 1,
        },
        # Op 2 missing type 12
        # Op 3 missing type 12
        {
            "type": 12,
            "pid": 200,
            "tid": 201,
            "name": "adv_4",
            "ret": 7,
            "fd": 7,
            "op": 2,
            "token": 104,
            "p": 1,
        },
        {
            "type": 12,
            "pid": 200,
            "tid": 201,
            "name": "adv_5",
            "ret": -1,
            "fd": -1,
            "op": 1,
            "token": 0,
            "p": 2,
        },  # Outcome mismatch!
        {
            "type": 12,
            "pid": 200,
            "tid": 201,
            "name": "adv_6",
            "ret": 9,
            "fd": 9,
            "op": 2,
            "token": 106,
            "p": 1,
        },
        {
            "type": 12,
            "pid": 200,
            "tid": 201,
            "name": "adv_7",
            "ret": 10,
            "fd": 10,
            "op": 2,
            "token": 107,
            "p": 1,
        },
        {
            "type": 12,
            "pid": 200,
            "tid": 201,
            "name": "adv_8",
            "ret": 11,
            "fd": 11,
            "op": 2,
            "token": 108,
            "p": 1,
        },
        {
            "type": 12,
            "pid": 200,
            "tid": 201,
            "name": "adv_9",
            "ret": 12,
            "fd": 12,
            "op": 2,
            "token": 109,
            "p": 1,
        },
    ]

    rec = reconcile_events(mock_workload["records"], captured_events, p_available=True)
    assert (
        rec["reconstructed_count"] == 5
    ), f"Expected 5 reconstructed, got {rec['reconstructed_count']}"
    assert (
        rec["incomplete_count"] == 5
    ), f"Expected 5 incomplete, got {rec['incomplete_count']}"
    assert (
        len(mock_workload["records"])
        == rec["reconstructed_count"] + rec["incomplete_count"]
    )

    mock_diag = {
        "pid": 200,
        "invalid": 0,
        "unknown_type": 0,
        "captured_count": len(captured_events),
        "captured_overflow": 0,
        "events": [
            {
                "scope": 1,
                "type": 2,
                "attempted": 10,
                "reserve_failed": 2,
                "submitted": 8,
                "received": 8,
            },
            {
                "scope": 1,
                "type": 12,
                "attempted": 10,
                "reserve_failed": 2,
                "submitted": 8,
                "received": 8,
            },
        ],
        "target_counters": [0] * 128,
        "captured_events": captured_events,
        "p": {
            "available": True,
            "success": 5,
            "filtered": 3,
            "correlation_deficiency": 0,
            "edge_suppressed": 0,
            "failed": 0,
        },
        "timing": {
            "first_event_proc_ts_ns": 1001000000,
            "last_event_proc_ts_ns": 1102000000,
        },
        "rusage": {"user_cpu_us": 1000, "sys_cpu_us": 2000, "max_rss_kb": 10000},
    }

    res = analyse(
        mock_diag,
        mock_workload,
        timing={
            "workload_duration_sec": 0.1,
            "drain_latency_sec": 0.002,
            "total_duration_sec": 0.102,
        },
    )
    pipe = res["pipeline_accounting"]
    assert pipe["ops_attempted"] == 10
    assert pipe["reconstructed"] == 5
    assert pipe["incomplete"] == 5
    assert pipe["operation_residual"] == 0
    assert pipe["completeness_c_e2e"] == 0.50
    assert pipe["incomplete_fraction_f"] == 0.50
    assert pipe["ring_loss"] == 4  # Total ring drops across types
    assert pipe["residual"] == 0

    print(
        "  [PASS] Adversarial multi-event loss reconciled without double counting or subtraction artifacts"
    )


def test_comparative_analyzer_rejection_rules():
    """Verify strict analyzer rules: invalid trials, small sample size, config mismatch, residual cancellation."""
    print("\n[TEST 4] Verifying comparative analyzer strict rejection rules...")

    # Helper to generate 5 valid trials for a workload
    def make_valid_trials(
        wl_name,
        count=5,
        c_e2e=1.0,
        f_inc=0.0,
        useful_thru=1000.0,
        drain_ms=20.0,
        rss=30.0,
        residual=0.0,
    ):
        trials = []
        for i in range(count):
            trials.append(
                {
                    "valid": True,
                    "status": "VALID",
                    "name": f"{wl_name}_{i+1}",
                    "ops_attempted": 500.0,
                    "reconstructed": 500.0 * c_e2e,
                    "completeness_c_e2e": c_e2e,
                    "incomplete_fraction_f": f_inc,
                    "ring_loss": 0.0,
                    "queue_loss": 0.0,
                    "gen_gap": 0.0,
                    "corr_def": 0.0,
                    "proc_fail": 0.0,
                    "residual": residual,
                    "corrupt_count": 0.0,
                    "incorrect_outcome": 0.0,
                    "offered_throughput_ops_sec": 1000.0,
                    "useful_throughput_ops_sec": useful_thru,
                    "drain_latency_ms": drain_ms,
                    "peak_rss_mib": rss,
                    "cpu_cost_attempted_us": 50.0,
                    "cpu_cost_reconstructed_us": 50.0,
                    "config": {
                        "workers": 1,
                        "iterations": 500,
                        "pace_us": 1000,
                        "hold": False,
                    },
                }
            )
        return trials

    # 1. Test sample size requirement (N < 5 must fail)
    trials_a = {
        "W_PACED": make_valid_trials("W_PACED", count=5),
        "W_BURST": make_valid_trials("W_BURST", count=5, f_inc=0.40),
        "W_SUSTAIN": make_valid_trials("W_SUSTAIN", count=5, useful_thru=5000.0),
    }
    trials_b_small = {
        "W_PACED": make_valid_trials("W_PACED", count=4),  # Only 4 runs!
        "W_BURST": make_valid_trials("W_BURST", count=5, f_inc=0.10),
        "W_SUSTAIN": make_valid_trials("W_SUSTAIN", count=5, useful_thru=7000.0),
    }
    aggs_a = {wl: aggregate_workload_metrics(t) for wl, t in trials_a.items()}
    aggs_b_small = {
        wl: aggregate_workload_metrics(t) for wl, t in trials_b_small.items()
    }
    tgts = evaluate_acceptance_targets(aggs_a, aggs_b_small)
    assert not tgts["target_1_control_completeness"][
        "pass"
    ], "Target 1 should fail when N < 5"
    assert (
        "Insufficient valid repetitions"
        in tgts["target_1_control_completeness"]["metric"]
    )

    # 2. Test invalid trial rejection (must not be silently dropped)
    trials_b_invalid = {
        "W_PACED": make_valid_trials("W_PACED", count=4)
        + [
            {
                "valid": False,
                "status": "INVALID",
                "name": "W_PACED_5",
                "error": "harness error",
            }
        ],
        "W_BURST": make_valid_trials("W_BURST", count=5, f_inc=0.10),
        "W_SUSTAIN": make_valid_trials("W_SUSTAIN", count=5, useful_thru=7000.0),
    }
    aggs_b_invalid = {
        wl: aggregate_workload_metrics(t) for wl, t in trials_b_invalid.items()
    }
    tgts_inv = evaluate_acceptance_targets(aggs_a, aggs_b_invalid)
    assert not tgts_inv["target_1_control_completeness"]["pass"]
    assert not tgts_inv["target_2_fidelity_invariants"]["pass"]
    assert "invalid_trials=1" in tgts_inv["target_2_fidelity_invariants"]["metric"]

    # 3. Test residual cancellation prevention
    # Trial 1 has residual +5, Trial 2 has residual -5 -> mean is 0.0, but per-trial check must FAIL!
    trials_b_cancelling = make_valid_trials("W_PACED", count=5)
    trials_b_cancelling[0]["residual"] = 5.0
    trials_b_cancelling[1]["residual"] = -5.0
    trials_b_cancelling_all = {
        "W_PACED": trials_b_cancelling,
        "W_BURST": make_valid_trials("W_BURST", count=5, f_inc=0.10),
        "W_SUSTAIN": make_valid_trials("W_SUSTAIN", count=5, useful_thru=7000.0),
    }
    aggs_b_cancelling = {
        wl: aggregate_workload_metrics(t) for wl, t in trials_b_cancelling_all.items()
    }
    tgts_cancelling = evaluate_acceptance_targets(aggs_a, aggs_b_cancelling)
    assert not tgts_cancelling["target_2_fidelity_invariants"][
        "pass"
    ], "Residual cancellation across trials must fail Target 2!"
    assert (
        "non_zero_residual_trials=2"
        in tgts_cancelling["target_2_fidelity_invariants"]["metric"]
    )

    # 4. Test configuration mismatch
    trials_b_mismatch = {
        "W_PACED": make_valid_trials("W_PACED", count=5),
        "W_BURST": make_valid_trials("W_BURST", count=5, f_inc=0.10),
        "W_SUSTAIN": make_valid_trials("W_SUSTAIN", count=5, useful_thru=7000.0),
    }
    trials_b_mismatch["W_BURST"][0]["config"] = {
        "workers": 8,
        "iterations": 5000,
        "pace_us": 0,
        "hold": False,
    }  # Mismatched!
    aggs_b_mismatch = {
        wl: aggregate_workload_metrics(t) for wl, t in trials_b_mismatch.items()
    }
    tgts_mismatch = evaluate_acceptance_targets(aggs_a, aggs_b_mismatch)
    assert not tgts_mismatch["target_3_burst_loss_reduction"]["pass"]
    assert (
        "Workload configuration mismatch"
        in tgts_mismatch["target_3_burst_loss_reduction"]["metric"]
    )

    # 5. Test no W_CONTENTION substitution for W_SUSTAIN
    trials_b_no_sustain = {
        "W_PACED": make_valid_trials("W_PACED", count=5),
        "W_BURST": make_valid_trials("W_BURST", count=5, f_inc=0.10),
        "W_CONTENTION": make_valid_trials("W_CONTENTION", count=5, useful_thru=9000.0),
    }
    aggs_b_no_sustain = {
        wl: aggregate_workload_metrics(t) for wl, t in trials_b_no_sustain.items()
    }
    tgts_no_sustain = evaluate_acceptance_targets(aggs_a, aggs_b_no_sustain)
    assert not tgts_no_sustain["target_4_sustained_throughput_gain"]["pass"]
    assert (
        "missing in A or B"
        in tgts_no_sustain["target_4_sustained_throughput_gain"]["metric"]
    )

    print("  [PASS] All strict comparative analyzer rejection rules verified")


def main():
    print("=" * 80)
    print("Running Benchmark Measurement Infrastructure & Adversarial Tests")
    print("=" * 80)
    test_workload_binary_extended_metrics()
    test_unique_operation_reconciliation_and_stage_conservation()
    test_adversarial_multiple_event_loss_per_operation()
    test_comparative_analyzer_rejection_rules()
    print("\n" + "=" * 80)
    print("ALL BENCHMARK MEASUREMENT INFRASTRUCTURE INVARIANTS VERIFIED!")
    print("=" * 80)


if __name__ == "__main__":
    main()
