#!/usr/bin/env python3
"""
Unit and integration test suite for the benchmark measurement infrastructure.
Validates:
1. Workload extended metrics (timestamps, rusage, duration).
2. Pipeline count conservation balance equation in runner.analyse().
3. Throughput, drain latency, and disaggregated CPU metrics computation.
4. Comparative analyzer statistical aggregation and acceptance target rules.
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
        # iterations=50, workers=2, pace=0, hold=0
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


def test_pipeline_balance_and_accounting():
    """Verify the pipeline count conservation balance equation in runner.analyse()."""
    print("\n[TEST 2] Verifying pipeline count conservation balance equation...")

    mock_workload = {
        "status": "VALID",
        "execution_failures": 0,
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
            {
                "scope": 1,
                "type": 2,
                "attempted": 1000,
                "reserve_failed": 0,
                "submitted": 1000,
                "received": 1000,
            },
            {
                "scope": 1,
                "type": 12,
                "attempted": 1000,
                "reserve_failed": 0,
                "submitted": 1000,
                "received": 1000,
            },
            {
                "scope": 1,
                "type": 15,
                "attempted": 1000,
                "reserve_failed": 0,
                "submitted": 1000,
                "received": 1000,
            },
            {
                "scope": 1,
                "type": 16,
                "attempted": 1000,
                "reserve_failed": 0,
                "submitted": 1000,
                "received": 1000,
            },
            {
                "scope": 1,
                "type": 17,
                "attempted": 1000,
                "reserve_failed": 0,
                "submitted": 1000,
                "received": 1000,
            },
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
        "p_checkpoint": {
            "available": True,
            "success": 1000,
            "filtered": 0,
            "correlation_deficiency": 0,
            "edge_suppressed": 0,
            "failed": 0,
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
    assert p["ring_loss"] == 0
    assert p["queue_loss"] == 0
    assert p["corr_def"] == 0
    assert p["proc_fail"] == 0
    assert p["completeness_c_e2e"] == 1.0
    assert p["incomplete_fraction_f"] == 0.0
    assert p["residual"] == 0  # Conservation law satisfied

    # Check throughputs
    thru = res["throughput"]
    assert abs(thru["offered_throughput_ops_sec"] - 2000.0) < 0.1
    assert abs(thru["useful_throughput_ops_sec"] - (1000.0 / 0.55)) < 0.1
    assert abs(thru["drain_latency_ms"] - 50.0) < 0.1

    # Check resources
    reso = res["resources"]
    assert reso["loader_cpu_us"] == 100000  # 40000 + 60000
    assert abs(reso["cpu_cost_attempted_us"] - 100.0) < 0.1
    assert abs(reso["cpu_cost_reconstructed_us"] - 100.0) < 0.1
    assert abs(reso["loader_max_rss_mib"] - 32.0) < 0.1

    print(
        "  [PASS] Pipeline balance equation verified: N_ops == N_reconstructed (loss-free)"
    )

    # Case B: Multi-stage losses (Ring loss + Queue loss + Correlation deficiency)
    mock_diag_lossy = copy.deepcopy(mock_diag_clean)
    # 200 ring drops on create
    mock_diag_lossy["events"][0]["reserve_failed"] = 200
    mock_diag_lossy["events"][0]["submitted"] = 800
    # Queue loss of 150 drops
    mock_diag_lossy["queue"] = {
        "capacity": 65536,
        "admission_attempts": 1600,
        "enqueued": 1450,
        "dequeued": 1450,
        "drops": 150,
        "high_water_mark": 1200,
    }
    # Correlation deficiency: 50 uncorrelate completions
    mock_diag_lossy["target_counters"][72] = 50

    res_lossy = analyse(mock_diag_lossy, mock_workload, timing=timing)
    p_lossy = res_lossy["pipeline_accounting"]
    assert p_lossy["ops_attempted"] == 1000
    assert p_lossy["ring_loss"] == 200
    assert p_lossy["queue_loss"] == 150
    assert p_lossy["corr_def"] == 50
    assert p_lossy["reconstructed"] == 600  # 1000 - (200 + 150 + 50)
    assert p_lossy["completeness_c_e2e"] == 0.60
    assert p_lossy["incomplete_fraction_f"] == 0.40
    assert p_lossy["residual"] == 0  # Conservation law strictly held!

    print("  [PASS] Multi-stage loss accounting strictly balanced across all stages")


def test_comparative_analyzer_acceptance_targets():
    """Verify statistical evaluation and numerical acceptance target checking in compare_architectures.py."""
    print("\n[TEST 3] Verifying comparative analyzer acceptance targets...")

    # Build synthetic trial aggregates for Architecture A and B
    # Target 1: W_PACED -> B has 100% completeness
    # Target 2: All B corrupt/inversions/residuals = 0
    # Target 3: W_BURST -> A has 40% loss, B has 10% loss (75% relative reduction >= 50%)
    # Target 4: W_SUSTAIN -> A has 5000 op/s, B has 6500 op/s (30% gain >= 20%)
    # Target 5: Memory -> Peak RSS A = 40 MiB, B = 70 MiB (Delta = 30 MiB <= 64 MiB)
    # Target 6: Drain Latency -> B drain = 450 ms (<= 1,000 ms)

    aggs_a = {
        "W_PACED": {
            "sample_size": 5,
            "completeness_c_e2e": compute_stats([1.0] * 5),
            "incomplete_fraction_f": compute_stats([0.0] * 5),
            "ring_loss": compute_stats([0.0] * 5),
            "queue_loss": compute_stats([0.0] * 5),
            "residual": compute_stats([0.0] * 5),
            "corrupt_count": compute_stats([0.0] * 5),
            "incorrect_outcome": compute_stats([0.0] * 5),
            "offered_throughput_ops_sec": compute_stats([1000.0] * 5),
            "useful_throughput_ops_sec": compute_stats([980.0] * 5),
            "drain_latency_ms": compute_stats([10.0] * 5),
            "peak_rss_mib": compute_stats([35.0] * 5),
        },
        "W_BURST": {
            "sample_size": 5,
            "completeness_c_e2e": compute_stats([0.60] * 5),
            "incomplete_fraction_f": compute_stats([0.40] * 5),
            "ring_loss": compute_stats([4000.0] * 5),
            "queue_loss": compute_stats([0.0] * 5),
            "residual": compute_stats([0.0] * 5),
            "corrupt_count": compute_stats([0.0] * 5),
            "incorrect_outcome": compute_stats([0.0] * 5),
            "offered_throughput_ops_sec": compute_stats([25000.0] * 5),
            "useful_throughput_ops_sec": compute_stats([15000.0] * 5),
            "drain_latency_ms": compute_stats([100.0] * 5),
            "peak_rss_mib": compute_stats([40.0] * 5),
        },
        "W_SUSTAIN": {
            "sample_size": 5,
            "completeness_c_e2e": compute_stats([0.70] * 5),
            "incomplete_fraction_f": compute_stats([0.30] * 5),
            "ring_loss": compute_stats([18000.0] * 5),
            "queue_loss": compute_stats([0.0] * 5),
            "residual": compute_stats([0.0] * 5),
            "corrupt_count": compute_stats([0.0] * 5),
            "incorrect_outcome": compute_stats([0.0] * 5),
            "offered_throughput_ops_sec": compute_stats([20000.0] * 5),
            "useful_throughput_ops_sec": compute_stats([5000.0] * 5),
            "drain_latency_ms": compute_stats([200.0] * 5),
            "peak_rss_mib": compute_stats([42.0] * 5),
        },
    }

    aggs_b_pass = {
        "W_PACED": {
            "sample_size": 5,
            "completeness_c_e2e": compute_stats([1.0] * 5),
            "incomplete_fraction_f": compute_stats([0.0] * 5),
            "ring_loss": compute_stats([0.0] * 5),
            "queue_loss": compute_stats([0.0] * 5),
            "residual": compute_stats([0.0] * 5),
            "corrupt_count": compute_stats([0.0] * 5),
            "incorrect_outcome": compute_stats([0.0] * 5),
            "offered_throughput_ops_sec": compute_stats([1000.0] * 5),
            "useful_throughput_ops_sec": compute_stats([990.0] * 5),
            "drain_latency_ms": compute_stats([15.0] * 5),
            "peak_rss_mib": compute_stats([60.0] * 5),
        },
        "W_BURST": {
            "sample_size": 5,
            "completeness_c_e2e": compute_stats([0.90] * 5),
            "incomplete_fraction_f": compute_stats(
                [0.10] * 5
            ),  # 75% relative reduction vs 0.40
            "ring_loss": compute_stats([500.0] * 5),
            "queue_loss": compute_stats([500.0] * 5),
            "residual": compute_stats([0.0] * 5),
            "corrupt_count": compute_stats([0.0] * 5),
            "incorrect_outcome": compute_stats([0.0] * 5),
            "offered_throughput_ops_sec": compute_stats([25000.0] * 5),
            "useful_throughput_ops_sec": compute_stats([22500.0] * 5),
            "drain_latency_ms": compute_stats([450.0] * 5),  # <= 1000 ms
            "peak_rss_mib": compute_stats([70.0] * 5),
        },
        "W_SUSTAIN": {
            "sample_size": 5,
            "completeness_c_e2e": compute_stats([0.88] * 5),
            "incomplete_fraction_f": compute_stats([0.12] * 5),
            "ring_loss": compute_stats([5000.0] * 5),
            "queue_loss": compute_stats([2200.0] * 5),
            "residual": compute_stats([0.0] * 5),
            "corrupt_count": compute_stats([0.0] * 5),
            "incorrect_outcome": compute_stats([0.0] * 5),
            "offered_throughput_ops_sec": compute_stats([20000.0] * 5),
            "useful_throughput_ops_sec": compute_stats(
                [6500.0] * 5
            ),  # +30% gain vs 5000
            "drain_latency_ms": compute_stats([600.0] * 5),
            "peak_rss_mib": compute_stats([72.0] * 5),
        },
    }

    targets_pass = evaluate_acceptance_targets(aggs_a, aggs_b_pass)
    assert all(
        t["pass"] for t in targets_pass.values()
    ), f"Expected all targets to pass, got: {targets_pass}"
    print(
        "  [PASS] All 6 acceptance targets evaluate correctly to PASS under qualifying metrics"
    )

    # Now verify fail conditions:
    # 1. Burst reduction < 50%
    aggs_b_fail = copy.deepcopy(aggs_b_pass)
    aggs_b_fail["W_BURST"]["incomplete_fraction_f"] = compute_stats(
        [0.25] * 5
    )  # only 37.5% reduction
    targets_fail = evaluate_acceptance_targets(aggs_a, aggs_b_fail)
    assert not targets_fail["target_3_burst_loss_reduction"]["pass"]

    # 2. Memory exceedance > 64 MiB delta
    aggs_b_fail = copy.deepcopy(aggs_b_pass)
    aggs_b_fail["W_BURST"]["peak_rss_mib"] = compute_stats(
        [120.0] * 5
    )  # Delta = 120 - 42 = 78 > 64
    targets_fail = evaluate_acceptance_targets(aggs_a, aggs_b_fail)
    assert not targets_fail["target_5_memory_cap"]["pass"]

    # 3. Burst drain latency > 1,000 ms
    aggs_b_fail = copy.deepcopy(aggs_b_pass)
    aggs_b_fail["W_BURST"]["drain_latency_ms"] = compute_stats([1250.0] * 5)
    targets_fail = evaluate_acceptance_targets(aggs_a, aggs_b_fail)
    assert not targets_fail["target_6_burst_drain_latency"]["pass"]

    print(
        "  [PASS] Acceptance targets evaluate correctly to FAIL when thresholds are not met"
    )


def main():
    print("=" * 80)
    print("Running Benchmark Measurement Infrastructure Verification Tests")
    print("=" * 80)
    test_workload_binary_extended_metrics()
    test_pipeline_balance_and_accounting()
    test_comparative_analyzer_acceptance_targets()
    print("\n" + "=" * 80)
    print("ALL BENCHMARK MEASUREMENT INFRASTRUCTURE INVARIANTS VERIFIED!")
    print("=" * 80)


if __name__ == "__main__":
    main()
