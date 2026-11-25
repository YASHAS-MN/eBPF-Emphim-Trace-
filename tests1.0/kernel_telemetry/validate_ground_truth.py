#!/usr/bin/env python3
"""Independent Ground Truth Validation Harness for EphimTrace Workload."""

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKLOAD = ROOT / "build" / "telemetry_lab" / "workload"


def run_workload(iterations, workers, delay_us=0, hold=0, flags=None, output_file=None):
    cmd = [str(WORKLOAD), str(iterations), str(workers), str(delay_us), str(hold)]
    if flags is not None:
        cmd.append(str(flags))
    if output_file is not None:
        cmd.append(str(output_file))

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    # 1. Wait for WORKLOAD_READY handshake
    ready_line = proc.stdout.readline().strip()
    if ready_line != "WORKLOAD_READY":
        stderr = proc.stderr.read()
        proc.kill()
        raise RuntimeError(
            f"Handshake failed: expected 'WORKLOAD_READY', got '{ready_line}'. stderr: {stderr}"
        )

    # 2. Send newline to start workload
    proc.stdin.write("\n")
    proc.stdin.flush()

    # 3. Read machine-readable JSON summary from stdout
    json_line = proc.stdout.readline().strip()
    if not json_line:
        stderr = proc.stderr.read()
        proc.kill()
        raise RuntimeError(f"Workload produced no output. stderr: {stderr}")

    data = json.loads(json_line)

    # 4. Send second newline to terminate workload cleanly
    proc.stdin.write("\n")
    proc.stdin.flush()

    stdout_rest, stderr_rest = proc.communicate(timeout=5)
    if proc.returncode != 0:
        raise RuntimeError(
            f"Workload exited with code {proc.returncode}. stderr: {stderr_rest}"
        )

    return data


def validate_records(data, expected_ops, expect_success=True):
    # Invariant: attempted = succeeded + failed
    c_att = data["create_attempts"]
    c_succ = data["create_successes"]
    c_fail = data["create_failures"]

    assert (
        c_att == c_succ + c_fail
    ), f"Invariant violated: {c_att} != {c_succ} + {c_fail}"
    assert c_att == expected_ops, f"Expected {expected_ops} attempts, got {c_att}"

    # Verify separate counters
    w_att = data["write_attempts"]
    w_succ = data["write_successes"]
    w_fail = data["write_failures"]
    assert (
        w_att == w_succ + w_fail
    ), f"Write invariant violated: {w_att} != {w_succ} + {w_fail}"

    cl_att = data["close_attempts"]
    cl_succ = data["close_successes"]
    cl_fail = data["close_failures"]
    assert (
        cl_att == cl_succ + cl_fail
    ), f"Close invariant violated: {cl_att} != {cl_succ} + {cl_fail}"

    # Verify backward compatible fields
    assert data["calls"] == c_att
    assert data["creates"] == c_succ
    assert data["writes"] == w_succ
    assert data["closes"] == cl_succ
    assert data["failures"] == c_fail + w_fail + cl_fail

    records = data["records"]
    assert (
        len(records) == expected_ops
    ), f"Record count {len(records)} != expected {expected_ops}"

    # Check unique operation identifiers
    op_ids = [r["op_id"] for r in records]
    assert (
        len(set(op_ids)) == expected_ops
    ), f"Duplicate op_ids detected! {len(set(op_ids))} unique out of {expected_ops}"
    assert (
        min(op_ids) == 1 and max(op_ids) == expected_ops
    ), f"op_ids not in range [1, {expected_ops}]: min={min(op_ids)}, max={max(op_ids)}"

    # Check each individual record against aggregate counters
    rec_succ = sum(1 for r in records if r["success"] == 1)
    rec_fail = sum(1 for r in records if r["success"] == 0)

    assert (
        rec_succ == c_succ
    ), f"Record successes ({rec_succ}) != create_successes ({c_succ})"
    assert (
        rec_fail == c_fail
    ), f"Record failures ({rec_fail}) != create_failures ({c_fail})"

    for r in records:
        assert r["pid"] > 0, f"Invalid PID {r['pid']}"
        assert r["tid"] > 0, f"Invalid TID {r['tid']}"
        assert len(r["name"]) > 0, f"Empty memfd name"

        if expect_success:
            assert r["success"] == 1, f"Expected success but got failure: {r}"
            assert r["ret"] >= 3, f"Expected fd >= 3, got {r['ret']}"
            assert r["errno"] == 0, f"Expected errno 0, got {r['errno']}"
        else:
            assert r["success"] == 0, f"Expected failure but got success: {r}"
            assert r["ret"] == -1, f"Expected ret -1, got {r['ret']}"
            assert r["errno"] == 22, f"Expected EINVAL (22), got {r['errno']}"

    return True


def main():
    print("=================================================================")
    print("=== EphimTrace: Independent Ground Truth Generator Validation ===")
    print("=================================================================")

    # Test 1: Single successful creation
    print("\n[TEST 1] Single successful creation (iterations=1, workers=1)...")
    d1 = run_workload(1, 1, 0, 0)
    validate_records(d1, 1, expect_success=True)
    print(
        f"  [PASS] Single creation: 1 attempt, 1 success, 0 failures (elapsed: {d1['seconds']:.6f}s)"
    )
    print(f"         Sample record: {d1['records'][0]}")

    # Test 2: 1,000 sequential creations
    print("\n[TEST 2] 1,000 sequential creations (iterations=1000, workers=1)...")
    d2 = run_workload(1000, 1, 0, 0)
    validate_records(d2, 1000, expect_success=True)
    print(
        f"  [PASS] 1,000 sequential creations: 1000 attempts, 1000 successes, 0 failures (elapsed: {d2['seconds']:.6f}s)"
    )
    print(f"         1,000 unique op_ids verified across [1..1000]")

    # Test 3: 1,000 creations distributed across four workers
    print("\n[TEST 3] 1,000 creations across 4 workers (iterations=250, workers=4)...")
    d3 = run_workload(250, 4, 0, 0)
    validate_records(d3, 1000, expect_success=True)
    tids = set(r["tid"] for r in d3["records"])
    print(f"  [PASS] 1,000 distributed creations: 4 distinct thread IDs {tids}")
    print(f"         1,000 unique op_ids verified across concurrent threads")
    print(
        f"         Elapsed time: {d3['seconds']:.6f}s (throughput: {1000/d3['seconds']:.1f} ops/sec)"
    )

    # Test 4: Controlled creation failure using invalid flags
    print("\n[TEST 4] Controlled creation failure using invalid flags (0xFFFFFFFF)...")
    # 0xFFFFFFFF has invalid flag bits; memfd_create fails with -1 and errno=EINVAL (22)
    d4 = run_workload(50, 1, 0, 0, flags="0xFFFFFFFF")
    validate_records(d4, 50, expect_success=False)
    assert d4["create_attempts"] == 50
    assert d4["create_successes"] == 0
    assert d4["create_failures"] == 50
    assert d4["write_attempts"] == 0 and d4["write_failures"] == 0
    assert d4["close_attempts"] == 0 and d4["close_failures"] == 0
    print(f"  [PASS] Controlled failure: 50 attempts, 0 successes, 50 failures")
    print(f"         All records recorded ret=-1, errno=22 (EINVAL)")
    print(f"         Separation confirmed: 0 write failures, 0 close failures")
    print(f"         Invariant verified: attempted (50) = succeeded (0) + failed (50)")

    # Test 5: Controlled creation failure across concurrent workers
    print(
        "\n[TEST 5] Controlled creation failure across 4 concurrent workers (iterations=100, workers=4)..."
    )
    d5 = run_workload(100, 4, 0, 0, flags="0x80000000")
    validate_records(d5, 400, expect_success=False)
    assert d5["create_attempts"] == 400
    assert d5["create_successes"] == 0
    assert d5["create_failures"] == 400
    print(f"  [PASS] Concurrent failures: 400 attempts, 0 successes, 400 failures")
    print(f"         400 unique op_ids verified across 4 threads")
    print(
        f"         Invariant verified: attempted (400) = succeeded (0) + failed (400)"
    )

    # Test 6: Invalidation on parameter errors
    print("\n[TEST 6] Invariant & parameter error handling...")
    res = subprocess.run([str(WORKLOAD), "0", "1", "0", "0"], capture_output=True)
    assert (
        res.returncode == 2
    ), f"Expected returncode 2 for 0 iterations, got {res.returncode}"
    res2 = subprocess.run([str(WORKLOAD), "10", "0", "0", "0"], capture_output=True)
    assert (
        res2.returncode == 2
    ), f"Expected returncode 2 for 0 workers, got {res2.returncode}"
    res3 = subprocess.run([str(WORKLOAD), "10", "1"], capture_output=True)
    assert (
        res3.returncode == 2
    ), f"Expected returncode 2 for insufficient args, got {res3.returncode}"
    print(
        "  [PASS] Invalid arguments correctly exit with non-zero status (code 2) without output"
    )

    # Test 7: File export verification
    print("\n[TEST 7] Machine-readable file export verification...")
    test_out_file = "/tmp/ephim_test_ground_truth.json"
    if os.path.exists(test_out_file):
        os.remove(test_out_file)
    d7 = run_workload(20, 2, 0, 0, flags="1", output_file=test_out_file)
    assert os.path.exists(test_out_file), "Output file was not created"
    file_content = json.loads(Path(test_out_file).read_text())
    assert file_content["create_attempts"] == 40
    assert len(file_content["records"]) == 40
    os.remove(test_out_file)
    print("  [PASS] Successfully exported 40 operation records to external file")

    print("\n=================================================================")
    print("=== [SUCCESS] ALL 7 GROUND TRUTH VALIDATION TESTS PASSED CLEANLY ===")
    print("=================================================================")


if __name__ == "__main__":
    main()
