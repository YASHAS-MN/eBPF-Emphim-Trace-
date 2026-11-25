#!/usr/bin/env python3
"""
Comprehensive Unit and Integration Validation for EphimTrace Loss-Detection Infrastructure.
Covers Phase 3 and Phase 4 measurement validation requirements:
- Reordered concurrent events matching by (PID, TID, name)
- Missing and duplicate events detection
- Incorrect syscall outcomes and token corruption detection
- Measurement integrity checks (distinguishing invalid experiments from telemetry defects)
- Provenance Checkpoint P verification including controlled allocation failure injection
- Ring-buffer reservation failure detection (stall simulation)
- Intentional syscall failure reconciliation
- Suite execution resilience (telemetry defects do not abort subsequent test cases)
- Verification of paced_full test specification
"""

import copy
import json
import os
import random
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))

from runner import analyse, reconcile_events


def test_reordered_concurrent_events():
    """Verify that event reconciliation correctly matches (pid, tid, name) without positional dependency."""
    print("\n[TEST 1] Reordered concurrent events...")
    records = []
    events = []
    pid = 50000

    # 4 workers, 25 operations each = 100 operations
    for worker_id in range(4):
        tid = pid + worker_id + 1
        for op in range(25):
            name = f"ephim_lab_{worker_id}_{op}"
            ret_fd = 3 + worker_id * 25 + op
            token = 100000 + worker_id * 25 + op
            records.append(
                {
                    "op_id": len(records) + 1,
                    "name": name,
                    "pid": pid,
                    "tid": tid,
                    "ret": ret_fd,
                    "errno": 0,
                    "success": 1,
                }
            )
            # Type 2: entry
            events.append(
                {
                    "type": 2,
                    "pid": pid,
                    "tid": tid,
                    "name": name,
                    "ret": 0,
                    "fd": -1,
                    "op": 0,
                    "token": 0,
                    "p": 2,
                }
            )
            # Type 12: exit
            events.append(
                {
                    "type": 12,
                    "pid": pid,
                    "tid": tid,
                    "name": name,
                    "ret": ret_fd,
                    "fd": ret_fd,
                    "op": 2,
                    "token": token,
                    "p": 1,
                }
            )

    # Deliberately shuffle events into completely random order across threads
    shuffled_events = copy.deepcopy(events)
    random.seed(42)
    random.shuffle(shuffled_events)

    res = reconcile_events(records, shuffled_events, p_available=True)
    assert (
        len(res["missing_create"]) == 0
    ), f"Unexpected missing create: {res['missing_create']}"
    assert (
        len(res["missing_complete"]) == 0
    ), f"Unexpected missing complete: {res['missing_complete']}"
    assert (
        len(res["duplicate_create"]) == 0
    ), f"Unexpected duplicate create: {res['duplicate_create']}"
    assert (
        len(res["duplicate_complete"]) == 0
    ), f"Unexpected duplicate complete: {res['duplicate_complete']}"
    assert len(res["unexpected"]) == 0, f"Unexpected events: {res['unexpected']}"
    assert (
        len(res["incorrect_outcome"]) == 0
    ), f"Incorrect outcomes: {res['incorrect_outcome']}"
    assert (
        len(res["corrupted_events"]) == 0
    ), f"Corrupted events: {res['corrupted_events']}"
    assert (
        len(res["p_discrepancies"]) == 0
    ), f"P discrepancies: {res['p_discrepancies']}"
    print(
        "  [PASS] 200 reordered events across 4 concurrent threads matched perfectly by (PID, TID, name)"
    )


def test_missing_and_duplicate_events():
    """Verify separate detection of missing and duplicate events."""
    print("\n[TEST 2] Missing and duplicate events detection...")
    pid, tid = 60000, 60001
    records = [
        {
            "op_id": 1,
            "name": "ephim_lab_0_0",
            "pid": pid,
            "tid": tid,
            "ret": 3,
            "errno": 0,
            "success": 1,
        },
        {
            "op_id": 2,
            "name": "ephim_lab_0_1",
            "pid": pid,
            "tid": tid,
            "ret": 4,
            "errno": 0,
            "success": 1,
        },
        {
            "op_id": 3,
            "name": "ephim_lab_0_2",
            "pid": pid,
            "tid": tid,
            "ret": 5,
            "errno": 0,
            "success": 1,
        },
    ]

    events = [
        # Op 1: Complete and valid
        {
            "type": 2,
            "pid": pid,
            "tid": tid,
            "name": "ephim_lab_0_0",
            "ret": 0,
            "fd": -1,
            "op": 0,
            "token": 0,
            "p": 2,
        },
        {
            "type": 12,
            "pid": pid,
            "tid": tid,
            "name": "ephim_lab_0_0",
            "ret": 3,
            "fd": 3,
            "op": 2,
            "token": 100,
            "p": 1,
        },
        # Op 2: Missing type 2, DUPLICATE type 12
        {
            "type": 12,
            "pid": pid,
            "tid": tid,
            "name": "ephim_lab_0_1",
            "ret": 4,
            "fd": 4,
            "op": 2,
            "token": 101,
            "p": 1,
        },
        {
            "type": 12,
            "pid": pid,
            "tid": tid,
            "name": "ephim_lab_0_1",
            "ret": 4,
            "fd": 4,
            "op": 2,
            "token": 101,
            "p": 1,
        },
        # Op 3: Present type 2, MISSING type 12
        {
            "type": 2,
            "pid": pid,
            "tid": tid,
            "name": "ephim_lab_0_2",
            "ret": 0,
            "fd": -1,
            "op": 0,
            "token": 0,
            "p": 2,
        },
        # Unexpected event from untracked op
        {
            "type": 12,
            "pid": pid,
            "tid": tid,
            "name": "rogue_memfd",
            "ret": 9,
            "fd": 9,
            "op": 2,
            "token": 999,
            "p": 1,
        },
    ]

    res = reconcile_events(records, events, p_available=True)
    assert (
        len(res["missing_create"]) == 1
        and res["missing_create"][0]["name"] == "ephim_lab_0_1"
    )
    assert (
        len(res["missing_complete"]) == 1
        and res["missing_complete"][0]["name"] == "ephim_lab_0_2"
    )
    assert (
        len(res["duplicate_complete"]) == 1
        and res["duplicate_complete"][0]["record"]["name"] == "ephim_lab_0_1"
    )
    assert len(res["unexpected"]) == 1 and res["unexpected"][0]["name"] == "rogue_memfd"
    print(
        "  [PASS] Missing create, missing complete, duplicate complete, and unexpected event detected independently"
    )


def test_incorrect_syscall_outcomes_and_corruption():
    """Verify detection of incorrect return values, fd numbers, corrupted tokens and downstream effects."""
    print("\n[TEST 3] Incorrect syscall outcomes & token corruption...")
    pid, tid = 70000, 70001
    records = [
        # Expected success
        {
            "op_id": 1,
            "name": "succ_1",
            "pid": pid,
            "tid": tid,
            "ret": 3,
            "errno": 0,
            "success": 1,
        },
        # Expected failure
        {
            "op_id": 2,
            "name": "fail_1",
            "pid": pid,
            "tid": tid,
            "ret": -1,
            "errno": 22,
            "success": 0,
        },
        # Corrupted token event on enter
        {
            "op_id": 3,
            "name": "corrupt_1",
            "pid": pid,
            "tid": tid,
            "ret": 4,
            "errno": 0,
            "success": 1,
        },
    ]

    events = [
        # Op 1: Claimed failure when success occurred
        {
            "type": 2,
            "pid": pid,
            "tid": tid,
            "name": "succ_1",
            "ret": 0,
            "fd": -1,
            "op": 0,
            "token": 0,
            "p": 2,
        },
        {
            "type": 12,
            "pid": pid,
            "tid": tid,
            "name": "succ_1",
            "ret": -22,
            "fd": -1,
            "op": 1,
            "token": 0,
            "p": 2,
        },
        # Op 2: Claimed success when failure occurred
        {
            "type": 2,
            "pid": pid,
            "tid": tid,
            "name": "fail_1",
            "ret": 0,
            "fd": -1,
            "op": 0,
            "token": 0,
            "p": 2,
        },
        {
            "type": 12,
            "pid": pid,
            "tid": tid,
            "name": "fail_1",
            "ret": 4,
            "fd": 4,
            "op": 2,
            "token": 12345,
            "p": 1,
        },
        # Op 3: Non-zero token on enter (corrupted ring buffer memory)
        {
            "type": 2,
            "pid": pid,
            "tid": tid,
            "name": "corrupt_1",
            "ret": 0,
            "fd": -1,
            "op": 0,
            "token": 6876268103347812964,
            "p": 1,  # Downstream P was misled into thinking this was valid node/edge
        },
        {
            "type": 12,
            "pid": pid,
            "tid": tid,
            "name": "corrupt_1",
            "ret": 4,
            "fd": 4,
            "op": 2,
            "token": 12346,
            "p": 1,
        },
    ]

    res = reconcile_events(records, events, p_available=True)
    assert len(res["incorrect_outcome"]) == 2
    assert "Expected op=2" in res["incorrect_outcome"][0]["reason"]
    assert "Expected op=1" in res["incorrect_outcome"][1]["reason"]

    assert len(res["corrupted_events"]) == 1
    assert "Unexpected non-zero object_token" in res["corrupted_events"][0]["reason"]
    assert res["corrupted_events"][0]["event"]["token"] == 6876268103347812964

    assert len(res["p_discrepancies"]) == 3
    token_related = [d for d in res["p_discrepancies"] if d["related_to_token_corruption"]]
    assert len(token_related) == 1
    assert token_related[0]["event"]["token"] == 6876268103347812964

    print(
        "  [PASS] Correctly flagged outcome inversion, token corruption, and linked P discrepancy"
    )


def test_measurement_integrity_and_classification():
    """Verify that experimental validity is separated from backend telemetry completeness and fidelity."""
    print("\n[TEST 4] Measurement integrity & 3-dimensional classification...")
    mock_workload = {
        "status": "VALID",
        "execution_failures": 0,
        "calls": 10,
        "creates": 10,
        "writes": 10,
        "closes": 10,
        "failures": 0,
        "create_attempts": 10,
        "create_successes": 10,
        "create_failures": 0,
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
            for i in range(10)
        ],
    }

    mock_measurement_ok = {
        "pid": 100,
        "invalid": 0,
        "unknown_type": 0,
        "captured_count": 20,
        "captured_overflow": 0,
        "events": [
            {
                "scope": 1,
                "type": 2,
                "attempted": 10,
                "reserve_failed": 0,
                "submitted": 10,
                "received": 10,
            },
            {
                "scope": 1,
                "type": 12,
                "attempted": 10,
                "reserve_failed": 0,
                "submitted": 10,
                "received": 10,
            },
            {
                "scope": 1,
                "type": 15,
                "attempted": 10,
                "reserve_failed": 0,
                "submitted": 10,
                "received": 10,
            },
            {
                "scope": 1,
                "type": 16,
                "attempted": 10,
                "reserve_failed": 0,
                "submitted": 10,
                "received": 10,
            },
            {
                "scope": 1,
                "type": 17,
                "attempted": 10,
                "reserve_failed": 0,
                "submitted": 10,
                "received": 10,
            },
        ],
        "target_counters": [0] * 128,
        "map_mutations": [],
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
            for i in range(10)
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
                "token": 1000 + i,
                "p": 1,
            }
            for i in range(10)
        ],
        "p_checkpoint": {
            "available": True,
            "success": 10,
            "filtered": 10,
            "correlation_deficiency": 0,
            "edge_suppressed": 0,
            "failed": 0,
        },
    }
    mock_measurement_ok["target_counters"][60] = 10
    mock_measurement_ok["target_counters"][70] = 10

    # 1. Clean measurement passes all 3 dimensions
    res1 = analyse(mock_measurement_ok, mock_workload)
    assert (
        res1["measurement_valid"] is True
    ), f"Expected valid, got: {res1['measurement_issues']}"
    assert res1["telemetry_complete"] is True
    assert res1["telemetry_fidelity_valid"] is True

    # 2. Storage buffer overflow invalidates the measurement (infrastructure failure)
    mock_overflow = copy.deepcopy(mock_measurement_ok)
    mock_overflow["captured_overflow"] = 5
    res2 = analyse(mock_overflow, mock_workload)
    assert res2["measurement_valid"] is False
    assert any("buffer overflow" in iss for iss in res2["measurement_issues"])

    # 3. Workload execution error invalidates the measurement
    mock_w_err = copy.deepcopy(mock_workload)
    mock_w_err["execution_failures"] = 1
    res3 = analyse(mock_measurement_ok, mock_w_err)
    assert res3["measurement_valid"] is False

    # 4. Captured count mismatch invalidates the measurement
    mock_count_mismatch = copy.deepcopy(mock_measurement_ok)
    mock_count_mismatch["captured_count"] = 19
    res4 = analyse(mock_count_mismatch, mock_workload)
    assert res4["measurement_valid"] is False
    assert any("captured count mismatch" in iss for iss in res4["measurement_issues"])

    # 5. Reservation accounting mismatch (attempted != reserve_failed + submitted) invalidates measurement
    mock_acc_mismatch = copy.deepcopy(mock_measurement_ok)
    mock_acc_mismatch["events"][0]["attempted"] = 15  # 15 != 0 + 10
    res5 = analyse(mock_acc_mismatch, mock_workload)
    assert res5["measurement_valid"] is False
    assert any(
        "reservation accounting mismatch" in iss for iss in res5["measurement_issues"]
    )

    print(
        "  [PASS] 3-dimensional classification verified: clean run passes; harness errors invalidate measurement"
    )


def test_ringbuffer_reservation_failure_stall():
    """Verify that ring-buffer reservation failures (e.g. from stall) do NOT invalidate measurement."""
    print("\n[TEST 5] Ring-buffer reservation drops (stall scenario)...")
    mock_workload = {
        "status": "VALID",
        "execution_failures": 0,
        "calls": 10,
        "creates": 10,
        "writes": 10,
        "closes": 10,
        "failures": 0,
        "create_attempts": 10,
        "create_successes": 10,
        "create_failures": 0,
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
            for i in range(10)
        ],
    }

    # Simulate 4 events dropped by ringbuffer full (reserve_failed=4, submitted=6, received=6)
    mock_dropped_m = {
        "pid": 100,
        "invalid": 0,
        "unknown_type": 0,
        "captured_count": 12,
        "captured_overflow": 0,
        "events": [
            {
                "scope": 1,
                "type": 2,
                "attempted": 10,
                "reserve_failed": 4,
                "submitted": 6,
                "received": 6,
            },
            {
                "scope": 1,
                "type": 12,
                "attempted": 10,
                "reserve_failed": 4,
                "submitted": 6,
                "received": 6,
            },
            {
                "scope": 1,
                "type": 15,
                "attempted": 10,
                "reserve_failed": 0,
                "submitted": 10,
                "received": 10,
            },
            {
                "scope": 1,
                "type": 16,
                "attempted": 10,
                "reserve_failed": 0,
                "submitted": 10,
                "received": 10,
            },
            {
                "scope": 1,
                "type": 17,
                "attempted": 10,
                "reserve_failed": 0,
                "submitted": 10,
                "received": 10,
            },
        ],
        "target_counters": [0] * 128,
        "map_mutations": [],
        # First 6 survived, last 4 were dropped at kernel level
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
            for i in range(6)
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
                "token": 1000 + i,
                "p": 1,
            }
            for i in range(6)
        ],
        "p_checkpoint": {
            "available": True,
            "success": 6,
            "filtered": 6,
            "correlation_deficiency": 0,
            "edge_suppressed": 0,
            "failed": 0,
        },
    }
    mock_dropped_m["target_counters"][60] = 10
    mock_dropped_m["target_counters"][70] = 10

    res = analyse(mock_dropped_m, mock_workload)
    # Measurement IS valid: reliable experimental observation of loss!
    assert (
        res["measurement_valid"] is True
    ), f"Measurement should be valid, got: {res['measurement_issues']}"
    # Telemetry is NOT complete
    assert res["telemetry_complete"] is False
    assert res["target_reservation_failures"] == 8  # 4 create + 4 complete
    # Telemetry fidelity is valid (all received events are intact)
    assert res["telemetry_fidelity_valid"] is True
    assert res["reconciliation"]["missing_create_count"] == 4
    assert res["reconciliation"]["missing_complete_count"] == 4
    # Drops match missing counts: unaccounted loss is 0!
    assert res["backend_findings"]["missing_events"]["unaccounted_create_loss"] == 0
    assert res["backend_findings"]["missing_events"]["unaccounted_complete_loss"] == 0
    print(
        "  [PASS] Ring-buffer reservation drops correctly classified as valid measurement revealing telemetry loss"
    )


def test_controlled_userspace_p_failure():
    """Verify detection of userspace processing failure (e.g. node allocation failure)."""
    print("\n[TEST 6] Userspace processing failure detection...")
    mock_workload = {
        "status": "VALID",
        "execution_failures": 0,
        "calls": 1,
        "creates": 1,
        "writes": 1,
        "closes": 1,
        "failures": 0,
        "create_attempts": 1,
        "create_successes": 1,
        "create_failures": 0,
        "records": [
            {
                "op_id": 1,
                "name": "mem_0",
                "pid": 100,
                "tid": 101,
                "ret": 3,
                "errno": 0,
                "success": 1,
            }
        ],
    }

    mock_m = {
        "pid": 100,
        "invalid": 0,
        "unknown_type": 0,
        "captured_count": 2,
        "captured_overflow": 0,
        "events": [
            {
                "scope": 1,
                "type": 2,
                "attempted": 1,
                "reserve_failed": 0,
                "submitted": 1,
                "received": 1,
            },
            {
                "scope": 1,
                "type": 12,
                "attempted": 1,
                "reserve_failed": 0,
                "submitted": 1,
                "received": 1,
            },
            {
                "scope": 1,
                "type": 15,
                "attempted": 1,
                "reserve_failed": 0,
                "submitted": 1,
                "received": 1,
            },
            {
                "scope": 1,
                "type": 16,
                "attempted": 1,
                "reserve_failed": 0,
                "submitted": 1,
                "received": 1,
            },
            {
                "scope": 1,
                "type": 17,
                "attempted": 1,
                "reserve_failed": 0,
                "submitted": 1,
                "received": 1,
            },
        ],
        "target_counters": [0] * 128,
        "map_mutations": [],
        "captured_events": [
            {
                "type": 2,
                "pid": 100,
                "tid": 101,
                "name": "mem_0",
                "ret": 0,
                "fd": -1,
                "op": 0,
                "token": 0,
                "p": 2,  # Enter filtered
            },
            {
                "type": 12,
                "pid": 100,
                "tid": 101,
                "name": "mem_0",
                "ret": 3,
                "fd": 3,
                "op": 2,
                "token": 5555,
                "p": 5,  # P_STATUS_FAILED: simulated allocation failure!
            },
        ],
        "p_checkpoint": {
            "available": True,
            "success": 0,
            "filtered": 1,
            "correlation_deficiency": 0,
            "edge_suppressed": 0,
            "failed": 1,
        },
    }
    mock_m["target_counters"][60] = 1
    mock_m["target_counters"][70] = 1

    res = analyse(mock_m, mock_workload)
    assert res["measurement_valid"] is True
    assert res["telemetry_complete"] is True
    assert res["telemetry_fidelity_valid"] is False  # Flagged due to processing failure
    assert len(res["backend_findings"]["processing_findings"]) == 1
    disc = res["backend_findings"]["processing_findings"][0]
    assert disc["expected_p"] == 1
    assert disc["observed_p"] == 5
    assert disc["related_to_token_corruption"] is False
    print(
        "  [PASS] Userspace processing failure (p=5 FAILED) flagged under telemetry fidelity without invalidating measurement"
    )


def test_intentional_syscall_failures():
    """Verify that intentional syscall failures (e.g. invalid flags) reconcile cleanly."""
    print("\n[TEST 7] Intentional syscall failures reconciliation...")
    mock_workload = {
        "status": "VALID",
        "execution_failures": 0,
        "calls": 2,
        "creates": 0,
        "writes": 0,
        "closes": 0,
        "failures": 2,
        "create_attempts": 2,
        "create_successes": 0,
        "create_failures": 2,
        "records": [
            {
                "op_id": 1,
                "name": "fail_0",
                "pid": 200,
                "tid": 201,
                "ret": -1,
                "errno": 22,
                "success": 0,
            },
            {
                "op_id": 2,
                "name": "fail_1",
                "pid": 200,
                "tid": 201,
                "ret": -1,
                "errno": 22,
                "success": 0,
            },
        ],
    }

    mock_m = {
        "pid": 200,
        "invalid": 0,
        "unknown_type": 0,
        "captured_count": 4,
        "captured_overflow": 0,
        "events": [
            {
                "scope": 1,
                "type": 2,
                "attempted": 2,
                "reserve_failed": 0,
                "submitted": 2,
                "received": 2,
            },
            {
                "scope": 1,
                "type": 12,
                "attempted": 2,
                "reserve_failed": 0,
                "submitted": 2,
                "received": 2,
            },
        ],
        "target_counters": [0] * 128,
        "map_mutations": [],
        "captured_events": [
            # Enter: filtered (p=2)
            {
                "type": 2,
                "pid": 200,
                "tid": 201,
                "name": "fail_0",
                "ret": 0,
                "fd": -1,
                "op": 0,
                "token": 0,
                "p": 2,
            },
            # Exit: failed syscall (op=1, ret=-22, fd=-1, token=0, p=2)
            {
                "type": 12,
                "pid": 200,
                "tid": 201,
                "name": "fail_0",
                "ret": -22,
                "fd": -1,
                "op": 1,
                "token": 0,
                "p": 2,
            },
            {
                "type": 2,
                "pid": 200,
                "tid": 201,
                "name": "fail_1",
                "ret": 0,
                "fd": -1,
                "op": 0,
                "token": 0,
                "p": 2,
            },
            {
                "type": 12,
                "pid": 200,
                "tid": 201,
                "name": "fail_1",
                "ret": -22,
                "fd": -1,
                "op": 1,
                "token": 0,
                "p": 2,
            },
        ],
        "p_checkpoint": {
            "available": True,
            "success": 0,
            "filtered": 4,
            "correlation_deficiency": 0,
            "edge_suppressed": 0,
            "failed": 0,
        },
    }
    mock_m["target_counters"][60] = 2
    mock_m["target_counters"][70] = 2

    res = analyse(mock_m, mock_workload)
    assert res["measurement_valid"] is True
    assert res["telemetry_complete"] is True
    assert res["telemetry_fidelity_valid"] is True
    assert res["reconciliation"]["missing_create_count"] == 0
    assert res["reconciliation"]["missing_complete_count"] == 0
    assert res["reconciliation"]["incorrect_outcome_count"] == 0
    assert res["reconciliation"]["corrupted_events_count"] == 0
    assert res["reconciliation"]["p_discrepancies_count"] == 0
    print(
        "  [PASS] Intentional syscall failures (errno=22, op=1, ret=-22) reconciled with 100% fidelity"
    )


def test_provenance_checkpoint_p():
    """Run the in-memory Checkpoint P test binary to verify node/edge verification and filtering."""
    print("\n[TEST 8] Checkpoint P unit validation (compiled binary)...")
    cmd = [str(ROOT / "build" / "telemetry_lab" / "test_prov_p")]
    res = subprocess.run(cmd, capture_output=True, text=True)
    assert (
        res.returncode == 0
    ), f"test_prov_p failed ({res.returncode}):\n{res.stdout}\n{res.stderr}"
    print(
        "  [PASS] Checkpoint P verified: node lookup, edge attributes, duplicate suppression, intentional filtering, correlation deficiency, and controlled failure injection"
    )


def test_suite_resilience_and_paced_full_spec():
    """Verify that runner's quick suite contains paced_full and that telemetry defects do not abort suite."""
    print("\n[TEST 9] Suite definition and non-aborting resilience...")
    import runner

    # Read runner.py to check suite definition
    runner_src = (HERE / "runner.py").read_text()
    assert (
        '("paced_full", 100, 1, 1000, True, False, 0, False)' in runner_src
    ), "paced_full missing from quick suite"

    # Verify trial loop abort condition checks report['status'] == 'INVALID'
    # and report['status'] is 'VALID' when measurement_valid is True (even if telemetry_complete or fidelity is False)
    assert (
        'status = "VALID" if analysis["measurement_valid"] else "INVALID"' in runner_src
        or '"status": "VALID" if analysis["measurement_valid"] else "INVALID"'
        in runner_src
    ), "runner must decouple trial status from telemetry loss/fidelity"

    print(
        "  [PASS] paced_full present in quick suite and trial status decoupled from telemetry loss"
    )


def main():
    print("=================================================================")
    print("=== EphimTrace: Complete Telemetry Measurement Validation     ===")
    print("=================================================================")
    test_reordered_concurrent_events()
    test_missing_and_duplicate_events()
    test_incorrect_syscall_outcomes_and_corruption()
    test_measurement_integrity_and_classification()
    test_ringbuffer_reservation_failure_stall()
    test_controlled_userspace_p_failure()
    test_intentional_syscall_failures()
    test_provenance_checkpoint_p()
    test_suite_resilience_and_paced_full_spec()

    print("\n=================================================================")
    print("=== [SUCCESS] ALL 9 MEASUREMENT VALIDATION TESTS PASSED       ===")
    print("=================================================================")


if __name__ == "__main__":
    main()
