#!/usr/bin/env python3
"""
Replays and reanalyses historical test evidence under tests1.0/kernel_telemetry/results/20261124-171215/
without modifying or overwriting original evidence files.

Verifies:
- 1,090 reservation failures in full_1.
- 172 missing creation events.
- 185 missing completion events.
- 49 corrupted creation-entry events (unexpected non-zero object_token).
- 49 corresponding downstream provenance processing discrepancies.
- Systematic FD_CLOSED generation gap across all runs.
- Non-double-counting: corruption and processing discrepancies are not counted as independent lost events.
- Measurement validity: measurement_valid is True across all runs (distinguishing measurement integrity from backend loss/corruption).
"""

import json
import pathlib
import sys

# Ensure local test framework is importable
HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import runner


def replay_historical_run(results_dir: pathlib.Path = None):
    if results_dir is None:
        results_dir = HERE / "results" / "20261124-171215"

    summary_file = results_dir / "summary.json"
    if not summary_file.exists():
        raise FileNotFoundError(f"Missing summary file: {summary_file}")

    with summary_file.open("r") as f:
        summary = json.load(f)

    print(f"Replaying historical run: {results_dir.name}")
    print(f"Found {len(summary)} test cases: {[c['test']['name'] for c in summary]}\n")

    reanalysed = {}
    for case in summary:
        name = case["test"]["name"]
        d = case["measurement"]
        w = case["workload"]

        # Ensure captured events are populated from separate file if not embedded in measurement
        cap_file = results_dir / f"{name}_captured_events.json"
        if (
            "captured_events" not in d or not d["captured_events"]
        ) and cap_file.exists():
            d["captured_events"] = json.loads(cap_file.read_text())

        analysis = runner.analyse(d, w)
        reanalysed[name] = {
            "test": case["test"],
            "workload": w,
            "measurement": d,
            "analysis": analysis,
        }

        print(f"Case: {name}")
        print(f"  measurement_valid:        {analysis['measurement_valid']}")
        print(f"  telemetry_complete:       {analysis['telemetry_complete']}")
        print(f"  telemetry_fidelity_valid: {analysis['telemetry_fidelity_valid']}")
        print(f"  target_reservation_drops: {analysis['target_reservation_failures']}")
        rec = analysis["reconciliation"]
        print(f"  missing_create_count:     {rec['missing_create_count']}")
        print(f"  missing_complete_count:   {rec['missing_complete_count']}")
        print(f"  corrupted_events_count:   {rec['corrupted_events_count']}")
        print(f"  incorrect_outcome_count:  {rec['incorrect_outcome_count']}")
        print(f"  p_discrepancies_count:    {rec['p_discrepancies_count']}")
        gaps = analysis["backend_findings"]["generation_gaps"]
        print(f"  generation_gaps:          {list(gaps.keys())}")
        if "close_attempt_records" in gaps:
            print(
                f"    close_attempt_records:  expected={gaps['close_attempt_records']['expected']} observed={gaps['close_attempt_records']['observed']}"
            )
        print()

    # --- Invariant Verifications ---
    # 1. Measurement validity
    for name, c in reanalysed.items():
        assert c["analysis"][
            "measurement_valid"
        ], f"{name}: measurement should be VALID (reliable experiment)"

    # 2. full_1 specific verifications
    full_1 = reanalysed["full_1"]["analysis"]
    assert (
        full_1["target_reservation_failures"] == 1090
    ), f"full_1 reservation failures: expected 1090, got {full_1['target_reservation_failures']}"

    by_type = full_1["backend_findings"]["reservation_drops"]["by_type"]
    expected_by_type = {2: 172, 12: 185, 13: 204, 14: 181, 15: 156, 17: 192}
    assert (
        by_type == expected_by_type
    ), f"full_1 drop distribution mismatch: {by_type} != {expected_by_type}"

    rec_full = full_1["reconciliation"]
    assert (
        rec_full["missing_create_count"] == 172
    ), f"missing_create: expected 172, got {rec_full['missing_create_count']}"
    assert (
        rec_full["missing_complete_count"] == 185
    ), f"missing_complete: expected 185, got {rec_full['missing_complete_count']}"
    assert (
        rec_full["corrupted_events_count"] == 49
    ), f"corrupted_events: expected 49, got {rec_full['corrupted_events_count']}"
    assert (
        rec_full["p_discrepancies_count"] == 49
    ), f"p_discrepancies: expected 49, got {rec_full['p_discrepancies_count']}"

    # Verify corrupt token identity
    corrupt_events = full_1["backend_findings"]["corruption_findings"]
    assert len(corrupt_events) == 49
    for ce in corrupt_events:
        token = ce["event"]["token"]
        assert token == 6876268103347812964, f"Unexpected token value: {token}"
        assert hex(token) == "0x5f6d696870653a64"

    # Verify all 49 p_discrepancies are attributed to token corruption
    p_disc = full_1["backend_findings"]["processing_findings"]
    assert len(p_disc) == 49
    for pd in p_disc:
        assert pd["related_to_token_corruption"] is True
        assert pd["expected_p"] == 2  # P_STATUS_FILTERED expected for enter
        assert (
            pd["observed_p"] == 1
        )  # P_STATUS_SUCCESS occurred because corrupt token tricked provenance engine into creating node

    # Verify non-double-counting
    # Neither corrupted events nor p_discrepancies should inflate missing_events
    missing = full_1["backend_findings"]["missing_events"]
    assert (
        missing["unaccounted_create_loss"] == 0
    )  # 172 missing == 172 ringbuffer drops
    assert (
        missing["unaccounted_complete_loss"] == 0
    )  # 185 missing == 185 ringbuffer drops
    assert rec_full["incorrect_outcome_count"] == 0

    # 3. Systematic FD_CLOSED generation gap across all 4 runs
    for name, c in reanalysed.items():
        gaps = c["analysis"]["backend_findings"]["generation_gaps"]
        assert (
            "close_attempt_records" in gaps
        ), f"{name}: missing close_attempt_records gap"
        assert (
            gaps["close_attempt_records"]["observed"] == 0
        ), f"{name}: close_attempt_records should be 0"
        expected_closes = c["workload"]["closes"]
        assert gaps["close_attempt_records"]["expected"] == expected_closes
        assert expected_closes > 0

    print("ALL HISTORICAL REPLAY INVARIANTS VERIFIED SUCCESSFULLY.")
    return reanalysed


if __name__ == "__main__":
    replay_historical_run()
