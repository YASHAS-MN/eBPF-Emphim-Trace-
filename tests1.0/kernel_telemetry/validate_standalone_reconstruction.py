#!/usr/bin/env python3
"""validate_standalone_reconstruction.py — Standalone Provenance Reconstruction Validation

Validates Issue #7 standalone provenance reconstruction from saved binary evidence:
Evidence: tests1.0/kernel_telemetry/results/persist_20261126-012121/model_p/W_SUSTAIN_1.evid
Ground Truth: tests1.0/kernel_telemetry/results/persist_20261126-012121/model_p/W_SUSTAIN_1_ground_truth.json

Validation criteria:
1. Evidence reader integrity & complete replay (zero corrupt records, sequence gaps, truncation).
2. Number of records processed (matches 420,074 verified records).
3. Provenance node and edge counts.
4. Graph export success and semantic correctness against 60,000 ground truth syscall operations.
5. Reconstruction duration and peak memory (RSS).
6. Repeatability across independent runs from identical immutable evidence.
"""

import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent


def parse_time_output(stderr_text: str):
    """Parses /usr/bin/time -v output from stderr."""
    metrics = {
        "max_rss_kb": None,
        "max_rss_mib": None,
        "wall_time_sec": None,
        "user_time_sec": None,
        "sys_time_sec": None,
        "cpu_percent": None,
    }
    for line in stderr_text.splitlines():
        line = line.strip()
        if "Maximum resident set size (kbytes):" in line:
            val = int(line.split(":")[-1].strip())
            metrics["max_rss_kb"] = val
            metrics["max_rss_mib"] = round(val / 1024.0, 2)
        elif "User time (seconds):" in line:
            metrics["user_time_sec"] = float(line.split(":")[-1].strip())
        elif "System time (seconds):" in line:
            metrics["sys_time_sec"] = float(line.split(":")[-1].strip())
        elif "Percent of CPU this job got:" in line:
            metrics["cpu_percent"] = line.split(":")[-1].strip()
        elif "Elapsed (wall clock) time" in line:
            raw = line.split("):")[-1].strip()
            parts = raw.split(":")
            if len(parts) == 2:
                metrics["wall_time_sec"] = float(parts[0]) * 60.0 + float(parts[1])
            elif len(parts) == 3:
                metrics["wall_time_sec"] = (
                    float(parts[0]) * 3600.0 + float(parts[1]) * 60.0 + float(parts[2])
                )
    return metrics


def execute_replay_run(
    replay_bin: pathlib.Path, evid_path: pathlib.Path, dot_out: pathlib.Path
):
    """Executes replay_provenance with /usr/bin/time -v and captures outputs."""
    time_bin = "/usr/bin/time"
    cmd = [time_bin, "-v", str(replay_bin), str(evid_path), str(dot_out)]

    t0 = time.monotonic()
    proc = subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    t1 = time.monotonic()

    stdout = proc.stdout.strip()
    stderr = proc.stderr.strip()

    # Parse JSON output from replay_provenance
    replay_json = None
    for line in stdout.splitlines():
        if line.startswith("{") and line.endswith("}"):
            try:
                replay_json = json.loads(line)
                break
            except json.JSONDecodeError:
                pass

    time_metrics = parse_time_output(stderr)
    time_metrics["python_wall_time_sec"] = round(t1 - t0, 4)

    dot_size = dot_out.stat().st_size if dot_out.exists() else 0
    dot_sha256 = (
        hashlib.sha256(dot_out.read_bytes()).hexdigest() if dot_out.exists() else None
    )

    return {
        "exit_code": proc.returncode,
        "replay_json": replay_json,
        "time_metrics": time_metrics,
        "dot_file": str(dot_out),
        "dot_size_bytes": dot_size,
        "dot_sha256": dot_sha256,
        "stdout": stdout,
        "stderr": stderr,
    }


def analyze_dot_semantic_correctness(dot_path: pathlib.Path, gt_path: pathlib.Path):
    """Validates semantic correctness of exported DOT graph against ground truth."""
    if not dot_path.exists():
        return {"valid": False, "error": f"DOT file does not exist: {dot_path}"}
    if not gt_path.exists():
        return {"valid": False, "error": f"Ground truth file does not exist: {gt_path}"}

    with open(gt_path, "r") as f:
        gt_data = json.load(f)
    gt_records = gt_data.get("records", [])
    expected_names = {r["name"] for r in gt_records}
    expected_pids = {r["pid"] for r in gt_records}

    memfd_nodes = 0
    process_nodes = 0
    other_nodes = 0
    total_edges = 0
    found_names = set()
    found_pids = set()

    with open(dot_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line.startswith('"') or not line.endswith("];"):
                continue
            if "->" in line:
                total_edges += 1
            else:
                node_id = line[1 : line.find('"', 1)]
                if node_id.startswith("memfd_"):
                    memfd_nodes += 1
                    idx = line.find("Name: ")
                    if idx != -1:
                        name_part = line[idx + 6 :]
                        name = name_part.split("\\n")[0].split('"')[0].strip()
                        found_names.add(name)
                elif node_id.startswith("proc_"):
                    process_nodes += 1
                    idx = line.find("PID: ")
                    if idx != -1:
                        pid_part = line[idx + 5 :]
                        pid_str = pid_part.split(" ")[0].split("\\n")[0].strip()
                        try:
                            found_pids.add(int(pid_str))
                        except ValueError:
                            pass
                else:
                    other_nodes += 1

    total_nodes = memfd_nodes + process_nodes + other_nodes
    matched_names = expected_names.intersection(found_names)
    missing_names = expected_names - found_names
    matched_pids = expected_pids.intersection(found_pids)

    return {
        "valid": len(missing_names) == 0 and len(matched_pids) > 0,
        "dot_total_nodes": total_nodes,
        "dot_memfd_nodes": memfd_nodes,
        "dot_process_nodes": process_nodes,
        "dot_other_nodes": other_nodes,
        "dot_total_edges": total_edges,
        "ground_truth_total_ops": len(gt_records),
        "ground_truth_unique_names": len(expected_names),
        "reconstructed_matched_names": len(matched_names),
        "reconstructed_missing_names": len(missing_names),
        "matched_target_pids": list(matched_pids),
        "completeness_ratio": (
            len(matched_names) / len(expected_names) if expected_names else 0.0
        ),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Standalone Provenance Reconstruction Validation"
    )
    parser.add_argument(
        "--evid",
        type=pathlib.Path,
        default=ROOT
        / "tests1.0"
        / "kernel_telemetry"
        / "results"
        / "persist_20261126-012121"
        / "model_p"
        / "W_SUSTAIN_1.evid",
        help="Path to binary evidence file",
    )
    parser.add_argument(
        "--gt",
        type=pathlib.Path,
        default=ROOT
        / "tests1.0"
        / "kernel_telemetry"
        / "results"
        / "persist_20261126-012121"
        / "model_p"
        / "W_SUSTAIN_1_ground_truth.json",
        help="Path to ground truth JSON file",
    )
    parser.add_argument(
        "--outdir",
        type=pathlib.Path,
        default=ROOT / "tests1.0" / "kernel_telemetry" / "standalone_reconstruction",
        help="Fresh output directory for graph exports and reports",
    )
    parser.add_argument(
        "--expected-records",
        type=int,
        default=420074,
        help="Expected record count in evidence file",
    )
    args = parser.parse_args()

    evid_path = args.evid.resolve()
    gt_path = args.gt.resolve()
    out_dir = args.outdir.resolve()
    expected_recs = args.expected_records

    print(
        "===================================================================================================="
    )
    print(
        "           Issue #7 — Standalone Provenance Reconstruction Validation Suite                         "
    )
    print(
        "===================================================================================================="
    )
    print(f"Target Evidence File: {evid_path}")
    print(f"Ground Truth File:    {gt_path}")
    print(f"Fresh Output Dir:     {out_dir}\n")

    # Verify input file existence and accessibility
    if not evid_path.exists():
        sys.exit(f"[FATAL] Evidence file does not exist: {evid_path}")
    if not os.access(evid_path, os.R_OK):
        print(
            f"[ERROR] Evidence file is not readable by current UID {os.getuid()} (mode 0600 root-owned)."
        )
        print(
            "\nElevated privileges are required to access this file without weakening file permissions."
        )
        print("Please execute the following command:")
        print(
            f"\n  sudo python3 tests1.0/kernel_telemetry/validate_standalone_reconstruction.py\n"
        )
        sys.exit(1)

    # Check replay_provenance binary
    replay_bin = ROOT / "build" / "telemetry_lab" / "replay_provenance"
    if not replay_bin.exists():
        sys.exit(f"[FATAL] replay_provenance binary not found at: {replay_bin}")

    out_dir.mkdir(parents=True, exist_ok=True)
    dot1 = out_dir / "W_SUSTAIN_1_run1.dot"
    dot2 = out_dir / "W_SUSTAIN_1_run2.dot"

    # --- RUN 1 ---
    print("[1/3] Executing Run 1 (reconstruction and graph export)...")
    res1 = execute_replay_run(replay_bin, evid_path, dot1)
    if res1["exit_code"] != 0 or not res1["replay_json"]:
        print(f"[FAIL] Run 1 failed with exit code {res1['exit_code']}")
        print(f"Stdout: {res1['stdout']}")
        print(f"Stderr: {res1['stderr']}")
        sys.exit(1)
    print(
        f"  -> Run 1 completed successfully in {res1['time_metrics']['wall_time_sec']}s (peak RSS: {res1['time_metrics']['max_rss_mib']} MiB)"
    )
    print(
        f"  -> Records verified/replayed: {res1['replay_json']['records_verified']}/{res1['replay_json']['records_replayed']}"
    )
    print(
        f"  -> Graph elements: {res1['replay_json']['nodes']} nodes, {res1['replay_json']['edges']} edges"
    )
    print(
        f"  -> Exported DOT file: {dot1} ({res1['dot_size_bytes']:,} bytes, SHA256: {res1['dot_sha256'][:16]}...)"
    )

    # --- RUN 2 (REPEATABILITY) ---
    print(
        "\n[2/3] Executing Run 2 (repeatability verification from same immutable evidence)..."
    )
    res2 = execute_replay_run(replay_bin, evid_path, dot2)
    if res2["exit_code"] != 0 or not res2["replay_json"]:
        print(f"[FAIL] Run 2 failed with exit code {res2['exit_code']}")
        sys.exit(1)
    print(
        f"  -> Run 2 completed successfully in {res2['time_metrics']['wall_time_sec']}s (peak RSS: {res2['time_metrics']['max_rss_mib']} MiB)"
    )
    print(
        f"  -> Exported DOT file: {dot2} ({res2['dot_size_bytes']:,} bytes, SHA256: {res2['dot_sha256'][:16]}...)"
    )

    # Repeatability check
    repeatable = (res1["dot_sha256"] == res2["dot_sha256"]) and (
        res1["dot_size_bytes"] == res2["dot_size_bytes"]
    )
    print(
        f"  -> Deterministic Repeatability Check: {'PASSED (Bit-for-bit identical)' if repeatable else 'FAILED'}"
    )

    # --- SEMANTIC GROUND TRUTH RECONCILIATION ---
    print(
        "\n[3/3] Validating graph semantic correctness against syscall ground truth..."
    )
    semantic_res = analyze_dot_semantic_correctness(dot1, gt_path)
    print(
        f"  -> Ground truth attempted ops:        {semantic_res.get('ground_truth_total_ops', 0):,}"
    )
    print(
        f"  -> Ground truth unique memfd names:   {semantic_res.get('ground_truth_unique_names', 0):,}"
    )
    print(
        f"  -> Reconstructed memfd nodes in DOT:  {semantic_res.get('dot_memfd_nodes', 0):,}"
    )
    print(
        f"  -> Reconstructed matched memfd names: {semantic_res.get('reconstructed_matched_names', 0):,}"
    )
    print(
        f"  -> Missing ground truth memfd names:  {semantic_res.get('reconstructed_missing_names', 0)}"
    )
    print(
        f"  -> Semantic Completeness:             {semantic_res.get('completeness_ratio', 0.0)*100:.2f}%"
    )
    print(
        f"  -> Target Process PID matched:        {semantic_res.get('matched_target_pids')}"
    )

    # Integrity verification
    r1_json = res1["replay_json"]
    corrupt = r1_json.get("corrupt_records", 0)
    gaps = r1_json.get("seq_gaps", 0)
    incomplete = r1_json.get("incomplete_records", 0)
    reader_integrity = corrupt == 0 and gaps == 0 and incomplete == 0

    # Summary object
    validation_summary = {
        "evidence_file": str(evid_path),
        "ground_truth_file": str(gt_path),
        "output_directory": str(out_dir),
        "reader_integrity": {
            "valid": reader_integrity,
            "corrupt_records": corrupt,
            "seq_gaps": gaps,
            "incomplete_records": incomplete,
        },
        "records_processed": {
            "records_verified": r1_json.get("records_verified"),
            "records_replayed": r1_json.get("records_replayed"),
            "expected_records": expected_recs,
            "match_expected": (r1_json.get("records_verified") == expected_recs),
        },
        "provenance_counts": {
            "nodes": r1_json.get("nodes"),
            "edges": r1_json.get("edges"),
            "dot_total_nodes": semantic_res.get("dot_total_nodes"),
            "dot_total_edges": semantic_res.get("dot_total_edges"),
        },
        "semantic_correctness": semantic_res,
        "performance": {
            "run1": {
                "replay_duration_ns": r1_json.get("replay_duration_ns"),
                "replay_duration_ms": round(
                    r1_json.get("replay_duration_ns", 0) / 1e6, 2
                ),
                "wall_time_sec": res1["time_metrics"]["wall_time_sec"],
                "user_time_sec": res1["time_metrics"]["user_time_sec"],
                "sys_time_sec": res1["time_metrics"]["sys_time_sec"],
                "max_rss_kb": res1["time_metrics"]["max_rss_kb"],
                "max_rss_mib": res1["time_metrics"]["max_rss_mib"],
                "events_per_sec": round(
                    r1_json.get("records_replayed", 0)
                    / (res1["time_metrics"]["wall_time_sec"] or 1e-4),
                    1,
                ),
            },
            "run2": {
                "replay_duration_ns": res2["replay_json"].get("replay_duration_ns"),
                "replay_duration_ms": round(
                    res2["replay_json"].get("replay_duration_ns", 0) / 1e6, 2
                ),
                "wall_time_sec": res2["time_metrics"]["wall_time_sec"],
                "user_time_sec": res2["time_metrics"]["user_time_sec"],
                "sys_time_sec": res2["time_metrics"]["sys_time_sec"],
                "max_rss_kb": res2["time_metrics"]["max_rss_kb"],
                "max_rss_mib": res2["time_metrics"]["max_rss_mib"],
            },
        },
        "repeatability": {
            "repeatable": repeatable,
            "run1_sha256": res1["dot_sha256"],
            "run2_sha256": res2["dot_sha256"],
        },
        "all_checks_passed": (
            reader_integrity
            and (r1_json.get("records_verified") == expected_recs)
            and semantic_res.get("valid", False)
            and repeatable
        ),
    }

    report_path = out_dir / "standalone_reconstruction_summary.json"
    report_path.write_text(json.dumps(validation_summary, indent=2))
    print(f"\nValidation summary written to: {report_path}")

    print(
        "\n===================================================================================================="
    )
    print(
        f"OVERALL VALIDATION STATUS: {'ALL CHECKS PASSED' if validation_summary['all_checks_passed'] else 'VALIDATION DEFECT DETECTED'}"
    )
    print(
        "===================================================================================================="
    )


if __name__ == "__main__":
    main()
