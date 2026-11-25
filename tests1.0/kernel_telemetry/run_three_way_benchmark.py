#!/usr/bin/env python3
"""run_three_way_benchmark.py — Randomized Interleaved Three-Way Benchmark Runner

Executes randomized trial blocks alternating between:
- Architecture A: Baseline (Kernel Registries + Synchronous Ring Buffer Consumer)
- Architecture B: Asynchronous Userspace Acquisition (Ring-Buffer Acq Thread + FIFO Queue + Worker)
- Architecture C: Minimal Kernel-Side State (Ring-Buffer Acq Thread + FIFO Queue + Worker + Userspace Canonical Correlator)

Evaluates the approved numerical acceptance targets across all three architectures under
identical test conditions, retaining all raw trial evidence in paired result directories.
"""

import argparse
import hashlib
import json
import os
import pathlib
import random
import subprocess
import sys
import time
from typing import Any, Dict, List, Tuple


def get_canonical_roots() -> Dict[str, pathlib.Path]:
    """Resolves canonical repository roots for Architecture A, B, and C regardless

    of whether the script is invoked from FM, FM-min, or FM-async.
    """
    here = pathlib.Path(__file__).resolve().parent
    base = here.parents[1]

    if base.name == "FM-min":
        root_c = base
        root_a = base.parent
        root_b = root_a / "FM-async"
    elif base.name == "FM-async":
        root_b = base
        root_a = base.parent
        root_c = root_a / "FM-min"
    else:
        root_a = base
        root_b = root_a / "FM-async"
        root_c = root_a / "FM-min"

    roots = {"A": root_a, "B": root_b, "C": root_c}
    for label, r in roots.items():
        if not r.exists():
            sys.exit(f"Error: Architecture {label} worktree not found at {r}")
        runner_file = r / "tests1.0" / "kernel_telemetry" / "runner.py"
        if not runner_file.exists():
            sys.exit(f"Error: Architecture {label} runner not found at {runner_file}")

    return roots


def compute_sha256(path: pathlib.Path) -> str:
    """Computes SHA256 hex digest of a file."""
    if not path.exists():
        return "MISSING"
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def get_git_provenance(root: pathlib.Path) -> Dict[str, str]:
    """Retrieves commit hash, branch name, and status cleanliness for a git repository."""
    try:
        commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=root, text=True
        ).strip()
    except Exception as e:
        commit = f"ERROR: {e}"
    try:
        branch = subprocess.check_output(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=root,
            text=True,
        ).strip()
    except Exception as e:
        branch = f"ERROR: {e}"
    try:
        status = subprocess.check_output(
            ["git", "status", "--porcelain"], cwd=root, text=True
        ).strip()
        is_clean = len(status) == 0
    except Exception:
        is_clean = False
    return {"commit": commit, "branch": branch, "clean": is_clean}


def preflight_verification(
    roots: Dict[str, pathlib.Path],
    cases: List[Tuple],
    args: argparse.Namespace,
    out_base: pathlib.Path,
) -> Dict[str, Any]:
    """Verifies all three diagnostic builds, commit identities, and workload configurations

    before execution, and records actual binary hashes in preflight provenance.
    """
    print("\n" + "=" * 95)
    print("=== THREE-WAY BENCHMARK PREFLIGHT VERIFICATION ===")
    print("=" * 95)

    provenance: Dict[str, Any] = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "mode": "smoke" if args.smoke else "full",
        "quiet": args.quiet,
        "seed": args.seed,
        "repeat": args.repeat if not args.smoke else 1,
        "workload_cases": [
            {
                "case_id": c[0],
                "iterations": c[1],
                "workers": c[2],
                "pace_us": c[3],
                "full": c[4],
                "stall": c[5],
                "delay_us": c[6],
                "hold": c[7],
            }
            for c in cases
        ],
        "architectures": {},
    }

    labels = {
        "A": "Architecture A (Reference Baseline)",
        "B": "Architecture B (Async Userspace)",
        "C": "Architecture C (Minimal Kernel)",
    }

    for arch, root in roots.items():
        git_info = get_git_provenance(root)

        # Check diagnostic build binaries
        loader_diag = root / "build" / "telemetry_lab" / "loader.diag"
        bpf_diag = root / "build" / "telemetry_lab" / "monitor.diag.bpf.o"
        workload = root / "build" / "telemetry_lab" / "workload"

        # If any binary is missing, invoke runner.py build
        if not (loader_diag.exists() and bpf_diag.exists() and workload.exists()):
            print(f"[{arch}] Diagnostic build missing in {root}; building...")
            build_res = subprocess.run(
                [
                    sys.executable,
                    str(root / "tests1.0" / "kernel_telemetry" / "runner.py"),
                    "build",
                ],
                cwd=root,
                capture_output=True,
                text=True,
            )
            if build_res.returncode != 0:
                sys.exit(
                    f"Fatal: Diagnostic build failed in {root}:\n{build_res.stderr}"
                )

        bpf_sha = compute_sha256(bpf_diag)
        loader_sha = compute_sha256(loader_diag)
        workload_sha = compute_sha256(workload)

        provenance["architectures"][arch] = {
            "label": labels[arch],
            "root": str(root),
            "git": git_info,
            "binaries": {
                "loader_diag_sha256": loader_sha,
                "monitor_diag_bpf_sha256": bpf_sha,
                "workload_sha256": workload_sha,
            },
        }

        print(f"\n[{arch}] {labels[arch]}")
        print(f"      Root:       {root}")
        print(f"      Branch:     {git_info['branch']} ({git_info['commit'][:10]})")
        print(f"      BPF SHA:    {bpf_sha[:16]}...")
        print(f"      Loader SHA: {loader_sha[:16]}...")

    # Write preflight provenance record
    prov_file = out_base / "preflight_provenance.json"
    prov_file.write_text(json.dumps(provenance, indent=2))
    print(
        f"\n[PASS] Preflight verification complete. Recorded provenance in {prov_file}"
    )
    print("=" * 95 + "\n")
    return provenance


def run_trial(
    root_dir: pathlib.Path,
    case_name: str,
    iterations: int,
    workers: int,
    pace_us: int,
    full: bool,
    stall: bool,
    delay_us: int,
    hold: bool,
    quiet: bool,
    out_dir: pathlib.Path,
) -> bool:
    """Executes a single trial via runner.py in the target architecture root.

    Preserves invalid trial evidence and surfaces subprocess errors.
    """
    runner_script = f"""
import sys, pathlib, json
sys.path.insert(0, str(pathlib.Path('{root_dir}') / 'tests1.0' / 'kernel_telemetry'))
import runner
out = pathlib.Path('{out_dir}')
report = runner.trial(out, '{case_name}', {iterations}, {workers}, {pace_us}, {full}, {stall}, {delay_us}, {hold}, quiet={quiet})
print('TRIAL_STATUS:', report.get('status'))
"""
    p = subprocess.run(
        [sys.executable, "-c", runner_script],
        cwd=root_dir,
        capture_output=True,
        text=True,
    )
    if p.returncode != 0:
        err_msg = p.stderr.strip() or p.stdout.strip()
        print(
            f"  [ERROR] Trial execution failed in {root_dir} (code {p.returncode}):\n{err_msg}",
            flush=True,
        )
        # Retain invalid trial evidence in out_dir so analyzer preserves complete failure record
        failure_json = out_dir / f"{case_name}.json"
        if not failure_json.exists():
            failure_data = {
                "status": "INVALID",
                "test": {
                    "name": case_name,
                    "iterations_per_worker": iterations,
                    "workers": workers,
                    "pace_us": pace_us,
                    "full_callback": full,
                    "hold_fds": hold,
                },
                "error": f"Subprocess exit code {p.returncode}: {err_msg}",
                "analysis": {
                    "measurement_valid": False,
                    "measurement_issues": [
                        f"Subprocess exit code {p.returncode}: {err_msg}"
                    ],
                },
            }
            failure_json.write_text(json.dumps(failure_data, indent=2))
        return False
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Run three-way randomized interleaved benchmark trials between Arch A, Arch B, and Arch C."
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=5,
        help="Number of triplet blocks (default: 5)",
    )
    parser.add_argument(
        "--smoke",
        action="store_true",
        help="Run small smoke test (low iterations, 1 repetition)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Enable quiet mode in all architectures",
    )
    parser.add_argument(
        "--seed", type=int, default=42, help="Random seed for trial ordering"
    )
    args = parser.parse_args()

    if os.geteuid() != 0:
        sys.exit(
            "Error: Benchmark execution requires root privileges. Please run with sudo."
        )

    roots = get_canonical_roots()
    root_a = roots["A"]
    root_b = roots["B"]
    root_c = roots["C"]

    # Workload definitions matching BENCHMARK_SPEC.md & runner.py
    if args.smoke:
        repeat = 1
        cases = [
            ("W_PACED", 50, 1, 1000, True, False, 0, False),
            ("W_BURST", 100, 2, 0, True, False, 0, False),
            ("W_SUSTAIN", 200, 2, 50, True, False, 0, False),
        ]
    else:
        repeat = args.repeat
        cases = [
            ("W_PACED", 500, 1, 1000, True, False, 0, False),
            ("W_BURST", 2500, 4, 0, True, False, 0, False),
            ("W_SUSTAIN", 15000, 4, 50, True, False, 0, False),
            ("W_CONTENTION", 5000, 8, 0, True, False, 0, False),
            ("W_REGISTRY", 10000, 1, 100, True, False, 0, True),
        ]

    random.seed(args.seed)
    ts = time.strftime("%Y%m%d-%H%M%S")
    out_base = root_a / "tests1.0" / "kernel_telemetry" / "results" / f"three_way_{ts}"
    out_a = out_base / "arch_a"
    out_b = out_base / "arch_b"
    out_c = out_base / "arch_c"
    out_a.mkdir(parents=True, exist_ok=True)
    out_b.mkdir(parents=True, exist_ok=True)
    out_c.mkdir(parents=True, exist_ok=True)

    # Preflight verification and provenance recording
    preflight_verification(roots, cases, args, out_base)

    total_triplets = repeat * len(cases)
    current_triplet = 0
    dirs = {"A": (root_a, out_a), "B": (root_b, out_b), "C": (root_c, out_c)}

    for blk in range(repeat):
        print(f"\n=======================================================")
        print(f"=== TRIPLET BLOCK {blk + 1} / {repeat}")
        print(f"=======================================================")
        for case in cases:
            case_id, iters, workers, pace, full, stall, delay, hold = case
            current_triplet += 1
            # Randomize order among Architecture A, B, and C
            triplet_order = random.sample(["A", "B", "C"], 3)
            print(
                f"\n[{current_triplet}/{total_triplets}] Running {case_id} (Block {blk+1}) — Order: {' -> '.join(triplet_order)}"
            )

            for arch in triplet_order:
                r_dir, o_dir = dirs[arch]
                print(
                    f"  -> Executing Architecture {arch} ({case_id}_{blk+1})...",
                    flush=True,
                )
                run_trial(
                    r_dir,
                    f"{case_id}_{blk+1}",
                    iters,
                    workers,
                    pace,
                    full,
                    stall,
                    delay,
                    hold,
                    args.quiet,
                    o_dir,
                )

    print("\n=======================================================")
    print("=== THREE-WAY EXECUTION COMPLETE. RUNNING ANALYZER ===")
    print("=======================================================\n")

    summary_json = out_base / "three_way_comparison_summary.json"
    analyzer_script = root_a / "tests1.0" / "kernel_telemetry" / "compare_three_way.py"
    compare_cmd = [
        sys.executable,
        str(analyzer_script),
        "--dir-a",
        str(out_a),
        "--dir-b",
        str(out_b),
        "--dir-c",
        str(out_c),
        "--json",
        str(summary_json),
    ]
    compare_proc = subprocess.run(compare_cmd, text=True)
    if compare_proc.returncode != 0:
        print(
            f"\n[ERROR] Three-way comparative analyzer returned error code {compare_proc.returncode}"
        )


if __name__ == "__main__":
    main()
