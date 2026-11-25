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
import json
import os
import pathlib
import random
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
ROOT_A = HERE.parents[1]
ROOT_B = ROOT_A / "FM-async"
ROOT_C = ROOT_A / "FM-min"


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
):
    """Executes a single trial via runner.py in the target architecture root."""
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
        print(f"Trial execution failed in {root_dir}:\n{p.stderr}")
    return p.returncode == 0


def main():
    parser = argparse.ArgumentParser(
        description="Run three-way randomized interleaved benchmark trials between Arch A, Arch B, and Arch C."
    )
    parser.add_argument(
        "--repeat", type=int, default=5, help="Number of triplet blocks (default: 5)"
    )
    parser.add_argument(
        "--smoke",
        action="store_true",
        help="Run small smoke test (low iterations, 1 repetition)",
    )
    parser.add_argument(
        "--quiet", action="store_true", help="Enable quiet mode in all architectures"
    )
    parser.add_argument(
        "--seed", type=int, default=42, help="Random seed for trial ordering"
    )
    args = parser.parse_args()

    if os.geteuid() != 0:
        sys.exit(
            "Error: Benchmark execution requires root privileges. Please run with sudo."
        )

    for p, label in [(ROOT_A, "Arch A"), (ROOT_B, "Arch B"), (ROOT_C, "Arch C")]:
        if not p.exists():
            sys.exit(f"Error: {label} worktree not found at {p}")

    random.seed(args.seed)
    ts = time.strftime("%Y%m%d-%H%M%S")
    out_base = HERE / "results" / f"three_way_{ts}"
    out_a = out_base / "arch_a"
    out_b = out_base / "arch_b"
    out_c = out_base / "arch_c"
    out_a.mkdir(parents=True, exist_ok=True)
    out_b.mkdir(parents=True, exist_ok=True)
    out_c.mkdir(parents=True, exist_ok=True)

    # Workload definitions matching BENCHMARK_SPEC.md & runner.py
    if args.smoke:
        print("[MODE] Running small smoke test suite (Arch A vs B vs C)...")
        repeat = 1
        cases = [
            ("W_PACED", 50, 1, 1000, True, False, 0, False),
            ("W_BURST", 100, 2, 0, True, False, 0, False),
            ("W_SUSTAIN", 200, 2, 50, True, False, 0, False),
        ]
    else:
        print(
            f"[MODE] Running full comparative three-way benchmark suite ({args.repeat} triplet blocks)..."
        )
        repeat = args.repeat
        cases = [
            ("W_PACED", 500, 1, 1000, True, False, 0, False),
            ("W_BURST", 2500, 4, 0, True, False, 0, False),
            ("W_SUSTAIN", 15000, 4, 50, True, False, 0, False),
            ("W_CONTENTION", 5000, 8, 0, True, False, 0, False),
            ("W_REGISTRY", 10000, 1, 100, True, False, 0, True),
        ]

    total_triplets = repeat * len(cases)
    current_triplet = 0

    roots = {"A": (ROOT_A, out_a), "B": (ROOT_B, out_b), "C": (ROOT_C, out_c)}

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
                root_dir, out_dir = roots[arch]
                print(
                    f"  -> Executing Architecture {arch} ({case_id}_{blk+1})...",
                    flush=True,
                )
                run_trial(
                    root_dir,
                    f"{case_id}_{blk+1}",
                    iters,
                    workers,
                    pace,
                    full,
                    stall,
                    delay,
                    hold,
                    args.quiet,
                    out_dir,
                )

    print("\n=======================================================")
    print("=== THREE-WAY EXECUTION COMPLETE. RUNNING ANALYZER ===")
    print("=======================================================\n")

    summary_json = out_base / "three_way_comparison_summary.json"
    compare_cmd = [
        sys.executable,
        str(HERE / "compare_three_way.py"),
        "--dir-a",
        str(out_a),
        "--dir-b",
        str(out_b),
        "--dir-c",
        str(out_c),
        "--json",
        str(summary_json),
    ]
    subprocess.run(compare_cmd)


if __name__ == "__main__":
    main()
