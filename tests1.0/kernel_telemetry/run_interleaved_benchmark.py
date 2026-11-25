#!/usr/bin/env python3
"""run_interleaved_benchmark.py — Paired Randomized Interleaved A/B Benchmark Runner

Executes randomized paired trial blocks alternating between Architecture A
and Architecture B to prevent systemic drift, cache bias, or thermal variation.
Retains all raw trial evidence in paired result directories and invokes
compare_architectures.py to evaluate acceptance targets.
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
    cmd = [
        sys.executable,
        str(root_dir / "tests1.0" / "kernel_telemetry" / "runner.py"),
        "run",
        "--iterations",
        str(iterations),
        "--workers",
        str(workers),
    ]
    # Use python directly to invoke trial with specific directory
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
        description="Run paired randomized interleaved benchmark trials between Arch A and Arch B."
    )
    parser.add_argument(
        "--repeat", type=int, default=5, help="Number of paired blocks (default: 5)"
    )
    parser.add_argument(
        "--smoke",
        action="store_true",
        help="Run small smoke test (low iterations, 1 repetition)",
    )
    parser.add_argument(
        "--quiet", action="store_true", help="Enable quiet mode in both architectures"
    )
    parser.add_argument(
        "--seed", type=int, default=42, help="Random seed for paired trial ordering"
    )
    args = parser.parse_args()

    if os.geteuid() != 0:
        sys.exit(
            "Error: Benchmark execution requires root privileges. Please run with sudo."
        )

    if not ROOT_B.exists():
        sys.exit(f"Error: Architecture B worktree not found at {ROOT_B}")

    random.seed(args.seed)
    ts = time.strftime("%Y%m%d-%H%M%S")
    out_base = HERE / "results" / f"interleaved_{ts}"
    out_a = out_base / "arch_a"
    out_b = out_base / "arch_b"
    out_a.mkdir(parents=True, exist_ok=True)
    out_b.mkdir(parents=True, exist_ok=True)

    # Workload definitions matching BENCHMARK_SPEC.md & runner.py
    if args.smoke:
        print("[MODE] Running small smoke test suite...")
        repeat = 1
        cases = [
            ("W_PACED", 50, 1, 1000, True, False, 0, False),
            ("W_BURST", 100, 2, 0, True, False, 0, False),
            ("W_SUSTAIN", 200, 2, 50, True, False, 0, False),
        ]
    else:
        print(
            f"[MODE] Running full comparative benchmark suite ({args.repeat} paired blocks)..."
        )
        repeat = args.repeat
        cases = [
            ("W_PACED", 500, 1, 1000, True, False, 0, False),
            ("W_BURST", 2500, 4, 0, True, False, 0, False),
            ("W_SUSTAIN", 15000, 4, 50, True, False, 0, False),
            ("W_CONTENTION", 5000, 8, 0, True, False, 0, False),
            ("W_REGISTRY", 10000, 1, 100, True, False, 0, True),
        ]

    total_pairs = repeat * len(cases)
    current_pair = 0

    for blk in range(repeat):
        print(f"\n=======================================================")
        print(f"=== TRIAL BLOCK {blk + 1} / {repeat}")
        print(f"=======================================================")
        for case in cases:
            case_id, iters, workers, pace, full, stall, delay, hold = case
            current_pair += 1
            # Randomize order between Architecture A and Architecture B
            pair_order = ["A", "B"] if random.random() < 0.5 else ["B", "A"]
            print(
                f"\n[{current_pair}/{total_pairs}] Running {case_id} (Block {blk+1}) — Order: {' -> '.join(pair_order)}"
            )

            for arch in pair_order:
                if arch == "A":
                    print(
                        f"  -> Executing Architecture A ({case_id}_{blk+1})...",
                        flush=True,
                    )
                    run_trial(
                        ROOT_A,
                        f"{case_id}_{blk+1}",
                        iters,
                        workers,
                        pace,
                        full,
                        stall,
                        delay,
                        hold,
                        args.quiet,
                        out_a,
                    )
                else:
                    print(
                        f"  -> Executing Architecture B ({case_id}_{blk+1})...",
                        flush=True,
                    )
                    run_trial(
                        ROOT_B,
                        f"{case_id}_{blk+1}",
                        iters,
                        workers,
                        pace,
                        full,
                        stall,
                        delay,
                        hold,
                        args.quiet,
                        out_b,
                    )

    print("\n=======================================================")
    print("=== PAIRED EXECUTION COMPLETE. RUNNING ANALYZER ===")
    print("=======================================================\n")

    summary_json = out_base / "comparison_summary.json"
    compare_cmd = [
        sys.executable,
        str(HERE / "compare_architectures.py"),
        "--dir-a",
        str(out_a),
        "--dir-b",
        str(out_b),
        "--json",
        str(summary_json),
    ]
    subprocess.run(compare_cmd)


if __name__ == "__main__":
    main()
