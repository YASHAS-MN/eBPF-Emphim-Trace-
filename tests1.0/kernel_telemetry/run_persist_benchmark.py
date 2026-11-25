#!/usr/bin/env python3
"""run_persist_benchmark.py — Paired Randomized Interleaved Benchmark Runner for Issue #7

Evaluates the two persistent evidence modes:
- Model M (Online): Receive -> Preserve original evidence -> Process -> Construct provenance.
- Model P (Deferred): Receive -> Preserve original evidence -> Complete collection -> Replay -> Construct provenance.

In --smoke mode, executes exactly 6 trials:
  3 workloads (W_PACED, W_BURST, W_SUSTAIN) x 2 modes (Model M, Model P) x 1 repetition.

In full benchmark mode:
  3 workloads (W_PACED, W_BURST, W_SUSTAIN) x 2 modes x 3 paired repetitions (18 trials total).
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
ROOT = HERE.parents[1]

# Ensure local test framework is importable
sys.path.insert(0, str(HERE))
import compare_persistent_evidence
import runner


def run_trial(
    case_name: str,
    iterations: int,
    workers: int,
    pace_us: int,
    full: bool,
    stall: bool,
    delay_us: int,
    hold: bool,
    quiet: bool,
    persist_mode: str,
    out_dir: pathlib.Path,
):
    """Executes a single trial via runner.trial()."""
    report = runner.trial(
        out=out_dir,
        name=case_name,
        iterations=iterations,
        workers=workers,
        pace=pace_us,
        full=full,
        stall=stall,
        delay=delay_us,
        hold=hold,
        quiet=quiet,
        persist_mode=persist_mode,
    )
    status = report.get("status", "UNKNOWN")
    print(f"    [{persist_mode}] {case_name}: status={status}")
    return report


def main():
    parser = argparse.ArgumentParser(
        description="Run paired randomized benchmark trials between Model M (Online) and Model P (Deferred)."
    )
    parser.add_argument(
        "--repeat", type=int, default=3, help="Number of paired blocks (default: 3)"
    )
    parser.add_argument(
        "--smoke",
        action="store_true",
        help="Run 6-trial smoke test (3 workloads x 2 modes, 1 repetition)",
    )
    parser.add_argument(
        "--quiet", action="store_true", default=True, help="Enable quiet mode in loader (default: True)"
    )
    parser.add_argument(
        "--non-quiet", action="store_false", dest="quiet", help="Disable quiet mode"
    )
    parser.add_argument(
        "--seed", type=int, default=42, help="Random seed for paired trial ordering"
    )
    args = parser.parse_args()

    if os.geteuid() != 0:
        sys.exit(
            "Error: Benchmark execution requires root privileges (BPF tracepoints). Please run with sudo."
        )

    print("Building diagnostic binaries before execution...")
    runner.build()

    random.seed(args.seed)
    ts = time.strftime("%Y%m%d-%H%M%S")
    out_base = HERE / "results" / f"persist_{ts}"
    out_m = out_base / "model_m"
    out_p = out_base / "model_p"
    out_m.mkdir(parents=True, exist_ok=True)
    out_p.mkdir(parents=True, exist_ok=True)

    if args.smoke:
        print("[MODE] Running 6-trial smoke test suite (3 workloads x 2 modes, 1 repetition)...")
        repeat = 1
        cases = [
            ("W_PACED", 50, 1, 1000, True, False, 0, False),
            ("W_BURST", 100, 2, 0, True, False, 0, False),
            ("W_SUSTAIN", 200, 2, 50, True, False, 0, False),
        ]
    else:
        print(
            f"[MODE] Running full comparative benchmark suite ({args.repeat} paired blocks, 3 approved workloads)..."
        )
        repeat = args.repeat
        cases = [
            ("W_PACED", 500, 1, 1000, True, False, 0, False),
            ("W_BURST", 2500, 4, 0, True, False, 0, False),
            ("W_SUSTAIN", 15000, 4, 50, True, False, 0, False),
        ]

    # Preflight Provenance Record
    commit_sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    branch_name = subprocess.run(["git", "branch", "--show-current"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    build_info = json.loads((ROOT / "build" / "telemetry_lab" / "build_info.json").read_text())
    preflight = {
        "timestamp": ts,
        "commit": commit_sha,
        "branch": branch_name,
        "kernel": os.uname().release,
        "seed": args.seed,
        "quiet": args.quiet,
        "repeat": repeat,
        "workloads": [c[0] for c in cases],
        "workload_configurations": cases,
        "binaries": build_info,
    }
    (out_base / "preflight_provenance.json").write_text(json.dumps(preflight, indent=2))

    total_pairs = repeat * len(cases)
    current_pair = 0

    print(f"\nTarget output directory: {out_base}")
    print(f"Total workload pairs: {total_pairs} (Total trials: {total_pairs * 2})\n")

    for blk in range(repeat):
        print(f"=======================================================")
        print(f"=== TRIAL BLOCK {blk + 1} / {repeat}")
        print(f"=======================================================")
        for case in cases:
            case_id, iters, workers, pace, full, stall, delay, hold = case
            current_pair += 1

            # Alternate between Model M and Model P with randomized order per block
            pair_order = ["M", "P"] if random.random() < 0.5 else ["P", "M"]
            print(
                f"\n[{current_pair}/{total_pairs}] Workload {case_id} (Block {blk+1}) — Order: {' -> '.join(pair_order)}"
            )

            for mode in pair_order:
                target_out = out_m if mode == "M" else out_p
                case_name = f"{case_id}_{blk + 1}"
                run_trial(
                    case_name=case_name,
                    iterations=iters,
                    workers=workers,
                    pace_us=pace,
                    full=full,
                    stall=stall,
                    delay_us=delay,
                    hold=hold,
                    quiet=args.quiet,
                    persist_mode=mode,
                    out_dir=target_out,
                )

    print("\n=======================================================")
    print("=== EXECUTING COMPARATIVE AUDIT")
    print("=======================================================")
    compare_persistent_evidence.audit_results_dir(out_base)


if __name__ == "__main__":
    main()
