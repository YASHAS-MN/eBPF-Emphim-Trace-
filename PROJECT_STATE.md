# EphimTrace — Project State

Last updated: 2026-11-25

## Objective

Develop an eBPF-based forensic telemetry collection
system prioritizing evidence completeness, fidelity,
and reliable provenance reconstruction.

## Project Resources

- Codebase: https://github.com/YASHAS-MN/eBPF-Emphim-Trace-
- Knowledge base: https://github.com/YASHAS-MN/Obsidian
- Project board: https://github.com/users/YASHAS-MN/projects/1
- Implementation checkpoint: 355ed8a
- Working branch: checkpoint/telemetry-remediation

## Current Architecture

Kernel hooks and BPF registries
    -> Kernel ring buffer (1 MiB)
    -> Synchronous userspace consumer
    -> Provenance engine

Alternative architectures are under consideration,
not approved for implementation.

## Completed Work

Accepted within the tested memfd lifecycle scope:

- Independent syscall-based ground truth.
- Telemetry loss-detection infrastructure.
- Quantitative baseline experiments.
- Correction 1: Event initialization.
- Correction 2: Ordinary descriptor-close coverage.
- Correction 3: Truthful registry correlation outcomes.

## Current Checkpoint

Correction 4A: Optional quiet event logging.

Implementation exists locally and in the checkpoint.
Comparative performance acceptance remains pending.
Review the Antigravity report before further changes.

## Outstanding Work

GitHub Issues is the authoritative task register.

- #2: Review logging optimization.
- #3: Evaluate asynchronous userspace acquisition.
- #4: Evaluate minimal kernel-side state.
- #5: Remaining descriptor and registry limitations.
- #6: Repair legacy test build paths.

## Known Limitations

- Significant ring-buffer loss under heavy workloads.
- Descriptor concurrency and registry cleanup risks.
- Incomplete lifecycle and kernel compatibility coverage.
- Diagnostic instrumentation overhead.
- Production export reliability not fully validated.
- Legacy Makefile test paths require correction.

## Validation Infrastructure

Location: tests1.0/kernel_telemetry/

Build:
  python3 tests1.0/kernel_telemetry/runner.py build

Quick suite:
  sudo python3 tests1.0/kernel_telemetry/runner.py run --suite quick

Pressure suite:
  sudo python3 tests1.0/kernel_telemetry/runner.py run --suite pressure --iterations 5000 --workers 4 --repeat 3

Historical results are preserved locally.
Do not overwrite or silently discard evidence.

## Development Rules

1. Read this file and the active GitHub issue first.
2. Inspect actual source before proposing changes.
3. Work on one implementation issue at a time.
4. Obtain approval before architectural changes.
5. Review source diffs and experimental evidence.
6. Do not equate valid measurements with zero loss.
7. Record decisions and unresolved limitations.
8. Update project state when the active task changes.
9. Keep generated artifacts and raw evidence out of Git.
10. GUI development is currently out of scope.

## Role Delegation

Project owner: Architecture and acceptance decisions.
ChatGPT: Engineering discussion and code review.
Antigravity: Scoped implementation and local validation.
GitHub: Development history and task tracking.
Obsidian: Technical knowledge and architectural decisions.

This file is a handoff index, not a replacement for
source code, experimental evidence or the knowledge base.
