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
- Reference Architecture A checkpoint: 49ece70dc72a14799aac6a94c6b62d65c2a78bfd
- Architecture A benchmark checkpoint: 36d4c6b
- Architecture B benchmark candidate: 8c2a0c1; later shutdown fix e497635 (exact full-run binary provenance unresolved)
- Architecture B branch: experiment/async-userspace
- Original remediation checkpoint: 355ed8a
- Working branch: checkpoint/telemetry-remediation

## Current Architecture

Kernel hooks and BPF registries
    -> Kernel ring buffer (1 MiB)
    -> Synchronous userspace consumer
    -> Provenance engine

Architecture B has been evaluated and preserved as an experimental candidate, not adopted. Architecture C (minimal essential kernel-side state, reusing B's acquisition/queue/worker topology) is approved for scoped design and experimentation under #4, with specific hook/map changes subject to design review. Final architecture selection or fusion is deferred until comparative evaluation.

## Completed Work

Accepted within the tested memfd lifecycle scope:

- Independent syscall-based ground truth.
- Telemetry loss-detection infrastructure.
- Quantitative baseline experiments.
- Correction 1: Event initialization.
- Correction 2: Ordinary descriptor-close coverage.
- Correction 3: Truthful registry correlation outcomes.
- Correction 4A: Optional quiet event logging (accepted strictly as diagnostic/benchmark optimization; not production evidence-equivalent).

## Current Checkpoint

Active task: #4 — Architecture C design and minimal-kernel-state feasibility review. No C implementation has started.

Issue #3 completed: 50 paired diagnostic trials (five repetitions per workload per architecture), local evidence `tests1.0/kernel_telemetry/results/interleaved_20261125-132015/`. B improved mean validated create-pair completeness on burst (7.90% to 84.54%) but failed sustained useful throughput, memory and drain targets. Original analyzer verdict 2/6; registry discrepancies reportedly truthful uncorrelated successes, not actual syscall inversions. Full lifecycle fidelity, production evidence equivalence and exact binary provenance not established. Preserve both candidates and historical evidence. No further B tuning.

Correction 4A accepted: Optional quiet event logging.

Accepted strictly as a diagnostic and benchmark optimization.
Deterministic callback equivalence verified.
Quiet mode is NOT production evidence-equivalent: un-modeled observations
(failed/uncorrelated memfds, file releases, syscall intent) are suppressed.
Default presentation logging remains unchanged.

## Outstanding Work

GitHub Issues is the authoritative task register.

- #2: Review logging optimization (closed/accepted as diagnostic optimization).
- #3: Evaluate asynchronous userspace acquisition (closed: experiment completed, not adopted).
- #4: Evaluate minimal kernel-side state (active: design and feasibility review).
- #5: Remaining descriptor and registry limitations.
- #6: Repair legacy test build paths.

## Known Limitations

- Significant ring-buffer loss under heavy workloads.
- Descriptor concurrency and registry cleanup risks.
- Incomplete lifecycle and kernel compatibility coverage.
- Diagnostic instrumentation overhead, differing measurement populations and limited record-level coverage (create pairs).
- Architecture B queue saturation, processing backlog and memory overhead under pressure; acquisition-error cleanup path not fully safe.
- Production export reliability not fully validated.
- Legacy Makefile test paths require correction.
- Quiet mode suppresses observations absent from provenance schema (failed/uncorrelated memfd, file release); not production evidence-equivalent.

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
