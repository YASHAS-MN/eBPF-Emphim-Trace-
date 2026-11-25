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
- Three-way benchmark checkpoints: A 82f0e3e, B e497635, C 4a5de9a
- Architecture C branch: experiment/minimal-kernel
- Original remediation checkpoint: 355ed8a
- Working branch: checkpoint/telemetry-remediation

## Current Architecture

Kernel hooks and BPF registries
    -> Kernel ring buffer (1 MiB)
    -> Synchronous userspace consumer
    -> Provenance engine

Architectures B and C have been evaluated and preserved as experimental candidates, not adopted. A remains the existing reference architecture, not an approved final lock-in. Owner selected A as the experimental reference for one final scoped persistence experiment (#7); this is not production adoption. Historical A/B/C evaluation remains frozen.

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

Active implementation task: #7 — persistent evidence capture versus online reconstruction. A is frozen as the reference (36d4c6b benchmark source). M and P share the same evidence writer and durability policy; compare immediate versus deferred graph processing. Separate worktree FM-persist, branch experiment/persistent-evidence. Provisional three workloads, three paired repetitions, native smoke review before full trials. #4 awaits final architectural disposition; no A/B/C tuning or product adoption.

Three-way diagnostic benchmark: `tests1.0/kernel_telemetry/results/three_way_20261125-194503/` (75 trials, 5 workloads, 5 repetitions each, full quiet diagnostic mode). Mean create-pair completeness A/B/C: paced 99.96/100/100%, burst 7.43/82.34/81.45%, sustained 12.25/28.89/28.64%, contention 1.86/12.87/11.30%, registry 40.96/40.96/100.00% rounded. B and C each passed 2/6 original analyzer targets. C registry improvement confounded by expanded maps; both async candidates suffer sustained queue saturation. Local audit classifies C 283810 discrepancy labels as queue losses and one as truthful uncorrelated success; A paced had one file-registry update failure. No full lifecycle fidelity or production evidence equivalence established. Review limitations documented in #4 comment 7165662311. Preserve artifacts and checkpoints; no further A/B/C tuning or reruns. Only #7 experiment approved.

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
- #4: Evaluate minimal kernel-side state (experimental phase complete; open for final owner architecture decision).
- #7: Persistent evidence versus online reconstruction (active, scoped experiment).
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
