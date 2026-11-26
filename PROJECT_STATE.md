# EphimTrace — Project State

Last updated: 2026-11-26

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
- Consolidated findings: RESULTS.md (includes verified persistence experiment)
- Persistence experiment: experiment/persistent-evidence (native 3774978, offline reader c4c9cf9)

## Selected Final Architecture (design lock-in; integration pending)

A kernel hooks, BPF registries and lifetime-assisted identity
    -> Kernel ring buffer (1 MiB experimental reference)
    -> P-derived lightweight acquisition
    -> Persistent original evidence and loss/session metadata
    -> Independent verified replay and correlation
    -> Existing provenance engine and graph/timeline exports

The owner has selected the collection-first direction following #7. A remains the frozen kernel reference; B/C remain experimental and are not adopted wholesale. The production integration is not yet implemented/accepted. Architecture selection is distinct from release acceptance.

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

Next phase: bounded final integration planning and correctness validation (see #7 owner direction/review comment 7183025765). Comparative performance experimentation is concluded. No code changes authorized by this documentation update. #7 results: six smoke and eighteen full trials in FM-persist, native capture 3774978, offline parser correction c4c9cf9. Actual readback of all 24 files detected zero CRC/framing corruption, gaps or truncation. M/P persisted create-pair completeness paced 100/100%, burst 5.2133/10.7733%, sustained 11.8061/100%. P retained all 180000 sustained pairs across three trials, but all three native sustained replay sessions timed out; confirmed sync completion and final graph outcomes unavailable. Burst loss remains severe. See RESULTS.md and #7 comment 7182734475. Standalone replay validation completed within bounded scope (29d695d): incoming adjacency lookup preserves relation predicate, W_SUSTAIN_1 420074 records replayed, 60022 nodes/240042 edges, 1.53/1.47 s with identical DOT exports and all 60000 expected memfd names. Per-edge/lifecycle semantics remain pending. Next: production capture/replay integration and bounded lifecycle chain/failure tests; no new architecture tournament. See #7 comment 7185160384 and RESULTS.md section 7.4.

Three-way diagnostic benchmark: `tests1.0/kernel_telemetry/results/three_way_20261125-194503/` (75 trials, 5 workloads, 5 repetitions each, full quiet diagnostic mode). Mean create-pair completeness A/B/C: paced 99.96/100/100%, burst 7.43/82.34/81.45%, sustained 12.25/28.89/28.64%, contention 1.86/12.87/11.30%, registry 40.96/40.96/100.00% rounded. B and C each passed 2/6 original analyzer targets. C registry improvement confounded by expanded maps; both async candidates suffer sustained queue saturation. Local audit classifies C 283810 discrepancy labels as queue losses and one as truthful uncorrelated success; A paced had one file-registry update failure. No full lifecycle fidelity or production evidence equivalence established. Review limitations documented in #4 comment 7165662311. Preserve artifacts and checkpoints; no further A/B/C tuning or reruns. #7 comparative experiment now complete; no further comparative reruns.

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
- #4: Evaluate minimal kernel-side state (experimental phase complete; C not adopted; disposition recorded in selected architecture).
- #7: Persistent evidence versus online reconstruction (experiment complete; integration/validation planning; issue remains open).
- Final product integration and correctness validation pending scoped implementation approval. Standalone replay demonstration accepted within tested scope.
- #5: Remaining descriptor and registry limitations.
- #6: Repair legacy test build paths.

## Known Limitations

- Severe burst loss remains even in P (10.77% persisted creation completeness); no universal losslessness claim.
- Historical P native replay timed out in all three sustained trials; corrected standalone replay of trial 1 now succeeds twice. Successful original final sync not independently confirmed; full graph/lifecycle fidelity and production evidence integrity not established.
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
