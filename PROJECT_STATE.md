# EphimTrace — Project State

Last updated: 2026-11-27

## Objective

Develop an eBPF-based forensic telemetry and provenance system prioritizing evidence completeness, fidelity, and reliable reconstruction of ephemeral and unlinked executable activity.

## Resources

- Codebase: https://github.com/YASHAS-MN/eBPF-Emphim-Trace-
- Knowledge base: https://github.com/YASHAS-MN/Obsidian
- Project board: https://github.com/users/YASHAS-MN/projects/1
- Current implementation checkpoint: 9d5bb5176278f1dd7e75b74302daafbf1cfe96a6
- Working branch: remediation/state-independence-and-loss-accountability
- Initial production benchmark baseline: 056ec9b
- Historical Architecture A reference: 49ece70dc72a14799aac6a94c6b62d65c2a78bfd

## Current Architecture

Kernel hooks and identity registries
    -> Configurable kernel ring buffer (64 MiB candidate default; 4 MiB low-memory)
    -> Synchronous userspace collector and evidence writer
    -> Persistent binary records and loss manifest
    -> Independent offline replay, provenance graph and exports

Collection and reconstruction are separate. The current architecture is retained for the next evaluation, not approved as universally optimal or release-ready.

## Completed Work

- A/B/C and online/deferred experiments; deferred evidence-first acquisition selected.
- Scoped native memfd execution and unlinked ELF reconstruction at 056ec9b.
- Production Benchmark 01: OSBench and controlled syscall ground truth.
- Remediation: registry-state independence for creation completion and exec cleanup, per-type ring reservation loss counters, distinction between persistence and capture completeness.
- Controlled fault injection and replay loss discrimination validated within tested scope at 7fea4b9.
- Capacity experiments (1/4/16/64 MiB); 64 MiB retained for tested bursts.
- Production Benchmark 01 repeated at 9d5bb51, five trials each paced/burst/sustained, ten paired OSBench runs per task.

## Telemetry Benchmark Status

Scoped performance and remediation cycle concluded. Owner-reported native results:

| Metric | 056ec9b | 9d5bb51 |
| --- | --- | --- |
| Paced creation completion matches | 500/500 | 500/500 each trial |
| Burst creation completion matches | 2212/10000 | 10000/10000 each trial |
| Sustained creation completion matches | 60000/60000 | 60000/60000 each trial |
| Ring reservation loss | unknown | zero reported in 15 trials |
| OSBench process creation overhead | 8.92% | 8.60% |
| OSBench program launch overhead | 0.41% | -0.03% |
| OSBench file operations overhead | 19.64% | 19.95% |
| Burst entry-to-reception p99 | 3.12 ms | 77.13 ms |

Raw local evidence has not been independently inspected by reviewer. Source review confirms the report must label type-12 completion matches rather than creation pairs; drain throughput has mismatched numerator/denominator scope; mmap RSS and physical ring memory overlap. Correct those report claims from retained artifacts. Zero reported reservation drops is not a universal completeness guarantee. No industry certification, external collector parity, or production qualification claimed.

See #7 and final benchmark review comment 7219218200.

## Current Task

#9 — Benchmark provenance reconstruction correctness and scalability.

Freeze collector semantics and current checkpoint while evaluating graph construction independently. First produce inspectable DOT/SVG/PNG, JSON and timeline examples for verified memfd and unlinked ELF sessions, with explicit evidence-to-node/edge correspondence. Then evaluate normalized graph correctness, attribute fidelity, missing/duplicate evidence behavior, deterministic replay, scalability and export performance. Existing graph tests are partial functional checks, not comprehensive benchmarks. No GUI or algorithm redesign before measuring the baseline.

## Outstanding Release Work

- #5 descriptor/registry concurrency and lifetime limitations.
- Broader telemetry coverage, field fidelity (notably process exit status placeholder), long-run operation, overload envelope, failure recovery, storage integrity and compatibility.
- Evidence manifest/replay hardening, export alias protection and graph allocation failure handling.
- End-to-end validation, deployment requirements and release qualification.
- Benchmark reporting corrections noted above.
- No merge or release implied by this update.

## Validation Infrastructure

- tests1.0/kernel_telemetry/benchmark_01/
- tests1.0/kernel_telemetry/runner.py (historical diagnostic lab, not production benchmarking)
- tests1.0/test_pipeline_integration.c
- tests1.0/test_m6_dag.c and test_m6_filtering.c

Keep raw evidence and generated artifacts private and out of Git. Preserve previous results; do not overwrite evidence.

## Development Rules

1. Read project state and active GitHub issue first; inspect actual source.
2. Keep one scoped implementation task active; obtain approval before architectural changes.
3. Review source and raw measurements; distinguish measured facts, assumptions and limitations.
4. Never equate clean persistence with complete capture or a rendered graph with correct reconstruction.
5. Record decisions and unresolved limitations; update this file when the active task changes.
6. GUI development remains out of scope.

## Role Delegation

Project owner: Architecture and acceptance decisions.
ChatGPT: Engineering discussion and code review.
Antigravity: Scoped implementation and local validation.
GitHub: Development history and task tracking.
Obsidian: Technical knowledge and architectural decisions.

This file is a handoff index, not a substitute for source, experiments or the knowledge base.
