# EphimTrace — Project State

Last updated: 2026-11-28

## Objective

Develop an eBPF-based forensic telemetry and provenance system prioritizing evidence completeness, fidelity, and reliable reconstruction of ephemeral and unlinked executable activity.

## Resources

- Codebase: https://github.com/YASHAS-MN/eBPF-Emphim-Trace-
- Knowledge base: https://github.com/YASHAS-MN/Obsidian
- Project board: https://github.com/users/YASHAS-MN/projects/1
- Current implementation checkpoint: 1115e2c (locally validated integrated Phase 1 candidate; Task 04 merge pending)
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

## Provenance Benchmark Status

Scoped #9 cycle completed. Visual examples at 83f27af; corrected benchmark harness at 1484ea9; fork deduplication and unresolved identity representation at 8f592d7; exit status unknown under actual producer contract at b6c89af. Reported corrected fixture results: six suites with exact typed node/edge matching and selected attributes. At 8f592d7 the 1M-event benchmark averaged 4.15 s and 393.43 MiB peak RSS (five repetitions); 1484ea9 averaged 3.67 s and 393.37 MiB. Final narrow exit-status correction received targeted regressions, not a full repeated performance suite. No further component optimization approved. Raw native evidence not independently inspected; historical M2.4 kernel loss counts unavailable. See #9 comment 7231709070.

## End-to-End Benchmark Status

Scoped #10 native campaign completed at frozen implementation b6c89af; final harness and report dcb8659. Reviewed committed aggregate JSON: 15/15 valid sessions, 110/110 selected expected entities, 170/170 selected typed directed relationships, all matrix timelines ordered, zero reported instrumented drops. Five concurrent sessions each preserved approximately 420.9k records and replayed in 2.764–2.975 s (first replay), ~114 MiB peak replay RSS. Soak preserved 507592 records / 353284096 bytes over ~1803 s (1797 s sampled span), 131.32 MiB peak sampled collector RSS without observed growth. Five bounded failure controls reported passed. Initial 64 MiB evidence-ceiling harness mistake and ground-truth parser errors corrected without production changes.

Scoped recall only; full precision, multiplicity and attribute fidelity not established by this harness. Reconciler establishes structural repeatability, not bit-identical DOT/JSON; raw evidence hashes and soak markers not independently checked. Observed concurrent wall-time difference +37.75% is not isolated collector overhead. Workload and shutdown mean 5.474 s includes deliberate 2 s sleep and excludes offline replay/export. Mean shutdown 0.927 s is not disk throughput. Failure control success means expected recovery/containment, not zero loss. See #10 conclusion comment 7234502858. Correct overclaims before publication.

## Release Qualification Task 01

Scoped descriptor remediation accepted at a61a3e7. Native abfe508 results (a66c342 report): 1512 frames, 666 workload events, 228 nodes/1076 edges, 27/27 hooks, zero reported losses; 5/5 expected installs, ordinary replacement false close eliminated, shared table child close attributed. Final a61a3e7 source reviewed, targeted synthetic tests and native workload-only assertions reported; integrated native smoke completed at 1115e2c after fixing a private-map CO-RE relocation failure exposed by the clean build; selected descriptor cases passed. Raw evidence not independently inspected. #5 remains open for deferred residual races, table lifetime and unobserved cleanup limitations; not universal concurrency safety. See comment 7235437800.

## Release Qualification Task 02

Scoped replay and evidence integrity qualification passed on the isolated qualification/replay-final-safety branch. Baseline 9ae8e30, final production changes at 6561bc4, validation at 5e996ab and ef84c41. Owner locally compiled replay and tests. At 5e996ab all 28 replay qualification checks and five bounded failure controls passed. An outdated integration assertion expecting acceptance of malformed counters was corrected in ef84c41; all ten integration suites then passed, including executable strict rejection (rc=7) without graph export. No production changes in the final test-only commit.

Replay CLI now rejects in-place overwrite flags; new files are required. Default exclusive creation protects existing evidence and manifest objects against output alias truncation. Strict missing-manifest replay requires explicit legacy opt-in. Manifest parser rejects oversized documents, malformed or missing persistence counters, invalid numeric loss fields and signed counter-sum overflow. Known positive loss and standard prefix recovery remain supported. This is tested-scope integrity protection, not cryptographic authentication or proof of universal crash durability; standalone provenance library overwrite API is not covered by the replay CLI guarantee. No new native collector run or performance benchmark performed.

## Release Qualification Task 03

At b036418 the owner locally built the normal replay binary and dedicated linker-wrapped fault-injection executable. All 23 fault-injection cases passed (including two no-fault controls), all six provenance correctness suites, ten pipeline integration suites and 28 replay safety checks passed. Initialization allocation failures return 3; detected ingestion failures return 8 and suppress graph exports in both standard and strict modes while continuing evidence verification; tested single-export scratch allocation failures return 6. Original evidence and manifest unchanged in fault tests. This does not establish recovery from OS OOM termination or atomic publication of multiple exports. Compiler warning from evidence_writer_init path copy into 256-byte buffer observed in the test build; short generated fixture path fits, but long-path validation remains a deployment task.

## Release Qualification Task 04

Candidate branch qualification/deployment-compatibility. At 3905dca clean compilation of BPF object, loader, replay and test binaries; 10/10 pipeline integration suites and 44/44 CLI checks passed. Checked numeric arguments, power-of-two ring sizes, evidence path length/character constraints, stale manifest rejection, regular input file checks and fail-closed ring resizing. Initial native smoke failed to load capture_do_dup2_exit because bpf_core_read generated a relocation for private map type pending_dup2.fd. At 1115e2c replaced only the indexed slot read with bpf_probe_read_kernel; native verification and attachment then succeeded.

Owner native results at 1115e2c, x86_64 kernel 7.0.0-44-generic, BTF present, CPUs 0-11, GCC 13.3.0, clang 16.0.6: 27/27 logical hooks, 60/60 per-CPU attachments; 28/28 workload assertions; orderly shutdown and finalized synchronized manifest. Two strict replays each verified and replayed 708 records, 23 nodes/658 edges, no reported corruption, gaps, short records, registry/token errors or ring drops. DOT, JSON and timeline byte-identical across replays; evidence SHA256 e0e6fd61993f120e5f12891defd1162feb8d4cbca427dd2be7e15411ed4767f1 and manifest b63bc9c26bb8b7ac9d10a97b6a85e364e1dabb8ff0d7f602018dc120f52ec858 unchanged. Five workload memfd tokens uniquely resolved; expected duplication FDs 3,4,30,35,36 matched raw events and graph; one replacement close before destroy, reuse close and child 74890 CLONE_FILES close matched graph; no negative FD install/close. Local private artifacts /tmp/ephim_native_2b5920qe. Raw binary evidence not independently inspected. No claim of universal losslessness or other-kernel support.

## Current Task

All four planned Phase 1 tasks validated within scope; awaiting owner merge of Task 04. Then proceed to Phase 2 comparative evaluation, followed by owner-operated CLI prototype demonstration and approval before GUI/productization, then external validation. No additional Phase 1 benchmark campaign.

## Outstanding Release Work

- #5 descriptor/registry concurrency and lifetime limitations.
- Broader telemetry coverage, field fidelity (actual exit status unavailable and now represented as unknown), long-run operation, overload envelope, failure recovery, storage integrity and compatibility.
- Multi-export publication atomicity, OS OOM termination, crash durability and cryptographic authentication remain unverified; additional kernel/host compatibility and broader capture coverage remain future work.
- Benchmark reporting corrections noted above.
- No merge or release implied by this update.

## Validation Infrastructure

- tests1.0/kernel_telemetry/benchmark_01/
- tests1.0/kernel_telemetry/runner.py (historical diagnostic lab, not production benchmarking)
- tests1.0/test_pipeline_integration.c
- tests1.0/test_qualification_replay.c
- tests1.0/test_graph_allocation_failure.c
- tests1.0/kernel_telemetry/qualification_deployment/
- tests1.0/test_m6_dag.c and test_m6_filtering.c
- tests1.0/kernel_telemetry/benchmark_e2e_01/

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
ChatGPT: Source investigation, implementation and tests on isolated GitHub branches, review, and project tracking.
Project owner: Local compilation, execution, and validation logs; approve integration.
Antigravity/Zed and Codex: Reserved for difficult local debugging, complex engineering, or independent review.
GitHub: Development history and task tracking.
Obsidian: Technical knowledge and architectural decisions.

This file is a handoff index, not a substitute for source, experiments or the knowledge base.
