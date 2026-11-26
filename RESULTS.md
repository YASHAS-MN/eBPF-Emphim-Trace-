# EphimTrace — Experimental Results and Proof-of-Concept Findings

**Date:** 2026-11-25  
**Status:** Experimental evaluation complete; implementation and current performance testing paused pending owner architecture selection.  
**Scope:** Diagnostic memfd creation-operation reconciliation and supporting lifecycle telemetry. This is a consolidated engineering results record, not a claim of production forensic completeness.

## 1. Objective and experimental design

EphimTrace investigates how eBPF-based telemetry can preserve evidence completeness, fidelity and provenance for ephemeral Linux objects. The experiment distinguishes kernel observation, event transport, queue admission and userspace reconstruction. Throughput is secondary to reliable evidence.

| Candidate | Kernel | Userspace |
|---|---|---|
| A | Stateful inode/file/descriptor registries and kernel object tokens | Synchronous ring consumer and existing provenance engine |
| B | Same stateful kernel approach | Dedicated acquisition, bounded FIFO, one processing worker, existing provenance engine |
| C | Compact inode/file/descriptor registries with expanded capacities, no kernel token generator | B topology plus userspace canonical correlator; existing provenance engine |

All three retain a 1 MiB kernel ring. B/C use a 65,536-record queue. C changes registry capacity as well as state placement, so its registry improvement cannot isolate the effect of relocation.

Final environment: Linux 7.0.0-44-generic, x86_64, 12 online CPUs, full-processing quiet diagnostic mode, five interleaved triplet blocks, seed 42. The independent workload executable hash was reported identical across candidates. The workload records per-create syscall returns/errno, PID/TID and unique names; write/close ground truth is primarily aggregate. The rigorous reconciled scope is **memfd_create intent and completion**, including expected processing outcomes; secondary lifecycle counters do not establish full per-operation lifecycle fidelity.

| Workload | Workers | Iterations/worker | Attempts/trial | Pace (us) | Held FDs |
|---|---:|---:|---:|---:|---|
| W_PACED | 1 | 500 | 500 | 1000 | No |
| W_BURST | 4 | 2500 | 10000 | 0 | No |
| W_SUSTAIN | 4 | 15000 | 60000 | 50 | No |
| W_CONTENTION | 8 | 5000 | 40000 | 0 | No |
| W_REGISTRY | 1 | 10000 | 10000 | 100 | Yes |

Final run: 75 trials, 1,807,500 configured operation attempts (120,500 per block per architecture). Earlier A/B run: 50 trials. Smoke and other validation experiments are separate. No production evidence-preserving sink comparison was completed.

## 2. Metrics and normalization

See [Benchmark Specification](tests1.0/kernel_telemetry/BENCHMARK_SPEC.md). Ground truth uses unique attempted operations, not event counts. H/K/S/R track hook execution, reservation, submission and reception; queue admission/drain adds a boundary for B/C; P evaluates processing outcomes. Use matching populations independently.

| Metric | Definition / unit |
|---|---|
| N attempted, reconstructed, incomplete | Independent syscall records; unique reconciled pairs; remainder |
| Creation completeness C_e2e | Reconstructed / attempted (percentage) |
| Incomplete fraction F | 1 - reconstructed / attempted |
| Generation gaps | Expected observations not generated; reported gap categories and deficits, not interchangeable with operations |
| Ring reservation failures | Failed reservations; report target event types 2/12 separately from global counts |
| Ring transport | Submitted vs received, after drain |
| Queue admission / drops / HWM | Attempts, enqueued, rejected and maximum occupancy, all-record population unless explicitly scoped |
| Queue drain | Enqueued vs dequeued |
| Fidelity | Corrupt tokens, actual outcome inversions, incorrect-outcome labels, correlation deficiencies, duplicates, Checkpoint P discrepancies |
| Residuals | Independent stage and operation conservation; zero residual does not imply no loss |
| Offered throughput | Attempted / monotonic workload duration, ops/s |
| Useful throughput | Reconstructed / elapsed workload plus target processing drain, ops/s |
| Drain latency | max(0, last target processing timestamp - workload done), ms; global backlog separately |
| CPU | Workload process rusage; telemetry all-thread active and total CPU; us/attempted and us/reconstructed |
| Memory | Peak userspace RSS, queue allocation, kernel map capacities and sizes separately |
| Profiling | Reception, process state, inclusive/exclusive provenance, logging, diagnostic P and callback/worker timing (ns/event, matching denominators) |

Conservation: attempted operations = reconstructed + incomplete. Ring attempts = submitted + reservation failures. Submitted = received + transport losses. Queue attempts = enqueued + rejected; admitted = dequeued + drain residual. Do not sum event and operation populations or infer unique causes from aggregate counts. Diagnostic sidecar is limited to 131,072 target type-2/type-12 records; overflow invalidates affected reconciliation. P=5 can represent queue rejection rather than a worker logic failure.

### Approved candidate acceptance targets

1. Paced 100% creation completeness, zero drops.
2. Zero corrupted tokens, outcome inversions and unexplained residuals.
3. At least 50% relative burst incomplete-fraction reduction versus fresh A (preserve zero loss if A has zero).
4. At least 20% sustained useful-throughput improvement versus A.
5. Additional peak RSS at most 64 MiB.
6. Mean burst drain at most 1,000 ms (as evaluated by original analyzer).

Five repetitions; report means, variation and per-trial validity. Original analyzer verdicts preserved; later discrepancy interpretation is not a retrospective threshold change.

## 3. Development and remediation results

Historical knowledge base: [Obsidian](https://github.com/YASHAS-MN/Obsidian), Master Engineering Timeline and M1/M2 validation notes. Initial implementation demonstrated syscall/process/VFS observation and ring transport; per-CPU attachment correction restored observed correlation on tested CPUs. M1 creation identity (entry -> fd_install -> exit) accepted 11 November within tested scope. PID generation information, syscall/VFS identity, and separation of FD slots, open-file descriptions and backing objects were established as necessary. Historical M2.1 duplicate-accounting and token-continuity concerns remained at handoff; do not read that milestone as universal lifecycle acceptance.

| Remediation | Result / boundary |
|---|---|
| C1: initialize object_token | Recycled ring memory could carry stale tokens; explicit initialization corrected detected corruption in subsequent validation |
| C2: ordinary descriptor close | file_close_fd entry hook added the seventh expected successful lifecycle observation in the tested workload; close intent is not confirmed successful removal |
| C3: registry correlation | Check insert outcomes before claiming correlation; success-correlated=2, failed=1, success-uncorrelated=3. Controlled insertion failures preserve successful return and token=0 with op=3. Natural mutation error causes and concurrency/rollback edge cases remain |
| C4A: optional quiet mode | Diagnostic only; normal logging default. Real callback replay of 26 events: identical final 2 processes, 1 thread, 6 nodes, 12 edges and P outcomes; stdout 3238 vs 0 bytes. Not production evidence retention equivalence |

### Quiet-mode native comparison (36 valid measurements reported)

| Metric | Normal | Quiet |
|---|---:|---:|
| Paced full callback (ns) | 3313 | 1494 |
| Full callback (ns) | 8200 | 7370 |
| Parallel full callback (ns) | 6728 | 7061 |
| Parallel full missing completions (of 20000) | 18480 | 18367 |
| Parallel full reservation failures (global/measurement population as reported) | 126729 | 128059 |

No reported corruption, P discrepancies or generation gaps. Paced latency reduction about 55%; no material high-pressure completeness improvement. Logging suppresses some observations not represented in graph, so quiet is not evidence-equivalent. [Issue #2 review](https://github.com/YASHAS-MN/eBPF-Emphim-Trace-/issues/2#issuecomment-7153784264), [callback source review](https://github.com/YASHAS-MN/eBPF-Emphim-Trace-/issues/2#issuecomment-7154110047).

### First A/B comparison (50 reported valid trials)

| Workload | A completeness % | B completeness % | A useful ops/s | B useful ops/s |
|---|---:|---:|---:|---:|
| Paced | 100 | 100 | 913.7 | 913.7 |
| Burst | 7.90 | 84.54 | 14679.4 | 3295.0 |
| Sustained | 12.34 | 28.98 | 3864.5 | 1156.4 |
| Contention | 1.88 | 12.28 | 6022.3 | 1393.7 |
| Registry | 40.96 | 40.96 | 2214.4 | 2224.9 |

B: burst incomplete fraction reduced 83.2%, sustained useful throughput -70.1%, peak RSS 98.2 vs A 23.7 MiB (+74.5), mean burst drain 2527.3 ms. Queue maximum occupancy 7 paced, 629 registry, 61509 burst, 65536 contention/sustained; zero burst queue rejection; sustained mean global queue drops 298268. Original verdict 2/6. Local audit reports 29520 truthful uncorrelated success labels per candidate across registry trials, not actual syscall inversions. [Issue #3 result](https://github.com/YASHAS-MN/eBPF-Emphim-Trace-/issues/3#issuecomment-7156413383), [audit review](https://github.com/YASHAS-MN/eBPF-Emphim-Trace-/issues/3#issuecomment-7157130486).

C implementation required corrective work on status constants, fast-mode provenance initialization, worker shutdown, raw/canonical separation, bounded state and missing-event detection. Native quick suite 20261125-191112: all six valid; five 100% completeness, deliberate stall 4.5%. Reported regression suites passed; synthetic tests do not prove complete lifetime identity under loss. Final C diagnostic harness added worker timing and correlator statistics. No candidate adopted.

## 4. Final three-way comparative results

Source: owner-supplied native terminal output for three_way_20261125-194503 and subsequent local 75-trial audit; five observations per workload/architecture. All 75 reported measurement-valid; this does not mean complete or faithful evidence. Values below are trial means unless stated otherwise.

### 4.1 Creation-operation completeness

| Workload | A reconstructed | B reconstructed | C reconstructed | A % | B % | C % |
|---|---:|---:|---:|---:|---:|---:|
| W_PACED | 500 | 500 | 500 | 99.96 | 100.00 | 100.00 |
| W_BURST | 743 | 8234 | 8145 | 7.43 | 82.34 | 81.45 |
| W_SUSTAIN | 7348 | 17335 | 17185 | 12.25 | 28.89 | 28.64 |
| W_CONTENTION | 743 | 5149 | 4522 | 1.86 | 12.87 | 11.30 |
| W_REGISTRY | 4096 | 4096 | 10000 | 40.96 | 40.96 | 100.00 |

Counts rounded by analyzer. A paced actual 2499/2500; C registry audit reports one incomplete creation (49999/50000, 99.998%, rounded 100.00). Original printed figures retained.

### 4.2 Stage loss counts

| Workload | A target create ring reservation failures | B | C | A global queue drops | B | C |
|---|---:|---:|---:|---:|---:|---:|
| Paced | 0 | 0 | 0 | 0 | 0 | 0 |
| Burst | 17351 | 2136 | 2256 | 0 | 0 | 0 |
| Sustained | 98925 | 0 | 0 | 0 | 299144 | 299497 |
| Contention | 75441 | 23461 | 29091 | 0 | 120091 | 100862 |
| Registry | 0 | 0 | 0 | 0 | 0 | 0 |

Rounded means; ring figures target create records (types 2/12), queue counts global, so cannot sum or compare as equivalent populations. Zero reported unexplained residuals do not imply no loss.

### 4.3 Offered and useful throughput

| Workload | Offered A | Offered B | Offered C | Useful A | Useful B | Useful C |
|---|---:|---:|---:|---:|---:|---:|
| Paced | 912.9 | 911.8 | 912.5 | 912.5 | 911.7 | 912.5 |
| Burst | 303491.8 | 201601.1 | 222113.7 | 15756.6 | 3235.2 | 3486.8 |
| Sustained | 33605.4 | 31776.4 | 31693.5 | 3833.3 | 1084.7 | 1121.6 |
| Contention | 423150.6 | 361507.4 | 375892.0 | 6323.2 | 1404.0 | 1504.0 |
| Registry | 5398.1 | 5403.1 | 5510.4 | 2211.0 | 2213.1 | 3156.1 |

Units ops/s. Mean useful throughput reported 95% CI half-widths A/B/C: burst 1177.3/186.2/110.0; sustained 68.7/98.1/47.0; contention 916.9/137.3/65.8; registry 10.4/11.6/30.3; paced 3.9/1.1/2.8. These are reported marginal intervals, not paired effect intervals or a significance claim. Higher A useful throughput occurs alongside much lower completeness and shorter measured windows; do not interpret as equivalent work processed faster.

### 4.4 Drain and memory

| Workload | Drain A ms | Drain B ms | Drain C ms | Mean peak RSS A MiB | B | C |
|---|---:|---:|---:|---:|---:|---:|
| Paced | 0.0 | 0.0 | 0.0 | 17.9 | 17.9 | 17.9 |
| Burst | 14.2 | 2522.1 | 2299.9 | 18.0 | 64.0 | 64.0 |
| Sustained | 131.7 | 14235.9 | 13457.9 | 23.2 | 97.7 | 99.8 |
| Contention | 23.7 | 3538.0 | 2906.8 | 17.9 | 82.5 | 78.4 |
| Registry | 0.0 | 0.0 | 1353.8 | 17.9 | 42.0 | 72.7 |

Maximum observed peak RSS across workloads: A 23.4, B 97.9, C 99.9 MiB (rounded). B/C queue storage: 65,536 x 672-byte entries = 44,040,192 bytes (42 MiB), reported 664-byte wire event; allocated storage is not necessarily fully resident in low-load trials.

### 4.5 CPU

| Workload | Producer CPU A ms | B | C | Loader active CPU A ms | B | C |
|---|---:|---:|---:|---:|---:|---:|
| Paced | 22.3 | 23.9 | 23.8 | 138.3 | 159.0 | 161.9 |
| Burst | 132.3 | 163.4 | 155.1 | 164.7 | 2709.0 | 2481.6 |
| Sustained | 1119.5 | 1508.4 | 1508.2 | 2035.8 | 16799.7 | 16043.5 |
| Contention | 646.4 | 756.3 | 728.0 | 240.3 | 3854.4 | 3216.8 |
| Registry | 302.5 | 304.9 | 279.5 | 699.3 | 828.8 | 3197.4 |

| Workload | Active CPU/attempt A | B | C | Active CPU/reconstructed A | B | C |
|---|---:|---:|---:|---:|---:|---:|
| Paced | 276.64 | 317.99 | 323.79 | 276.75 | 317.99 | 323.79 |
| Burst | 16.47 | 270.90 | 248.16 | 221.72 | 327.07 | 304.02 |
| Sustained | 33.93 | 279.99 | 267.39 | 277.10 | 968.90 | 933.53 |
| Contention | 6.01 | 96.36 | 80.42 | 325.88 | 759.97 | 711.19 |
| Registry | 69.93 | 82.88 | 319.74 | 170.72 | 202.34 | 319.75 |

Units us/op. Total loader CPU per attempted op A/B/C: paced 762.96/798.28/807.69; burst 40.50/294.84/271.89; sustained 37.94/284.01/271.35; contention 12.09/102.37/86.36; registry 93.92/106.84/343.65. No matched no-monitor producer control reported: do not attribute producer CPU differences specifically to BPF overhead. C vs B lower active CPU on burst/contention/sustained also accompanies fewer reconstructed operations; not isolated algorithm speedup.

### 4.6 Registry footprint: source-based estimates

| Map | A/B capacity x value bytes | C capacity x value bytes |
|---|---|---|
| inode registry | 4096 x 312 | 16384 x 32 |
| file registry | 8192 x 8 | 32768 x 32 |
| descriptor registry | 16384 x 24 | 32768 x 24 |

Value payload totals approximately 1.66 MiB (A/B) and 2.25 MiB (C), excluding keys, hash overhead, per-CPU maps, allocator and other maps. Source layout assumptions for x86_64; not actual allocated kernel RAM. Both descriptor values 24 bytes, correcting final audit's 16-byte figure. C reduces inode value size but increases overall capacity and eliminates kernel token generator. This is compacting selected state, not removing all three registries.

### 4.7 Fidelity and uncertainty audit

Original analyzer labels all incorrect_outcome records as inversions. This is not equivalent to semantic success/failure inversion.
- B: 29,520 reported labels from W_REGISTRY, interpreted as truthful uncorrelated successes (5904/trial).
- C: 283,811 labels: 212,175 sustained, 71,635 contention, 1 registry. Local audit reports 283,810 zero-token raw op2 records with P=5 caused by queue rejection before token assignment; one registry file-map insertion error yielded truthful op3. This explains the classification artifact, not a recovery of lost evidence. P=5 also represents processing failures in other paths; aggregate labels alone do not prove the precise cause of every record.
- A: 2499/2500 paced creates; one W_PACED_1 file registry other_error, truthful op3, no reported target transport loss. Exact kernel errno/underlying cause remains unresolved.
- C registry rounded 100% includes the one incomplete operation; no claim of flawless registry or lifecycle attribution.

Local audit reported aggregate P discrepancies A/B/C: paced 1/0/0; burst 0/0/0; contention 0/168730/141575; sustained 0/410374/411693; registry 29520/29520/1. Generation gap category counts: paced 2/0/0, registry 15/15/2, other workloads zero. These counts reflect stage classifications and may overlap, not unique lost operations. Audit claim of zero C uncorrelated creations conflicts with its own op3/P=3 report; actual uncertainty counter is uncertain_correlation_count. No claim of 100% attribution across all worker-ingested events. Lifetime identity propagation, stale descriptor matches, correlator state limits and raw/canonical field preservation remain bounded.

### 4.8 Original acceptance verdicts (unchanged)

| Criterion | B vs A | C vs A |
|---|---|---|
| Paced 100%, zero drops | PASS | PASS |
| Fidelity | FAIL (29520 labels) | FAIL (283811 labels) |
| Burst incomplete fraction reduction >=50% | PASS (80.9%) | PASS (80.0%) |
| Sustained useful throughput gain >=20% | FAIL (-71.7%) | FAIL (-70.7%) |
| Additional peak RSS <=64 MiB | FAIL (+74.6 MiB reported) | FAIL (+76.5 MiB) |
| Burst drain <=1000ms | FAIL (2522.1) | FAIL (2299.9) |
| Overall | 2/6 | 2/6 |

A is reference, not a candidate evaluated against itself; A paced did not meet the ideal 100% control criterion. No candidate passed all requirements.

## 5. Findings and architecture implications

1. Functional proof of concept: native eBPF observation, controlled creation identity, transport and provenance graph reconstruction work within evaluated scope; independent reconciliation exposes loss and correlation failures.
2. A's synchronous path has low resident memory and short drain but severe kernel loss at pressure. Its higher useful rate is conditioned on admitted work and short completion window, not evidence-equivalent superiority.
3. Decoupling improves burst absorption: B/C capture roughly 82/81% of create pairs versus A 7.43%. Under sustained load, queue admission replaces target creation ring reservation as dominant observed loss boundary. A larger finite queue alone cannot eliminate persistent arrival/service imbalance.
4. Registry compaction/capacity changes in C greatly improve held-FD stress. This is a candidate feature, not proof that all kernel correlation should be moved. C retains three compact registries and introduces extra userspace identity machinery.
5. Processing/provenance and instrumentation costs remain important. Exact bottleneck attribution to a specific graph algorithm, token atomic, queue lock or reaping scan is not isolated. C code reaps by scanning buckets at new allocations; possible cost, not separately measured.
6. No automatic adoption: A's simplicity and kernel-assisted identity, B's burst buffering, C's compact metadata and uncertainty handling are options for a later owner-led design discussion. Existing code can be reused, but feature fusion is not guaranteed correct by existing experiments; scoped correctness/integration validation is needed after selection.

## 6. Reproducibility and evidence boundaries

Historical results retained locally under tests1.0/kernel_telemetry/results/:

| Dataset | Purpose |
|---|---|
| 20261125-105108, -105116, -105125, -105146 | Normal/quiet quick and pressure |
| interleaved_20261125-132015 | Initial 50-trial A/B |
| 20261125-191112 (C worktree) | C native quick |
| three_way_20261125-194414 | 9-trial A/B/C smoke |
| three_way_20261125-194503 | Final 75-trial comparison; preflight_provenance.json, per-architecture trial JSON/logs, three_way_comparison_summary.json |

Reference A source checkpoint: 49ece70dc72a14799aac6a94c6b62d65c2a78bfd. Reported final-run preflight commits: A 82f0e3e25db4995ea24e4d84ca30e0f5c934a0db, B e49763549e0da6007cb0c9e9c1ffd543e3953ccc, C 4a5de9a4a512cad889af987a7e8056aff658f26c. Reported identical workload digest 7b7386acb3f9cd92e65d7b71260425c7f66f98c4ef22123ec32d1e0e23ada156. Native preflight records actual binary digests but builds only absent binaries; full source-to-binary correspondence not independently verified. Earlier A/B exact build identity unresolved. Raw logs and manifests were not independently accessed by reviewer; result tables transcribed from user-supplied native outputs and local audit, selected source behavior independently inspected via GitHub. Preserve originals, do not commit generated/raw artifacts; the document is a traceable summary, not a substitute for original evidence.

Known limits: only tested memfd creation-pair scope; no persistent production evidence equivalence, universal kernel compatibility, complete descriptor/fork/dup/reopen/close lifecycle, independent lifetime identity or isolated kernel overhead proven. Different loss populations and instrumentation overhead complicate comparisons. Full benchmark verdict remains unchanged. No new performance runs or implementation changes are authorized by this results record.

### Review trail

- [Project state](PROJECT_STATE.md)
- [Issue #2 — quiet diagnostic optimization](https://github.com/YASHAS-MN/eBPF-Emphim-Trace-/issues/2)
- [Issue #3 — asynchronous experiment](https://github.com/YASHAS-MN/eBPF-Emphim-Trace-/issues/3)
- [Issue #4 — minimal kernel state and three-way comparison](https://github.com/YASHAS-MN/eBPF-Emphim-Trace-/issues/4)
- [Final native comparison review](https://github.com/YASHAS-MN/eBPF-Emphim-Trace-/issues/4#issuecomment-7165195502)
- [Final audit review and pause](https://github.com/YASHAS-MN/eBPF-Emphim-Trace-/issues/4#issuecomment-7165662311)

**Conclusion:** The experimental phase establishes a working bounded proof of concept and measured architectural trade-offs, not a production-qualified system. Final architecture selection is deferred to the project owner.


## 7. Persistence experiment — online versus deferred reconstruction (26 November 2026)

This subsequent owner-approved experiment (Issue #7) freezes A's kernel hooks, identity, registries, 1 MiB ring and existing graph engine. M appends evidence then constructs provenance online; P uses the same bounded evidence writer during collection and defers graph processing until capture ends. Neither uses B/C's intermediate FIFO. This is an exploratory diagnostic experiment, not a production-qualified storage design.

Native run: `persist_20261126-012121` (18 trials, 3 paired repetitions, seed 42, matched quiet mode), with preceding corrected six-trial smoke `persist_20261126-012106`. Native capture commit `3774978f75305fa15101c79478bfd076adc11b8a`; offline reader correction `c4c9cf91b3520e911b315d1a0961203bf89457be`. Original analyzer reports contain erroneous 0% persistence and corruption flags due to Python integer-magic byte order and payload-index defects. Preserve original reports; corrected owner-executed read-only disk audit used actual binary files, target PID, event types 2/12, and independent syscall ground truth with P evaluation disabled. No workload reruns. Audit results are user-supplied terminal measurements, not raw files independently accessed by the reviewer.

### 7.1 Verified persisted creation pairs

| Workload | Attempts per trial | M reconstructed, trials 1/2/3 | P reconstructed, trials 1/2/3 | M completeness | P completeness |
|---|---:|---|---|---:|---:|
| W_PACED | 500 | 500 / 500 / 500 | 500 / 500 / 500 | 100.0000% | 100.0000% |
| W_BURST | 10000 | 515 / 550 / 499 | 1242 / 833 / 1157 | 5.2133% | 10.7733% |
| W_SUSTAIN | 60000 | 6814 / 7232 / 7205 | 60000 / 60000 / 60000 | 11.8061% | 100.0000% |

All six smoke files reconcile every attempted operation (50 paced, 200 burst, 400 sustained per mode). Full experiment: M and P each preserve 1500/1500 paced pairs; burst M 1564/30000 vs P 3232/30000 (2.07x retained pairs); sustained M 21251/180000 vs P 180000/180000 (8.47x retained pairs, +88.19 percentage points). Both models retain original wire records; completion correlation is assessed with the existing kernel token and return/descriptor fields. This is verified correlated creation-pair completeness, not whole-lifecycle or graph completeness.

### 7.2 Verified evidence records (all recorded event types)

| Workload | M verified records, trials 1/2/3 | P verified records, trials 1/2/3 |
|---|---|---|
| W_PACED | 3551 / 3527 / 3525 | 3582 / 3527 / 3511 |
| W_BURST | 9737 / 10042 / 9936 | 23347 / 21255 / 21680 |
| W_SUSTAIN | 46584 / 47652 / 47904 | 420074 / 420101 / 420082 |

All 24 audited files report zero detected CRC/framing corruption, sequence gaps or truncations. P sustained contains 1,260,257 verified records across three trials. File framing and sequence integrity do not prove zero upstream loss, complete kernel coverage, adversarial tamper resistance, or successful power-loss durability. The three P sustained sessions timed out during native graph replay; their saved files were readable and intact, but successful final synchronization is not independently recorded in completed reports. Treat those sessions as valid evidence-readback observations with unavailable native end-to-end graph and phase metrics. Do not infer graph completion, graph throughput, or zero ring loss from disk reconciliation.

### 7.3 Interpretation and remaining boundaries

The experiment provides direct evidence that removing immediate graph construction from the collection path improves retained creation completeness in the tested sustained workload, without changing the underlying kernel approach. Burst capture remains highly incomplete (P 10.77%); this architecture is not generally lossless. Native M/P comparison is not equivalent to the earlier A/B/C graph-completeness comparison. The P sustained replay timeout is a genuine unresolved end-to-end limitation; source inspection reveals an O(n^2) diagnostic lookup, but its sole causal responsibility has not been established. Graph-engine complexity, actual production sink throughput, storage failure and crash durability, full lifecycle coverage and external collector parity are not proven. The raw evidence and ground truth remain locally preserved. No further performance reruns are recommended for architectural selection.

**Recommendation (not owner approval):** retain A's kernel-assisted identity and adopt a P-derived collection-first persistence architecture, with separate replayable provenance analysis. Make live graphs optional and independent of acquisition. Scope remaining work to integration and correctness validation after owner lock-in; do not revive B/C or general performance tuning without explicit need.

[Final direct disk-readback audit and review](https://github.com/YASHAS-MN/eBPF-Emphim-Trace-/issues/7#issuecomment-7182734475).
