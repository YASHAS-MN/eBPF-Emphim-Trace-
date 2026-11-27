# EphimTrace — Provenance Benchmark 01 Report
## Comprehensive Graph Engine Evaluation under GitHub Issue #9

**Date**: 2026-11-27  
**Repository Worktree**: `/home/magellan/Garage/prototypes/FM/FM-persist`  
**Active Branch**: `remediation/state-independence-and-loss-accountability`  
**Engine Under Test**: Offline Provenance Reconstruction Engine (`src/user/replay.c`, `src/user/provenance.c`, `src/user/evidence_io.h`)  
**Constraint**: Evaluated strictly without modifications to production code (`src/user/provenance.c`, `src/user/replay.c`).

---

## Executive Summary

To fulfill **Provenance Benchmark 01** under **GitHub Issue #9**, this campaign performed an exhaustive quantitative evaluation of the EphimTrace provenance reconstruction engine across three rigorous dimensions:

1. **Reconstruction Correctness**: Evaluated against an independently specified mathematical ground-truth contract covering standard lifecycles, PID recycling, descriptor reuse, memfd reopening, execution success versus failure, and stress conditions (missing, duplicated, and reordered events). All evaluations use exact typed, directed entity and multiplicity matching ($P = \frac{TP}{TP+FP}$, $R = \frac{TP}{TP+FN}$).
2. **Computational Performance**: Measured across 4 event scales ($10^3$, $10^4$, $10^5$, and $10^6$ events) with 5 isolated repetitions per configuration, capturing ingestion throughput, CPU utilization, isolated peak resident set size (RSS), valid non-empty subgraph extraction latency, and serialization costs for DOT, JSON, and forensic timeline markdown.
3. **Native Forensic Validation**: Verified against native kernel evidence sessions:
   - Milestone M2.4 Memfd Execution (`native_exec_7Q2iUm`, 599 verified records, 0 drops)
   - Milestone M2.4 Unlinked Executable (`native_unlinked_T4pJiz`, 385 verified records, 0 drops)
   - 15 Native Pressure Workloads (`W_PACED`, `W_BURST`, `W_SUSTAIN` $\times$ 5 repetitions in `benchmark_01/data/`, up to 420,669 events/session)
   - Replayed and exported to fresh, writable destination `tests1.0/kernel_telemetry/benchmark_01/native_exports/`.

---

## Dimension 1: Reconstruction Correctness

### 1.1 Independent Ground-Truth Contract Specification
The provenance engine reconstructs a Directed Acyclic Graph (DAG) $G = (V, E)$ from an event stream $\mathcal{E} = \langle e_1, e_2, \dots, e_N \rangle$:

- **Node Identity Invariants**:
  - **Process Node** $v_{\text{proc}} \in V$: Identity is strictly $(pid, start\_time\_ns)$ formatted as `proc_<pid>_<start_time>`. If $start\_time\_ns = 0$, falls back to active PID registry lookup, or `proc_<pid>_0` if inactive.
  - **Memfd Node** $v_{\text{memfd}} \in V$: Identity is strictly the monotonically allocated kernel token formatted as `memfd_<object_token>`.
  - **FS Object Node** $v_{\text{fs}} \in V$: Identity is strictly $(dev\_id, inode\_no)$ formatted as `fs_<dev>_<inode>`. Validated via `VFS_IDENTITY_INODE_VALID | VFS_IDENTITY_DEV_VALID`.
  - **Net Endpoint Node** $v_{\text{net}} \in V$: Identity is $(family, ip, port)$ formatted as `net_<family>_<ip>_<port>`.

- **Directed Edge Semantics**:
  - $e_{\text{FORK}}: v_{\text{parent}} \to v_{\text{child}}$
  - $e_{\text{MEMFD\_CREATE}}: v_{\text{proc}} \to v_{\text{memfd}}$
  - $e_{\text{FD\_INSTALLED}}: v_{\text{proc}} \to v_{\text{memfd}}$ (attributes: `install_type` $\in$ {`CREATION`, `REOPEN`, `DUP`}, `fd`)
  - $e_{\text{FD\_CLOSED}}: v_{\text{proc}} \to v_{\text{memfd}}$ (attributes: `duration_ns`, `fd`)
  - $e_{\text{MEMFD\_WRITE}}: v_{\text{proc}} \to v_{\text{memfd}}$ (attributes: `offset`, `bytes`)
  - $e_{\text{MEMFD\_EXEC\_ATTEMPT}}: v_{\text{proc}} \to v_{\text{memfd}}$ (attributes: `target_filename`)
  - $e_{\text{MEMFD\_EXEC\_SUCCESS}}: v_{\text{proc}} \to v_{\text{memfd}}$ (attributes: `binary_comm`, transforms process `comm`)
  - $e_{\text{FS\_EXEC\_SUCCESS}}: v_{\text{proc}} \to v_{\text{fs}}$ (attributes: `binary_comm`, transforms process `comm`)
  - $e_{\text{UNLINK}}: v_{\text{proc}} \to v_{\text{fs}}$ (attributes: `path`, `status` $\in$ {`SUCCESS`, `FAILED`})
  - $e_{\text{CONNECT}}: v_{\text{proc}} \to v_{\text{net}}$ (attributes: `result`)

### 1.2 Quantitative Correctness Results
Evaluated using the dedicated test suite `tests1.0/test_provenance_correctness.c` using exact typed, directed multiset matching with multiplicity accounting:

| Test Suite | Expected Nodes | Actual Nodes | Node Prec. / Rec. | Expected Edges | Actual Edges | Edge Prec. / Rec. | Attr. Fidelity | False Joins | False Splits | Result |
|---|---|---|---|---|---|---|---|---|---|---|
| **1. Standard Lifecycle** | 5 | 5 | 100.0% / 100.0% | 9 | 9 | 100.0% / 100.0% | 100.0% (12/12) | 0 | 0 | **SUCCESS** |
| **2. PID Reuse Separation** | 5 | 5 | 100.0% / 100.0% | 4 | 4 | 100.0% / 100.0% | 100.0% (4/4) | 0 | 0 | **SUCCESS** |
| **3. FD Reuse & Reopening** | 4 | 4 | 100.0% / 100.0% | 4 | 4 | 100.0% / 100.0% | 100.0% (4/4) | 0 | 0 | **SUCCESS** |
| **4. Exec Representation** | 7 | 7 | 100.0% / 100.0% | 7 | 7 | 100.0% / 100.0% | 100.0% (6/6) | 0 | 0 | **SUCCESS** |
| **5. Robustness & Faults** | 5 | 5 | 100.0% / 100.0% | 4 | 5 | 80.0% / 100.0% | 100.0% (3/3) | 0 | 0 | **SUCCESS\*** |

*\*Note on Test 5: Test execution succeeded as a benchmark harness. The edge precision deficit (80.0%, 4 TP / 5 Actual) was an intentional fault injection exposing an engine deficiency where duplicate FORK edges are unconditionally appended.*

### 1.3 Key Correctness Findings
1. **PID Reuse Separation**: When processes with identical PIDs have distinct `start_time_ns`, the engine creates completely separate nodes (`proc_3000_1000000` vs `proc_3000_2000000`) with zero cross-contamination of descriptors or edges (0 false joins, 0 false splits).
2. **FD Recycling**: When a process reuses file descriptor 3 across successive memfd allocations, the engine uses the unique kernel `object_token`, keeping `memfd_201` and `memfd_202` completely distinct.
3. **Execution Representation (Success vs Failure)**:
   - **Successful Exec**: Produces an `EDGE_MEMFD_EXEC_ATTEMPT` followed by an `EDGE_MEMFD_EXEC_SUCCESS`, successfully updating the process node's `comm` attribute to the new binary identity.
   - **Failed Exec (e.g., -ENOEXEC)**: Produces an `EDGE_MEMFD_EXEC_ATTEMPT` but **no** `EDGE_MEMFD_EXEC_SUCCESS`. The process `comm` remains unchanged, and process exit records the failure exit status (e.g., 126).
4. **Memfd Reopening Across Processes**: When a child or peer process reopens a memfd via `/proc/<pid>/fd/N` or `/dev/fd/N` (`EVENT_FD_INSTALLED` with `op_type=2`), the edge connects from the reopening process to the original `memfd_<token>` node, accurately modeling shared memory IPC.

---

## Dimension 2: Computational Performance

### 2.1 Methodology & Measurement Integrity
- **Experimental Protocol**: Evaluated at 4 event scales: 1,000, 10,000, 100,000, and 1,000,000 events.
- **Repetitions**: 5 independent runs per scale.
- **Process Isolation**: Each trial was executed inside an isolated forked subprocess (`fork` + `wait4`), ensuring `ru_maxrss` accurately reflects the exact physical resident set size of the reconstruction engine at that scale, without monotonic process-lifetime accumulation errors.
- **Valid Subgraph Targets**: Coordinator PID 1000 and target token 1 were decoupled via a coprime prime cycle (23) ensuring non-empty, connected subgraphs across all scales (`sub.node_count > 0`, `sub.edge_count > 0`).
- **Export Verification**: All export return codes were strictly validated (`rc == 0`), file sizes verified non-zero, and content headers confirmed (`digraph`, `{`, `# EphimTrace`).
- **Adjacency Mode**: Production default incoming search mode ($O(1)$ in-degree lookup).

### 2.2 Aggregate Performance Results (5 Repetitions per Configuration)

| Scale ($N$ Events) | Graph Structure (Nodes / Edges) | Replay Throughput (events/s) | Ingestion Duration (s) | User CPU (ms) | Sys CPU (ms) | Isolated Peak RSS (MiB) | Subgraph Extr. (PID filter) | Subgraph Extr. (Token filter) | Export DOT (ms) | Export JSON (ms) | Export Timeline (ms) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **1,000** | 174 / 950 | $256,342.3 \pm 13,791.9$ | $0.0039 \pm 0.0002$ | $1.4 \pm 0.9$ | $2.5 \pm 1.0$ | **$1.68 \pm 0.00$** | $25.73 \pm 10.53\ \mu\text{s}$ | $10.58 \pm 0.70\ \mu\text{s}$ | $0.43 \pm 0.07$ (161 KB) | $0.58 \pm 0.04$ (207 KB) | $0.73 \pm 0.09$ (229 KB) |
| **10,000** | 1,074 / 9,500 | $286,221.1 \pm 3,339.4$ | $0.0349 \pm 0.0004$ | $21.9 \pm 3.3$ | $13.0 \pm 3.1$ | **$5.04 \pm 0.09$** | $481.61 \pm 192.00\ \mu\text{s}$ | $192.62 \pm 5.52\ \mu\text{s}$ | $3.29 \pm 0.30$ (1.47 MB) | $4.85 \pm 0.16$ (1.92 MB) | $6.74 \pm 0.31$ (2.28 MB) |
| **100,000** | 10,074 / 95,000 | $288,301.1 \pm 1,823.8$ | $0.3469 \pm 0.0022$ | $213.1 \pm 5.8$ | $133.7 \pm 7.0$ | **$40.40 \pm 0.08$** | $14.29 \pm 3.32\ \text{ms}$ | $11.95 \pm 3.99\ \text{ms}$ | $36.82 \pm 0.74$ (14.6 MB) | $57.56 \pm 0.93$ (19.0 MB) | $93.12 \pm 3.67$ (22.8 MB) |
| **1,000,000** | 100,074 / 950,000 | $272,854.5 \pm 5,085.8$ | $3.6662 \pm 0.0691$ | $2,179.6 \pm 18.3$ | $1,441.4 \pm 11.8$ | **$393.37 \pm 0.11$** | $175.78 \pm 9.53\ \text{ms}$ | $171.31 \pm 5.14\ \text{ms}$ | $390.94 \pm 3.54$ (145.9 MB) | $576.10 \pm 6.18$ (190.0 MB) | $979.99 \pm 15.64$ (228.2 MB) |

### 2.3 Computational Performance Observations
1. **Sustained High Throughput**: Ingestion throughput consistently exceeds **250,000 events/second** across all scales, reaching a peak of $288,301\ \text{events/s}$ at 100,000 events and $272,855\ \text{events/s}$ at 1,000,000 events. Replaying 1,000,000 forensic events completes in **3.67 seconds**.
2. **Linear Physical Memory Scaling**: Peak resident set size scales strictly linearly $O(N)$ with graph density:
   - 1K events: 1.68 MiB
   - 10K events: 5.04 MiB
   - 100K events: 40.40 MiB
   - 1M events: 393.37 MiB (~393 bytes per event, encapsulating node structures, edge structures, adjacency linked lists, hash buckets, and string allocations).
3. **Subgraph Extraction Latency**:
   - For a 10,000-event graph: Subgraph extraction takes **$193\\ \\mu\\text{s}$ to $482\\ \\mu\\text{s}$**.
   - For a 1,000,000-event graph (100k nodes, 950k edges): Full multi-hop connected subgraph traversal completes in **171 to 176 ms**.
4. **Serialization and Timeline Scaling**:
   - Writing full graph DOT (145.9 MB) requires **391 ms**.
   - Writing full graph JSON (190.0 MB) requires **576 ms**.
   - Sorting and serializing a 950,000-event chronological forensic markdown timeline (228.2 MB) completes in **980 ms**.

---

## Dimension 3: Native Forensic Validation

### 3.1 Scenario 1: Native Memfd Execution (`native_exec_7Q2iUm`)
- **Evidence Session**: 599 verified records, 0 drops, lossless.
- **File Ownership & Permissions**: Owned by `root:root` mode `0600` (captured during privileged loader session); replayed and rendered to `reconstruction/`.
- **Workload Verification**:
  - Test 1 (`execveat(AT_EMPTY_PATH)`): Child 17550 executed token 7 (`m2_exec_script_1`). Replay constructed `EDGE_FORK` $\to$ `MEMFD_CREATE` $\to$ `MEMFD_WRITE` $\to$ `MEMFD_EXEC_ATTEMPT` $\to$ `MEMFD_EXEC_SUCCESS` $\to$ comm updated to `/dev/fd/3`.
  - Test 2 (`fexecve()`): Child 17551 executed token 8 (`m2_exec_fexecve`). Replay constructed full execution sequence and comm transform.
  - Test 3 (`/proc/self/fd/N` reopening): Child 17552 executed token 9 (`m2_exec_proc_reopen`). Replay constructed reopen descriptor install $\to$ `MEMFD_EXEC_SUCCESS`.
  - Test 4 (Invalid memfd execution abort): Child 17553 attempted execution of corrupted token 10. Replay constructed `MEMFD_EXEC_ATTEMPT` with **no** `MEMFD_EXEC_SUCCESS`, maintaining comm `test_m2_exec`.
- **Metrics**: 103 nodes, 227 edges, duration: 0.0019 s (309,101 eps), peak RSS: 2.59 MiB. Match rate: 4 of 4 test cases (100.0% precision).

### 3.2 Scenario 2: Native Unlinked Executable (`native_unlinked_T4pJiz`)
- **Evidence Session**: 385 verified records, 0 drops, lossless.
- **Forensic Causality Reconstructed**:
  - Parent coordinator 26660 forked worker child 26661 at `5609153731716 ns`.
  - Child 26661 successfully executed binary file `fs_66309_926197` (`/tmp/ephim_unlinked_a9yQSP/unlinked_worker`) at `5609154192924 ns`.
  - Parent 26660 unlinked file `fs_66309_926197` at `5609154802662 ns` while child 26661 was executing. Node transitioned to `[UNLINKED]`.
  - Parent 26660 unlinked directory `fs_66309_926187` at `5609155114530 ns`. Node transitioned to `[UNLINKED]`.
- **Metrics**: 58 nodes, 152 edges, duration: 0.0012 s (318,190 eps), peak RSS: 2.66 MiB.
- **Forensic Integrity**: Preserved complete causal provenance and original pathname for the deleted binary even though the file no longer exists on disk.

### 3.3 Scenario 3: Native Pressure Workloads (`benchmark_01/data/`)
Replayed natively into fresh writable directory `tests1.0/kernel_telemetry/benchmark_01/native_exports/`:

| Workload | Repetition | Verified Records | Capture Status | Nodes | Edges | Ingestion Duration | Throughput (events/s) | Peak RSS (MiB) | Workload Creations Matched |
|---|---|---|---|---|---|---|---|---|---|
| **W_PACED** | Rep 1 | 3,901 | **COMPLETE_LOSSLESS** | 616 | 2,221 | 0.017 s | 226,210.3 | 855.18* | 500 / 500 (100.0%) |
| | Rep 2 | 3,873 | **COMPLETE_LOSSLESS** | 611 | 2,205 | 0.014 s | 276,500.0 | 855.18* | 500 / 500 (100.0%) |
| | Rep 3 | 3,898 | **COMPLETE_LOSSLESS** | 613 | 2,220 | 0.014 s | 281,581.1 | 855.18* | 500 / 500 (100.0%) |
| | Rep 4 | 3,904 | **COMPLETE_LOSSLESS** | 618 | 2,225 | 0.015 s | 262,179.9 | 855.18* | 500 / 500 (100.0%) |
| | Rep 5 | 3,871 | **COMPLETE_LOSSLESS** | 610 | 2,205 | 0.015 s | 258,946.8 | 855.18* | 500 / 500 (100.0%) |
| **W_BURST** | Rep 1 | 70,301 | **COMPLETE_LOSSLESS** | 10,092 | 40,166 | 0.284 s | 247,610.6 | 855.18* | 10,000 / 10,000 (100.0%) |
| | Rep 2 | 70,303 | **COMPLETE_LOSSLESS** | 10,095 | 40,169 | 0.252 s | 278,948.6 | 855.18* | 10,000 / 10,000 (100.0%) |
| | Rep 3 | 70,295 | **COMPLETE_LOSSLESS** | 10,088 | 40,164 | 0.253 s | 277,382.2 | 855.18* | 10,000 / 10,000 (100.0%) |
| | Rep 4 | 70,308 | **COMPLETE_LOSSLESS** | 10,092 | 40,170 | 0.260 s | 270,087.5 | 855.18* | 10,000 / 10,000 (100.0%) |
| | Rep 5 | 70,319 | **COMPLETE_LOSSLESS** | 10,096 | 40,177 | 0.255 s | 275,861.8 | 855.18* | 10,000 / 10,000 (100.0%) |
| **W_SUSTAIN** | Rep 1 | 420,669 | **COMPLETE_LOSSLESS** | 60,185 | 240,363 | 1.742 s | 241,467.2 | 855.18* | 60,000 / 60,000 (100.0%) |
| | Rep 2 | 420,627 | **COMPLETE_LOSSLESS** | 60,168 | 240,334 | 1.531 s | 274,698.9 | 855.18* | 60,000 / 60,000 (100.0%) |
| | Rep 3 | 420,627 | **COMPLETE_LOSSLESS** | 60,167 | 240,333 | 1.539 s | 273,347.0 | 855.18* | 60,000 / 60,000 (100.0%) |
| | Rep 4 | 421,050 | **COMPLETE_LOSSLESS** | 60,217 | 240,593 | 1.557 s | 270,493.5 | 855.18* | 60,000 / 60,000 (100.0%) |
| | Rep 5 | 420,678 | **COMPLETE_LOSSLESS** | 60,178 | 240,371 | 1.541 s | 273,017.4 | 855.18* | 60,000 / 60,000 (100.0%) |

*\*Note on Peak RSS in standalone CLI: The standalone `build/replay` CLI utility process allocates an evidence read buffer and standard glibc dynamic arena. In contrast, the isolated sub-process tests in Section 2 measure the exact RSS of the graph engine structures.*

### 3.4 Capture-Completeness Epistemic Boundary
- **Candidate Default (64 MiB)**: In the 15 production telemetry sessions shown above, all 15 sessions achieved **COMPLETE_LOSSLESS** capture status (0 ring buffer drops, 0 sequence gaps, 0 storage persistence errors).
- **Constrained Capacity Comparison (1 MiB / 4 MiB)**: In contrast, the capacity benchmark campaign (`ring_capacity_20261127-174712`) demonstrated that burst workloads under 4 MiB suffered **29,094 kernel drops** (capture recall 98.50%). Thus, the collector's buffer capacity governs kernel event completeness, while the provenance engine independently reconstructs 100% of persisted evidence.

---

## Deficiency Analysis & Attribution

In strict adherence to `PROJECT_STATE.md` and Issue #9 reporting integrity rules, we categorize and attribute all identified limitations:

### 4.1 Collection Deficiencies (Kernel Hook / BPF Layer)
1. **Ring Buffer Overflows Under High Burst Pressure**:
   - Under smaller buffer capacities (1 MiB / 4 MiB), kernel reservation drops occur during intense concurrent bursts.
   - *Impact*: Events dropped in the kernel never reach userspace evidence files.
2. **Process Comm Truncation**:
   - The Linux kernel `task_struct.comm` is fixed at 16 bytes (`TASK_COMM_LEN = 16`). Long executable paths (e.g., `./build/test_m2_unlinked_exec`) are truncated in `comm` to `test_m2_unlinke`.
   - *Impact*: In the graph engine, if `EVENT_PROCESS_EXEC.path` is empty, comm is used as fallback, resulting in truncated process labels.
3. **Execution Exit Code Granularity**:
   - When an execve syscall fails with `-ENOEXEC` or `-EACCES`, `sched_process_exec` does not fire (as the process did not transform). Telemetry relies on `EVENT_MEMFD_EXEC_ATTEMPT` without a corresponding `EVENT_MEMFD_EXEC_SUCCESS`. The terminating exit code is only captured when the process subsequently calls `exit_group()`.

### 4.2 Reconstruction Deficiencies (Userspace Provenance Engine)
1. **Unconditional Edge Insertion on Duplicate Events**:
   - In `src/user/provenance.c`, `prov_add_edge()` unconditionally inserts a new edge struct into the source outbound and destination inbound lists.
   - *Demonstrated Deficiency*: Duplicate `EVENT_FORK`, `EVENT_MEMFD_WRITE`, or `EVENT_FD_INSTALLED` records produce multiple identical parallel edges in the graph (multiplicity violation, dropping edge precision to 80.0% in Test 5). Only `EVENT_MEMFD_COMPLETED` is explicitly deduplicated against `EVENT_MEMFD_CREATE`.
2. **PID Reuse Fallback Merging (`start_time_ns = 0`)**:
   - When `EVENT_PROCESS_EXIT` fires, `unregister_active_proc(pid)` removes the PID from `g_active_pid_buckets`.
   - If a subsequent event for the same PID arrives with `start_time_ns = 0`, `find_active_proc(pid)` returns `NULL`, causing `prov_upsert_process` to create or merge into `proc_<pid>_0`. If multiple distinct generations arrive with zero start times, they falsely merge into `proc_<pid>_0`.
3. **Missing Parent Event Orphanage**:
   - If an `EVENT_FORK` record is dropped in the kernel, subsequent child events still instantiate the child node, but the node has `ppid = 0`, `comm = "<unknown>"`, and no inbound causal edge connects it to the parent process.
4. **Fixed Hash Bucket Capacity**:
   - Node hash table is statically sized at `PROV_HASH_SIZE = 16384` buckets without dynamic rehashing. At 1,000,000 events (100,074 nodes), average bucket chain length increases to ~6.1 nodes. While throughput remains high (>272k eps), dynamically resized hash tables would be required for >10M scale graphs.

---

## Reproducible Commands

All benchmarks, correctness evaluations, and native validations can be independently reproduced using the following commands executed from the active worktree root (`/home/magellan/Garage/prototypes/FM/FM-persist`):

### 1. Build Production and Test Binaries
```bash
make clean && make all
```

### 2. Run Reconstruction Correctness Suite
```bash
./build/test_provenance_correctness
```

### 3. Run Computational Performance Benchmark (1K to 1M events, 5 reps each)
```bash
./build/test_provenance_perf
# Verified machine-readable outputs saved to:
# tests1.0/kernel_telemetry/benchmark_provenance_perf_results.json
```

### 4. Replay Native Pressure Workloads into Fresh Writable Directory
```bash
mkdir -p tests1.0/kernel_telemetry/benchmark_01/native_exports

# Replay W_PACED
./build/replay tests1.0/kernel_telemetry/benchmark_01/data/W_PACED_rep_1.evid \
    --dot tests1.0/kernel_telemetry/benchmark_01/native_exports/paced_dag.dot \
    --json tests1.0/kernel_telemetry/benchmark_01/native_exports/paced_dag.json \
    --timeline tests1.0/kernel_telemetry/benchmark_01/native_exports/paced_timeline.md \
    --summary-json tests1.0/kernel_telemetry/benchmark_01/native_exports/paced_summary.json

# Replay W_BURST
./build/replay tests1.0/kernel_telemetry/benchmark_01/data/W_BURST_rep_1.evid \
    --dot tests1.0/kernel_telemetry/benchmark_01/native_exports/burst_dag.dot \
    --json tests1.0/kernel_telemetry/benchmark_01/native_exports/burst_dag.json \
    --timeline tests1.0/kernel_telemetry/benchmark_01/native_exports/burst_timeline.md \
    --summary-json tests1.0/kernel_telemetry/benchmark_01/native_exports/burst_summary.json

# Replay W_SUSTAIN
./build/replay tests1.0/kernel_telemetry/benchmark_01/data/W_SUSTAIN_rep_1.evid \
    --dot tests1.0/kernel_telemetry/benchmark_01/native_exports/sustain_dag.dot \
    --json tests1.0/kernel_telemetry/benchmark_01/native_exports/sustain_dag.json \
    --timeline tests1.0/kernel_telemetry/benchmark_01/native_exports/sustain_timeline.md \
    --summary-json tests1.0/kernel_telemetry/benchmark_01/native_exports/sustain_summary.json
```

### 5. Inspect Forensic Reconstructions
```bash
# Verify rendered SVG and PNG graphs
ls -l docs/provenance_reconstruction/
```

---

## Review & Acceptance State

- [x] **Dimension 1**: Precision, recall, PID reuse, FD reuse, and exec representation quantitatively verified using exact typed, directed multiset matching.
- [x] **Dimension 2**: 4 scales ($10^3, 10^4, 10^5, 10^6$) $\times$ 5 repetitions evaluated with isolated RSS, non-empty subgraphs, return code checks, and serialization costs.
- [x] **Dimension 3**: Native memfd execution, unlinked execution, and 15 pressure workloads replayed and exported to fresh writable directory.
- [x] **Epistemic boundary preserved**: Collection vs reconstruction deficiencies explicitly separated.
- [x] **Production code kept 100% frozen**: No optimizations or graph engine modifications implemented ahead of review.
