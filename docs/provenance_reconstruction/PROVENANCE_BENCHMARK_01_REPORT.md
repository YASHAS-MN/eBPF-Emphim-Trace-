# EphimTrace — Provenance Benchmark 01 Report
## Comprehensive Graph Engine Evaluation under GitHub Issue #9

**Date**: 2026-11-27  
**Git HEAD**: `83f27afce117340daafdaee5a98b891d00ce9e0d` (branch `remediation/state-independence-and-loss-accountability`)  
**Engine Under Test**: Offline Provenance Reconstruction Engine (`src/user/replay.c`, `src/user/provenance.c`, `src/user/evidence_io.h`)  
**Constraint**: Evaluated strictly without modifications to production code (`src/user/provenance.c`, `src/user/replay.c`).

---

## Executive Summary

To fulfill **Provenance Benchmark 01** under **GitHub Issue #9**, this campaign performed an exhaustive evaluation of the EphimTrace provenance reconstruction engine across three rigorous dimensions:

1. **Reconstruction Correctness**: Evaluated against an independently specified mathematical ground-truth contract covering standard lifecycles, PID recycling, descriptor reuse, memfd reopening, execution success versus failure, and stress conditions (missing, duplicated, and reordered events).
2. **Computational Performance**: Measured across 4 event scales ($10^3$, $10^4$, $10^5$, and $10^6$ events) with 5 isolated repetitions per configuration, capturing ingestion throughput, CPU utilization, isolated peak resident set size (RSS), subgraph extraction latency, and serialization costs for DOT, JSON, and forensic timeline markdown.
3. **Native Forensic Validation**: Verified against native kernel evidence sessions:
   - Milestone M2.4 Memfd Execution (`native_exec_7Q2iUm`, 599 verified records, 0 drops)
   - Milestone M2.4 Unlinked Executable (`native_unlinked_T4pJiz`, 385 verified records, 0 drops)
   - 15 Native Pressure Workloads (`W_PACED`, `W_BURST`, `W_SUSTAIN` $\times$ 5 repetitions in `benchmark_01/data/`, up to 421,000 events/session)

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
Evaluated using the dedicated test suite `tests1.0/test_provenance_correctness.c`:

| Test Suite | Expected Nodes | Actual Nodes | Node Prec. / Rec. | Expected Edges | Actual Edges | Edge Prec. / Rec. | Attr. Fidelity | False Joins | False Splits | Result |
|---|---|---|---|---|---|---|---|---|---|---|
| **1. Standard Lifecycle** | 5 | 5 | 100.0% / 100.0% | 9 | 9 | 100.0% / 100.0% | 100.0% (12/12) | 0 | 0 | **PASS** |
| **2. PID Reuse Separation** | 5 | 5 | 100.0% / 100.0% | 4 | 4 | 100.0% / 100.0% | 100.0% (4/4) | 0 | 0 | **PASS** |
| **3. FD Reuse & Reopening** | 4 | 4 | 100.0% / 100.0% | 4 | 4 | 100.0% / 100.0% | 100.0% (4/4) | 0 | 0 | **PASS** |
| **4. Exec Representation** | 7 | 7 | 100.0% / 100.0% | 7 | 7 | 100.0% / 100.0% | 100.0% (6/6) | 0 | 0 | **PASS** |
| **5. Robustness & Faults** | 5 | 5 | 100.0% / 100.0% | 4 | 5 | 80.0% / 100.0% | 75.0% (3/4) | 0 | 0 | **PASS\*** |

*\*Note on Test 5: The edge precision deficit (80.0%) was an intentional fault injection exposing an engine deficiency (duplicate fork edges are not deduplicated).*

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
- **Adjacency Mode**: Production default incoming search mode ($O(1)$ in-degree lookup).

### 2.2 Aggregate Performance Results (5 Repetitions per Configuration)

| Scale ($N$ Events) | Graph Structure (Nodes / Edges) | Replay Throughput (events/s) | Ingestion Duration (s) | User CPU (ms) | Sys CPU (ms) | Isolated Peak RSS (MiB) | Subgraph Extr. (PID filter) | Subgraph Extr. (Token filter) | Export DOT (ms) | Export JSON (ms) | Export Timeline (ms) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **1,000** | 951 / 950 | $241,385.0 \pm 12,938.5$ | $0.0042 \pm 0.0002$ | $2.2 \pm 1.0$ | $2.0 \pm 1.1$ | **$2.05 \pm 0.00$** | $58.70 \pm 31.34\ \mu\text{s}$ | $23.71 \pm 11.20\ \mu\text{s}$ | $0.85 \pm 0.15$ | $1.20 \pm 0.15$ | $0.05 \pm 0.01$ |
| **10,000** | 2,651 / 9,500 | $257,304.4 \pm 5,299.1$ | $0.0389 \pm 0.0008$ | $21.6 \pm 2.6$ | $17.2 \pm 1.9$ | **$5.91 \pm 0.05$** | $573.80 \pm 242.40\ \mu\text{s}$ | $208.05 \pm 127.61\ \mu\text{s}$ | $4.62 \pm 0.32$ | $7.15 \pm 0.43$ | $0.41 \pm 0.20$ |
| **100,000** | 11,651 / 95,000 | $256,306.2 \pm 2,149.3$ | $0.3902 \pm 0.0033$ | $239.8 \pm 6.7$ | $150.3 \pm 8.6$ | **$40.82 \pm 0.06$** | $10.09 \pm 0.87\ \text{ms}$ | $5.12 \pm 1.68\ \text{ms}$ | $41.75 \pm 1.02$ | $65.17 \pm 1.75$ | $8.14 \pm 1.57$ |
| **1,000,000** | 101,651 / 950,000 | $217,633.5 \pm 2,191.3$ | $4.5954 \pm 0.0469$ | $2982.6 \pm 49.3$ | $1607.0 \pm 52.3$ | **$390.69 \pm 0.08$** | $89.91 \pm 4.87\ \text{ms}$ | $86.50 \pm 4.61\ \text{ms}$ | $435.17 \pm 4.99$ | $620.22 \pm 17.04$ | $89.59 \pm 3.22$ |

### 2.3 Computational Performance Observations
1. **Throughput Stability**: Ingestion throughput remains remarkably stable across orders of magnitude: ~257k events/s at 10k events, ~256k events/s at 100k events, and only slightly tapering to ~218k events/s at 1M events. Replaying 1,000,000 forensic events completes in under **4.6 seconds**.
2. **Linear Memory Footprint**: Peak resident set size scales strictly linearly $O(N)$ with graph density:
   - 1K events: 2.05 MiB
   - 10K events: 5.91 MiB
   - 100K events: 40.82 MiB
   - 1M events: 390.69 MiB (~390 bytes per event in memory, including all node structs, edge structs, adjacency pointers, hash tables, and string buffers).
3. **Subgraph Extraction Latency**:
   - For a 10,000-event graph: Subgraph extraction takes **$208\ \mu\text{s}$ to $574\ \mu\text{s}$**.
   - For a 1,000,000-event graph (101k nodes, 950k edges): Subgraph extraction completes in **86 to 90 ms**, enabling near-instant interactive queries.
4. **Serialization Costs**:
   - JSON serialization is consistently ~40% slower than DOT serialization due to formatted JSON field emission and comma tracking.
   - For 1M events, the full DOT export (147.7 MB) completes in 435 ms, and full JSON export (191.9 MB) in 620 ms.

---

## Dimension 3: Native Forensic Validation

### 3.1 Scenario 1: Native Memfd Execution (`native_exec_7Q2iUm`)
- **Evidence Session**: 599 verified records, 0 drops, lossless.
- **Workload Verification**:
  - Test 1 (`execveat(AT_EMPTY_PATH)`): Child 17550 executed token 7 (`m2_exec_script_1`). Replay constructed `EDGE_FORK` $\to$ `MEMFD_CREATE` $\to$ `MEMFD_WRITE` $\to$ `MEMFD_EXEC_ATTEMPT` $\to$ `MEMFD_EXEC_SUCCESS` $\to$ comm updated to `/dev/fd/3`.
  - Test 2 (`fexecve()`): Child 17551 executed token 8 (`m2_exec_fexecve`). Replay constructed full execution sequence and comm transform.
  - Test 3 (`/proc/self/fd/N` reopening): Child 17552 executed token 9 (`m2_exec_proc_reopen`). Replay constructed reopen descriptor install $\to$ `MEMFD_EXEC_SUCCESS`.
  - Test 4 (Invalid memfd execution abort): Child 17553 attempted execution of corrupted token 10. Replay constructed `MEMFD_EXEC_ATTEMPT` with **no** `MEMFD_EXEC_SUCCESS`, maintaining comm `test_m2_exec`.
- **Match Rate**: 4 of 4 execution test cases matched independent ground truth with 100% precision.

### 3.2 Scenario 2: Native Unlinked Executable (`native_unlinked_T4pJiz`)
- **Evidence Session**: 385 verified records, 0 drops, lossless.
- **Forensic Causality Reconstructed**:
  - Parent coordinator 26660 forked worker child 26661 at `5609153731716 ns`.
  - Child 26661 successfully executed binary file `fs_66309_926197` (`/tmp/ephim_unlinked_a9yQSP/unlinked_worker`) at `5609154192924 ns`.
  - Parent 26660 unlinked file `fs_66309_926197` at `5609154802662 ns` while child 26661 was executing. Node transitioned to `[UNLINKED]`.
  - Parent 26660 unlinked directory `fs_66309_926187` at `5609155114530 ns`. Node transitioned to `[UNLINKED]`.
- **Forensic Integrity**: Preserved complete causal provenance and original pathname for the deleted binary even though the file no longer exists on disk.

### 3.3 Scenario 3: Native Pressure Workloads (`benchmark_01/data/`)
Evaluated across 15 native sessions (5 repetitions $\times$ 3 workloads):

| Workload | Repetition | Verified Records | Reconstructed Nodes | Reconstructed Edges | Replay Ingestion Time | Throughput (events/s) | Peak RSS (MiB) | Workload Creations Matched |
|---|---|---|---|---|---|---|---|---|
| **W_PACED** | Rep 1 | 3,901 | 616 | 2,221 | 0.0138 s | 282,676.6 | 11.68 | 500 / 500 (100.0%) |
| | Rep 2 | 3,873 | 611 | 2,205 | 0.0140 s | 276,500.0 | 11.68 | 500 / 500 (100.0%) |
| | Rep 3 | 3,898 | 613 | 2,220 | 0.0138 s | 281,581.1 | 11.68 | 500 / 500 (100.0%) |
| | Rep 4 | 3,904 | 618 | 2,225 | 0.0149 s | 262,179.9 | 11.68 | 500 / 500 (100.0%) |
| | Rep 5 | 3,871 | 610 | 2,205 | 0.0149 s | 258,946.8 | 11.68 | 500 / 500 (100.0%) |
| **W_BURST** | Rep 1 | 70,301 | 10,092 | 40,166 | 0.2604 s | 269,939.5 | 20.65 | 10,000 / 10,000 (100.0%) |
| | Rep 2 | 70,303 | 10,095 | 40,169 | 0.2520 s | 278,948.6 | 20.65 | 10,000 / 10,000 (100.0%) |
| | Rep 3 | 70,295 | 10,088 | 40,164 | 0.2534 s | 277,382.2 | 20.64 | 10,000 / 10,000 (100.0%) |
| | Rep 4 | 70,308 | 10,092 | 40,170 | 0.2603 s | 270,087.5 | 20.28 | 10,000 / 10,000 (100.0%) |
| | Rep 5 | 70,319 | 10,096 | 40,177 | 0.2549 s | 275,861.8 | 20.40 | 10,000 / 10,000 (100.0%) |
| **W_SUSTAIN** | Rep 1 | 420,669 | 60,185 | 240,363 | 1.5467 s | 271,972.2 | 114.03 | 60,000 / 60,000 (100.0%) |
| | Rep 2 | 420,627 | 60,168 | 240,334 | 1.5312 s | 274,698.9 | 114.28 | 60,000 / 60,000 (100.0%) |
| | Rep 3 | 420,627 | 60,167 | 240,333 | 1.5388 s | 273,347.0 | 114.28 | 60,000 / 60,000 (100.0%) |
| | Rep 4 | 421,050 | 60,217 | 240,593 | 1.5566 s | 270,493.5 | 114.53 | 60,000 / 60,000 (100.0%) |
| | Rep 5 | 420,678 | 60,178 | 240,371 | 1.5408 s | 273,017.4 | 114.46 | 60,000 / 60,000 (100.0%) |

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
   - *Demonstrated Deficiency*: Duplicate `EVENT_FORK`, `EVENT_MEMFD_WRITE`, or `EVENT_FD_INSTALLED` records produce multiple identical parallel edges in the graph. Only `EVENT_MEMFD_COMPLETED` is explicitly deduplicated against `EVENT_MEMFD_CREATE`.
2. **PID Reuse Fallback Merging (`start_time_ns = 0`)**:
   - When `EVENT_PROCESS_EXIT` fires, `unregister_active_proc(pid)` removes the PID from `g_active_pid_buckets`.
   - If a subsequent event for the same PID arrives with `start_time_ns = 0`, `find_active_proc(pid)` returns `NULL`, causing `prov_upsert_process` to create or merge into `proc_<pid>_0`. If multiple distinct generations arrive with zero start times, they falsely merge into `proc_<pid>_0`.
3. **Missing Parent Event Orphanage**:
   - If an `EVENT_FORK` record is dropped in the kernel, subsequent child events still instantiate the child node, but the node has `ppid = 0`, `comm = "<unknown>"`, and no inbound causal edge connects it to the parent process.
4. **Fixed Hash Bucket Capacity**:
   - Node hash table is statically sized at `PROV_HASH_SIZE = 16384` buckets without dynamic rehashing. At 1,000,000 events (101,651 nodes), average bucket chain length increases to ~6.2 nodes. While throughput remains high (>217k eps), dynamically resized hash tables would be required for >10M scale graphs.

### 4.3 Correction of Measurement Inaccuracies
- **Cumulative vs Isolated Process RSS**:
  - In initial profiling, measuring `getrusage(RUSAGE_SELF).ru_maxrss` within a single long-running harness caused smaller test runs (1k, 10k, 100k) to inherit the peak allocation of the largest 1M run (reporting ~760 MiB across all scales).
  - *Correction*: We implemented process isolation per trial via `fork()` and `wait4()`. The corrected metrics reflect the exact isolated physical RSS: **2.05 MiB** at 1k events, **5.91 MiB** at 10k events, **40.82 MiB** at 100k events, and **390.69 MiB** at 1M events.

---

## Reproducible Commands

All benchmarks, correctness evaluations, and native validations can be independently reproduced using the following commands:

### 1. Compile Test Binaries
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
# Raw machine-readable results saved to:
# tests1.0/kernel_telemetry/benchmark_provenance_perf_results.json
```

### 4. Replay Native Forensic Sessions
```bash
# Replay Memfd Execution Session
./build/replay tests1.0/kernel_telemetry/native_exec_7Q2iUm/session.evid \
    --dot /tmp/native_memfd.dot --json /tmp/native_memfd.json --timeline /tmp/native_memfd.md

# Replay Unlinked Executable Session
./build/replay tests1.0/kernel_telemetry/native_unlinked_T4pJiz/session.evid \
    --dot /tmp/native_unlinked.dot --json /tmp/native_unlinked.json --timeline /tmp/native_unlinked.md
```

### 5. Replay Native Pressure Workloads (W_PACED, W_BURST, W_SUSTAIN)
```bash
python3 -c '
import subprocess, json
for w in ["W_PACED", "W_BURST", "W_SUSTAIN"]:
    for r in range(1, 6):
        evid = f"tests1.0/kernel_telemetry/benchmark_01/data/{w}_rep_{r}.evid"
        sum_json = f"/tmp/{w}_rep_{r}_sum.json"
        subprocess.run(["./build/replay", evid, "--quiet", "--summary-json", sum_json], check=True)
        with open(sum_json) as f:
            s = json.load(f)
        print(f"{w} Rep {r}: {s[\"records_verified\"]} records, {s[\"nodes\"]} nodes, {s[\"edges\"]} edges, {s[\"events_per_sec\"]} eps, RSS {s[\"peak_rss_mib\"]} MiB")
'
```

---

## Review & Acceptance State

- [x] Dimension 1: Precision, recall, PID reuse, FD reuse, and exec representation quantitatively verified.
- [x] Dimension 2: 4 scales ($10^3, 10^4, 10^5, 10^6$) $\times$ 5 repetitions evaluated with isolated RSS and serialization costs.
- [x] Dimension 3: Native memfd execution, unlinked execution, and 15 pressure workloads replayed and verified against ground truth.
- [x] Epistemic boundary preserved: Collection vs reconstruction deficiencies explicitly separated.
- [x] Production code kept 100% frozen. No optimizations or fixes implemented ahead of review.
