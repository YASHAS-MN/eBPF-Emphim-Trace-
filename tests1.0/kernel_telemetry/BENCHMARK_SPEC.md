# EphimTrace — Telemetry Architecture Benchmark Specification
**Version:** 2.0 (Issue #3 Approved Protocol)
**Reference Baseline:** Checkpoint `49ece70dc72a14799aac6a94c6b62d65c2a78bfd`

---

## 1. Scope & Objective

This specification defines the rigorous, normalized, and reproducible benchmark protocol for evaluating userspace acquisition and processing architectures for EphimTrace.

### Architectures Evaluated:
- **Architecture A (Reference Baseline):**
  Kernel Hooks + Stateful Registries $\rightarrow$ 1 MiB BPF Ring Buffer $\rightarrow$ Synchronous Userspace Poller (`handle_event`) $\rightarrow$ In-memory Provenance Engine.
- **Architecture B (Asynchronous Userspace Acquisition):**
  Kernel Hooks + Stateful Registries $\rightarrow$ 1 MiB BPF Ring Buffer $\rightarrow$ Dedicated Ring-Buffer Acquisition Thread $\rightarrow$ Bounded Preallocated FIFO Queue $\rightarrow$ Single Processing Worker $\rightarrow$ In-memory Provenance Engine.
- **Architecture C (Minimal Kernel-Side State):**
  Unapproved for implementation; reserved for subsequent evaluation under GitHub Issue #4.

---

## 2. Evidence Contract & Dual-Mode Evaluation

Telemetry completeness must not be achieved by dropping un-modeled observations.

### 2.1 Common Invariant Observations
For every memfd operation within the validated lifecycle scope (`create`, `write`, `close`), the pipeline must preserve:
1. **Creation Intent:** Calling process identity (`PID`, `TID`, `PPID`, `start_time_ns`), monotonic entry timestamp, initial name, and creation flags.
2. **Object Identity & Attribution:** Inode number, device ID, mount namespace, file descriptor (`fd`), unique lifecycle token (`object_token`).
3. **Mutations & Operations:** Write offsets, byte counts, and descriptor duplication.
4. **Lifecycle Termination:** Descriptor close (`file_close_fd`), file release, and inode destruction.

### 2.2 Dual Evaluation Modes
Output overhead must be accounted for by testing under two explicit modes:
1. **Diagnostic-Only Mode (`--quiet` / `EPHIM_QUIET=1`):**
   Evaluates transport, queuing, and graph processing engine throughput without presentation formatting serialization.
2. **Evidence-Preserving Mode:**
   Evaluates end-to-end performance under identical persistent evidence sink conditions across both architectures (structured event logging and timeline graph export).

### 2.3 Diagnostic Capture Ceilings
The diagnostic sidecar array in `user_probe.inc` is bounded to `DIAG_MAX_CAPTURED = 131,072` records and limited to event types 2 and 12. For workloads generating $> 131,072$ events:
- Capture overflow (`captured_overflow`) is recorded as diagnostic sidecar truncation.
- Kernel transport loss counters (`diag_stats`) and workload ground truth remain authoritative for loss accounting.

---

## 3. Workload Matrix & Concurrency

Workloads are generated using [`workload.c`](workload.c):

| Workload ID | Profile | Workers | Iterations / Worker | Total Ops | Pacing (`us`) | Held FDs | Purpose |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `W_PACED` | Control Baseline | 1 | 500 | 500 | 1,000 | No | Zero-loss functional baseline; establishes loss-free reference. |
| `W_BURST` | Transient Saturation | 4 | 2,500 | 10,000 | 0 | No | Tests buffer absorbency and queue admission under transient spikes. |
| `W_SUSTAIN` | Sustained Pressure | 4 | 15,000 | 60,000 | 50 | No | Tests steady-state producer arrival exceeding single-stage processing. |
| `W_CONTENTION` | Multi-Core Contention | 8 | 5,000 | 40,000 | 0 | No | Severe concurrent producer lock contention on the 1 MiB ring buffer. |
| `W_REGISTRY` | Map Capacity Boundary | 1 | 10,000 | 10,000 | 100 | **Yes** | Verifies BPF registry bounds (4,096 inode / 8,192 file capacity). |

---

## 4. Normalization & Count Reconciliation

All metrics are normalized against independent workload ground-truth operations $N_{\text{ops\_attempted}}$. Raw event rates across different event populations are never added or multiplied against operation populations.

### 4.1 Operation-Level Reconciliation & Completeness
Every attempted syscall operation $r \in \text{Workload}$ is verified against captured telemetry:
$$N_{\text{ops\_attempted}} = N_{\text{reconstructed}} + N_{\text{incomplete}}$$

Where:
- **$N_{\text{ops\_attempted}}$:** Total unique operations recorded in independent ground truth.
- **$N_{\text{reconstructed}}$:** Unique operations whose full lifecycle (creation, completion, return code, descriptor, token, and provenance attributes) was completely and truthfully observed without discrepancies.
- **$N_{\text{incomplete}}$:** Operations suffering any form of omission, corruption, or discrepancy.
- **$\text{Operation Residual}$:** $N_{\text{ops\_attempted}} - (N_{\text{reconstructed}} + N_{\text{incomplete}}) = 0$.
- **Evaluated Scope:** Current phase rigorously evaluates creation-operation completeness ($C_{\text{e2e\_create}}$) over `memfd_create` intent and completion pairs. Extended lifecycle operations (`write`, `close`) are tracked as secondary metrics.

### 4.2 Independent Stage-Wise Event Conservation
Event populations are reconciled independently per stage on their matching event populations, rather than mixed with operation counts:
1. **BPF Probe to Ring Buffer:**
   $$E_{\text{attempted}} = E_{\text{submitted}} + E_{\text{ring\_reserve\_failed}}$$
   $$\text{Residual}_{\text{ring}} = E_{\text{attempted}} - (E_{\text{submitted}} + E_{\text{ring\_reserve\_failed}})$$
2. **Ring Buffer Transport:**
   $$E_{\text{submitted}} = E_{\text{received}} + E_{\text{transport\_loss}}$$
3. **Userspace Intermediate Queue (Architecture B):**
   $$E_{\text{admission\_attempts}} = E_{\text{enqueued}} + E_{\text{queue\_drops}}$$
   $$\text{Residual}_{\text{queue}} = E_{\text{admission\_attempts}} - (E_{\text{enqueued}} + E_{\text{queue\_drops}})$$
   $$E_{\text{enqueued}} = E_{\text{dequeued}} + E_{\text{queue\_drain\_loss}}$$
   $$\text{Residual}_{\text{drain}} = E_{\text{enqueued}} - E_{\text{dequeued}}$$
4. **Userspace Processing & Checkpoint P:**
   $$E_{\text{dequeued}} = E_{\text{p\_evaluated}} + E_{\text{proc\_unaccounted}}$$

### 4.3 Primary Performance Metrics
1. **End-to-End Completeness ($C_{\text{e2e}}$):**
   $$C_{\text{e2e}} = \frac{N_{\text{reconstructed}}}{N_{\text{ops\_attempted}}}$$
2. **Incomplete-Operation Fraction ($F_{\text{incomplete}}$):**
   $$F_{\text{incomplete}} = 1 - C_{\text{e2e}} = \frac{N_{\text{ops\_attempted}} - N_{\text{reconstructed}}}{N_{\text{ops\_attempted}}}$$
3. **Offered Workload Throughput ($\Theta_{\text{offered}}$):**
   $$\Theta_{\text{offered}} = \frac{N_{\text{ops\_attempted}}}{T_{\text{workload\_done}} - T_{\text{workload\_start}}} \quad [\text{ops/sec}]$$
   *(Timestamps measured in workload monotonic clock at worker completion, before process exit).*
4. **Useful System Throughput ($\Theta_{\text{useful}}$):**
   $$\Theta_{\text{useful}} = \frac{N_{\text{reconstructed}}}{T_{\text{processing\_complete}} - T_{\text{workload\_start}}} \quad [\text{ops/sec}]$$
5. **Processing Drain Latency ($\Delta T_{\text{drain}}$):**
   $$\Delta T_{\text{drain}} = T_{\text{processing\_complete}} - T_{\text{workload\_done}} \quad [\text{milliseconds}]$$
   *(Processing timestamps measure target-scoped event populations where `pid == diag_pid`. Global event backlog drain is reported separately as $\Delta T_{\text{global\_backlog}}$).*

---

## 5. Disaggregated Resource Accounting

1. **Producer-Side CPU:** Measured via workload process rusage (`user_cpu_us`, `sys_cpu_us`).
2. **Userspace Telemetry CPU:** Measured via `getrusage(RUSAGE_SELF)`. Baseline rusage is captured at `DIAG_READY` to isolate active processing CPU from fixed harness overhead (BPF load/attach).
   - $\text{CPU}_{\text{active}} = \text{CPU}_{\text{total}} - \text{CPU}_{\text{baseline}}$
   - Whole-trial total CPU is reported separately for complete execution accounting.
3. **CPU Cost Per Attempted Op:** $\text{Cost}_{\text{attempted}} = \text{CPU}_{\text{active}} / N_{\text{ops\_attempted}}$
4. **CPU Cost Per Reconstructed Op:** $\text{Cost}_{\text{reconstructed}} = \text{CPU}_{\text{active}} / N_{\text{reconstructed}}$
5. **Memory Footprint:** Peak RSS polled from `/proc/self/statm` during trial and post-quiescence. Intermediate queue capacity strictly bounded to $Q_{\text{max}} = 65,536$ events ($\le 64\text{ MiB}$ preallocated memory).

---

## 6. Experimental Controls

- **Randomized Block Order:** 5 paired trial blocks. Within each block, architecture execution order is randomized (`[A, B]` or `[B, A]`) with a fixed seed.
- **Repetitions:** 5 independent trials per case.
- **Reporting:** Arithmetic mean ($\mu$), sample standard deviation ($\sigma$), min, max, and 95% confidence interval ($CI_{95}$).

---

## 7. Numerical Acceptance Targets

To justify architectural adoption, Architecture B must satisfy the following owner-approved criteria compared to freshly collected Architecture A baselines under identical test conditions:

1. **Control Completeness:** $C_{\text{e2e}} = 100.0\%$ (0 drops across all stages) on `W_PACED`.
2. **Fidelity Invariants:** Zero corrupted tokens, zero outcome inversions, zero unexplained accounting residuals.
3. **Burst Incomplete-Operation Reduction:** $\ge 50\%$ relative reduction in $F_{\text{incomplete}}$ on `W_BURST` vs. Architecture A (or preservation of zero loss if A exhibits zero loss).
4. **Sustained Useful Throughput Gain:** $\ge 20\%$ gain in $\Theta_{\text{useful}}$ on `W_SUSTAIN` vs. Architecture A.
5. **Memory Cap:** Peak $\text{RSS}(\text{Arch B}) \le \text{Peak } \text{RSS}(\text{Arch A}) + 64\text{ MiB}$.
6. **Burst Drain Latency:** $\Delta T_{\text{drain}} \le 1,000\text{ ms}$ on `W_BURST`.
