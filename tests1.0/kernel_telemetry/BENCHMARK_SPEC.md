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

All metrics are normalized against independent workload ground-truth operations $N_{\text{ops\_attempted}}$. Raw event rates across different event populations are never multiplied.

### 4.1 Exhaustive Pipeline Balance Equation
$$N_{\text{ops\_attempted}} = N_{\text{reconstructed}} + N_{\text{gen\_gap}} + N_{\text{ring\_loss}} + N_{\text{queue\_loss}} + N_{\text{corr\_def}} + N_{\text{proc\_fail}}$$

- **$N_{\text{ops\_attempted}}$:** Total syscall attempts verified by workload ground truth.
- **$N_{\text{gen\_gap}}$:** Workload attempts unobserved by kernel probes.
- **$N_{\text{ring\_loss}}$:** Kernel ring-buffer reservation drops (`bpf_ringbuf_reserve` returning NULL).
- **$N_{\text{queue\_loss}}$:** Drops at userspace queue admission due to intermediate queue saturation.
- **$N_{\text{corr\_def}}$:** Syscall successes lacking valid object identity (`op_type = 3`, `token = 0`).
- **$N_{\text{proc\_fail}}$:** Userspace parsing, memory allocation, or Checkpoint P failures (`p_status = 5`).
- **$N_{\text{reconstructed}}$:** Operations completely and truthfully reconstructed in userspace.

### 4.2 Primary Performance Metrics
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

---

## 5. Disaggregated Resource Accounting

1. **Producer-Side CPU:** Measured via workload process rusage (`user_cpu_us`, `sys_cpu_us`).
2. **Userspace Telemetry CPU:** Measured across acquisition and worker threads (`clock_gettime(CLOCK_THREAD_CPUTIME_ID)` and `getrusage(RUSAGE_SELF)`).
3. **CPU Cost Per Attempted Op:** $\text{Cost}_{\text{attempted}} = \text{CPU}_{\text{telemetry\_total}} / N_{\text{ops\_attempted}}$
4. **CPU Cost Per Reconstructed Op:** $\text{Cost}_{\text{reconstructed}} = \text{CPU}_{\text{telemetry\_total}} / N_{\text{reconstructed}}$
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
