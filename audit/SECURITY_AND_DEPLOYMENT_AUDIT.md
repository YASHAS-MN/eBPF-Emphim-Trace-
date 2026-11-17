# EphimTrace Backend Security, Reliability, and Deployment Audit

**Report status:** Final for repository review; runtime kernel validation is environment-limited  
**Review scope:** Backend only (`src/bpf/`, `src/user/`, `tests/`, `tools/`, build and product documentation)  
**Excluded:** `gui/` as requested  
**Audit approach:** Read-only implementation review plus bounded local test/build/benchmark execution. No external targets, privileged loader attachment, destructive machine operations, or application-code modifications were used.

## 1. Executive summary

**Disposition: NOT READY FOR PRODUCTION DEPLOYMENT.**

EphimTrace has a meaningful prototype foundation: a compiled eBPF object and userspace loader, syscall-to-VFS correlation, memfd tracking, process lifecycle events, a userspace provenance graph, filtering/export functions, and multiple scenario harnesses. The backend test sources are substantial and the local graph/filtering and scenario tests passed in the available environment.

However, the current evidence does not demonstrate a functioning end-to-end monitor. The kernel BPF object could not be loaded here because the runtime environment denies BPF (`Operation not permitted`); the product's core hooks and actual event capture therefore remain unvalidated. The Milestone 7 scenario test runs operating-system scenarios, then constructs a separate graph by feeding synthetic, hard-coded events into the provenance engine. Its passing result validates the graph/export path for that fixture, not sensor detection of the preceding operations.

There are also deployment-significant correctness and assurance gaps: the overhead script returns PASS for zero drops when the loader did not run; the standard build target does not build all tools and `make` exposes no target that runs the full suite; map and ring-buffer losses are not comprehensively measured; BPF descriptor bookkeeping has likely stale-entry cases around dup/close and unchecked map updates; loader export errors are ignored; and graph state is unbounded and single-threaded without explicit capacity or synchronization. These issues must be addressed and validated on a supported privileged kernel before deployment approval.

### Overall ratings

| Area | Rating | Basis |
|---|---|---|
| Source/build readiness | Partial | Build dry-run and host build artifacts indicate compile path exists; no clean isolated full build was performed in this audit. |
| Unit/synthetic behavior | Partial pass | DAG, filtering and scenario harnesses ran successfully. Scenarios are partly synthetic and do not establish live capture. |
| Live eBPF runtime | Not verified | BPF load denied by the audit environment; 0/25 hooks attached. |
| Security/privacy | Needs work | Tracing captures paths, process and network metadata; access, retention, output-file safety and data-handling policy are not established. |
| Performance/overhead | Not established | Workload throughput measured; no valid monitored-versus-baseline overhead comparison. Benchmark can falsely report zero drops. |
| Production deployment | Fail / hold | Core runtime, loss accounting, lifecycle and operational safety gates remain open. |

## 2. Product and architecture understood

The backend is a Linux eBPF tracing and forensic-provenance service:

1. `src/bpf/monitor.bpf.c` attaches syscall tracepoints, scheduler tracepoints/raw tracepoints, and fentry/fexit hooks. It records syscall attempts, VFS unlink/rmdir completion and resolved identity, memfd create/write/descriptor/exec lifecycle, network connect attempts, and process lifecycle.
2. `src/user/loader.c` opens and loads `build/monitor.bpf.o`, attaches 25 logical hooks (with five syscall-entry hooks attached per CPU), consumes a ring buffer, prints events and counters, and exports provenance data on shutdown or signal.
3. `src/user/provenance.c` holds process/memfd/filesystem/network nodes and event edges in process memory, applies PID/token filtering, and exports DOT, JSON, and Markdown timeline output.
4. `tests/` includes operating-system workload tests and synthetic graph tests. `tools/verify_scenarios.py` checks a sample JSON and Markdown output; `tools/benchmark_overhead.sh` runs a churn workload and tries to start/sample the loader.

The declared product objective in `README.md` is deterministic syscall-to-VFS pathname/filesystem identity correlation, process lifecycle monitoring, memfd provenance and forensic event correlation.

## 3. Audit activity and evidence

### 3.1 Checks performed

- Inspected backend source, tests, build rules, verifier, benchmark script, sample graph/timeline and README.
- Ran `python3 tools/verify_scenarios.py`: **PASS** on the checked-in/generated sample fixture.
- Ran `./build/test_m6_dag`: **PASS** for synthetic DAG construction and exports; its live memfd exec workload is separate from that in-memory graph assertion.
- Ran `./build/test_m6_filtering`: **PASS** for synthetic filtering/timeline/export assertions, including noisy fixture exclusion.
- Ran `./build/test_syscall_correlation`: **PASS** as a workload/expectation harness; without attached BPF it does not validate observed EphimTrace event output.
- Ran `./build/test_m7_scenarios`: **PASS** for three local OS scenarios and generation of a synthetic graph from hard-coded events.
- Ran `./build/churn_workload 5000`: **PASS**, 5,000 memfd create/write/close loops, 0 workload failures, observed 118,014.8 iterations/sec in this environment. This is workload throughput only, not monitor overhead or event-delivery performance.
- Ran `./tools/benchmark_overhead.sh 20`: it reported loader skipped due to permission denial, then still reported **zero drops / PASS**. This reproduces a benchmark validity failure.
- Ran the loader with an invalid PID option while unprivileged: argument parsing did not reject the nonnumeric PID; it proceeded to BPF load and failed on permissions. No kernel hooks were attached.
- Tried sanitizer builds/runs for graph/scenario tests. With `ASAN_OPTIONS=detect_leaks=0`, exercised filtering and scenario tests completed without ASan/UBSan findings. LeakSanitizer's default mode failed in this environment with its own fatal “does not work under ptrace” diagnostic; leak validation is inconclusive.
- Build status: pre-existing `build/` binaries were present, and `make -n all` showed expected commands. `make -j2 all` then reported nothing to do, so a clean rebuild was not established by that run. No Makefile test target runs every suite.

### 3.2 Runtime constraint

The kernel reports Linux `7.0.0-42-generic`, but the audit process is unprivileged and BPF program load probing returns `Operation not permitted` (with a libbpf memlock warning). Loader summary: **0/25 logical hooks, 0/60 per-CPU events**. This is an environment permission limitation, not a finding that the hooks fail on a correctly privileged host. It leaves all runtime attachment, verifier acceptance, hook ABI compatibility, capture completeness, ring-buffer pressure and teardown behavior unproven.

### 3.3 Workspace integrity

No tracked application files were changed. The existing untracked `gui/` tree was present before audit and was not inspected or modified. A temporary Python `__pycache__` created by syntax checking was removed. The only new artifact from this resumed audit is this report.

## 4. Findings

Severity uses a practical deployment scale: **Critical** blocks safe operation; **High** can invalidate detection or cause material operational/privacy risk; **Medium** is a significant gap requiring remediation or explicit acceptance; **Low** is hygiene or non-blocking quality improvement.

### F-01 — Benchmark reports clean drops when no monitor was running

**Severity: High — confirmed**  
**Component/phase:** Milestone 7 benchmark / `tools/benchmark_overhead.sh` (fallback branch, lines 47–59 and 136–149)

If the loader fails to launch, the script initializes both drop counts to zero, labels them “0 (PASS),” prints a zero-drop verification, and exits successfully. In this audit the loader was explicitly skipped because BPF loading was denied, but the benchmark still returned a successful zero-drop result. The counters are therefore unobserved, not zero. The script also labels a fixed “Sub-millisecond” baseline without measuring that latency. This makes the current benchmark output unsuitable as release evidence and can conceal total monitor unavailability.

**Recommendation:** Make loader readiness a hard prerequisite for any monitored/drop assertion. Return a distinct skipped/error status when unprivileged or not attached; never translate missing counters into zero. Validate all required hooks and per-CPU attachment counts before accepting the run. Report actual counters and workload/event totals with an explicit measurement provenance. Remove unsupported latency claims. Add automated tests for loader-not-found, load-failure, missing counter, and nonzero-drop cases.

### F-02 — Milestone 7 “attack scenario” pass does not prove live sensor detection

**Severity: High — confirmed assurance gap**  
**Component/phase:** Milestone 7 scenario/verification pipeline (`tests/test_m7_scenarios.c`, `tools/verify_scenarios.py`)

The test executes local memfd, unlink and connect operations, then `generate_and_export_forensic_dag()` creates a new graph using hard-coded tokens, PIDs, timestamps, paths and outcomes. It does not consume loader output or verify the BPF sensors observed the preceding OS actions. The Python verifier checks only that expected node and edge type tokens occur in order and timestamps do not decrease; it does not validate graph connectivity, node references, counts, timestamps against the timeline, event provenance, or that the graph came from actual execution. Thus both the OS scenario and synthetic graph can pass while BPF capture is absent.

**Recommendation:** Split workload tests from integration acceptance. In a privileged CI/VM job, launch the actual loader, run uniquely identified scenarios, read actual event streams/counters/exported graphs, and assert event identities/relationships and no unexplained loss. Preserve synthetic graph tests as unit tests and label them accordingly. Strengthen verifier schema and semantic checks, including edge endpoint existence, unique IDs, declared counts, per-edge event-to-timeline values, causal chain connectivity, and required runtime provenance metadata.

### F-03 — Kernel sensor path and supported-kernel compatibility are not validated

**Severity: High — deployment gate / unverified**  
**Component/phase:** BPF attach and runtime integration (`src/bpf/monitor.bpf.c`, `src/user/loader.c`)

No BPF program was loaded in this environment, so verifier acceptance and attach support for all required tracepoints/fentry targets are unknown. The repo describes a kernel-specific Linux 7.0 per-CPU carrier workaround and the loader requires every listed hook; one missing symbol or permission failure prevents READY. A successful C compilation is not a substitute for kernel verifier and attach testing.

**Recommendation:** Before release, validate on a clean, privileged VM matching each supported kernel/version/configuration, including BTF and tracepoint availability. Archive verifier/load/attach logs and assert exact hook totals. Define and publish a kernel support matrix. Exercise startup failure, partial attach rollback, normal event capture, SIGINT/SIGUSR handling and teardown. Test CPU hotplug and non-contiguous CPU IDs/topology changes.

### F-04 — BPF descriptor tracking has stale and unchecked bookkeeping paths

**Severity: High — code-review risk; needs runtime regression tests**  
**Component/phase:** Milestone 2 registry / descriptor lifecycle (`src/bpf/monitor.bpf.c`, especially `capture_fd_install`, `capture_close_fd`)

- `memfd_desc_registry` is keyed by `(tgid, fd)` and a new installation writes with `BPF_ANY`, but the shown install path does not first reconcile any existing key. Descriptor replacement/reuse paths (e.g. `dup2` replacing an already tracked descriptor) need explicit close/replacement semantics so an old token cannot be retained or attributed incorrectly.
- `bpf_map_update_elem` results for descriptor records are ignored in both initial memfd installation and reopen/dup handling. A successful OS operation can be emitted as tracked even if registry insertion failed, or registry counters can miss a descriptor-map exhaustion.
- `capture_close_fd` deletes the descriptor slot but not the open-file (`memfd_file_registry`) entry, which is tied to `__fput`; that can be valid while another reference exists, but must be tested across last close, inherited descriptors, dup, `/proc/self/fd` reopen and descriptor replacement. The existing tests exercise these kernel operations, but without an attached tracer they do not establish that the maps stay correct.

**Recommendation:** Define invariants for descriptor slot, file object and inode object lifetimes; check every BPF map update/delete result and expose loss/error counters. Add privileged integration cases for dup2/dup3 target replacement, FD reuse, close/dup races, fork inheritance, exec/close-on-exec, reopen, map pressure and object eviction. Verify every emitted token/fd against kernel fixture identities and assert no stale association.

### F-05 — Ring-buffer and map loss accounting is incomplete and can misstate completeness

**Severity: High — telemetry integrity**  
**Component/phase:** BPF event submission and Milestone 7 metrics (`src/bpf/monitor.bpf.c`, `src/user/loader.c`, `tools/benchmark_overhead.sh`)

Most `bpf_ringbuf_submit()` results are not tracked (submit is void); only selected reserve failures such as memfd completion increment a ring-buffer error counter. Some event paths return silently on `new_event()` failure, and multiple map operations ignore errors. Consequently the current counters cannot establish “zero ring-buffer drops” or complete event delivery across all sensors. The benchmark checks only two selected counters and treats their absence as zero.

**Recommendation:** Count reservation failures by event/hook category, map update/delete errors by map, and userspace callback/export failures. Report attempted, reserved, submitted, consumed and correlated counts where feasible; define reconciliation invariants and fail completeness assertions when counters are absent or inconsistent. Stress with a deliberately slow consumer and controlled map capacity to prove the alarms work.

### F-06 — Unbounded in-memory provenance graph can exhaust userspace memory

**Severity: High for long-running service / Medium for prototype**  
**Component/phase:** Milestone 6 graph engine (`src/user/provenance.c`)

Every event may allocate a node or edge and is retained until shutdown. There is no graph size limit, retention window, persistence/backpressure policy or allocation-failure telemetry beyond local return values. A long-running host with ordinary process/connect/file activity can grow the graph indefinitely; allocation failure can silently omit nodes/edges because event processing ignores many helper return values. Export also allocates arrays proportional to the entire graph. This is an availability and forensic completeness risk.

**Recommendation:** Specify retention and maximum resource budgets; use bounded/rotating storage or streaming persistence with explicit loss markers. Propagate allocation/export errors and expose graph counts, memory, dropped records and high-water marks. Add long-duration churn and allocation-pressure tests with defined resource ceilings.

### F-07 — Provenance engine and export APIs lack concurrency protection and error propagation

**Severity: Medium — code-review confirmed design limitation**  
**Component/phase:** Milestone 6 engine and export (`src/user/provenance.c`)

The graph is implemented as process-global mutable lists/hash buckets and filtering mutates per-node `filter_marked` flags. There are no locks. Current loader invokes event callbacks and exports from the same main loop, which reduces immediate exposure in this executable, but the public engine API and future threaded/export integrations are not safe for concurrent event processing and export. Render functions and `fclose()` results are ignored; export functions return success even if rendering or output flush/close fails. The `prov_engine_init()` API also does not guard against repeated initialization, which can leak prior allocations if called twice.

**Recommendation:** Document and enforce a single-thread contract or protect all engine state with appropriate synchronization/snapshotting. Avoid shared mutable filter flags. Check `fprintf`/`ferror`/`fclose` and return failures; use atomic temporary-file replacement where output integrity matters. Make init/destroy idempotent or reject repeated initialization. Add concurrency and failing-output tests.

### F-08 — Export paths can overwrite files and output handling is not hardened

**Severity: Medium — deployment/privacy/operational risk**  
**Component/phase:** Milestone 6 export and loader CLI (`src/user/provenance.c`, `src/user/loader.c`)

Exports use `fopen(filepath, "w")`, truncating any file at the selected path and following symlinks. The loader has a user-supplied `--timeline` path and fixed current-directory graph output names. A privileged deployment running the loader from an untrusted or shared directory could overwrite an unintended file or expose sensitive telemetry through permissive file modes/locations. No output directory ownership, permissions, rotation or retention policy is documented. Data includes process names, paths, inode/device identity and network endpoints.

**Recommendation:** Run with a dedicated service account and a protected state directory. Use directory-relative safe creation (`openat` with no-follow/exclusive policy as appropriate), restrictive permissions, atomic replacement and explicit ownership. Validate user-supplied paths and document data classification, access control, retention and deletion policy. Do not run the privileged collector from an untrusted working directory.

### F-09 — PID/token CLI parsing accepts malformed and overflowing inputs

**Severity: Medium — confirmed**  
**Component/phase:** Loader CLI (`src/user/loader.c`, `main` argument parsing)

`strtoul`/`strtoull` are called without checking `errno`, end pointer, sign or range. For example a nonnumeric PID is accepted as zero, which disables filtering; negative and overflow values can also be converted/truncated. This is not a kernel exploit, but it can silently produce whole-graph exports or incorrect targeting and undermines operator expectations.

**Recommendation:** Require nonempty decimal input with full-string consumption, range-check against `uint32_t`/`uint64_t`, reject signs where inappropriate and report a usage error before loading BPF. Add malformed, negative, overflow and boundary-value CLI tests.

### F-10 — Filter behavior for combined PID and token is restrictive and under-specified

**Severity: Medium — functional edge case / needs product requirement**  
**Component/phase:** Milestone 6 subgraph filter (`src/user/provenance.c`, `prov_engine_filter_subgraph`)

When both PID and token filters are supplied, the implementation seeds both matching nodes, but traversal from a memfd back to a process only accepts the process whose PID equals the target PID. It does not traverse other related processes in the same lineage unless directly seeded; the comment says “or its descendants,” but no descendant condition is implemented. Also, PID seeds match numeric PID only, not process-generation start time, so historical PID reuse may seed multiple process nodes. The intended AND/OR semantics and PID-generation semantics are not stated.

**Recommendation:** Define filter semantics explicitly (intersection vs union, direct process vs process tree, whether PID means current or all historical generations). Implement against process generation IDs and add adversarial fixtures with reused PIDs, multiple tokens, cross-process memfd use and unrelated background edges. Assert exact node and edge sets, not just one happy-path component.

### F-11 — Test suite gives false confidence; tests are not wired into a reproducible CI target

**Severity: Medium — assurance/process gap**  
**Component/phase:** Build and validation (`Makefile`, `tests/`)

`make all` builds binaries but does not execute tests. The Makefile exposes only a few individual dependency targets and no aggregate `test`/`check` command. Several harnesses print expected observations rather than asserting actual monitor telemetry. `test_pid_reuse.c` succeeds even when no PID reuse occurs, and `test_m7_scenarios.c` asserts broad minimum graph sizes instead of exact expected edges. Many tests rely on `assert`, which is disabled if built with `NDEBUG`. Audit could not establish a clean build because existing `build/` outputs made `make` report nothing to do.

**Recommendation:** Add deterministic `make test`/CI jobs, clean-build verification, per-test exit/result summaries and a privileged eBPF integration test tier. Separate unit, workload, integration and privileged tests. Make every test validate its stated condition or report SKIP rather than PASS. Test with release flags and `NDEBUG` behavior explicitly.

### F-12 — Test harnesses perform destructive/path-collision operations in shared `/tmp`

**Severity: Medium — test isolation risk**  
**Component/phase:** Milestone 7 and some OS workload tests (`tests/test_m7_scenarios.c`, other tests)

The scenario harness uses fixed global paths including `/tmp/ephim_stage.dat` and `/tmp/ephim_c2_artifact.dat`, truncates/creates them, then unlinks them. Concurrent execution or pre-existing files can cause interference or data loss. The audit did not run the aggregate suite because it contains filesystem/process workloads and no isolated harness is provided; selected tests used their own temporary paths. Other tests use unique `mkstemp` paths, showing an available safer pattern.

**Recommendation:** Use `mkdtemp` per test run and exclusively create all artifacts underneath it; clean only files created by that run. Add concurrency tests and guaranteed cleanup paths. Do not run scenario tests against production directories or data.

### F-13 — Workload benchmark does not measure monitored overhead or robust throughput

**Severity: Medium — benchmark methodology**  
**Component/phase:** Milestone 7 (`tools/benchmark_overhead.sh`, `tools/churn_workload.c`)

The churn tool counts successful writes but its iteration throughput is computed using requested iterations, not successful operations; its single write does not retry partial writes, and close failures are ignored. The shell script times the workload separately, but does not run a baseline/monitored paired comparison or calculate latency distribution. It samples CPU/RSS at 50 ms intervals, too coarsely for a short 5,000-iteration workload. More importantly, it can claim PASS without an active monitor (F-01). The measured 5,000-iteration rate is not a product overhead or event throughput result.

**Recommendation:** Use monotonic timing in one authoritative harness; count verified successful operations; handle partial writes and close errors. Run repeated baseline and monitored trials with confidence intervals, workload-duration normalization, event counts, CPU/RSS and latency percentiles. Confirm loader readiness and event/drop reconciliation before calculating overhead; retain raw measurements and environment metadata.

### F-14 — Diagnostic mode alters tracefs state and cleanup assumes ownership

**Severity: Medium — operational safety**  
**Component/phase:** Loader diagnostics (`src/user/loader.c`, setup/cleanup diagnostic instance)

Verbose mode attempts to create/use a fixed tracefs instance name `ephim_diag`, enables events, and cleanup disables events and removes that path whenever setup marked the instance created—including when `mkdir` returned `EEXIST`. If an existing instance with that name belongs to another process/operator, the loader can change its tracing state or remove it. Cleanup errors are ignored. This code path was not exercised due to BPF load permissions.

**Recommendation:** Use a unique instance name and track whether this process actually created it. Never alter/remove a pre-existing instance. Record and restore only settings the process owns; check all tracefs operations and clean up on every partial-startup path. Keep diagnostics opt-in and document privileges/side effects.

### F-15 — Event semantics overstate memory-write and network-connect outcomes

**Severity: Medium — telemetry correctness**  
**Component/phase:** BPF write/connect capture and provenance (`src/bpf/monitor.bpf.c`, `src/user/provenance.c`, `src/user/loader.c`)

`capture_shmem_write_iter` is an fentry probe and records requested `iov_iter.count` before knowing the write's returned byte count, casting count to signed 32-bit `ret_val`. Partial or failed writes can therefore be reported as if all requested bytes were written, and large counts can truncate. `capture_connect` records syscall entry only; the userspace provenance edge treats it as a connect event with default `ret_val` (zero), even though the syscall may later fail. The sample fixture manually injects `-111`, but the live connect sensor shown does not capture syscall exit.

**Recommendation:** Capture write completion return values (including partial/failure) and use a 64-bit byte field. Pair connect entry/exit by TID and operation generation or label events explicitly as attempts with unknown result. Add tests for partial/error writes, failed and successful connects, IPv4/IPv6, short/invalid sockaddr and event ordering.

## 5. Edge-case test scenarios to add/require

These are recommendations for a privileged, isolated test VM. They were not all executed here because core BPF attachment is unavailable.

### Syscall/VFS correlation

- `unlink`, `unlinkat(AT_FDCWD)`, relative `unlinkat(dirfd)`, absolute paths with dirfd, `AT_REMOVEDIR`, invalid dirfd, empty path, inaccessible/invalid user pointer, path lengths exactly 255/256/257 bytes, non-UTF-8 bytes, and rapid concurrent calls from multiple threads.
- Success, `ENOENT` before VFS, `EACCES` after path resolution, `ENOTEMPTY`, filesystem-specific failure, and kernel-internal VFS call without matching syscall context.
- Reentrant/concurrent per-thread operations, TID reuse, process exit between entry/exit, map-full and ring-buffer-full behavior, and stale pending-entry cleanup.
- Mount namespace changes, bind mounts, overlay/tmpfs, renamed/replaced paths and inode reuse; verify resolved inode/device/mount namespace rather than only user path.

### Memfd/descriptor/exec tracking

- Creation success/failure, invalid flags/name edge limits, creation under CPU migration, parallel thread creation, and pending-map saturation.
- `dup`, `dup2` replacing a tracked memfd, `dup3`, `fcntl(F_DUPFD*)`, close/reuse, inherited FDs across fork, `CLONE_FILES`, `exec` close-on-exec, `/proc/self/fd` reopen, SCM_RIGHTS transfer, and last-reference release.
- Writes through `write`, `pwrite`, `writev`, `pwritev`, mmap/shared mappings, splice/sendfile/copy paths, partial/faulting writes, sealed memfd and failed write; compare actual bytes to emitted count.
- Exec success/failure through `execveat(AT_EMPTY_PATH)`, `fexecve`, procfs reopen, scripts/interpreters, rename/close races, denied execution, and failed attempt followed by successful attempt on same TID.
- Object-token monotonicity, inode/file pointer reuse, provisional rollback on each failure point, map-full behavior and duplicate/reopen identity.

### Process lifecycle, network and graph behavior

- Thread clone versus process fork, multithreaded exec/TID changes, rapid PID reuse, exit/exec event order, parent exit before child, process namespaces, and unavailable BTF task fields.
- IPv4/IPv6, short/invalid sockaddr, failed `connect`, nonblocking in-progress connect, repeated endpoint connects, and syscall exit result correlation.
- Combined PID+token filters, PID reuse generations, descendant and cross-process object use, empty/no-match filters, very large connected graph, allocation failure, timestamp ties/out-of-order delivery, and duplicate events.
- JSON/DOT escaping for quotes, backslashes, newline, tabs, control/non-ASCII bytes; output path permission errors, existing symlinks, disk-full/short writes, and interrupted export.

### Operations and performance

- Start with no privileges, missing capabilities, restrictive memlock, missing BTF/hook symbols, partial attach failure, CPU topology changes and SIGINT at each startup phase.
- Repeated start/stop with no leaked links, perf FDs, tracefs instances or maps; verify only owned resources are changed.
- High-rate event producer with intentionally stalled userspace consumer; assert ring-buffer loss is detected and reported.
- BPF map saturation, long-running graph retention, memory high-water behavior and clean service restart.
- Paired baseline/monitored throughput and latency tests across supported kernel configurations with raw artifacts and repeated trials.

## 6. Remediation roadmap by phase/module

### P0 — before any deployment or efficacy claim

1. **Milestone 7 validation/benchmark:** fix F-01/F-02/F-05/F-13. Missing loader or counters must be FAIL/SKIP, never PASS. Gate scenario assertions on actual observed event output and known loader readiness.
2. **Privileged integration:** establish a reproducible VM/CI environment and validate all 25 hooks and 60 expected CPU attachments on the declared kernel support matrix (F-03). No deployment approval without captured evidence.
3. **Milestone 2 memfd registry:** resolve descriptor-map replacement/update/error handling (F-04) and verify lifecycle under the scenarios above.
4. **Milestone 2 write/connect telemetry:** capture completion outcomes and correct byte semantics (F-15), or explicitly narrow product claims to attempt/requested-count data.
5. **Security/operations:** harden output directory/path creation, permissions, retention and tracefs ownership (F-08/F-14).

### P1 — before production scale

1. **Milestone 6 provenance engine:** add bounded retention/resource budgets and loss reporting (F-06); propagate allocation and export errors and define thread safety (F-07).
2. **Milestone 6 filter:** specify/implement PID-generation and combined-filter semantics with tests (F-10).
3. **Loader CLI and lifecycle:** strict argument parsing, robust initialization/error cleanup and signal/tracefs ownership tests (F-09/F-14).
4. **Build/test engineering:** clean build plus aggregate deterministic test and privileged integration targets; make skipped tests explicit (F-11).

### P2 — quality and ongoing assurance

- Expand malformed-input, saturation, long-duration and cross-kernel regressions.
- Add fuzz/property tests for DAG JSON/timeline consistency and string escaping.
- Publish supported kernels, capabilities, data fields/retention and measured overhead methodology.
- Archive release test logs and reproducible benchmark raw data.

## 7. Deployment decision and acceptance criteria

**Current decision: HOLD — backend is not approved for end-to-end deployment.** The source provides a credible prototype, but the measured evidence is not sufficient to establish that the eBPF collector loads reliably, sees the claimed behaviors, does not silently lose or misattribute events, or remains within operational resource limits.

Minimum re-audit gates:

1. Clean reproducible build and all unprivileged unit/workload tests pass from a fresh checkout.
2. Privileged CI/VM loads all required hooks on every declared supported kernel and confirms teardown/resource cleanup.
3. Live integration tests prove expected events and causal IDs derive from actual workloads (not synthetic fixture injection), including failure and concurrency edge cases.
4. Missing loader, missing counters, map exhaustion and ring-buffer pressure cannot produce false PASS; losses are measured and reconciled.
5. Graph memory/retention is bounded and allocation/export failures are visible.
6. Output permissions, symlink/path safety, data retention and tracefs ownership are addressed.
7. Benchmark reports paired baseline-versus-monitor results with reproducible methodology and no unsupported performance claims.

## 8. Limitations and confidence

This is a source and local-test audit, not a full live-kernel penetration test. BPF loading was blocked by environment permissions, so no actual hook callback, verifier acceptance, runtime map behavior, event correlation or end-to-end sensor detection was observed. The existing tests are useful but several validate workloads or synthetic data rather than the running collector. No external targets were attacked. No product code changes were made.

**Confidence:** High in the confirmed source/test/benchmark observations; low for live kernel capture and performance conclusions until privileged integration evidence is available.
