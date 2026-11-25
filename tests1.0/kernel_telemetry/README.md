# EphimTrace — kernel telemetry diagnostic lab

## Install and run

Extract the archive into the repository root; it contains `tests/kernel_telemetry/`.
From the root, in Zed's terminal on a local Linux x86-64 host:

```bash
python3 tests/kernel_telemetry/runner.py build
sudo python3 tests/kernel_telemetry/runner.py run --suite quick
```

Uses the project's existing compiler and libbpf dependencies (`clang-16`, GCC,
libbpf development headers, pkg-config, pthreads, Python 3.8+). Set `CLANG` or
`BPF_CFLAGS` during build if your existing Makefile uses different settings.
Stop any other EphimTrace instance before running. BPF load, all required
hook attachments, and the existing CPU topology checks must succeed. Missing
capabilities or verifier errors invalidate the run; inspect the generated log.
No production files are modified. Generated files go under `build/telemetry_lab`.
The instrumentation is not overhead-free; this is a diagnostic experiment,
not a final uninstrumented throughput benchmark. The original 1 MiB buffer,
map capacities, hook logic, and attachment sequence are preserved.

## Tests

| Suite | Case | Workload / consumer |
|---|---|---|
| quick | single | 1 memfd creation/write/close; minimal consumer |
| quick | paced | 100 cycles, 1 ms pacing; minimal consumer |
| quick | fast | 5,000 cycles, no pacing; minimal consumer |
| quick | full | same workload, production callback, stdout to a file |
| quick | stall | same workload, consumer SIGSTOP before workload, SIGCONT after |
| pressure | parallel_fast | 4 threads x 5,000 cycles; minimal |
| pressure | parallel_full | same workload, production callback |
| pressure | slow | same workload, 100 us artificial delay per callback |
| pressure | parallel_stall | same workload, consumer stopped |
| map | hold_paced | 10,000 memfds held open before closing; 100 us pacing |
| cpu | cpu_N | 100 cycles pinned to each allowed CPU |

```bash
sudo python3 tests/kernel_telemetry/runner.py run --suite pressure --repeat 3
sudo python3 tests/kernel_telemetry/runner.py run --suite map --hold 10000
sudo python3 tests/kernel_telemetry/runner.py run --suite cpu
```

Optional `--iterations`, `--workers`, `--repeat`. Map test uses the current
4,096 inode registry capacity and 8,192 file registry capacity; a hold test
may also exhaust the OS fd limit. Workload errors are separately reported;
use a controlled local machine, not a production host. No external network
activity is generated. The workload process waits for explicit attachment
readiness and stays alive until the report is taken. Only the first quick
run is needed initially.

## Evidence and interpretation

Results live in `tests/kernel_telemetry/results/<timestamp>/`:
`summary.json`, `environment.json`, individual JSON/CSV files and loader logs.
Scope 0 = all activity, scope 1 = workload TGID (all worker threads). Counts
are cumulative across startup and run; the target does not start the
measured workload until all hooks are attached. Background events share the
same ring, so global load still matters. Deferred cleanup may run in a
separate task and therefore not be attributed to the target TGID. Cleanup
records are counted globally but are not included in strict target ground-truth
assertions. `EVENT_MEMFD_WRITE` is write-hook entry, not a verified return;
successful one-byte writes are used as reference for this simple workload.

1. Ground truth: workload reports actual attempted memfd syscalls and
   successful create/write/close operations. Compare against existing
   target-scoped memfd entry/exit counters and event reservation attempts.
   A difference **before reservation** indicates an upstream observation or
   correlation gap, not necessarily a ring-buffer failure.
2. Kernel transport: instrument every `new_event` reservation attempt and
   failure, all 24 existing submit sites, and every current direct map
   update/delete call. Map errors are divided into ENOENT and other errors;
   ENOENT on cleanup deletes may be expected. The original counter indices
   are preserved and increment-only counters are also scoped by target TGID.
   Direct pointer mutations and lookup misses are not all instrumented;
   zero map helper errors is not proof of correct correlation.
3. Userspace: count validated records immediately before the original
   callback. After the workload, detach producers and drain the ring before
   reading counters. Compare attempted = failed + submitted and submitted =
   received by event type. A mismatch requires investigation; it may be due
   to accounting, attribution, shutdown, or reception rather than a proven
   userspace drop. `full` runs the original callback, but graph/export success
   is NOT measured; exports are intentionally disabled and output is a log
   file rather than an interactive terminal. Compare minimal/full across
   repeated runs with comparable workload rates. A positive-control stall
   demonstrates loss is possible, not that it occurs during ordinary use.

Known current code path: `capture_memfd_create_exit()` reserves a record
before finalizing the provisional registry. On reserve failure it deletes the
pending memfd entry and returns. Therefore saturation may also induce later
correlation gaps. Compare `target_counters[74]`, correlated/uncorrelated
completion counts, map mutation errors, and write/close attempts.

`VALID` means the harness ran and the workload reported no syscall failures;
it does **not** mean loss-free or that all sensors were validated. Missing
report, load/attach/poll error, or timeout is `INVALID`; never treat it as
zero drops. Scope is the core memfd path, not exhaustive semantic tests for
all unlink, exec, fork and connect scenarios. All emitted event types are
counted, but only the memfd workload has independent operation ground truth.
No live BPF verifier or attachment testing was performed in the authoring
sandbox; first local build/run is required.
