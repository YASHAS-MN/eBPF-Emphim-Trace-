# Backend freeze reassessment: host evidence

Date: 2026-11-19  
Scope: backend only; review of `audit/evidence/`, readable `logs/`, and existing freeze report. The recorded host is Linux Mint 22.3, x86-64, kernel `7.0.0-42-generic`. The evidence does not independently record a Git commit or source/build hashes, so its exact correspondence to a revision cannot be proven from these logs alone.

## Decision

The new evidence supports a stronger conclusion than the earlier sandbox-limited review: **the collector loaded, attached and captured real workload events on this host**. This is meaningful live validation of the prototype on the recorded kernel. It does not yet establish complete or causally accurate collection, and the other identified correctness and assurance issues remain. The backend is suitable to preserve as a **frozen experimental host-tested baseline**, with its limitations recorded. It is not yet suitable to call a **validated forensic baseline** or production-ready.

This reassessment supersedes any suggestion in the earlier report that no live capture evidence was available; that report described what the auditor had observed at the time, not proof of a sensor failure.

## What the evidence establishes

- `host_env.log` records the host and kernel; `build.log` records compilation of the BPF program, loader and tests. The log has no explicit build exit status or commit hash.
- `loader_live_attach.log:1204-1268` shows 25/25 logical hooks and 60/60 per-CPU attachments, followed by READY. This demonstrates successful loading and attachment in that run on the recorded host, not compatibility across kernels or topology changes.
- `loader_live_events.log:2424-2509` records real scenario activity, including `dropper_payload` creation correlated to PID 13668 and token 5, staging-file unlink, `c2_beacon` creation for PID 13670 and token 6, an IPv4 connect attempt to 127.0.0.1:8443, and successful VFS completion for unlink of `/tmp/ephim_c2_artifact.dat`. These observations substantiate real sensor capture, beyond the synthetic M7 fixture. They do not alone prove every expected event or graph edge is correct.
- `scenario_run.log` reports all three OS scenarios passing; its separately constructed 5-node, 6-edge graph remains synthetic. `all_tests_live.log` contains numerous reported passes across descriptor, write, execution, graph and workload tests; the log alone does not establish each test's exit status or prove that each assertion checked collector output. It should not be treated as blanket live sensor acceptance.
- `verify_output.log` reports a 108-node, 130-edge graph, matching the counts in `live_timeline.md`. This is evidence that a larger graph was exported and parsed. The verifier's asserted sequence is not proof of one causal chain: its selected fork is for child 13581, creation is for PID 1337/token 1, write and exec are PID 13668/token 5, unlink is PID 13667, and connect is PID 13670. Ordered events from different subjects are insufficient to prove their causal relationship.
- `benchmark_live_run.log` reports a running loader and 5,000 successful workload iterations, and prints zero for two counters. It does not preserve sufficient readiness and raw counter reconciliation in that log to establish no losses, and there is no paired unmonitored comparison. The known fallback that can print zero when the loader fails remains in the script; this particular run reports RUNNING, so it must not be described as the fallback case. The sampler process was reported killed during cleanup; that alone does not prove workload failure.

## Remaining gates

1. Tie evidence to the candidate commit, dirty-tree state, compiler versions, binary hashes, command lines and exit statuses; archive raw graph, timeline, loader and counters from the same run.
2. Verify scenario-specific causal chains against actual observed identifiers and event outcomes, including expected versus observed counts. Fix the verifier's disconnected-edge acceptance and retain synthetic tests as unit tests.
3. Address or explicitly narrow write and connect outcome semantics, descriptor replacement and unchecked map updates, and loss accounting. Exercise failure, partial write, dup2/dup3 replacement, map exhaustion and ring-buffer pressure.
4. Correct benchmark readiness and missing-counter behavior; run repeated paired baseline and monitored measurements with raw data. Zero in selected counters does not prove complete loss accounting.
5. Define supported host/kernel scope and validate attachment, event capture and cleanup across any additional claimed configurations. Address bounded graph memory and safe export/diagnostic ownership before operational deployment.

The detailed source findings and additional acceptance criteria are in `BACKEND_FREEZE_READINESS_AUDIT.md` and `SECURITY_AND_DEPLOYMENT_AUDIT.md`; interpret their live-evidence statements in light of this reassessment.

## Access and review limitations

Readable text logs and the archive inventory were inspected; the archive contains the listed live logs and graph/timeline files. Older `logs/perf.data` and `logs/perf.data.old` are root-owned mode 600 and could not be read by this session. They were not necessary to establish the attachment and scenario events above; their contents and any additional findings remain unassessed. This review did not rerun privileged tests or modify backend code.
