# EphimTrace backend freeze-readiness audit

Date: 2026-11-19  
Audited revision: `59cae3007434f844f383b193c94f29457c45e9da`  
Scope: backend collection, correlation, provenance, validation, build and operations. GUI excluded.

## Decision

**Do not call this an accepted or validated frozen backend.** The revision can be preserved as a **frozen experimental snapshot** for reproducibility, provided the known limitations and open findings accompany it. Freezing a snapshot is a change-control decision; acceptance as a reliable baseline requires the evidence and corrections below. Production readiness is not established.

The backend has meaningful implementation and tests, but forensic correctness and completeness remain exposed to unresolved descriptor tracking, incomplete loss accounting, misleading write/connect semantics, and a validation pipeline that can report success without live capture. The documentation records host verification, but the evidence examined here does not establish repeatable end-to-end results or a supported-kernel matrix.

## Scope and evidence

Reviewed the knowledge-base architecture and validation records in `repomix-output.md`, the current backend source, build/test configuration, selected test paths and the existing `audit/SECURITY_AND_DEPLOYMENT_AUDIT.md`. The knowledge base identifies baseline `0613147` and records findings F-01–F-15; this audit examines the current revision above and does not assume historical claims prove current behavior. The prior audit's complete finding descriptions and scenario recommendations remain useful supplementary material, not independently rerun results.

Fresh build: `make BUILD_DIR=/tmp/ephim-audit-C9QkRy/build -j2 all` **passed**, compiling the BPF object, loader and all Makefile test binaries from the current workspace. Run from an isolated temporary working directory, `test_m6_dag` and `test_m6_filtering` both exited **0** with all their assertions passing. These exercise synthetic graph and filter behavior; they do not validate sensor capture. Logs and build artifacts were left in `/tmp/ephim-audit-C9QkRy` for inspection. No privileged attachment, live kernel capture, clean-host matrix, full test suite or benchmark was run in this audit. Some tests use shared fixed `/tmp` paths, and the benchmark manipulates processes and temporary files; avoiding those runs prevents interference with unrelated work.

Git reported an existing deletion of `GPT_Context`; it was not changed in this audit. No backend source was modified.

## Findings and freeze implications

### 1. Validation can claim zero loss without a collector — blocker

`tools/benchmark_overhead.sh:47-59,136-149` permits an unavailable loader and prints zero drops as PASS. Missing measurements are not zero. A process being alive also does not establish all hooks are ready. Require verified readiness, valid counter reads and distinct failure or skip on missing data; make measured results traceable to the workload and collector instance. The script does not provide a controlled paired baseline/monitored overhead measurement. Prior audit: F-01, F-13.

### 2. M7 graph assertions are not live detection evidence — blocker

`tests/test_m7_scenarios.c:318-344` initializes a separate graph and feeds constructed events with fixed token and timestamps after running OS scenarios. Passing validates the fixture and processing path, not that BPF observed the scenarios. Require isolated integration tests that start the actual loader, verify readiness, run uniquely identifiable scenarios, and assert observed event identities, outcomes, graph relationships and loss counters. Keep synthetic tests explicitly labelled unit tests. Prior audit: F-02.

### 3. Sensor outcomes are not faithfully represented — blocker

`src/bpf/monitor.bpf.c:729-760` observes connect entry, not its return. `src/bpf/monitor.bpf.c:1714-1751` observes write entry, records requested count before completion, and narrows it to signed 32 bits. Failed or partial operations can therefore be represented inaccurately. Capture completion and full-width results, or document and encode the data as attempts/requested bytes with unknown outcomes throughout exports. Test success, failure, partial results and concurrency. mmap and other uncovered paths must remain explicit limitations. Prior audit: F-15.

### 4. Descriptor tracking and loss visibility are unresolved — blocker

The descriptor registry uses `(tgid, fd)` and unchecked `BPF_ANY` updates at `src/bpf/monitor.bpf.c:1327,1471`; replacement and failure paths require careful validation. Other updates, including `unlink_identity_map` at line 929 and `pending_memfd_exec` at line 1824, are unchecked. A missed map operation or ring-buffer reservation can invalidate causal reconstruction without reliable completeness indicators. Establish correct slot replacement and cleanup, check and count failures consistently, and exercise dup2/dup3 replacement, close/reuse, inheritance, map saturation and ring-buffer pressure on a privileged test host. The precise runtime impact remains to be established. Prior audit: F-04, F-05.

### 5. Live compatibility and end-to-end repeatability are insufficiently evidenced — blocker

The vault records host verification, while the prior audit reports BPF load denial in its own environment. Both can be true. This audit did not independently observe either attachment or capture. Preserve dated host logs tied to the exact source revision, kernel, configuration, capabilities and test inputs; verify every required hook, actual event capture, teardown and failure handling. Define supported kernels and test each declared target, including CPU topology changes. Prior audit: F-03.

### 6. Resource and export behavior limits operational use — high

The in-memory provenance graph has no established bounded retention or resource budget. Export functions use `fopen(filepath, "w")` (`src/user/provenance.c:1047` and following), which truncates existing files and follows symlinks, and do not reliably propagate all output/close failures. The prior audit also identifies diagnostic tracefs ownership concerns. Define bounded operation and explicit omission/error behavior; harden output and ownership and test disk-full, allocation failure, restart and teardown. Prior audit: F-06–F-08, F-14.

### 7. Reproducible acceptance and filter semantics remain incomplete — medium

`Makefile` builds tests but offers no aggregate execution target or privileged integration gate. Passing workload programs alone does not establish monitored behavior. The prior audit identifies malformed CLI acceptance, ambiguous combined PID/token filtering, and shared fixed test paths. Specify expected filter behavior including PID generations, validate input and isolate test artifacts. Prior audit: F-09–F-12.

## Acceptance gates for a validated freeze

1. Resolve or explicitly narrow claims for findings 1–4, with regression tests and a reviewed error/loss model.
2. Produce reproducible, isolated live-capture evidence tied to the exact candidate commit and declared host configuration. Demonstrate success and failure cases, identity continuity, descriptor replacement, loss and saturation handling, and cleanup.
3. Establish a supported-kernel matrix or restrict the freeze claim to the one verified configuration, with archived logs and known gaps.
4. Make test outcomes distinguish unit, workload, integration, skipped and failed checks. Missing collector or counters must never pass. Provide a repeatable clean build and test procedure.
5. Define graph resource limits, export safety and operational assumptions appropriate to the intended use; document any accepted residual risks and their owner.
6. Freeze the resulting commit, test artifacts and known-limitations register together. Any later change requires revalidation proportional to its effect.

## Limits of this conclusion

This is a targeted source and evidence review with a fresh build and two synthetic tests, not an exhaustive line-by-line audit or a privileged runtime assessment. Risks identified from code review are distinguished from observed failures; absence of a live test here does not establish a kernel defect. The decision is based on unresolved correctness and assurance gates, not a claim that the prototype has no working functionality.
