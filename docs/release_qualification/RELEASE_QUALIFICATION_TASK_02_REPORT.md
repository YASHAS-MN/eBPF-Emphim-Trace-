# EphimTrace — Release Qualification Task 02 Report
## Evidence Integrity, Replay Safety, and Manifest Lifecycle Hardening (GitHub Issue #11)

**Date**: 2026-11-28  
**Scope**: Release Qualification Task 02 under GitHub Issue #11 and `PROJECT_STATE.md`  
**Base Implementation Checkpoint**: `a61a3e7` (Descriptor Remediation Checkpoint)  
**Remediated Checkpoint**: `4b1706c` (`fix(replay): harden manifest handling, protect export aliases, and report truthful integrity classifications`)  
**Host Environment**: Linux `7.0.0-44-generic #44~24.04.1-Ubuntu SMP PREEMPT_DYNAMIC x86_64`  
**Compiler**: `gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0`, `Ubuntu clang version 16.0.6`  
**Worktree**: `/home/magellan/Garage/prototypes/FM/FM-persist`  
**Branch**: `remediation/state-independence-and-loss-accountability`  

---

## 1. Executive Summary

This qualification report evaluates forensic evidence integrity, session manifest validation, export path safety, and truthful classification under offline replay reconstruction. 

Following the completion of Release Qualification Task 01 (`a61a3e7`), Task 02 addresses four critical failure modes identified under GitHub Issue #11:
1. **Accidental overwriting of evidence or session manifests through replay export paths**: Replay export targets (`--dot`, `--json`, `--summary-json`, `--timeline`, `--filtered-dot`, `--filtered-json`) truncating or overwriting input evidence or accompanying session manifests via direct paths, symlinks, hardlinks, or path aliases.
2. **Missing, malformed and inconsistent manifest handling**: Inconsistent loss accounting (where `ring_buffer_total_drops` conflicts with the sum of per-type drops) accepted without rejection; malformed JSON or incompatible manifest versions allowed to proceed.
3. **Misleading integrity and completeness classifications**: Replay conflating "unverified / legacy completeness" with "lossy telemetry captured," falsely claiming packet loss when zero drops occurred.
4. **Strict replay failure handling and preservation of recoverable evidence**: Enforcing strict fail-closed semantics (`rc=7` on unfinalized or inconsistent manifests; `rc=4` on corrupt/truncated records) with absolute export suppression under strict mode, while guaranteeing clean prefix recovery under standard mode without mutating input artifacts.

### Key Qualification Verdicts:
- **Manifest & Evidence Protection**: 100% of tested export alias vectors (direct path, symlink, hardlink, parent-relative resolution, evidence alias, inter-output collisions) successfully rejected with exit code `1` prior to file creation. All input evidence and manifest SHA-256 hashes verified completely unchanged.
- **Inconsistent Manifest Validation**: Strict replay rejects discrepancies between total and per-type loss counters with exit code `7` and suppresses exports. Standard replay recovers intact prefix and explicitly reports `SUCCESS (Inconsistent Loss Manifest)`.
- **Truthful Status Classification**: Clean legacy evidence without a manifest reports `SUCCESS (Unverified Telemetry Completeness)`, eliminating false loss claims. Truly lossy telemetry continues to report `SUCCESS (Lossy Telemetry Captured)`.
- **Architectural Preservation**: The kernel eBPF collection architecture, `struct event` ABI, and ring buffer performance configurations remain 100% untouched.

---

## 2. Tested Binary Hashes & Environment Checkpoint

All binaries were compiled from source tree at commit `4b1706c`:

| Binary / Artifact Component | SHA-256 Digest | Role / Purpose |
|:---|:---|:---|
| `build/replay` | `db3cadd0c91861ca8ca9ebd6410b1a3dede859b7c86b847467666f487faace99` | Hardened offline replay reconstruction utility |
| `build/test_qualification_replay` | `911d1c5b225e1d9a4d301dc429fdd3a5b47e3ba8a660009ab19de4c253bbb040` | Dedicated Release Qualification Task 02 test suite |
| `build/test_failure_controls` | `4198a51a8b3a5214f7c31b94abe7066909a0a8f6fb2d26a6c907a8958f07246d` | Bounded failure controls & resilience test suite |
| `build/test_pipeline_integration` | `36b2a8940b3be5b906a6b2e2c960f50dfe7e1a873029267085ee69ee0d389663` | End-to-end collection-first integration test suite |
| `build/test_descriptor_lifecycle_reconstruction` | `6d4a74ef8e57457458caea6d2138c107fe562a9bdd2fece81530646799184992` | Descriptor lifecycle regression harness |
| `build/test_provenance_correctness` | `3586f2db7572e4dc69fd7d51bbad59c3778a711512c21157d61365bc275a0817` | Provenance DAG correctness evaluation suite |

---

## 3. Empirical Deficiency Demonstration (Before vs After)

Using disposable evidence fixtures generated in isolated environments, each deficiency was demonstrated on the baseline binary and compared against the remediated binary:

### 3.1 Suite 1: Session Manifest & Evidence Overwrite Protection

| Test Case | Scenario / Vector | Baseline Behavior (`a61a3e7`) | Remediated Behavior (`4b1706c`) | Verdict |
|:---|:---|:---|:---|:---|
| **1.1** | Direct `--dot <evid>.manifest` | `rc=0`; Manifest truncated and overwritten with DOT graph; SHA-256 corrupted (`a307...` -> `97bd...`) | `rc=1`; Replay aborts with error before opening; Manifest SHA-256 unchanged | **CORRECTED** |
| **1.2** | Direct `--json <evid>.manifest` | `rc=0`; Manifest overwritten with JSON graph data | `rc=1`; Overwrite rejected; Manifest SHA-256 unchanged | **CORRECTED** |
| **1.3** | Direct `--summary-json <evid>.manifest` | `rc=0`; Manifest overwritten with summary JSON | `rc=1`; Overwrite rejected; Manifest SHA-256 unchanged | **CORRECTED** |
| **1.4** | Symlink to Manifest (`--dot symlink.dot`) | `rc=0`; Replay followed symlink and destroyed target manifest | `rc=1`; Inode/device check detected symlink target alias; rejected | **CORRECTED** |
| **1.5** | Hardlink to Manifest (`--dot hardlink.dot`) | `rc=0`; Replay truncated inode shared with manifest | `rc=1`; `st_ino` equality detected; rejected | **CORRECTED** |
| **1.6** | Overwrite Evidence File (`--dot <evid>`) | Caught by existing check (`rc=1`) | `rc=1`; Canonical path & parent-dir matching preserved; evidence SHA-256 unchanged | **VERIFIED** |

### 3.2 Suite 2: Inconsistent Manifest Handling

| Test Case | Scenario / Inconsistency | Baseline Behavior (`a61a3e7`) | Remediated Behavior (`4b1706c`) | Verdict |
|:---|:---|:---|:---|:---|
| **2.1** | Strict mode: `ring_buffer_total_drops=10`, per-type sum=0 | `rc=0`; Replay succeeded; Graph exports written; `"manifest_verified": true` in JSON | `rc=7`; Replay failed closed; Graph exports suppressed (`access(dot)==ENOENT`); `"status": "ERROR"` | **CORRECTED** |
| **2.2** | Standard mode: Inconsistent manifest | `rc=0`; Reported `SUCCESS (Lossy Telemetry Captured)` | `rc=0`; Recovered intact prefix; Truthfully reported `SUCCESS (Inconsistent Loss Manifest)` | **CORRECTED** |

### 3.3 Suite 3: Missing Manifest & Truthful Telemetry Classification

| Test Case | Scenario / Manifest State | Baseline Behavior (`a61a3e7`) | Remediated Behavior (`4b1706c`) | Verdict |
|:---|:---|:---|:---|:---|
| **3.1** | Clean Legacy v1 evidence (no manifest file) | `rc=0`; Reported `SUCCESS (Lossy Telemetry Captured)` despite 0 drops | `rc=0`; Truthfully reported `SUCCESS (Unverified Telemetry Completeness)`; Evidence SHA-256 unchanged | **CORRECTED** |

### 3.4 Suite 4: Malformed Manifest Handling

| Test Case | Scenario / Malformed State | Baseline Behavior (`a61a3e7`) | Remediated Behavior (`4b1706c`) | Verdict |
|:---|:---|:---|:---|:---|
| **4.1** | Incompatible manifest version (`"manifest_version": 99`) | Version check missing; attempted partial parse | `rc=7`; Version mismatch rejected in strict mode; Exports suppressed | **CORRECTED** |
| **4.2** | Truncated / malformed JSON | `rc=7` under strict; standard reported `Lossy Telemetry` | `rc=7` under strict; standard reports `SUCCESS (Corrupt Manifest / Unverified Completeness)` | **CORRECTED** |

### 3.5 Suite 5: Truncated Evidence Handling & Hash Preservation

| Test Case | Operating Mode | Exit Code | Graph Export Behavior | Input File SHA-256 Status | Verdict |
|:---|:---|:---|:---|:---|:---|
| **5.1 (Standard)** | Truncated record frame at EOF | `rc=4` | Prefix recovered; valid nodes/edges exported | Unchanged (`9b5fbf22...`) | **VERIFIED** |
| **5.1 (Strict)** | Truncated record frame at EOF | `rc=4` | Aborted; exports strictly suppressed | Unchanged (`9b5fbf22...`) | **VERIFIED** |

---

## 4. Remediation Implementation Details

### 4.1 Authoritative Alias & Inode Collision Protection ([`src/user/replay.c`](file:///home/magellan/Garage/prototypes/FM/FM-persist/src/user/replay.c))
```c
static bool is_same_file_or_alias(const char *target_path, const struct stat *st_target, bool has_st_target, const char *out_path)
{
    if (!target_path || !target_path[0] || !out_path || !out_path[0])
        return false;

    if (strcmp(target_path, out_path) == 0)
        return true;

    /* Authoritative kernel inode/dev matching (covers symlinks, hardlinks, bind mounts) */
    if (has_st_target && st_target) {
        struct stat st_out;
        if (stat(out_path, &st_out) == 0) {
            if (st_out.st_dev == st_target->st_dev && st_out.st_ino == st_target->st_ino)
                return true;
        }
    }

    /* Canonical path equivalence when both exist */
    char r_target[4096], r_out[4096];
    if (realpath(target_path, r_target) && realpath(out_path, r_out)) {
        if (strcmp(r_target, r_out) == 0)
            return true;
    }

    /* Canonical parent directory + basename matching (covers non-existent target files) */
    char dir_target[4096], dir_out[4096], base_target[4096], base_out[4096];
    // ... extracts dir & basename ...
    char r_dir_target[4096], r_dir_out[4096];
    if (realpath(dir_target, r_dir_target) && realpath(dir_out, r_dir_out)) {
        if (strcmp(r_dir_target, r_dir_out) == 0 && strcmp(base_target, base_out) == 0)
            return true;
    }
    return false;
}
```
All export paths are validated before running replay. If any target matches `cfg.evid_path`, `<evid_path>.manifest`, or another export argument, execution terminates with code `1` with descriptive stderr logging.

### 4.2 Manifest Consistency & Strict Rejection ([`src/user/replay.c`](file:///home/magellan/Garage/prototypes/FM/FM-persist/src/user/replay.c))
In `main()`:
```c
loss_st = evidence_manifest_evaluate_loss(&manifest, &computed_drops, &capture_desc);
telemetry_lossless = (loss_st == EVIDENCE_LOSS_LOSSLESS);

if (loss_st == EVIDENCE_LOSS_INCONSISTENT) {
    manifest_verified = false;
    persist_desc = "INCONSISTENT (Discrepancy in loss counters)";
    manifest_status = "INCONSISTENT (Discrepancy in loss counters)";
} else if (size_match && count_match && final_clean && loss_clean) {
    manifest_verified = true;
    persist_desc = "VERIFIED (Storage & CRC clean)";
    manifest_status = persist_desc;
} else {
    manifest_verified = false;
    persist_desc = "DISCREPANCY (Storage corruption or size/count mismatch)";
    manifest_status = persist_desc;
}
```
Under `--strict`, `manifest_acceptable` requires `manifest_verified == true`. If `loss_st == EVIDENCE_LOSS_INCONSISTENT`, `manifest_verified` is forced to `false`, causing strict replay to fail with exit code `7` and set `exports_aborted = true`.

### 4.3 Truthful Reconstruction Status Reporting ([`src/user/replay.c`](file:///home/magellan/Garage/prototypes/FM/FM-persist/src/user/replay.c))
Reconstruction status reporting in `replay.c` now evaluates all lifecycle and loss dimensions:
- If no manifest is present: `SUCCESS (Unverified Telemetry Completeness)`
- If manifest verified & lossless: `SUCCESS (Complete & Lossless)`
- If manifest verified & positive drops: `SUCCESS (Lossy Telemetry Captured)`
- If manifest verified & counters unavailable: `SUCCESS (Telemetry Completeness Unverified)`
- If manifest inconsistent: `SUCCESS (Inconsistent Loss Manifest)`
- If manifest corrupt: `SUCCESS (Corrupt Manifest / Unverified Completeness)`
- If storage size/count mismatch: `SUCCESS (Unfinalized / Storage Discrepancy)`

### 4.4 Robust JSON Manifest Parsing ([`src/user/evidence_io.h`](file:///home/magellan/Garage/prototypes/FM/FM-persist/src/user/evidence_io.h))
- Added `manifest_version` validation (`m_ver == 1`).
- Expanded manifest read buffer to `8192` bytes.
- Updated `evidence_manifest_find_val()` to skip carriage returns (`\r`) and newlines (`\n`) as well as spaces and tabs.
- Key parsing decoupled from strict `:` suffix, supporting formatted and indented JSON.

---

## 5. Full Test Inventory & Regression Summary

| Test Binary | Suites / Cases | Passed | Failed | Status | Notes |
|:---|:---|:---|:---|:---|:---|
| `test_qualification_replay` | 5 Suites / 11 Checks | 11 | 0 | **PASS** | Alias protection, manifest consistency, classification, truncation |
| `test_failure_controls` | 5 Failure Controls | 5 | 0 | **PASS** | Orderly, abrupt kill (`rc=7`), truncation (`rc=4`), bitflip (`rc=4`), storage bounds |
| `test_pipeline_integration` | 10 Integration Suites | 10 | 0 | **PASS** | Legacy v1, alias protection, exact sample size, loss validation |
| `test_descriptor_lifecycle_reconstruction` | 6 Regression Cases | 6 | 0 | **PASS** | `dup2`/`dup3`, ordinary file replacement, `CLONE_FILES`, -EBUSY |
| `test_provenance_correctness` | 6 Correctness Suites | 6 | 0 | **PASS** | 100% precision and recall across typed entity/edge reconstructions |
| `test_qualification_descriptor` | 28 Native Assertions | 28 | 0 | **PASS** | Descriptor reuse, replacement, and concurrency smoke test |
| `test_m6_dag` | DAG Export Verification | 1 | 0 | **PASS** | DOT/JSON graph construction; exit status unknown invariant |

---

## 6. Checkpoint State & Commitments

- **Checkpoint**: Commit [`4b1706c`](https://github.com/YASHAS-MN/eBPF-Emphim-Trace-/commit/4b1706c) pushed to `remediation/state-independence-and-loss-accountability`.
- **Collection Freeze**: eBPF bytecode (`src/bpf/monitor.bpf.c`), hook points, ring buffer configurations, and binary wire formats remain frozen and unchanged.
- **Evidence Immutability**: All replay operations verified read-only against input evidence and session manifests.
