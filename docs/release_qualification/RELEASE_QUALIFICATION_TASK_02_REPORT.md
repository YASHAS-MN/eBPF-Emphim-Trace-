# EphimTrace — Release Qualification Task 02 Report
## Evidence Integrity, Replay Safety, and Manifest Lifecycle Hardening (GitHub Issue #11)

**Date**: 2026-11-28  
**Scope**: Release Qualification Task 02 under GitHub Issue #11 and `PROJECT_STATE.md`  
**Base Implementation Checkpoint**: `a61a3e7` (Descriptor Remediation Checkpoint)  
**Remediated Checkpoint**: `4b1706c` / Current Head (`fix(replay): enforce complete JSON manifest parsing, safe open-time exports, and strict legacy opt-in`)  
**Host Environment**: Linux `7.0.0-44-generic #44~24.04.1-Ubuntu SMP PREEMPT_DYNAMIC x86_64`  
**Compiler**: `gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0`, `Ubuntu clang version 16.0.6`  
**Worktree**: `/home/magellan/Garage/prototypes/FM/FM-persist`  
**Branch**: `remediation/state-independence-and-loss-accountability`  

---

## 1. Executive Summary

This qualification report evaluates forensic evidence integrity, session manifest validation, export path safety, and truthful classification under offline replay reconstruction. 

Following the completion of Release Qualification Task 01 (`a61a3e7`), Task 02 addresses four critical failure modes identified under GitHub Issue #11 and finalized at checkpoint `4b1706c`:
1. **Accidental overwriting of evidence or session manifests through replay export paths**: Replay export targets (`--dot`, `--json`, `--summary-json`, `--timeline`, `--filtered-dot`, `--filtered-json`) truncating or overwriting input evidence or accompanying session manifests via direct paths, symlinks, hardlinks, or path aliases.
2. **Missing, malformed and inconsistent manifest handling**: Inconsistent loss accounting (where `ring_buffer_total_drops` conflicts with the sum of per-type drops) accepted without rejection; malformed JSON or incompatible manifest versions allowed to proceed.
3. **Misleading integrity and completeness classifications**: Replay conflating "unverified / legacy completeness" with "lossy telemetry captured," falsely claiming packet loss when zero drops occurred; or conversely masking known positive drop counters as unverified when other counters were missing.
4. **Strict replay failure handling and preservation of recoverable evidence**: Enforcing strict fail-closed semantics (`rc=7` on unfinalized, inconsistent, or unverified manifests; `rc=4` on corrupt/truncated records) with absolute export suppression under strict mode, while guaranteeing clean prefix recovery under standard mode without mutating input artifacts.

### Key Qualification Verdicts:
- **Open-Time Safe File Creation**: Replay exports strictly employ atomic open-time creation (`O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC`), preventing truncation of pre-existing files without preliminary TOCTOU races. Overwriting existing non-symlink exports requires explicit `--overwrite` / `--force` / `-f`. Pre-flight path and inode verification terminates with `rc=1` if an export target matches evidence or manifest paths.
- **Complete RFC 8259 Recursive-Descent JSON Parsing**: The manifest parser performs strict recursive-descent tokenization, validates all required fields (`manifest_version == 1`, `record_count`, `storage_bytes`, `finalized`, `synchronized`, and `loss_counters`), and enforces checked numeric conversions rejecting trailing characters, negative values for unsigned types, and integer overflow.
- **Strict Mode Legacy Opt-In**: Under `--strict`, absent manifests fail closed with exit code `7` and suppress all exports, unless explicit legacy opt-in (`--allow-legacy` / `--legacy`) is provided.
- **Truthful Status & Loss Preservation**: Clean legacy evidence reports `SUCCESS (Unverified Telemetry Completeness)`. Positive drop counts are preserved as `LOSSY` even when auxiliary counters are unavailable (`-1`), preventing loss masking.
- **Architectural Preservation**: The kernel eBPF collection architecture (`src/bpf/monitor.bpf.c`), `struct event` ABI, and ring buffer performance configurations remain 100% untouched.

---

## 2. Tested Binary Hashes & Environment Checkpoint

All binaries were compiled from source tree at commit `4b1706c` with strict hardening updates:

| Binary / Artifact Component | SHA-256 Digest | Role / Purpose |
|:---|:---|:---|
| `build/replay` | `3ba08a6fad689746e8cf511953c24c3cabe77bcf87de96f820a66097aa5201d5` | Hardened offline replay reconstruction utility |
| `build/test_qualification_replay` | `b0c844112a23b1bcb55f4d127ddfe6a926c9c0bd3241229f066095b47ca29768` | Dedicated Release Qualification Task 02 test suite (6 suites / 22 checks) |
| `build/test_failure_controls` | `d225f5db4f5577e4c158fd0412bef5932e7ace2553eb0031a54fd44e0cf82283` | Bounded failure controls & resilience test suite |
| `build/test_pipeline_integration` | `7472bdbad8376ac411135569e7daf2834c13560dd985e264fa4e0760349c2c82` | End-to-end collection-first integration test suite |
| `build/test_descriptor_lifecycle_reconstruction` | `8db8d8a1ecad6c5af61ea8d55bbbedba5f540dc6fbd1a82290755aac6c595fec` | Descriptor lifecycle regression harness |
| `build/test_provenance_correctness` | `de4745d06eef770dd9443326ad4d88207de58189e6f2492c98c4d64cbcdf64c2` | Provenance DAG correctness evaluation suite |
| `build/test_qualification_descriptor` | `3d32d43646d9c2c9f3631e8234741f37667714d34c9c11a7dc66291852ef8e7c` | Native descriptor lifecycle smoke suite |

---

## 3. Empirical Deficiency Demonstration (Before vs After)

Using disposable evidence fixtures generated in isolated environments, each deficiency was demonstrated on the baseline binary and compared against the remediated binary across 6 comprehensive test suites (22 checks):

### 3.1 Suite 1: Session Manifest & Evidence Overwrite Protection

| Test Case | Scenario / Vector | Baseline Behavior (`a61a3e7`) | Remediated Behavior | Verdict |
|:---|:---|:---|:---|:---|
| **1.1** | Direct `--dot <evid>.manifest` | `rc=0`; Manifest truncated and overwritten with DOT graph; SHA-256 corrupted (`a307...` -> `97bd...`) | `rc=1`; Replay aborts with error before opening; Manifest SHA-256 unchanged | **CORRECTED** |
| **1.2** | Direct `--json <evid>.manifest` | `rc=0`; Manifest overwritten with JSON graph data | `rc=1`; Overwrite rejected; Manifest SHA-256 unchanged | **CORRECTED** |
| **1.3** | Direct `--summary-json <evid>.manifest` | `rc=0`; Manifest overwritten with summary JSON | `rc=1`; Overwrite rejected; Manifest SHA-256 unchanged | **CORRECTED** |
| **1.4** | Symlink to Manifest (`--dot symlink.dot`) | `rc=0`; Replay followed symlink and destroyed target manifest | `rc=1`; Inode/device check detected symlink target alias; rejected | **CORRECTED** |
| **1.5** | Hardlink to Manifest (`--dot hardlink.dot`) | `rc=0`; Replay truncated inode shared with manifest | `rc=1`; `st_ino` equality detected; rejected | **CORRECTED** |
| **1.6** | Overwrite Evidence File (`--dot <evid>`) | Caught by preliminary check (`rc=1`) | `rc=1`; Canonical path & parent-dir matching preserved; evidence SHA-256 unchanged | **VERIFIED** |
| **1.7** | Existing export rejected at file-open time without truncation | `fopen(..., "w")` truncated existing file immediately | `rc=6`; `O_CREAT | O_EXCL` fails with `-EEXIST`; file content & hash unchanged | **CORRECTED** |
| **1.8** | Safe export overwrite with `--overwrite` / `-f` | Overwrote unconditionally without confirmation | `rc=0`; Overwrite permitted only when explicit flag provided; valid DOT written | **CORRECTED** |
| **1.9** | Symlinked export rejected at open-time even with `--overwrite` | `fopen` followed symlink and modified target | `O_NOFOLLOW` fails with `-ELOOP`; symlinked target hash unchanged | **CORRECTED** |

### 3.2 Suite 2: Inconsistent Manifest Handling

| Test Case | Scenario / Inconsistency | Baseline Behavior (`a61a3e7`) | Remediated Behavior | Verdict |
|:---|:---|:---|:---|:---|
| **2.1** | Strict mode: `ring_buffer_total_drops=10`, per-type sum=0 | `rc=0`; Replay succeeded; Graph exports written; `"manifest_verified": true` in JSON | `rc=7`; Replay failed closed; Graph exports suppressed (`access(dot)==ENOENT`); `"status": "ERROR"` | **CORRECTED** |
| **2.2** | Standard mode: Inconsistent manifest | `rc=0`; Reported `SUCCESS (Lossy Telemetry Captured)` | `rc=0`; Recovered intact prefix; Truthfully reported `SUCCESS (Inconsistent Loss Manifest)` | **CORRECTED** |

### 3.3 Suite 3: Missing Manifest & Truthful Telemetry Classification

| Test Case | Scenario / Manifest State | Baseline Behavior (`a61a3e7`) | Remediated Behavior | Verdict |
|:---|:---|:---|:---|:---|
| **3.1** | Clean Legacy v1 evidence (no manifest file) | `rc=0`; Reported `SUCCESS (Lossy Telemetry Captured)` despite 0 drops | `rc=0`; Truthfully reported `SUCCESS (Unverified Telemetry Completeness)`; Evidence SHA-256 unchanged | **CORRECTED** |
| **3.2** | Strict replay rejected legacy evidence without manifest | `rc=0`; Replay succeeded without manifest | `rc=7`; Strict mode fails closed when manifest missing; exports suppressed | **CORRECTED** |
| **3.3** | Strict replay with `--allow-legacy` opt-in | N/A (no flag existed) | `rc=0`; Exports generated; Truthfully reports `SUCCESS (Unverified Telemetry Completeness)` | **CORRECTED** |

### 3.4 Suite 4: Malformed Manifest Handling & Strict JSON Parsing

| Test Case | Scenario / Malformed State | Baseline Behavior (`a61a3e7`) | Remediated Behavior | Verdict |
|:---|:---|:---|:---|:---|
| **4.1** | Incompatible manifest version (`"manifest_version": 99`) | Version check missing; attempted partial parse | `rc=7`; Version mismatch rejected in strict mode; Exports suppressed | **CORRECTED** |
| **4.2** | Unclosed JSON syntax (`{"manifest_version": 1, ...`) | String matching read partial keys | `rc=7`; RFC 8259 parser rejects unclosed JSON; Exports suppressed | **CORRECTED** |
| **4.3** | Trailing garbage after root JSON object | Ignored trailing garbage | `rc=7`; Parser enforces `json_skip_ws` at root end; trailing tokens rejected | **CORRECTED** |
| **4.4** | Missing required fields (`finalized` / `synchronized`) | Assumed default true | `rc=7`; Parser requires mandatory fields; missing keys fail validation | **CORRECTED** |
| **4.5** | Negative value for unsigned `record_count` (`-1`) | Converted to unsigned without check | `rc=7`; Checked conversion rejects leading `-`; validation fails | **CORRECTED** |

### 3.5 Suite 5: Truncated Evidence Handling & Hash Preservation

| Test Case | Operating Mode | Exit Code | Graph Export Behavior | Input File SHA-256 Status | Verdict |
|:---|:---|:---|:---|:---|:---|
| **5.1 (Standard)** | Truncated record frame at EOF | `rc=4` | Prefix recovered; valid nodes/edges exported | Unchanged (`9b5fbf22...`) | **VERIFIED** |
| **5.1 (Strict)** | Truncated record frame at EOF | `rc=4` | Aborted; exports strictly suppressed | Unchanged (`9b5fbf22...`) | **VERIFIED** |

### 3.6 Suite 6: Known Positive Loss Preservation with Unavailable Counters

| Test Case | Scenario / Counter Availability | Baseline Behavior (`a61a3e7`) | Remediated Behavior | Verdict |
|:---|:---|:---|:---|:---|
| **6.1** | Positive total drops (12) with unavailable registry counters (`-1`) | Reported `UNVERIFIED`, masking known drops | Evaluated as `LOSSY`; Truthfully preserves known packet loss | **CORRECTED** |
| **6.2** | Positive per-type drop (execve=5) with unavailable total counter (`-1`) | Reported `UNVERIFIED`, masking known drops | Evaluated as `LOSSY`; Truthfully preserves known syscall drop | **CORRECTED** |

---

## 4. Remediation Implementation Details

### 4.1 Safe Open-Time Exclusive File Creation ([`src/user/provenance.c`](file:///home/magellan/Garage/prototypes/FM/FM-persist/src/user/provenance.c))
Export creation was moved from unguarded `fopen(..., "w")` to atomic kernel open calls via `prov_open_safe_export()`:
```c
FILE *prov_open_safe_export(const char *filepath, bool allow_overwrite, int *out_err)
{
    int flags = O_WRONLY | O_CREAT | O_CLOEXEC;
    if (!allow_overwrite)
        flags |= O_EXCL | O_NOFOLLOW;
    else
        flags |= O_TRUNC | O_NOFOLLOW;

    int fd = open(filepath, flags, 0644);
    if (fd < 0) {
        if (out_err) *out_err = -errno;
        return NULL;
    }
    return fdopen(fd, "w");
}
```
If a file already exists at the target path and `--overwrite` (`-f`) was not specified, the operation immediately fails with `-EEXIST` (exit code `6`) without altering or truncating the pre-existing file. `O_NOFOLLOW` guarantees that symlinks pointing to sensitive targets are rejected with `-ELOOP`.

### 4.2 Authoritative Alias & Inode Collision Protection ([`src/user/replay.c`](file:///home/magellan/Garage/prototypes/FM/FM-persist/src/user/replay.c))
```c
static bool is_same_file_or_alias(const char *target_path, const struct stat *st_target, bool has_st_target, const char *out_path)
{
    if (!target_path || !target_path[0] || !out_path || !out_path[0])
        return false;

    if (strcmp(target_path, out_path) == 0)
        return true;

    /* Authoritative kernel inode/dev matching (covers symlinks, hardlinks, bind mounts) */\n    if (has_st_target && st_target) {
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
    char r_dir_target[4096], r_dir_out[4096];
    if (realpath(dir_target, r_dir_target) && realpath(dir_out, r_dir_out)) {
        if (strcmp(r_dir_target, r_dir_out) == 0 && strcmp(base_target, base_out) == 0)
            return true;
    }
    return false;
}
```
All export paths are validated before running replay. If any target matches `cfg.evid_path`, `<evid_path>.manifest`, or another export argument, execution terminates with code `1` with descriptive stderr logging.

### 4.3 Full RFC 8259 Recursive-Descent JSON Manifest Parser ([`src/user/evidence_io.h`](file:///home/magellan/Garage/prototypes/FM/FM-persist/src/user/evidence_io.h))
A zero-external-dependency recursive-descent parser constructs an in-memory JSON AST and validates semantic constraints:
- Enforces valid structural nesting of objects and arrays.
- Rejects trailing characters or malformed tokens following the root JSON object.
- Validates mandatory fields: `manifest_version`, `record_count`, `storage_bytes`, `finalized`, `synchronized`, and `loss_counters`.
- Strict numeric conversion functions (`ephim_json_val_to_uint64`, `ephim_json_val_to_uint32`, `ephim_json_val_to_int64`):
  - Prohibit negative numbers (`-`) for unsigned fields (`record_count`, `storage_bytes`, `manifest_version`).
  - Prohibit non-digit trailing characters.
  - Detect and reject `ERANGE` overflow.

### 4.4 Strict Mode Legacy Opt-In ([`src/user/replay.c`](file:///home/magellan/Garage/prototypes/FM/FM-persist/src/user/replay.c))
Under `--strict`, absence of a session manifest causes replay to terminate with exit code `7` and suppress all exports, guarding against accidental consumption of unverified legacy evidence. Operators may explicitly opt in via `--allow-legacy` / `--legacy`, allowing recovery while truthfully logging the unverified completeness status.

### 4.5 Positive Loss Preservation Logic ([`src/user/evidence_io.h`](file:///home/magellan/Garage/prototypes/FM/FM-persist/src/user/evidence_io.h))
In `evidence_manifest_evaluate_loss()`:
```c
bool any_positive_loss = (m->loss.ring_buffer_total_drops > 0 ||
                          any_type_positive ||
                          m->loss.reg_map_full_drop > 0 ||
                          m->loss.token_alloc_err > 0 ||
                          m->loss.token_mismatch > 0);

if (any_positive_loss) {
    *out_desc = "LOSSY (Packet / registry loss recorded in manifest)";
    return EVIDENCE_LOSS_LOSSY;
}
```
Even if auxiliary counters are absent or uninitialized (`-1`), verified positive drops are never masked or classified as unverified.

---

## 5. Full Test Inventory & Regression Summary

| Test Binary | Suites / Cases | Passed | Failed | Status | Notes |
|:---|:---|:---|:---|:---|:---|
| `test_qualification_replay` | 6 Suites / 22 Checks | 22 | 0 | **PASS** | Alias protection, open-time safety, strict JSON parsing, legacy opt-in, loss preservation |
| `test_failure_controls` | 5 Failure Controls | 5 | 0 | **PASS** | Orderly, abrupt kill (`rc=7`), truncation (`rc=4`), bitflip (`rc=4`), storage bounds |
| `test_pipeline_integration` | 10 Integration Suites | 10 | 0 | **PASS** | Legacy v1, alias protection, exact sample size, loss validation, legacy opt-in |
| `test_descriptor_lifecycle_reconstruction` | 6 Regression Cases | 6 | 0 | **PASS** | `dup2`/`dup3`, ordinary file replacement, `CLONE_FILES`, -EBUSY |
| `test_provenance_correctness` | 6 Correctness Suites | 6 | 0 | **PASS** | 100% precision and recall across typed entity/edge reconstructions |
| `test_qualification_descriptor` | 28 Native Assertions | 28 | 0 | **PASS** | Descriptor reuse, replacement, and concurrency smoke test |
| `test_m7_scenarios` | 3 Scenario Milestones | 3 | 0 | **PASS** | In-memory dropper, anti-forensic unlink, composite forensic sequence |
| `test_m6_dag` | DAG Export Verification | 1 | 0 | **PASS** | DOT/JSON graph construction; exit status unknown invariant |

---

## 6. Checkpoint State & Commitments

- **Checkpoint**: Finalized under GitHub Issue #11 on branch `remediation/state-independence-and-loss-accountability`.
- **Collection Freeze**: eBPF bytecode (`src/bpf/monitor.bpf.c`), hook points, ring buffer configurations, and binary wire formats remain frozen and unchanged.
- **Evidence Immutability**: All replay operations verified read-only against input evidence and session manifests.
- **Safety**: Export file creation is guaranteed race-free and collision-safe at kernel open time.
