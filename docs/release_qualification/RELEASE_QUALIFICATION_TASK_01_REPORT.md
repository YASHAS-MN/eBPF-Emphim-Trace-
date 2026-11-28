# EphimTrace — Release Qualification Task 01 Report
## Descriptor Lifecycle Correctness & Concurrency Qualification (GitHub Issue #5)

**Date**: 2026-11-28  
**Scope**: Release Qualification Task 01 under GitHub Issue #5 and `PROJECT_STATE.md`  
**Base Implementation Checkpoint**: `b6c89af` (Frozen Production Implementation)  
**Remediated Checkpoint**: `abfe508` (Exit-Status Validation, -EBUSY Handling & Authoritative Removal)  
**Host Environment**: Linux `7.0.0-44-generic #44~24.04.1-Ubuntu SMP PREEMPT_DYNAMIC x86_64`  
**Worktree**: `/home/magellan/Garage/prototypes/FM/FM-persist`  
**Branch**: `remediation/state-independence-and-loss-accountability`  

---

## 1. Executive Summary

This qualification report evaluates the correctness of file descriptor lifecycle tracking and in-kernel descriptor registries (`memfd_desc_registry`) under native Linux kernel execution with persistent evidence capture and deterministic graph reconstruction.

The evaluation covers four critical operating conditions mandated by GitHub Issue #5:
1. **Descriptor Duplication and Replacement** (`dup`, `dup2`, `dup3`, `fcntl(F_DUPFD)`)
2. **Replacement of Tracked Descriptors with Ordinary Files** (atomically overwriting tracked memfd slots)
3. **Descriptor Reuse and Failed Operations** (negative error returns, slot recycling, unclosed process exits)
4. **Concurrent Operations Involving Shared Descriptor Tables** (`pthread` concurrency and `clone(CLONE_FILES)` cross-process sharing)

### Qualification Results Summary:
- **Baseline Investigation (`98d3e14`)**: Exposed three critical deficiencies under native kernel execution:
  - Missing coverage for `dup2`/`dup3` duplication (FDs 35 and 36 omitted from telemetry and graph).
  - Stale registry state leading to false close attribution when a tracked memfd was replaced by an ordinary file (+25,288 ns false lifetime).
  - Cross-process attribution loss under `CLONE_FILES` due to descriptor registry keying by `(tgid, fd)` rather than `files_struct *`.
- **Remediated Production Capture (`abfe508`)**:
  - Full native pipeline execution (`descriptor_qual.evid`, 1,052,416 bytes; 1,512 verified frames; 0 drops).
  - Reconstructed provenance graph: 228 nodes, 1,076 edges.
  - 100% double-replay determinism verified between `exports/run1` and `exports/run2`.
  - All 4 native qualification suites **PASSED with 100% precision and zero false attributions**.

---

## 2. Tested Binary Hashes & Environment Checkpoint

All binaries were compiled from source tree at commit `abfe508` using `clang-16` (BPF target) and `gcc` (Ubuntu 13.3.0):

| Binary / Artifact Component | SHA-256 Digest | Role / Purpose |
|:---|:---|:---|
| `build/loader` | `ebde87ed9990d391f6705a3d83fe6106bad503add68b459970a1f2d4b4a3df28` | Production eBPF loader & evidence serializer |
| `build/replay` | `87074bbec4e4bdf9ab237faf1505169f7240b5476ce35604c06e7096e64dd731` | Forensic replay engine & DAG generator |
| `build/monitor.bpf.o` | `5318ee1a5adf335fa9df89d80b53121a51a2c689b35404bc76b43f44a90209b4` | Compiled eBPF telemetry bytecode |
| `build/test_qualification_descriptor` | `3d32d43646d9c2c9f3631e8234741f37667714d34c9c11a7dc66291852ef8e7c` | Native kernel test workload (28 assertions) |
| `build/test_descriptor_lifecycle_reconstruction` | `6d4a74ef8e57457458caea6d2138c107fe562a9bdd2fece81530646799184992` | Reconstruction & concurrency regression suite |
| `build/test_provenance_correctness` | `3586f2db7572e4dc69fd7d51bbad59c3778a711512c21157d61365bc275a0817` | End-to-end provenance correctness suite |
| `data/descriptor_qual.evid` | `dfbd7a3c679f6fb7ea934235bcca546373f3389ec41bc2baa4466b1ae4b5016d` | Remediated native evidence capture (1,512 frames) |
| `data/descriptor_qual.evid.manifest` | `1cb422118e55241074e61dec05c94cc4c37403f7caf08ddc13f3d4611c947da9` | Cryptographic session manifest |

**Runner Label Correction**: The runner script `tests1.0/kernel_telemetry/qualification_descriptor/run_qualification_descriptor.sh` was updated to correct the obsolete `b6c89af` label to `abfe508`.

---

## 3. Production Hook Inventory & Loss Accountability

### 3.1 Attached Kernel Probes (27 Logical Hooks / 60 Per-CPU Events)
The production collector loaded all 27 required hooks without errors (`STATUS: READY`):

```
[Process lifecycle]
  [OK] capture_process_fork      (sched/sched_process_fork)
  [OK] capture_process_exec      (sched/sched_process_exec)
  [OK] capture_process_exit      (sched/sched_process_exit)

[Syscall entry]
  [OK] capture_execve            (syscalls/sys_enter_execve)
  [OK] capture_memfd_create      (syscalls/sys_enter_memfd_create)
  [OK] capture_unlink            (syscalls/sys_enter_unlink)
  [OK] capture_unlinkat          (syscalls/sys_enter_unlinkat)
  [OK] capture_rmdir             (syscalls/sys_enter_rmdir)
  [OK] capture_connect           (syscalls/sys_enter_connect)

[Syscall exit]
  [OK] capture_unlink_exit       (syscalls/sys_exit_unlink)
  [OK] capture_unlinkat_exit     (syscalls/sys_exit_unlinkat)
  [OK] capture_rmdir_exit        (syscalls/sys_exit_rmdir)
  [OK] capture_memfd_create_exit (syscalls/sys_exit_memfd_create)
  [OK] capture_execve_exit       (syscalls/sys_exit_execve)
  [OK] capture_execveat_exit     (syscalls/sys_exit_execveat)

[VFS]
  [OK] capture_fd_install        (vfs/fd_install)
  [OK] capture_shmem_evict_inode (vfs/shmem_evict_inode)
  [OK] capture_fput              (vfs/__fput)
  [OK] capture_shmem_write_iter  (vfs/shmem_file_write_iter)
  [OK] capture_close_fd          (vfs/file_close_fd) [fexit]
  [OK] capture_do_dup2_entry     (vfs/do_dup2)       [fentry]
  [OK] capture_do_dup2_exit      (vfs/do_dup2)       [fexit]
  [OK] capture_bprm_check        (security/security_bprm_check)
  [OK] capture_vfs_unlink_entry  (vfs/vfs_unlink)
  [OK] capture_vfs_unlink_exit   (vfs/vfs_unlink)
  [OK] capture_vfs_rmdir_entry   (vfs/vfs_rmdir)
  [OK] capture_vfs_rmdir_exit    (vfs/vfs_rmdir)

LOGICAL HOOKS ATTACHED: 27/27 (100%)
PER-CPU EVENTS ATTACHED: 60/60
STATUS: READY
```

### 3.2 Loss Counter Accountability
Telemetry loss metrics extracted from `descriptor_qual_loader.log` and session manifest:
- **Ring Buffer Total Drops**: 0 (`CNT_RING_BUF_DROPS = 0`)
- **Kernel Registry Drops**: 0 (`CNT_REG_MAP_FULL_DROP = 0`)
- **Kernel Token Errors**: 0 (`CNT_REG_TOKEN_ERR = 0`)
- **Token Mismatches**: 0 (`CNT_REG_TOKEN_MISMATCH = 0`)
- **Sample Size Mismatches**: 0
- **Storage Persistence**: `SYNCHRONIZED (Storage & CRC clean)`
- **Telemetry Completeness**: `COMPLETE_LOSSLESS (0 drops recorded across all stages)`

---

## 4. Empirical Evaluation: Native Capture vs. Baseline

The remediated native capture was executed against the running Linux kernel (Workload Parent PID: 43900, `CLONE_FILES` Child PID: 43905):

### Suite 1: Duplication and Replacement (`dup`, `dup2`, `dup3`, `fcntl`)
- **Workload Log Ground Truth**: FDs `[3 (orig), 4 (dup), 30 (fcntl), 35 (dup2), 36 (dup3)]`.
- **Baseline Behavior (`98d3e14`)**: FDs 35 and 36 had **0 events** and were omitted from the DAG.
- **Native Remediated Behavior (`abfe508`)**:
  - `Frame Seq 459 @ 8867877845240 ns`: `EVENT_FD_INSTALLED` (FD 3, Token 5, `CREATION`)
  - `Frame Seq 461 @ 8867877853476 ns`: `EVENT_FD_INSTALLED` (FD 4, Token 5, `DUP`)
  - `Frame Seq 462 @ 8867877856471 ns`: `EVENT_FD_INSTALLED` (FD 30, Token 5, `DUP`)
  - `Frame Seq 463 @ 8867877860158 ns`: `EVENT_FD_INSTALLED` (FD 35, Token 5, `DUP`)
  - `Frame Seq 464 @ 8867877866721 ns`: `EVENT_FD_INSTALLED` (FD 36, Token 5, `DUP`)
- **Reconstructed Graph**:
  - `memfd_5` (`qual_mfd_dup`) contains all 5 `EDGE_FD_INSTALLED` edges: FDs `[3, 4, 30, 35, 36]`.
  - **Verdict**: **VERIFIED RESOLVED**.

### Suite 2: Replacement of Tracked Memfd with Ordinary File
- **Workload Ground Truth**:
  - Memfd `qual_mfd_replace` created at FD 3 (inode 382635).
  - Ordinary file created at FD 5 (`/tmp/ephim_qual_ordinary_isdO18`, inode 918235).
  - `dup2(5, 3)` overwrites slot 3 with ordinary file.
  - Workload closes FD 3.
- **Baseline Behavior (`98d3e14`)**:
  - Memfd destroyed at `6408333180285` ns.
  - Ordinary file close at `6408333205573` ns emitted false `EVENT_FD_CLOSED` with duration 106,891 ns (+25,288 ns inflated lifetime).
- **Native Remediated Behavior (`abfe508`)**:
  - `Frame Seq 473 @ 8867877903329 ns`: `EVENT_FD_INSTALLED` (FD 3, Token 6)
  - `Frame Seq 474 @ 8867877904832 ns`: `EVENT_MEMFD_COMPLETED` (FD 3, Token 6)
  - `Frame Seq 475 @ 8867877984080 ns`: `EVENT_FD_CLOSED` (FD 3, Token 6, Duration 81,172 ns) — **Emitted at replacement time!**
  - `Frame Seq 476 @ 8867877986325 ns`: `EVENT_MEMFD_FILE_RELEASED` (Token 6)
  - `Frame Seq 477 @ 8867877988128 ns`: `EVENT_MEMFD_DESTROYED` (Token 6)
  - **Ordinary File Close**: When `close(3)` was called on the ordinary file, `capture_close_fd` (`fexit`) received `ret`, observed `ret->f_inode != memfd_inode`, purged any stale mapping, and **suppressed close telemetry (0 events)**.
- **Reconstructed Graph**:
  - `memfd_6` contains `EDGE_FD_CLOSED` with timestamp `8867877984080` ns $\le$ `8867877988128` ns (`EVENT_MEMFD_DESTROYED`).
  - **Verdict**: **VERIFIED RESOLVED**.

### Suite 3: Descriptor Reuse and Failed Operations
- **Negative Syscalls**: `dup(-1)`, `dup2(-1, 50)`, `dup3(50, 50)`, `close(-1)` all produced **0 events**.
- **Slot Recycling**: Slot FD 3 recycled for `/tmp/ephim_qual_reuse_isdO18` without false attribution.
- **Verdict**: **VERIFIED CLEAN**.

### Suite 4: Shared Descriptor Tables Across Processes (`CLONE_FILES`)
- **Workload Ground Truth**: Parent PID 43900 created `qual_mfd_clone` at FD 3. Spawed Child PID 43905 with `CLONE_FILES`. Child wrote 25 bytes and closed FD 3.
- **Baseline Behavior (`98d3e14`)**: Child close dropped (0 events) due to `tgid` mismatch in registry. `memfd_9` remained unclosed in graph.
- **Native Remediated Behavior (`abfe508`)**:
  - Child PID 43905 close resolved via shared `files_ptr`.
  - Telemetry contains `EVENT_FD_CLOSED` for Child PID 43905 on Token 9.
  - Reconstructed Graph edges for `memfd_9`:
    - `proc_43900_8867873778987 -> memfd_9 [EDGE_FD_INSTALLED]` (FD 3)
    - `proc_43900_8867873778987 -> memfd_9 [EDGE_MEMFD_CREATE]` (FD 3)
    - `proc_43905_8867878737311 -> memfd_9 [EDGE_MEMFD_WRITE]` (25 bytes)
    - `proc_43905_8867878737311 -> memfd_9 [EDGE_FD_CLOSED]` (FD 3, attributed to Child!)
- **Verdict**: **VERIFIED RESOLVED**.

---

## 5. Distinction: Native-Verified vs. Synthetic Concurrency Results

To maintain strict reporting integrity, the validation methodologies are explicitly separated:

### 5.1 Native-Verified Corrections (Live Linux Kernel Telemetry)
These behaviors were executed against the live host kernel under `build/loader` and verified from persistent evidence `descriptor_qual.evid`:
1. **`dup2` / `dup3` installation**: Verified in kernel via `capture_do_dup2_exit` emitting `EVENT_FD_INSTALLED` for FDs 35 and 36.
2. **Replacement-time closure**: Verified in kernel emitting `EVENT_FD_CLOSED` before `EVENT_MEMFD_DESTROYED`.
3. **Ordinary file close suppression**: Verified authoritatively in kernel using `ret->f_inode` check in `fexit/file_close_fd`.
4. **`CLONE_FILES` shared table close**: Verified in kernel across Parent PID 43900 and Child PID 43905 using `files_ptr` keying.

### 5.2 Synthetic Concurrency Regression Results (`test_descriptor_lifecycle_reconstruction`)
These edge cases were verified via targeted deterministic unit regressions in userspace:
1. **`do_dup2` Failure Path (`-EBUSY` / `-EBADF`)**:
   - Case 5 verifies that when `do_dup2` returns `< 0`, zero events are emitted, and the descriptor registry entry remains uncorrupted and active until a legitimate subsequent close.
2. **Concurrent `file_close_fd` Race Deduplication**:
   - Case 6 verifies that when multiple threads race on `close(fd)`, the loser receiving `ret == NULL` emits zero events, ensuring exactly one typed `EDGE_FD_CLOSED` edge is created in the DAG.
3. **Unknown Duration Export Rendering**:
   - Case 4 verifies that unverified lifetimes render as `"duration_ns": "unknown"` across JSON, DOT, and Markdown formats.

---

## 6. Residual Concurrency & Descriptor-Table Lifetime Limitations

While the remediated implementation resolves all operational deficiencies identified in GitHub Issue #5, the following residual architectural boundaries remain documented:

1. **Unclosed Process Termination (`exit_files()` Bypass)**:
   - When a process terminates without explicitly calling `close()`, the kernel cleanup routine `exit_files(task)` calls `filp_close()` on all open descriptors, completely bypassing `file_close_fd()`.
   - In accordance with project forensic constraints (**no synthetic closure events**), EphimTrace does not fabricate synthetic `EVENT_FD_CLOSED` events on process exit.
   - Consequently, in reconstructed graphs, descriptors that were not closed before process termination remain as open edges originating from the dead process node.
2. **Cross-Process Table Unsharing (`unshare(CLONE_FILES)`)**:
   - If a child process created with `CLONE_FILES` subsequently calls `unshare(CLONE_FILES)`, the kernel allocates a new distinct `files_struct` for the child.
   - Operations performed after `unshare` will use the child's new `files_ptr`, meaning modifications made by the parent will no longer reflect in the child's registry mapping.
3. **Non-Atomic Kernel Replacement Paths Outside `do_dup2`**:
   - If a file descriptor were replaced through an undocumented or specialized internal kernel subsystem that does not route through `do_dup2` or `fd_install`, replacement-time closure would not fire.
   - However, false attribution is still completely prevented: when the descriptor is eventually closed, `fexit/file_close_fd` inspects `ret->f_inode`, detects the inode mismatch, and strictly suppresses the close event.
