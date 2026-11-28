# EphimTrace — Release Qualification Task 01 Report
## Descriptor Lifecycle Correctness & Concurrency Diagnosis (GitHub Issue #5)

**Date**: 2026-11-28  
**Scope**: Release Qualification Task 01 under GitHub Issue #5 and `PROJECT_STATE.md`  
**Base Implementation Checkpoint**: `b6c89af` (Frozen Production Implementation)  
**Host Environment**: Linux `7.0.0-44-generic #44~24.04.1-Ubuntu SMP PREEMPT_DYNAMIC x86_64`  
**Worktree**: `/home/magellan/Garage/prototypes/FM/FM-persist`  
**Branch**: `remediation/state-independence-and-loss-accountability`  

---

## 1. Executive Summary

This diagnostic investigation evaluates the correctness of file descriptor lifecycle tracking and in-kernel descriptor registries (`memfd_desc_registry`) under native Linux kernel execution. The investigation covers four critical operating conditions mandated by GitHub Issue #5:
1. **Descriptor Duplication and Replacement** (`dup`, `dup2`, `dup3`, `fcntl(F_DUPFD)`)
2. **Replacement of Tracked Descriptors with Ordinary Files** (atomically overwriting tracked memfd slots)
3. **Descriptor Reuse and Failed Operations** (negative error returns, slot recycling, unclosed process exits)
4. **Concurrent Operations Involving Shared Descriptor Tables** (`pthread` concurrency and `clone(CLONE_FILES)` cross-process sharing)

### Diagnostic Verdict Summary:
- **`dup()` and `fcntl(F_DUPFD)`**: **VERIFIED ACCURATE**. In the Linux kernel, these syscalls invoke `fd_install(newfd, file)`, which triggers `capture_fd_install`. BPF updates `memfd_desc_registry` and emits `EVENT_FD_INSTALLED (op_type = DUP)`.
- **`dup2()` and `dup3()` Duplication**: **CONFIRMED DEFICIENCY (MISSING COVERAGE)**. The kernel executes `ksys_dup3()` $\to$ `do_dup2()`, directly updating the file table via `rcu_assign_pointer(fdt->fd[newfd], file)` without calling `fd_install()`. EphimTrace attaches no probes to `dup2`/`dup3`, resulting in zero telemetry and complete graph omission of the new descriptor.
- **Replacement with Ordinary Files**: **CONFIRMED DEFICIENCY (INCORRECT ATTRIBUTION)**. Overwriting a tracked memfd slot via `dup2(ord_fd, memfd_fd)` invokes `filp_close(tofree)` inside `do_dup2()`, bypassing `file_close_fd()`. The in-kernel registry `memfd_desc_registry` retains a stale `(tgid, fd) -> memfd_token` mapping. When the ordinary file is later closed, `capture_close_fd` fires and falsely emits an `EVENT_FD_CLOSED` attributing the closure of the ordinary file to the old memfd with a corrupted lifetime duration.
- **Process Exit Cleanup**: **CONFIRMED DEFICIENCY (REGISTRY LEAK)**. `exit_files()` calls `filp_close()` on open descriptors, bypassing `file_close_fd()`. `memfd_desc_registry` permanently leaks descriptor entries upon unclosed process termination, creating a false attribution hazard upon PID recycling.
- **Shared Descriptor Tables (`clone(CLONE_FILES)`)**: **CONFIRMED DEFICIENCY (ARCHITECTURAL ATTRIBUTION LOSS)**. `memfd_desc_registry` is keyed by `(tgid, fd)` rather than `(files_struct *, fd)`. A child process created with `CLONE_FILES` shares the descriptor table but possesses a different TGID. Descriptor closures by the child fail registry lookup and are dropped silently, leaving orphaned entries under the parent's TGID.

---

## 2. Targeted Test Matrix & Verification Artifacts

Two dedicated diagnostic test suites were constructed and verified on the host kernel:

### 2.1 Native Test Workload: `tests1.0/test_qualification_descriptor.c`
Executes native system calls directly against the running Linux kernel, validating expected ground-truth behavior across 28 distinct operational assertions:
- **Suite 1 (Duplication)**: Verifies `dup()`, `fcntl(F_DUPFD)`, `dup2()`, and `dup3()` inode equality and offset sharing.
- **Suite 2 (Replacement)**: Creates a tracked memfd, replaces it via `dup2()` with `/tmp/ephim_qual_ordinary_XXXXXX`, performs writes, and closes the replaced descriptor.
- **Suite 3 (Negative Ops & Reuse)**: Validates `-EBADF` on invalid descriptors, `-EINVAL` on failed `memfd_create()`, clean closure, and descriptor slot recycling.
- **Suite 4 (Concurrency & `CLONE_FILES`)**: Validates 4-thread concurrent `dup`/`write`/`close` (50 iterations) and cross-process shared descriptor tables via `clone(CLONE_FILES | SIGCHLD)`.

**Execution Result**:
```
=== Qualification Suite Summary: 28/28 Assertions Passed (0 Failed) ===
```

### 2.2 Provenance Reconstruction Diagnosis: `tests1.0/test_descriptor_lifecycle_reconstruction.c`
Simulates the exact telemetry sequences produced by `src/bpf/monitor.bpf.c` and feeds them into `prov_engine_process_event()` in `src/user/provenance.c`, isolating reconstruction behavior:
```
[CASE 1: dup() vs dup2() Graph Reconstruction]
  - FD 3 (creation): Preserved as EDGE_FD_INSTALLED (CREATION) [OK]
  - FD 5 (dup):      Preserved as EDGE_FD_INSTALLED (DUP)      [OK]
  - FD 20 (dup2):    MISSING FROM GRAPH (Missing Coverage)    [DEFICIENCY]

[CASE 2: Replacement with Ordinary File & Stale Close Attribution]
  - EDGE_FD_CLOSED was generated at T=5001000 with duration 3ms.
  - Ground Truth: The memfd was closed at T=2001000 by dup2! FD 3 closed at T=5001000 was an ordinary file!
  - Forensic Verdict: INCORRECT ATTRIBUTION (Stale Registry State Corrupts Graph) [DEFICIENCY]

[CASE 3: Shared Files Table Across Processes via clone(CLONE_FILES)]
  - Graph contains EDGE_FD_INSTALLED for Parent 300.
  - Graph contains NO EDGE_FD_CLOSED for either Parent or Child!
  - Forensic Verdict: MISSING COVERAGE & ORPHANED REGISTRY ENTRY under CLONE_FILES [DEFICIENCY]
```

---

## 3. Deep-Dive Findings by Investigation Area

### Area 1: Descriptor Duplication & Replacement (`dup`, `dup2`, `dup3`, `fcntl`)

#### Kernel Implementation vs. Hook Surface:
| Syscall | Kernel Path | Calls `fd_install()`? | Hooked in EphimTrace? | Observed Telemetry | Graph Reconstruction |
|---|---|---|---|---|---|
| `dup(oldfd)` | `ksys_dup()` $\to$ `fd_install()` | **YES** | `fentry/fd_install` | `EVENT_FD_INSTALLED (DUP)` | `EDGE_FD_INSTALLED` (DUP) [OK] |
| `fcntl(F_DUPFD)` | `fcntl_dupfd()` $\to$ `fd_install()` | **YES** | `fentry/fd_install` | `EVENT_FD_INSTALLED (DUP)` | `EDGE_FD_INSTALLED` (DUP) [OK] |
| `dup2(oldfd, newfd)` | `ksys_dup3()` $\to$ `do_dup2()` | **NO** (`rcu_assign_pointer`) | **NONE** | **ZERO EVENTS** | **MISSING FROM GRAPH** [DEFICIENCY] |
| `dup3(oldfd, newfd, fl)` | `ksys_dup3()` $\to$ `do_dup2()` | **NO** (`rcu_assign_pointer`) | **NONE** | **ZERO EVENTS** | **MISSING FROM GRAPH** [DEFICIENCY] |

#### Mechanism:
In `src/bpf/monitor.bpf.c`:
- Lines 1296–1358 attach to `fentry/fd_install(unsigned int fd, struct file *file)`.
- When `dup()` runs, `fd_install` receives the file. BPF checks `file->f_inode`, finds the entry in `memfd_inode_registry`, determines that `memfd_file_registry` already contains `file` (`res_fil == -EEXIST`), updates `memfd_desc_registry` with `(tgid, newfd)`, and emits `EVENT_FD_INSTALLED` with `op_type = FD_INSTALL_OP_DUP`.
- When `dup2()` or `dup3()` runs, the kernel never calls `fd_install`. No BPF probe fires.
- **Classification**: **MISSING COVERAGE**.

---

### Area 2: Replacement of Tracked Descriptors with Ordinary Files

#### The Stale Registry Vulnerability:
1. Process allocates memfd `M` at slot `FD 3` (`object_token = 100`).
   - `memfd_desc_registry` registers `(tgid, 3) -> 100`.
2. Process opens regular file `/tmp/plain.txt` at slot `FD 5`.
3. Process calls `dup2(5, 3)` to atomically replace slot `3` with the regular file.
   - Kernel executes `do_dup2()`:
     ```c
     tofree = fdt->fd[3];
     rcu_assign_pointer(fdt->fd[3], file_plain);
     if (tofree)
         filp_close(tofree, files);
     ```
   - In EphimTrace: `filp_close()` is **not hooked**. Only `fentry/file_close_fd` is hooked.
   - `memfd_desc_registry` is **not updated**. It still contains `(tgid, 3) -> 100`.
4. Process writes to slot `3`:
   - Writes pass to ext4/xfs. `shmem_file_write_iter` does not fire.
5. Process closes slot `3` via `close(3)`:
   - Kernel executes `file_close_fd(3)`.
   - BPF probe `capture_close_fd(3)` fires:
     ```c
     struct descriptor_key dk = { .tgid = tgid, .fd = 3 };
     struct descriptor_entry *de = bpf_map_lookup_elem(&memfd_desc_registry, &dk);
     // LOOKUP SUCCEEDS! de->object_token is 100!
     token = __sync_lock_test_and_set(&de->object_token, 0);
     bpf_map_delete_elem(&memfd_desc_registry, &dk);
     // EMITS FALSE EVENT_FD_CLOSED!
     ```
6. **Provenance Graph Output**:
   - The graph emits `EDGE_FD_CLOSED` connecting the process to memfd `100` at the close timestamp, with a duration spanning from the original memfd creation to the close of the ordinary file.
- **Classification**: **INCORRECT ATTRIBUTION**.

---

### Area 3: Descriptor Reuse and Failed Operations

1. **Negative Syscall Returns (`-EBADF`, `-EINVAL`)**:
   - `close(-1)` and `dup(-1)` return `-EBADF` before reaching VFS file allocation.
   - `memfd_create("", invalid_flags)` returns `-EINVAL`. The exit probe (`sys_exit_memfd_create`, lines 1607–1620) detects `ret < 0` and deletes provisional map elements from `pending_memfd_map`.
   - **Verdict**: **ACCURATE**. Failed operations do not pollute in-kernel registries.
2. **Clean Reuse**:
   - When a memfd is closed with standard `close()`, `capture_close_fd` deletes `(tgid, fd)`.
   - When that slot is subsequently reused by `open("/etc/hosts")` and closed, `capture_close_fd` finds no entry and exits cleanly.
   - **Verdict**: **ACCURATE under standard `close()`**.
3. **Process Exit Cleanup Leak (`exit_files()`)**:
   - If a process terminates while holding open memfd descriptors, `exit_files()` calls `filp_close()` directly, bypassing `file_close_fd()`.
   - `capture_process_exit` (lines 2091–2115) clears per-thread pending maps, but cannot iterate `memfd_desc_registry`.
   - Stale entries remain in `memfd_desc_registry` indefinitely until TGID recycling.
   - **Classification**: **RESOURCE LEAK & PID RECYCLING HAZARD**.

---

### Area 4: Concurrent Operations & Shared Descriptor Tables

1. **Multithreaded Descriptor Concurrency (`pthread`)**:
   - Threads in the same thread group share `files_struct` and share `tgid`.
   - In `capture_close_fd` (lines 1860–1868):
     `token = __sync_lock_test_and_set(&de->object_token, 0);`
     `if (token == 0) return 0;`
     `bpf_map_delete_elem(&memfd_desc_registry, &dk);`
   - Atomic test-and-set guarantees only one thread claims the close event.
   - **Verdict**: **THREAD-SAFE within identical TGID**.
2. **Cross-Process Shared Descriptor Tables (`clone(CLONE_FILES)`)**:
   - When `clone()` is invoked with `CLONE_FILES | SIGCHLD` (distinct TGID, shared files table):
     - Parent (`tgid_P`) creates memfd at `FD 4`. Entry stored as `(tgid_P, 4) -> token`.
     - Child (`tgid_C`) operates on shared `FD 4`.
     - Child calls `close(4)`.
     - `capture_close_fd` runs with `current->tgid = tgid_C`.
     - Key lookup `(tgid_C, 4)` **FAILS (returns NULL)**.
     - Child close produces **ZERO events**.
     - `(tgid_P, 4)` is **NEVER DELETED**.
     - Parent observes `FD 4` is closed (`-EBADF`), but BPF registry retains the stale entry permanently.
   - **Classification**: **MISSING COVERAGE & REGISTRY ORPHANING**.

---

## 4. Deficiencies Summary: Missing Coverage vs. Incorrect Attribution

| Scenario | Trigger / Operation | Impacted Component | Category | Detailed Consequence |
|---|---|---|---|---|
| **1. `dup2` / `dup3` Duplication** | `dup2(mfd, newfd)` | `monitor.bpf.c` (no `do_dup2` probe) | **Missing Coverage** | New descriptor is invisible; subsequent execution has no prior `EDGE_FD_INSTALLED`. |
| **2. Replacement with Ordinary File** | `dup2(ord_fd, mfd_fd)` | `monitor.bpf.c` (bypasses `file_close_fd`) | **Incorrect Attribution** | Old memfd not deregistered; subsequent close of ordinary file emits false `EDGE_FD_CLOSED` for memfd. |
| **3. `close_range()` Syscall** | `close_range(first, last, 0)` | `monitor.bpf.c` (bypasses `file_close_fd`) | **Missing Coverage** | Descriptors closed in bulk never emit `EVENT_FD_CLOSED`; entries leak in registry. |
| **4. Unclosed Process Termination** | Process exits with open memfd | `monitor.bpf.c` (`exit_files` bypass) | **Resource Leak** | Stale `(tgid, fd)` entries survive; hazard for false close attribution if TGID is recycled. |
| **5. `CLONE_FILES` Shared Tables** | Child closes descriptor | `monitor.bpf.c` (registry keyed by `tgid`) | **Missing Coverage & Attribution Loss** | Child close dropped silently; parent entry orphaned in registry. |

---

## 5. Minimal Proposed Corrections (Non-Architectural)

In accordance with project constraints, no production code was modified during this diagnosis. The following targeted, minimal remediations are proposed for implementation in the next remediation cycle:

### Proposal 1: Hook `ksys_dup3` (or `sys_enter_dup2/3` + `sys_exit_dup2/3`)
- **Hook**: `fentry/ksys_dup3(unsigned int oldfd, unsigned int newfd, int flags)`.
- **Logic**:
  1. On entry/exit of successful `ksys_dup3`:
     - If `(files_key, newfd)` was previously registered in `memfd_desc_registry`:
       - Atomic claim token, delete old entry, and submit `EVENT_FD_CLOSED` for the replaced descriptor.
     - If `oldfd` is a tracked memfd:
       - Register `(files_key, newfd) -> token` in `memfd_desc_registry`.
       - Submit `EVENT_FD_INSTALLED` (`op_type = FD_INSTALL_OP_DUP`).
- **Effect**: Resolves both Missing Coverage for `dup2`/`dup3` and Incorrect Attribution upon replacement.

### Proposal 2: Key `memfd_desc_registry` by `(files_struct *, fd)`
- **Change**:
  ```c
  struct descriptor_key {
      __u64 files_ptr;  /* (struct files_struct *)current->files */
      __s32 fd;
  };
  ```
- **Logic**:
  - In `capture_fd_install` and `capture_close_fd`, obtain `files_ptr` via `bpf_get_current_task_btf()->files`.
- **Effect**: Seamlessly handles threads and `CLONE_FILES` child processes sharing the same descriptor table, eliminating cross-process registry mismatch.

### Proposal 3: Clean up Descriptors on Group Exit in Userspace Provenance Engine
- **Logic**:
  - In `src/user/provenance.c`, when `EVENT_PROCESS_EXIT` marks a process as dead (`is_alive = false`), automatically mark any unclosed memfd descriptors associated with that process as terminated at the process exit timestamp.
- **Effect**: Eliminates open-descriptor dangling edges in reconstructed graphs for processes that terminate without calling `close()`.

---

## 6. Reproducibility & Test Verification

Both diagnostic test binaries can be compiled and executed locally:

```bash
# 1. Compile targeted native test workloads
make build/test_qualification_descriptor
make build/test_descriptor_lifecycle_reconstruction

# 2. Execute native syscall validation (28 assertions)
./build/test_qualification_descriptor

# 3. Execute provenance reconstruction edge-case diagnosis
./build/test_descriptor_lifecycle_reconstruction
```
