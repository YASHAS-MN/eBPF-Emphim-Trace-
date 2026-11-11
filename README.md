# EphimTrace (eBPF-Emphim-Trace)

A kernel-level eBPF tracing engine providing deterministic syscall-to-VFS pathname and filesystem identity correlation, alongside process lifecycle monitoring.

## Overview

EphimTrace correlates user-space syscall entry attempts with kernel-space VFS execution events and process lifecycle milestones:
- **Syscall Entry**: Intercepts `sys_enter_unlink`, `sys_enter_unlinkat`, `sys_enter_rmdir`, `sys_enter_execve`, `sys_enter_memfd_create`, and `sys_enter_connect`.
- **VFS Completion**: Captures resolved filesystem identity (`inode`, `dev_id`, `mnt_ns_id`, target basename, and return code) via `vfs_unlink` and `vfs_rmdir` trampolines (`fentry`/`fexit`).
- **Process Lifecycle**: Monitors thread and process lifecycles via `sched_process_fork`, `sched_process_exec`, and `sched_process_exit`.
- **Kernel Workaround for Linux 7.0**: Implements a per-CPU carrier perf-event attachment architecture to resolve the upstream/Ubuntu 7.0 (`7.0.0-42-generic`) syscall-entry tracepoint regression on faultable syscalls.

## Architecture

- **Correlation Model**: Maps pending syscall entry contexts to VFS completion hooks via TID keys, validated against TGID, process start boot-time, and operation types.
- **Fail-Safe Handling**: Explicitly classifies and handles unmatched operations, permission failures, nonexistent paths (`-ENOENT`), and truncated path buffers (>256 bytes) without corrupting telemetry.
- **Ordered Teardown**: Performs reverse-ordered teardown of per-CPU carrier events, libbpf links, ring buffers, and BPF objects to prevent in-flight tracepoint invocations on deallocated memory.

## Repository Structure

```
├── Makefile                    # Build automation for BPF programs, loader, and tests
├── GPT_Context                 # Environment verification notes
├── src/
│   ├── bpf/
│   │   ├── monitor.bpf.c       # eBPF tracepoints, fentry/fexit trampolines, and maps
│   │   └── vmlinux.h           # Kernel BTF type definitions
│   └── user/
│       └── loader.c            # Userspace loader, per-CPU attachment, and event processor
└── tests/
    ├── test_syscall_correlation.c # 11-scenario correlation test suite
    ├── test_lifecycle.c           # Process fork/thread/exec lifecycle harness
    ├── test_pid_reuse.c           # Rapid PID reuse and generation validation
    ├── test_unlink_identity.c     # Unlink target identity resolution
    └── test_rmdir_identity.c      # Rmdir target identity resolution
```

## Requirements

- Linux Kernel with BTF support (`CONFIG_DEBUG_INFO_BTF=y`)
- `clang` (version 16 or newer recommended)
- `gcc`
- `libbpf` (version 1.3.0 or compatible)
- `pkg-config`

## Building

To build the eBPF object, the userspace loader, and all test suites:

```bash
make
```

To clean build artifacts:

```bash
make clean
```

## Usage

Start the loader with root privileges:

```bash
sudo ./build/loader
```

To enable verbose debug diagnostics:

```bash
sudo ./build/loader --verbose
```

## Running Tests

Execute the test suites in a separate terminal:

```bash
./build/test_syscall_correlation
./build/test_lifecycle
./build/test_pid_reuse
./build/test_unlink_identity
./build/test_rmdir_identity
```
