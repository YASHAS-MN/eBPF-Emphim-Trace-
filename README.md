# EphimTrace (eBPF-Emphim-Trace)

A high-performance kernel-level eBPF forensic tracing engine providing deterministic syscall-to-VFS pathname and filesystem identity correlation, process lifecycle monitoring, and tamper-evident provenance reconstruction.

## Architecture: Collection-First Decoupled Design

EphimTrace employs a **collection-first decoupled architecture** (Model P) separating high-frequency kernel event capture from computational provenance graph reconstruction:

1. **Capture Agent (`build/loader`)**:
   - Privileged kernel interface (`CAP_BPF` / `root`).
   - Attaches eBPF tracepoints, per-CPU perf-event carrier hooks, and `fentry`/`fexit` trampolines.
   - Streams raw kernel event payloads directly into an append-only, bounded, immutable binary evidence file (`.evid`) with IEEE 802.3 CRC32 framing and strict monotonic sequencing.
   - Enforces exact sample sizes (`sizeof(struct event) = 664`) on every kernel observation.
   - Zero live graph computation or presentation overhead on the collection hot path.
   - Orderly shutdown: detaches kernel hooks, drains ring buffers, flushes write buffers, synchronizes to disk (`fdatasync`), and persists an accompanying private session manifest (`.evid.manifest`, mode `0600`).

2. **Reconstruction Engine (`build/replay`)**:
   - Completely unprivileged user-space utility (requires no root privileges or eBPF subsystem access).
   - Validates session headers, frame integrity, CRC32 checksums, and sequence continuity.
   - Prevents accidental evidence truncation by rejecting output path aliases, symlinks, hardlinks, and output collisions.
   - Reconstructs complete forensic DAGs using $O(1)$ incoming-adjacency lookup for instant scaling under sustained high-frequency workloads.
   - Distinguishes verified records from finalized sessions via the private session manifest, while maintaining full backward compatibility with legacy v1 evidence files.
   - Suppresses graph exports upon validation errors in `--strict` mode to prevent generating misleading outputs.
   - Generates Graphviz DOT graphs, structured JSON graphs, and markdown forensic timelines, with optional PID/token subgraph filtering.

```
+-------------------------------------------------------------+
|                     COLLECTION PHASE                        |
|                                                             |
|  [Kernel Hooks] ---> [Ring Buffer] ---> [build/loader]      |
|  (eBPF/carrier)                           |                 |
|                                           +--> session.evid |
|                                           +--> session.evid.manifest
+-------------------------------------------------------------+
                               |
                               v
+-------------------------------------------------------------+
|                   RECONSTRUCTION PHASE                      |
|                                                             |
|  [session.evid] ---> [build/replay] (Unprivileged)          |
|  [session.evid.manifest]                  |                 |
|                                           |                 |
|        +--------------------+-------------+------+          |
|        v                    v                    v          |
|   [graph.dot]          [graph.json]        [timeline.md]    |
+-------------------------------------------------------------+
```

## Repository Structure

```
├── Makefile                          # Build automation for BPF, loader, replay, and tests
├── src/
│   ├── bpf/
│   │   ├── monitor.bpf.c             # eBPF tracepoints, trampolines, and maps
│   │   └── vmlinux.h                 # Kernel BTF type definitions
│   └── user/
│       ├── loader.c                  # Privileged capture agent (streams to .evid)
│       ├── replay.c                  # Unprivileged offline provenance reconstructor
│       ├── evidence_io.h             # Bounded binary evidence I/O, CRC32, and manifest
│       ├── provenance.c              # Provenance DAG engine (O(1) incoming adjacency)
│       └── provenance.h              # Provenance graph definitions and event types
└── tests1.0/
    ├── test_pipeline_integration.c   # End-to-end collection, replay, and reliability test
    ├── test_syscall_correlation.c    # Correlation test suite
    ├── test_lifecycle.c              # Process fork/exec/exit lifecycle harness
    ├── test_pid_reuse.c              # Rapid PID reuse validation
    ├── test_unlink_identity.c        # Unlink target identity resolution
    ├── test_rmdir_identity.c         # Rmdir target identity resolution
    └── test_m6_dag.c                 # DAG construction and export test
```

## Requirements

- Linux Kernel with BTF support (`CONFIG_DEBUG_INFO_BTF=y`)
- `clang` (version 16 or newer recommended)
- `gcc`
- `libbpf` (version 1.3.0 or compatible)
- `pkg-config`

## Building

To build the eBPF object, the capture loader, the offline replay reconstructor, and all test suites:

```bash
make
```

Or build specific components:

```bash
make loader    # Builds build/loader (capture agent)
make replay    # Builds build/replay (offline reconstruction utility)
```

To clean build artifacts:

```bash
make clean
```

## Usage

### Step 1: Capture Forensic Telemetry (`build/loader`)

Start the capture agent with root privileges. By default, it captures kernel events into `ephimtrace.evid`:

```bash
# Monitor system-wide and save evidence to custom path
sudo ./build/loader -o /var/log/ephimtrace_session.evid

# Record target workload PID metadata with a 2 GiB storage bound
sudo ./build/loader -p 12345 -b 2147483648 -o session_12345.evid
```

**Capture Options**:
- `-o, --output <file.evid>`: Path to write immutable binary evidence file (default: `ephimtrace.evid`). Refuses to overwrite existing files, symlinks, or hardlinks.
- `-p, --filter-pid <pid>`: Target workload PID recorded as session metadata (default: `0`). **Note**: Kernel capture is system-wide and does not drop background activity; use `build/replay -p <pid>` for subgraph filtering during reconstruction.
- `-b, --max-bytes <bytes>`: Maximum evidence file size bound in bytes (default: 1 GiB).
- `-v, --verbose`: Enable debug logging and kernel tracepoint diagnostics.
- `-q, --quiet`: Suppress runtime event messages (default in capture mode).
- `-h, --help`: Display help and options.

To stop collection, press `Ctrl+C` or send `SIGINT`/`SIGTERM`. The loader detaches all kernel hooks, drains remaining ring-buffer events, flushes and synchronizes (`fdatasync`) the evidence file, and persists an accompanying private session manifest (`<file.evid>.manifest`, mode `0600`).

### Step 2: Reconstruct Provenance Offline (`build/replay`)

Reconstruct provenance graphs offline from the saved `.evid` file without requiring root privileges or eBPF subsystem access:

```bash
# Standard reconstruction generating DOT, JSON, and timeline exports
./build/replay session_12345.evid --dot dag.dot --json dag.json --timeline timeline.md

# Filtered export targeting a specific PID or object token
./build/replay session_12345.evid -p 12345 --filtered-dot target.dot --filtered-json target.json

# Strict validation mode with machine-readable summary
./build/replay session_12345.evid --strict --summary-json summary.json
```

**Replay Options**:
- `-d, --dot <filepath>`: Path to export full DAG in Graphviz DOT format (default: `ephimtrace_dag.dot`).
- `-j, --json <filepath>`: Path to export full graph in JSON format (default: `ephimtrace_dag.json`).
- `-t, --timeline <filepath>`: Path to export forensic timeline markdown (default: `ephimtrace_timeline.md`).
- `-p, --filter-pid <pid>`: Target PID for filtered subgraph & timeline export.
- `-k, --filter-token <token>`: Target object token for filtered export.
- `--filtered-dot <filepath>`: Path to export filtered DOT graph (default: `ephimtrace_filtered.dot`).
- `--filtered-json <filepath>`: Path to export filtered JSON graph (default: `ephimtrace_filtered.json`).
- `--summary-json <filepath>`: Path to write machine-readable reconstruction summary.
- `--strict`: Fail closed on corrupt records, sequence gaps, or unfinalized sessions; aborts graph exports on validation failure.
- `--progress <n>`: Report reconstruction progress every N records (default: 50,000, `0` to disable).
- `--incoming`: Use default incoming-adjacency search mode ($O(1)$ in-degree lookup).
- `--outgoing`: Use reference outgoing search mode (for diagnostic benchmarking).
- `-v, --verbose`: Enable verbose log output.
- `-q, --quiet`: Suppress per-interval progress output.
- `-h, --help`: Display help and options.

## Running Tests

Execute the integrated pipeline test and component test suites:

```bash
# End-to-end collection, replay, and reliability test (8 verification stages)
./build/test_pipeline_integration

# Core unit tests
./build/test_syscall_correlation
./build/test_lifecycle
./build/test_pid_reuse
./build/test_unlink_identity
./build/test_rmdir_identity
./build/test_m6_dag
./build/test_m6_filtering
```
