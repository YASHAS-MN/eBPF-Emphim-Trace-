#!/usr/bin/env bash
# ==============================================================================
# EphimTrace — Controlled Ring Buffer Capacity Benchmark Campaign Runner
# Baseline: Checkpoint 7fea4b9
# Evaluates capacities: 1, 4, 16, and 64 MiB across W_PACED, W_BURST, W_SUSTAIN
# ==============================================================================
set -euo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Benchmark requires elevated root privileges for eBPF tracepoint attachment."
    echo "Usage: sudo $0 [OPTIONS]"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PERSIST_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${PERSIST_DIR}"

python3 tests1.0/kernel_telemetry/benchmark_ring_capacity.py "$@"
