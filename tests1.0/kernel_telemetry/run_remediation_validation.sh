#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${ROOT_DIR}"

echo "==============================================================================="
echo "      EphimTrace — Phase 1 Remediation Validation Campaign                     "
echo "==============================================================================="
echo "Working Directory: ${ROOT_DIR}"
echo "Current Branch:    $(git branch --show-current)"
echo "Current HEAD:      $(git rev-parse --short HEAD)"
echo "==============================================================================="

echo -e "\n[STEP 1/3] Running Controlled Fault Injection Validation..."
python3 tests1.0/kernel_telemetry/test_controlled_remediation.py

echo -e "\n[STEP 2/3] Running Native Memfd Lifecycle & Execution Regression..."
./build/test_m2_exec

echo -e "\n[STEP 3/3] Running 5-Trial Burst Telemetry Benchmark..."
python3 tests1.0/kernel_telemetry/benchmark_burst_investigation.py

echo -e "\n==============================================================================="
echo "      Phase 1 Remediation Validation Campaign Completed Successfully          "
echo "==============================================================================="
