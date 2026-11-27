#!/usr/bin/env bash
# ==============================================================================
# EphimTrace — Production Telemetry Benchmark 01 Orchestration Script
# Baseline: Commit 056ec9b on integration/collection-first
# Target: Configurable Ring Buffer (64 MiB Candidate Default, 4 MiB Low-Mem)
# ==============================================================================
set -euo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Benchmark 01 requires elevated privileges for eBPF hook attachment."
    echo "Usage: sudo $0"
    exit 1
fi

TARGET_USER="${SUDO_USER:-magellan}"
TARGET_UID=$(id -u "$TARGET_USER")
TARGET_GID=$(id -g "$TARGET_USER")

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PERSIST_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
DATA_DIR="$SCRIPT_DIR/data"
LOADER_BIN="$PERSIST_DIR/build/loader"
REPLAY_BIN="$PERSIST_DIR/build/replay"
BPF_OBJ="$PERSIST_DIR/build/monitor.bpf.o"
WORKLOAD_BIN="$PERSIST_DIR/tests1.0/kernel_telemetry/workload"
OSBENCH_DIR="$PERSIST_DIR/tests1.0/kernel_telemetry/osbench/out"

# Configuration variables
RING_BUFFER_MB="${EPHIM_RING_BUFFER_MB:-64}"
TELEMETRY_REPS="${TELEMETRY_REPS:-5}"

# Change working directory to PERSIST_DIR so loader resolves build/monitor.bpf.o
cd "$PERSIST_DIR"

echo "==============================================================================="
echo "        EphimTrace — Production Telemetry Benchmark 01 Campaign                "
echo "==============================================================================="
echo "Target User:          $TARGET_USER (UID: $TARGET_UID, GID: $TARGET_GID)"
echo "Repository Root:      $PERSIST_DIR"
echo "Working Directory:    $(pwd)"
echo "Data Directory:       $DATA_DIR"
echo "Production Loader:    $LOADER_BIN"
echo "Workload Binary:      $WORKLOAD_BIN"
echo "OSBench Directory:    $OSBENCH_DIR"
echo "Ring Buffer Capacity: ${RING_BUFFER_MB} MiB (Candidate Default)"
echo "Telemetry Repetitions: ${TELEMETRY_REPS} per workload"
echo "==============================================================================="

# Verify binaries exist
for b in "$LOADER_BIN" "$REPLAY_BIN" "$BPF_OBJ" "$WORKLOAD_BIN" \
         "$OSBENCH_DIR/create_processes" "$OSBENCH_DIR/launch_programs" "$OSBENCH_DIR/create_files"; do
    if [ ! -f "$b" ]; then
        echo "ERROR: Required binary or object not found: $b"
        exit 1
    fi
done

# Prepare data directory
mkdir -p "$DATA_DIR"
chown "$TARGET_USER:$TARGET_USER" "$DATA_DIR"
chmod 0750 "$DATA_DIR"

# Helper to run commands as unprivileged user
run_unprivileged() {
    sudo -u "$TARGET_USER" bash -c "cd '$PERSIST_DIR' && $1"
}

# ------------------------------------------------------------------------------
# Phase 1: Environment & System Metadata Baselining
# ------------------------------------------------------------------------------
echo ""
echo "[PHASE 1/3] Baselining environment, hardware, and binary hashes..."

KERNEL_VER=$(uname -r -v)
CPU_MODEL=$(lscpu | grep "Model name:" | sed 's/Model name:[ \t]*//' | head -n 1 || echo "Unknown CPU")
CPU_CORES=$(lscpu | grep "Core(s) per socket:" | sed 's/Core(s) per socket:[ \t]*//' | head -n 1 || echo "N/A")
CPU_THREADS=$(lscpu | grep "CPU(s):" | head -n 1 | sed 's/CPU(s):[ \t]*//' || echo "N/A")
MEM_TOTAL=$(free -h | awk '/^Mem:/ {print $2}')
OSBENCH_REV="b59817311df3298394eb776e3b15fa6e7b29a9bc"
GIT_COMMIT=$(cd "$PERSIST_DIR" && git rev-parse HEAD)

HASH_LOADER=$(sha256sum "$LOADER_BIN" | awk '{print $1}')
HASH_REPLAY=$(sha256sum "$REPLAY_BIN" | awk '{print $1}')
HASH_BPF=$(sha256sum "$BPF_OBJ" | awk '{print $1}')
HASH_WORKLOAD=$(sha256sum "$WORKLOAD_BIN" | awk '{print $1}')
HASH_CP=$(sha256sum "$OSBENCH_DIR/create_processes" | awk '{print $1}')
HASH_LP=$(sha256sum "$OSBENCH_DIR/launch_programs" | awk '{print $1}')
HASH_CF=$(sha256sum "$OSBENCH_DIR/create_files" | awk '{print $1}')

cat <<EOF > "$DATA_DIR/system_metadata.json"
{
  "benchmark": "EphimTrace Production Telemetry Benchmark 01",
  "baseline_commit": "$GIT_COMMIT",
  "kernel_version": "$KERNEL_VER",
  "cpu_model": "$CPU_MODEL",
  "cpu_cores": "$CPU_CORES",
  "cpu_threads": "$CPU_THREADS",
  "memory_total": "$MEM_TOTAL",
  "osbench_revision": "$OSBENCH_REV",
  "ring_buffer_mb": $RING_BUFFER_MB,
  "binary_hashes": {
    "loader": "$HASH_LOADER",
    "replay": "$HASH_REPLAY",
    "monitor.bpf.o": "$HASH_BPF",
    "workload": "$HASH_WORKLOAD",
    "create_processes": "$HASH_CP",
    "launch_programs": "$HASH_LP",
    "create_files": "$HASH_CF"
  }
}
EOF
echo "Metadata written to $DATA_DIR/system_metadata.json"

# ------------------------------------------------------------------------------
# Phase 2: Standard Performance Benchmark (OSBench)
# ------------------------------------------------------------------------------
echo ""
echo "[PHASE 2/3] Executing OSBench Standard Performance Benchmark..."
echo "Protocol: 10 paired repetitions, alternating execution order."

# Arrays for raw results
declare -a CP_DIS=()
declare -a CP_ENA=()
declare -a LP_DIS=()
declare -a LP_ENA=()
declare -a CF_DIS=()
declare -a CF_ENA=()

OSBENCH_TEMP_DIR="/tmp/osbench_work_${TARGET_USER}"

run_osbench_disabled() {
    local rep=$1
    echo "  [Rep #$rep - Disabled] Running OSBench suite (collector OFF)..."
    
    # 1. create_processes
    local out_cp
    out_cp=$(run_unprivileged "$OSBENCH_DIR/create_processes")
    local val_cp
    val_cp=$(echo "$out_cp" | awk '/us \/ process/ {print $1}')
    CP_DIS+=("$val_cp")
    
    # 2. launch_programs
    local out_lp
    out_lp=$(run_unprivileged "$OSBENCH_DIR/launch_programs")
    local val_lp
    val_lp=$(echo "$out_lp" | awk '/us \/ program/ {print $1}')
    LP_DIS+=("$val_lp")
    
    # 3. create_files
    run_unprivileged "rm -rf '$OSBENCH_TEMP_DIR' && mkdir -p '$OSBENCH_TEMP_DIR'"
    local out_cf
    out_cf=$(run_unprivileged "$OSBENCH_DIR/create_files '$OSBENCH_TEMP_DIR'")
    run_unprivileged "rm -rf '$OSBENCH_TEMP_DIR'"
    local val_cf
    val_cf=$(echo "$out_cf" | awk '/us \/ file/ {print $1}')
    CF_DIS+=("$val_cf")
    
    echo "    -> create_processes: ${val_cp} us | launch_programs: ${val_lp} us | create_files: ${val_cf} us"
}

run_osbench_enabled() {
    local rep=$1
    echo "  [Rep #$rep - Enabled] Running OSBench suite (collector ON)..."
    
    local temp_evid="/tmp/bm01_osbench_rep_${rep}.evid"
    rm -f "$temp_evid" "${temp_evid}.manifest"
    
    # Start loader in background (with candidate default 64 MiB ring buffer)
    "$LOADER_BIN" --ring-buffer-mb "$RING_BUFFER_MB" -o "$temp_evid" -q > /tmp/bm01_loader_osbench.log 2>&1 &
    local loader_pid=$!
    
    # Wait for hooks to attach
    sleep 2
    if ! kill -0 "$loader_pid" 2>/dev/null; then
        echo "ERROR: Loader failed to start for OSBench rep #$rep"
        cat /tmp/bm01_loader_osbench.log
        exit 1
    fi
    
    # 1. create_processes
    local out_cp
    out_cp=$(run_unprivileged "$OSBENCH_DIR/create_processes")
    local val_cp
    val_cp=$(echo "$out_cp" | awk '/us \/ process/ {print $1}')
    CP_ENA+=("$val_cp")
    
    # 2. launch_programs
    local out_lp
    out_lp=$(run_unprivileged "$OSBENCH_DIR/launch_programs")
    local val_lp
    val_lp=$(echo "$out_lp" | awk '/us \/ program/ {print $1}')
    LP_ENA+=("$val_lp")
    
    # 3. create_files
    run_unprivileged "rm -rf '$OSBENCH_TEMP_DIR' && mkdir -p '$OSBENCH_TEMP_DIR'"
    local out_cf
    out_cf=$(run_unprivileged "$OSBENCH_DIR/create_files '$OSBENCH_TEMP_DIR'")
    run_unprivileged "rm -rf '$OSBENCH_TEMP_DIR'"
    local val_cf
    val_cf=$(echo "$out_cf" | awk '/us \/ file/ {print $1}')
    CF_ENA+=("$val_cf")
    
    # Stop loader cleanly
    kill -INT "$loader_pid" 2>/dev/null || true
    wait "$loader_pid" 2>/dev/null || true
    rm -f "$temp_evid" "${temp_evid}.manifest" /tmp/bm01_loader_osbench.log
    
    echo "    -> create_processes: ${val_cp} us | launch_programs: ${val_lp} us | create_files: ${val_cf} us"
}

# Run 10 paired repetitions with alternating order
for rep in {1..10}; do
    if (( rep % 2 != 0 )); then
        # Odd repetition: Disabled first, then Enabled
        run_osbench_disabled "$rep"
        run_osbench_enabled "$rep"
    else
        # Even repetition: Enabled first, then Disabled
        run_osbench_enabled "$rep"
        run_osbench_disabled "$rep"
    fi
done

# Serialize raw timings to JSON
python3 -c "
import json
data = {
  'create_processes': {'disabled': [float(x) for x in '${CP_DIS[*]}'.split()], 'enabled': [float(x) for x in '${CP_ENA[*]}'.split()]},
  'launch_programs': {'disabled': [float(x) for x in '${LP_DIS[*]}'.split()], 'enabled': [float(x) for x in '${LP_ENA[*]}'.split()]},
  'create_files': {'disabled': [float(x) for x in '${CF_DIS[*]}'.split()], 'enabled': [float(x) for x in '${CF_ENA[*]}'.split()]},
  'execution_order': ['Dis->Ena', 'Ena->Dis'] * 5
}
with open('$DATA_DIR/osbench_raw_timings.json', 'w') as f:
    json.dump(data, f, indent=2)
"
echo "Raw OSBench measurements saved to $DATA_DIR/osbench_raw_timings.json"

# ------------------------------------------------------------------------------
# Phase 3: Telemetry Correctness Benchmark (Paced, Burst, Sustained)
# ------------------------------------------------------------------------------
echo ""
echo "[PHASE 3/3] Executing Telemetry Correctness Benchmark..."
echo "Protocol: 5 repetitions per workload profile (W_PACED, W_BURST, W_SUSTAIN)."

run_correctness_workload() {
    local wl_name=$1
    local iter=$2
    local workers=$3
    local delay_us=$4
    local hold=$5
    local rep=$6
    local flags="0x1"
    
    local total_ops=$(( iter * workers ))
    echo "==============================================================================="
    echo "Starting Workload: $wl_name [Rep $rep/$TELEMETRY_REPS] ($workers workers x $iter iter = $total_ops ops, delay: ${delay_us}us)"
    echo "==============================================================================="
    
    local evid_path="$DATA_DIR/${wl_name}_rep_${rep}.evid"
    local gt_path="$DATA_DIR/${wl_name}_rep_${rep}_gt.json"
    local log_path="$DATA_DIR/${wl_name}_rep_${rep}_loader.log"
    local stat_path="$DATA_DIR/${wl_name}_rep_${rep}_collector_stat.json"
    
    # Remove existing artifacts
    rm -f "$evid_path" "${evid_path}.manifest" "$gt_path" "$log_path" "$stat_path"
    
    # Start production loader (from PERSIST_DIR) with configured ring buffer capacity
    "$LOADER_BIN" --ring-buffer-mb "$RING_BUFFER_MB" -o "$evid_path" -q > "$log_path" 2>&1 &
    local loader_pid=$!
    
    # Wait for attachment
    sleep 2
    if ! kill -0 "$loader_pid" 2>/dev/null; then
        echo "ERROR: Loader failed to start for workload $wl_name rep $rep"
        cat "$log_path"
        exit 1
    fi
    
    # Execute unprivileged workload with ground truth generation
    echo "  Executing workload as $TARGET_USER..."
    local t_wl_start
    t_wl_start=$(date +%s%N)
    run_unprivileged "echo '' | '$WORKLOAD_BIN' $iter $workers $delay_us $hold $flags '$gt_path'"
    local t_wl_end
    t_wl_end=$(date +%s%N)
    local wl_wall_sec
    wl_wall_sec=$(awk "BEGIN {print ($t_wl_end - $t_wl_start) / 1000000000}")
    
    # Allow collector to drain ring buffer events in userspace
    sleep 2
    
    # Capture collector process metrics from /proc before stopping
    local peak_rss_kib=0
    local rss_kib=0
    local vm_size_kib=0
    local vm_peak_kib=0
    local cpu_seconds=0.0
    if [ -f "/proc/$loader_pid/status" ]; then
        peak_rss_kib=$(awk '/VmHWM:/ {print $2}' "/proc/$loader_pid/status" || echo 0)
        rss_kib=$(awk '/VmRSS:/ {print $2}' "/proc/$loader_pid/status" || echo 0)
        vm_size_kib=$(awk '/VmSize:/ {print $2}' "/proc/$loader_pid/status" || echo 0)
        vm_peak_kib=$(awk '/VmPeak:/ {print $2}' "/proc/$loader_pid/status" || echo 0)
    fi
    if [ -f "/proc/$loader_pid/stat" ]; then
        local stat_line
        stat_line=$(cat "/proc/$loader_pid/stat")
        local utime
        utime=$(echo "$stat_line" | awk '{print $14}')
        local stime
        stime=$(echo "$stat_line" | awk '{print $15}')
        local clk_tck
        clk_tck=$(getconf CLK_TCK || echo 100)
        cpu_seconds=$(awk "BEGIN {print ($utime + $stime) / $clk_tck}")
    fi
    
    # Stop loader with SIGINT and wait for orderly shutdown, final drain, and flush
    echo "  Stopping collector and finalizing session..."
    local t_stop_start
    t_stop_start=$(date +%s%N)
    kill -INT "$loader_pid" 2>/dev/null || true
    wait "$loader_pid" 2>/dev/null || true
    local t_stop_end
    t_stop_end=$(date +%s%N)
    local drain_sync_sec
    drain_sync_sec=$(awk "BEGIN {print ($t_stop_end - $t_wl_end) / 1000000000}")
    
    local kern_phys_kib=$(( RING_BUFFER_MB * 1024 ))
    local kern_virt_kib=$(( RING_BUFFER_MB * 2 * 1024 + 8 ))
    
    cat <<EOF > "$stat_path"
{
  "workload": "$wl_name",
  "repetition": $rep,
  "loader_pid": $loader_pid,
  "configured_ring_buffer_mb": $RING_BUFFER_MB,
  "physical_memory": {
    "collector_peak_rss_kib": $peak_rss_kib,
    "collector_resident_rss_kib": $rss_kib,
    "kernel_ring_buffer_physical_kib": $kern_phys_kib
  },
  "virtual_mappings": {
    "collector_vm_peak_kib": $vm_peak_kib,
    "collector_vm_size_kib": $vm_size_kib,
    "kernel_ring_buffer_virtual_kib": $kern_virt_kib
  },
  "peak_rss_kib": $peak_rss_kib,
  "cpu_total_seconds": $cpu_seconds,
  "workload_wall_seconds": $wl_wall_sec,
  "drain_sync_seconds": $drain_sync_sec
}
EOF
    
    # Ensure evidence file permissions
    chmod 0600 "$evid_path"
    if [ -f "${evid_path}.manifest" ]; then
        chmod 0600 "${evid_path}.manifest"
    fi
    
    echo "  Preserved: $evid_path ($(stat -c%s "$evid_path") bytes)"
    echo "  Manifest:  ${evid_path}.manifest"
    echo "  Ground Truth: $gt_path"
}

# Execute 5 repetitions per workload
for rep in $(seq 1 "$TELEMETRY_REPS"); do
    run_correctness_workload "W_PACED" 500 1 1000 0 "$rep"
done

for rep in $(seq 1 "$TELEMETRY_REPS"); do
    run_correctness_workload "W_BURST" 2500 4 0 0 "$rep"
done

for rep in $(seq 1 "$TELEMETRY_REPS"); do
    run_correctness_workload "W_SUSTAIN" 15000 4 50 0 "$rep"
done

# ------------------------------------------------------------------------------
# Phase 4: Offline Reconciliation & Report Generation
# ------------------------------------------------------------------------------
echo ""
echo "[PHASE 4/4] Executing Bit-for-Bit Telemetry Reconciliation & Generating Comparative Report..."
python3 "$SCRIPT_DIR/reconcile_benchmark_01.py" "$DATA_DIR" "$DATA_DIR/benchmark_01_report.json"

# Set permissions for user
chown -R "$TARGET_USER:$TARGET_USER" "$DATA_DIR"
# Keep evid files 0600
chmod 0600 "$DATA_DIR"/*.evid* 2>/dev/null || true

echo ""
echo "==============================================================================="
echo "        Benchmark 01 Complete! Full report saved to:                           "
echo "        $DATA_DIR/benchmark_01_report.json                                     "
echo "==============================================================================="
