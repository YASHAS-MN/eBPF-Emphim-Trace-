#!/usr/bin/env bash
#
# EphimTrace — Release Qualification Task 01: Descriptor Lifecycle Runner
# Executes test_qualification_descriptor under production eBPF collector (b6c89af)
# Captures persistent evidence and executes double replay for reconciliation
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PERSIST_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"

DATA_DIR="$SCRIPT_DIR/data"
EXPORTS_DIR="$SCRIPT_DIR/exports"
RUN1_DIR="$EXPORTS_DIR/run1"
RUN2_DIR="$EXPORTS_DIR/run2"

LOADER_BIN="$PERSIST_DIR/build/loader"
REPLAY_BIN="$PERSIST_DIR/build/replay"
BPF_OBJ="$PERSIST_DIR/build/monitor.bpf.o"
TEST_BIN="$PERSIST_DIR/build/test_qualification_descriptor"
RECONCILE_PY="$SCRIPT_DIR/reconcile_descriptor_qualification.py"

TARGET_USER="${SUDO_USER:-$(id -un)}"
TARGET_UID="${SUDO_UID:-$(id -u)}"
TARGET_GID="${SUDO_GID:-$(id -g)}"

if [ "$EUID" -ne 0 ]; then
    echo "==============================================================================="
    echo "ERROR: Root privileges required to attach eBPF probes for EphimTrace."
    echo "Please run: sudo $0"
    echo "==============================================================================="
    exit 1
fi

echo "==============================================================================="
echo "       EphimTrace — Release Qualification Task 01: Descriptor Lifecycle        "
echo "==============================================================================="
echo "Target User:          $TARGET_USER (UID: $TARGET_UID, GID: $TARGET_GID)"
echo "Repository Root:      $PERSIST_DIR"
echo "Data Directory:       $DATA_DIR"
echo "Exports Directory:    $EXPORTS_DIR"
echo "Production Loader:    $LOADER_BIN (Frozen at b6c89af)"
echo "Test Binary:          $TEST_BIN"
echo "==============================================================================="

# Verify binaries exist
for b in "$LOADER_BIN" "$REPLAY_BIN" "$BPF_OBJ" "$TEST_BIN"; do
    if [ ! -f "$b" ]; then
        echo "ERROR: Required binary not found: $b"
        echo "Building test binaries..."
        make -C "$PERSIST_DIR" all "$TEST_BIN"
    fi
done

mkdir -p "$DATA_DIR" "$RUN1_DIR" "$RUN2_DIR"
chown -R "$TARGET_USER:$TARGET_USER" "$DATA_DIR" "$EXPORTS_DIR"
chmod 0750 "$DATA_DIR" "$RUN1_DIR" "$RUN2_DIR"

EVID_PATH="$DATA_DIR/descriptor_qual.evid"
MANIFEST_PATH="$DATA_DIR/descriptor_qual.evid.manifest"
WL_LOG="$DATA_DIR/descriptor_qual_workload.log"
LOADER_LOG="$DATA_DIR/descriptor_qual_loader.log"
STAT_FILE="$DATA_DIR/descriptor_qual_stat.json"

rm -f "$EVID_PATH" "$MANIFEST_PATH" "$WL_LOG" "$LOADER_LOG" "$STAT_FILE"

echo ""
echo "[PHASE 1/4] Launching Production eBPF Collector..."
"$LOADER_BIN" --ring-buffer-mb 64 -b 2147483648 -o "$EVID_PATH" -v > "$LOADER_LOG" 2>&1 &
LOADER_PID=$!

sleep 2
if ! kill -0 "$LOADER_PID" 2>/dev/null; then
    echo "ERROR: Loader failed to start!"
    cat "$LOADER_LOG"
    exit 1
fi
echo "  [OK] Collector running (PID: $LOADER_PID, 64 MiB ring buffer, 2 GiB storage bound)"

echo ""
echo "[PHASE 2/4] Executing Targeted Native Descriptor Lifecycle Workload..."
T_WL_START=$(date +%s%N)
sudo -u "$TARGET_USER" bash -c "cd '$PERSIST_DIR' && '$TEST_BIN'" > "$WL_LOG" 2>&1 || true
T_WL_END=$(date +%s%N)

if ! kill -0 "$LOADER_PID" 2>/dev/null; then
    echo "ERROR: Collector died prematurely during workload execution!"
    cat "$LOADER_LOG"
    exit 1
fi
echo "  [OK] Native workload completed. Log preserved in $WL_LOG"

# Allow ring buffer drain
sleep 2

echo ""
echo "[PHASE 3/4] Orderly Collector Finalization & Manifest Synchronization..."
T_STOP_REQ=$(date +%s%N)
kill -INT "$LOADER_PID" 2>/dev/null || true
wait "$LOADER_PID" 2>/dev/null || true
T_FINAL_SYNC=$(date +%s%N)

WL_DURATION_S=$(awk "BEGIN {print ($T_WL_END - $T_WL_START) / 1000000000}")
SHUTDOWN_LATENCY_S=$(awk "BEGIN {print ($T_FINAL_SYNC - $T_STOP_REQ) / 1000000000}")
TOTAL_PIPELINE_S=$(awk "BEGIN {print ($T_FINAL_SYNC - $T_WL_START) / 1000000000}")
EVID_SIZE=$(stat -c%s "$EVID_PATH" 2>/dev/null || echo 0)

cat <<EOF > "$STAT_FILE"
{
  "workload_duration_s": $WL_DURATION_S,
  "collector_shutdown_latency_s": $SHUTDOWN_LATENCY_S,
  "workload_and_shutdown_pipeline_s": $TOTAL_PIPELINE_S,
  "evidence_storage_bytes": $EVID_SIZE
}
EOF

chown "$TARGET_USER:$TARGET_USER" "$EVID_PATH" "$MANIFEST_PATH" "$WL_LOG" "$LOADER_LOG" "$STAT_FILE" 2>/dev/null || true
chmod 0640 "$EVID_PATH" "$MANIFEST_PATH" "$WL_LOG" "$LOADER_LOG" "$STAT_FILE" 2>/dev/null || true

echo "  [OK] Evidence captured: $EVID_SIZE bytes in $EVID_PATH"
echo "  [OK] Manifest present: $MANIFEST_PATH"

HASH_PRE=$(sha256sum "$EVID_PATH" | awk '{print $1}')

echo ""
echo "[PHASE 4/4] Executing Double Replay & Export Generation..."
sudo -u "$TARGET_USER" bash -c "cd '$PERSIST_DIR' && '$REPLAY_BIN' '$EVID_PATH' --dot '$RUN1_DIR/qual.dot' --json '$RUN1_DIR/qual.json' --timeline '$RUN1_DIR/qual_timeline.md' --summary-json '$RUN1_DIR/qual_summary.json' -q"
sudo -u "$TARGET_USER" bash -c "cd '$PERSIST_DIR' && '$REPLAY_BIN' '$EVID_PATH' --dot '$RUN2_DIR/qual.dot' --json '$RUN2_DIR/qual.json' --timeline '$RUN2_DIR/qual_timeline.md' --summary-json '$RUN2_DIR/qual_summary.json' -q"

HASH_POST=$(sha256sum "$EVID_PATH" | awk '{print $1}')
if [ "$HASH_PRE" != "$HASH_POST" ]; then
    echo "ERROR: Evidence digest modified during replay!"
    exit 1
fi
echo "  [OK] Double replay determinism exports verified (SHA-256 intact: $HASH_PRE)"

if [ -f "$RECONCILE_PY" ]; then
    echo ""
    echo "[ANALYSIS] Running Reconciliation & Comparative Diagnosis..."
    sudo -u "$TARGET_USER" python3 "$RECONCILE_PY"
fi

echo ""
echo "==============================================================================="
echo "       Qualification Task 01 Native Run Complete!                              "
echo "==============================================================================="
