#!/usr/bin/env python3
"""
EphimTrace — Controlled Fault Injection & State Independence Validation Test
Phase 1 Remediation Verification:
1. Simulates controlled ring-buffer reservation failure on EVENT_MEMFD_COMPLETED.
2. Executes test_m2_exec (reopen via /proc/self/fd/N and execution via fexecve/execveat).
3. Verifies that despite 100% dropped creation records:
   - Registry commitment and state independence succeed.
   - Subsequent descriptor reopening (/proc/self/fd/N) successfully correlates to object_token.
   - Subsequent execution successfully correlates to object_token and emits EVENT_MEMFD_EXEC_SUCCESS.
   - Event ordering is preserved: EVENT_PROCESS_EXEC (7) precedes EVENT_MEMFD_EXEC_SUCCESS (19) by PID and token.
   - Demonstrates actual raw token correspondence from binary evidence (bytes 656..664).
   - Reservation failures are accurately counted per-event-type and recorded in .manifest.
   - Consumers distinguish successful persistence from complete telemetry capture.
"""

import json
import os
import shutil
import struct
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
BUILD = ROOT / "build" / "controlled_test"
BUILD.mkdir(parents=True, exist_ok=True)

EVENT_NAMES = {
    1: "EVENT_EXECVE",
    2: "EVENT_MEMFD_CREATE",
    3: "EVENT_UNLINK",
    4: "EVENT_UNLINKAT",
    5: "EVENT_CONNECT",
    6: "EVENT_FORK",
    7: "EVENT_PROCESS_EXEC",
    8: "EVENT_PROCESS_EXIT",
    9: "EVENT_VFS_UNLINK_COMPLETED",
    10: "EVENT_VFS_RMDIR_COMPLETED",
    11: "EVENT_RMDIR",
    12: "EVENT_MEMFD_COMPLETED",
    13: "EVENT_MEMFD_DESTROYED",
    14: "EVENT_MEMFD_FILE_RELEASED",
    15: "EVENT_FD_INSTALLED",
    16: "EVENT_FD_CLOSED",
    17: "EVENT_MEMFD_WRITE",
    18: "EVENT_MEMFD_EXEC_ATTEMPT",
    19: "EVENT_MEMFD_EXEC_SUCCESS",
    99: "EVENT_DEBUG",
}


def build_controlled_binaries():
    bpf_src = (ROOT / "src/bpf/monitor.bpf.c").read_text()

    # Inject fault: force new_event(EVENT_MEMFD_COMPLETED) to fail
    fault_code = """
static __always_inline struct event *new_event(__u32 type)
{
    struct event *e;
    if (type == EVENT_MEMFD_COMPLETED) {
        /* Injected controlled reservation failure */
        count_rb_drop(type);
        return NULL;
    }
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        count_rb_drop(type);
        return NULL;
    }
"""
    bpf_src = bpf_src.replace(
        """static __always_inline struct event *new_event(__u32 type)
{
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        count_rb_drop(type);
        return NULL;
    }""",
        fault_code,
        1,
    )

    controlled_bpf_c = BUILD / "monitor.controlled.bpf.c"
    controlled_bpf_o = BUILD / "monitor.controlled.bpf.o"
    controlled_bpf_c.write_text(bpf_src)

    cmd_clang = [
        "clang-16",
        "-O2",
        "-g",
        "-target",
        "bpf",
        "-D__TARGET_ARCH_x86",
        "-I",
        "src/bpf",
        "-I/usr/include/x86_64-linux-gnu",
        "-I/usr/include",
        "-c",
        str(controlled_bpf_c),
        "-o",
        str(controlled_bpf_o),
    ]
    subprocess.run(cmd_clang, cwd=ROOT, check=True)

    loader_src = (ROOT / "src/user/loader.c").read_text()
    loader_src = loader_src.replace(
        'bpf_object__open_file("build/monitor.bpf.o", NULL)',
        f'bpf_object__open_file("{controlled_bpf_o}", NULL)',
        1,
    )
    controlled_loader_c = BUILD / "loader.controlled.c"
    controlled_loader = BUILD / "loader.controlled"
    controlled_loader_c.write_text(loader_src)

    cmd_gcc = [
        "gcc",
        "-O2",
        "-Wall",
        "-Wextra",
        "-I",
        "src/user",
        "-I",
        "src/bpf",
        str(controlled_loader_c),
        "-o",
        str(controlled_loader),
        "-lbpf",
    ]
    subprocess.run(cmd_gcc, cwd=ROOT, check=True)
    print("[BUILD] Controlled test binaries built successfully.")
    return controlled_loader


def parse_evidence_file(evid_path):
    HEADER_FMT = "<IIIIQIIQQ12sI"
    HEADER_SIZE = struct.calcsize(HEADER_FMT)  # 64
    FRAME_FMT = "<IIQQII"
    FRAME_SIZE = struct.calcsize(FRAME_FMT)  # 32

    events = []
    with open(evid_path, "rb") as f:
        hdr_data = f.read(HEADER_SIZE)
        if len(hdr_data) < HEADER_SIZE:
            return events

        while True:
            frame_data = f.read(FRAME_SIZE)
            if not frame_data or len(frame_data) < FRAME_SIZE:
                break
            magic, flags, seq, rec_ts, plen, pcrc = struct.unpack(FRAME_FMT, frame_data)
            payload = f.read(plen)
            if len(payload) < plen:
                break

            ev_type, pid, tid, ppid = struct.unpack("<IIII", payload[:16])
            fd = struct.unpack("<i", payload[40:44])[0]
            name = (
                payload[56 : 56 + 256]
                .split(b"\x00")[0]
                .decode("utf-8", errors="replace")
            )
            object_token = struct.unpack("<Q", payload[656:664])[0]
            events.append(
                {
                    "seq": seq,
                    "type": ev_type,
                    "type_name": EVENT_NAMES.get(ev_type, f"TYPE_{ev_type}"),
                    "pid": pid,
                    "tid": tid,
                    "ppid": ppid,
                    "fd": fd,
                    "name": name,
                    "object_token": object_token,
                    "raw_token_bytes": payload[656:664].hex(),
                    "raw": payload,
                }
            )

    return events


def run_controlled_test():
    if os.geteuid() != 0:
        print("ERROR: Controlled test must be run as root (sudo).")
        sys.exit(1)

    loader = build_controlled_binaries()
    evid_file = BUILD / "controlled_test.evid"
    if evid_file.exists():
        evid_file.unlink()
    manifest_file = Path(str(evid_file) + ".manifest")
    if manifest_file.exists():
        manifest_file.unlink()

    target_bin = ROOT / "build" / "test_m2_exec"
    if not target_bin.exists():
        subprocess.run(["make", "build/test_m2_exec"], cwd=ROOT, check=True)

    # Run loader with controlled reservation failure
    cmd_loader = [str(loader), "-o", str(evid_file), "-q"]

    print("\n[STEP 1] Launching controlled loader with injected reservation failure...")
    loader_proc = subprocess.Popen(
        cmd_loader, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )

    time.sleep(1.0)

    print("[STEP 2] Running test_m2_exec under controlled fault injection...")
    t_out = subprocess.run([str(target_bin)], cwd=ROOT, capture_output=True, text=True)
    print(t_out.stdout)
    if t_out.returncode != 0:
        print("test_m2_exec FAILED:", t_out.stderr)
        loader_proc.terminate()
        sys.exit(1)

    time.sleep(1.0)
    print("[STEP 3] Stopping controlled loader...")
    import signal

    loader_proc.send_signal(signal.SIGINT)
    stdout, _ = loader_proc.communicate(timeout=10)
    print(stdout)

    if evid_file.exists():
        os.chmod(evid_file, 0o666)
    if manifest_file.exists():
        os.chmod(manifest_file, 0o666)

    # 1. Verify manifest
    print(
        "[STEP 4] Verifying private session manifest loss accounting & persistence..."
    )
    assert manifest_file.exists(), f"Manifest {manifest_file} was not generated!"
    m = json.loads(manifest_file.read_text())
    print("Session Manifest Summary:")
    print(f"  Persistence Status:        {m.get('persistence_status')}")
    print(f"  Telemetry Capture Status:  {m.get('telemetry_capture_status')}")
    print(f"  Telemetry Loss Free:       {m.get('telemetry_loss_free')}")
    print(f"  Storage Bytes:             {m.get('storage_bytes')}")
    print(f"  Record Count:              {m.get('record_count')}")
    print("  Loss Counters:")
    print(json.dumps(m["loss_counters"], indent=4))

    assert m.get("persistence_status") == "PERSISTED_CLEAN", "Persistence must be clean"
    assert (
        m.get("telemetry_loss_free") is False
    ), "Telemetry capture must be flagged as lossy"
    assert (
        m.get("telemetry_capture_status")
        == "LOSSY (Drops recorded in kernel ring buffer or registry)"
    ), f"Status must match current loss contract, got: {m.get('telemetry_capture_status')}"

    drops = m["loss_counters"]["ring_buffer_total_drops"]
    per_type = m["loss_counters"]["ring_buffer_per_type_drops"]
    memfd_drops = per_type.get("memfd_completed", 0)
    debug_drops = per_type.get("debug", 0)

    print(
        f"  Total Drops: {drops}, memfd_completed Drops: {memfd_drops}, debug Drops: {debug_drops}"
    )
    assert drops > 0, f"Expected non-zero ring buffer drops (measured: {drops})"
    assert (
        memfd_drops > 0
    ), f"Expected non-zero memfd_completed drops (measured: {memfd_drops})"
    assert debug_drops == 0, f"Expected debug drops to be 0 (measured: {debug_drops})"

    # All 20 defined types must be in per_type
    expected_types = [
        "execve",
        "memfd_create",
        "unlink",
        "unlinkat",
        "connect",
        "fork",
        "process_exec",
        "process_exit",
        "vfs_unlink_completed",
        "vfs_rmdir_completed",
        "rmdir",
        "memfd_completed",
        "memfd_destroyed",
        "memfd_file_released",
        "fd_installed",
        "fd_closed",
        "memfd_write",
        "memfd_exec_attempt",
        "memfd_exec_success",
        "debug",
    ]
    for et in expected_types:
        assert et in per_type, f"Missing event type in manifest: {et}"
        assert (
            per_type[et] >= 0
        ), f"Counter for {et} must be non-negative, got {per_type[et]}"

    type_sum = sum(v for v in per_type.values() if v > 0)
    assert (
        drops == type_sum
    ), f"Total drops ({drops}) must match sum of per-type drops ({type_sum})"

    # 2. Parse and verify raw evidence file
    print(
        "\n[STEP 5] Inspecting raw binary evidence for token correspondence & ordering..."
    )
    events = parse_evidence_file(str(evid_file))
    print(f"Total raw evidence records parsed: {len(events)}")

    type_counts = {}
    for ev in events:
        type_counts[ev["type_name"]] = type_counts.get(ev["type_name"], 0) + 1
    print(f"Event distribution: {type_counts}")

    # EVENT_MEMFD_COMPLETED (12) must be 0 in evidence
    assert (
        type_counts.get("EVENT_MEMFD_COMPLETED", 0) == 0
    ), "Expected 0 EVENT_MEMFD_COMPLETED due to 100% injected reservation drop"

    # Correlate tokens from raw payload byte offsets 656..664
    reopen_events = [e for e in events if e["type"] == 15 and e["object_token"] != 0]
    exec_events = [e for e in events if e["type"] == 7 and e["object_token"] != 0]
    success_events = [e for e in events if e["type"] == 19 and e["object_token"] != 0]

    print(f"\nDiscovered Reopened FDs (EVENT_FD_INSTALLED): {len(reopen_events)}")
    for r in reopen_events:
        print(
            f"  [FD_INSTALLED] Seq={r['seq']} PID={r['pid']} FD={r['fd']} "
            f"Token=0x{r['object_token']:016x} (Raw bytes: {r['raw_token_bytes']})"
        )

    print(f"\nDiscovered Exec Events (EVENT_PROCESS_EXEC): {len(exec_events)}")
    for ex in exec_events:
        print(
            f"  [PROCESS_EXEC] Seq={ex['seq']} PID={ex['pid']} Name='{ex['name']}' "
            f"Token=0x{ex['object_token']:016x} (Raw bytes: {ex['raw_token_bytes']})"
        )

    print(
        f"\nDiscovered Success Events (EVENT_MEMFD_EXEC_SUCCESS): {len(success_events)}"
    )
    for s in success_events:
        print(
            f"  [EXEC_SUCCESS] Seq={s['seq']} PID={s['pid']} Name='{s['name']}' "
            f"Token=0x{s['object_token']:016x} (Raw bytes: {s['raw_token_bytes']})"
        )

    assert (
        len(success_events) > 0
    ), "Expected EVENT_MEMFD_EXEC_SUCCESS records in evidence"
    assert len(exec_events) > 0, "Expected EVENT_PROCESS_EXEC records in evidence"
    assert (
        len(reopen_events) > 0
    ), "Expected reopened descriptor records (EVENT_FD_INSTALLED)"

    # Check ordering: For each EVENT_MEMFD_EXEC_SUCCESS, matching EVENT_PROCESS_EXEC must precede it for that PID and token
    print(
        "\nVerifying Event Sequence Ordering (EVENT_PROCESS_EXEC precedes EVENT_MEMFD_EXEC_SUCCESS by PID and Token)..."
    )
    matched_pairs = 0
    for s in success_events:
        s_pid = s["pid"]
        s_tok = s["object_token"]
        s_seq = s["seq"]

        # Match preceding EVENT_PROCESS_EXEC events for the same process identity and token
        matching_execs = [
            e
            for e in exec_events
            if e["pid"] == s_pid and e["object_token"] == s_tok and e["seq"] < s_seq
        ]
        assert len(matching_execs) > 0, (
            f"No preceding EVENT_PROCESS_EXEC found for PID={s_pid}, "
            f"Token=0x{s_tok:016x} before Seq={s_seq}"
        )
        exec_ev = matching_execs[-1]
        print(
            f"  Matched pair: Exec Seq {exec_ev['seq']} -> Success Seq {s_seq} "
            f"(PID={s_pid}, Token=0x{s_tok:016x})"
        )
        assert (
            exec_ev["seq"] < s_seq
        ), f"Exec sequence {exec_ev['seq']} must precede success sequence {s_seq}"
        assert (
            exec_ev["pid"] == s_pid
        ), f"PID mismatch: exec {exec_ev['pid']} vs success {s_pid}"
        assert (
            exec_ev["object_token"] == s_tok
        ), f"Token mismatch: exec {exec_ev['object_token']} vs success {s_tok}"

        # Verify no interleaving EVENT_MEMFD_EXEC_SUCCESS occurred between exec_ev and s for this PID and token
        interleaving_success = [
            e
            for e in success_events
            if e["pid"] == s_pid
            and e["object_token"] == s_tok
            and exec_ev["seq"] < e["seq"] < s_seq
        ]
        assert (
            len(interleaving_success) == 0
        ), f"Unexpected duplicate EVENT_MEMFD_EXEC_SUCCESS found between Seq {exec_ev['seq']} and {s_seq}"
        matched_pairs += 1
    print(
        f"  [PASS] Verified {matched_pairs} execution sequences: EVENT_PROCESS_EXEC correctly precedes EVENT_MEMFD_EXEC_SUCCESS for all (PID, Token) pairs!"
    )

    # Check token correspondence across reopening and execution
    print("\nVerifying Token Correspondence Across Reopen and Execution...")
    reopen_tokens = {r["object_token"] for r in reopen_events}
    exec_tokens = {s["object_token"] for s in success_events}
    shared_tokens = reopen_tokens.intersection(exec_tokens)
    print(f"  Reopened Tokens:  {[f'0x{t:016x}' for t in reopen_tokens]}")
    print(f"  Executed Tokens:  {[f'0x{t:016x}' for t in exec_tokens]}")
    print(f"  Shared Tokens:    {[f'0x{t:016x}' for t in shared_tokens]}")
    assert (
        len(shared_tokens) > 0
    ), "Reopened descriptor token must match executed memfd token!"
    print(
        f"  [PASS] Verified token correspondence: Reopened token 0x{list(shared_tokens)[0]:016x} matches executed memfd token!"
    )

    # 3. Verify evidence consumer replay output
    print("\n[STEP 6] Testing Evidence Consumer (replay) Discrimination...")
    summary_json = BUILD / "replay_summary.json"
    cmd_replay = [
        str(ROOT / "build" / "replay"),
        str(evid_file),
        "--summary-json",
        str(summary_json),
    ]
    rep_out = subprocess.run(cmd_replay, cwd=ROOT, capture_output=True, text=True)
    print(rep_out.stdout)
    assert rep_out.returncode == 0, f"replay failed: {rep_out.stderr}"

    assert summary_json.exists()
    s = json.loads(summary_json.read_text())
    print("Replay Summary JSON:")
    print(json.dumps(s, indent=4))

    assert s.get("persistence_verified") is True, "Replay must verify persistence"
    assert (
        s.get("telemetry_loss_free") is False
    ), "Replay must report telemetry as lossy"
    assert (
        s.get("telemetry_capture_status")
        == "LOSSY (Drops recorded in kernel ring buffer or registry)"
    ), f"Replay capture status must match contract, got: {s.get('telemetry_capture_status')}"
    assert (
        s.get("ring_buffer_total_drops") == drops
    ), f"Replay must report measured drop count {drops}"
    assert (
        "Lossy Telemetry Captured" in rep_out.stdout
    ), "Replay stdout must indicate lossy telemetry"

    print("\n=======================================================")
    print("ALL PHASE 1 REMEDIATION CORRECTIVE ASSERTIONS PASSED!")
    print("=======================================================")


if __name__ == "__main__":
    run_controlled_test()
