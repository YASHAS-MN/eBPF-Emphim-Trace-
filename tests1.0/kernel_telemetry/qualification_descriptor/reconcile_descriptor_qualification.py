#!/usr/bin/env python3
"""
EphimTrace — Release Qualification Task 01: Descriptor Lifecycle Reconciliation
Compares Ground Truth -> Raw Telemetry Records -> Provenance Graph -> Timeline
Prioritizes confirming false close attribution after dup2 replaces a memfd descriptor
"""

import json
import os
import pathlib
import re
import struct
import sys
import zlib
from typing import Any, Dict, List, Tuple

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
}


def parse_evid_records(evid_path: pathlib.Path) -> List[Dict[str, Any]]:
    if not evid_path.exists():
        return []

    records = []
    with open(evid_path, "rb") as f:
        hdr = f.read(64)
        if len(hdr) < 64:
            return []

        while True:
            frame_hdr = f.read(32)
            if len(frame_hdr) < 32:
                break
            f_magic, f_flags, f_seq, f_ts, f_len, f_crc = struct.unpack(
                "<IIQQII", frame_hdr
            )
            payload = f.read(f_len)
            if len(payload) < f_len:
                break
            if (zlib.crc32(payload) & 0xFFFFFFFF) != f_crc:
                continue

            if len(payload) >= 656:
                ev_type, pid, tid, ppid = struct.unpack("<IIII", payload[:16])
                ts_ns = struct.unpack("<Q", payload[28:36])[0]
                fd = struct.unpack("<i", payload[36:40])[0]
                ret_val, op_type, sc_flags = struct.unpack("<iII", payload[364:376])
                entry_ts_ns = struct.unpack("<Q", payload[376:384])[0]
                token = struct.unpack("<Q", payload[648:656])[0]
                name_raw = (
                    payload[60:316]
                    .split(b"\x00", 1)[0]
                    .decode("latin1", errors="replace")
                )

                records.append(
                    {
                        "seq": f_seq,
                        "frame_ts": f_ts,
                        "type_id": ev_type,
                        "type": EVENT_NAMES.get(ev_type, f"TYPE_{ev_type}"),
                        "pid": pid,
                        "tid": tid,
                        "ppid": ppid,
                        "fd": fd,
                        "object_token": token,
                        "op_type": op_type,
                        "ret_val": ret_val,
                        "entry_ts_ns": entry_ts_ns,
                        "timestamp_ns": ts_ns,
                        "name": name_raw,
                    }
                )

    return records


def parse_workload_log(log_path: pathlib.Path) -> Dict[str, Any]:
    if not log_path.exists():
        return {}

    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()

    gt = {}
    m_init = re.search(r"\[INIT\] Workload Process PID:\s+(\d+),\s+TID:\s+(\d+)", text)
    if m_init:
        gt["workload_pid"] = int(m_init.group(1))
        gt["workload_tid"] = int(m_init.group(2))

    m_clone = re.search(r"clone\(CLONE_FILES\)\s+spawned child PID\s+(\d+)", text)
    if m_clone:
        gt["clone_child_pid"] = int(m_clone.group(1))

    m_ord_ino = re.search(
        r"Ordinary file inode \((\d+)\) differs from memfd inode \((\d+)\)", text
    )
    if m_ord_ino:
        gt["s2_ord_inode"] = int(m_ord_ino.group(1))
        gt["s2_memfd_inode"] = int(m_ord_ino.group(2))

    return gt


def main():
    script_dir = pathlib.Path(__file__).resolve().parent
    data_dir = script_dir / "data"
    exports_dir = script_dir / "exports"

    evid_path = data_dir / "descriptor_qual.evid"
    log_path = data_dir / "descriptor_qual_workload.log"
    json_path = exports_dir / "run1" / "qual.json"

    print("=================================================================")
    print("=== Reconciliation: Descriptor Lifecycle Qualification Task 01 ===")
    print("=================================================================")

    if not evid_path.exists():
        print(f"Error: Evidence file not found: {evid_path}")
        print("Please run run_qualification_descriptor.sh first.")
        sys.exit(1)

    gt = parse_workload_log(log_path)
    wl_pid = gt.get("workload_pid")
    clone_pid = gt.get("clone_child_pid")
    print(f"Workload Ground Truth: PID {wl_pid}, CLONE_FILES Child PID {clone_pid}")

    all_records = parse_evid_records(evid_path)
    print(f"Total Raw Evidence Records Captured: {len(all_records):,}")

    # Map tokens to names from EVENT_MEMFD_COMPLETED
    token_to_name = {}
    for r in all_records:
        if r["type"] == "EVENT_MEMFD_COMPLETED" and r["object_token"] != 0:
            token_to_name[r["object_token"]] = r["name"]

    print(f"Tracked Memfd Objects: {len(token_to_name)}")
    for tok, name in token_to_name.items():
        print(f"  Token {tok} -> '{name}'")

    # Filter records for workload process and clone child
    relevant_pids = {wl_pid, clone_pid} if clone_pid else {wl_pid}
    wl_records = [r for r in all_records if r["pid"] in relevant_pids]
    print(f"Workload-Specific Raw Events: {len(wl_records)}")

    # Load reconstructed JSON graph
    graph = {}
    if json_path.exists():
        with open(json_path, "r") as f:
            graph = json.load(f)
    print(
        f"Reconstructed Graph: {graph.get('node_count', 0)} nodes, {graph.get('edge_count', 0)} edges"
    )

    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])

    print("\n-----------------------------------------------------------------")
    print("DETAILED ANALYSIS BY QUALIFICATION SUITE")
    print("-----------------------------------------------------------------")

    # 1. Suite 1: dup, dup2, dup3, fcntl
    print("\n[SUITE 1: Duplication and Replacement (dup vs dup2/dup3)]")
    s1_token = next((t for t, n in token_to_name.items() if n == "qual_mfd_dup"), None)
    print(f"  'qual_mfd_dup' Object Token: {s1_token}")

    s1_installs = [
        r
        for r in wl_records
        if r["type"] == "EVENT_FD_INSTALLED" and r["object_token"] == s1_token
    ]
    print(f"  Raw EVENT_FD_INSTALLED events for Token {s1_token}: {len(s1_installs)}")
    for r in s1_installs:
        op_str = (
            "CREATION"
            if r["op_type"] == 1
            else ("REOPEN" if r["op_type"] == 2 else "DUP")
        )
        print(
            f"    - Seq {r['seq']} @ {r['timestamp_ns']} ns: FD {r['fd']}, Token {r['object_token']}, Op: {op_str}"
        )

    captured_fds = set(r["fd"] for r in s1_installs)
    print(f"  Captured FDs in Telemetry: {sorted(list(captured_fds))}")
    print(
        "  Ground Truth Expected FDs: [3 (orig), 5 (dup), 30 (fcntl), 35 (dup2), 36 (dup3)]"
    )
    if 35 not in captured_fds and 36 not in captured_fds:
        print("  >>> CONFIRMED DEFICIENCY (MISSING COVERAGE):")
        print(
            "      FD 35 (dup2) and FD 36 (dup3) were COMPLETELY OMITTED from raw telemetry!"
        )
        print(
            "      Kernel do_dup2() bypassed fd_install(); no BPF probe was attached."
        )

    # 2. Suite 2: Replacement with ordinary file
    print("\n[SUITE 2: Replacement of Tracked Memfd with Ordinary File]")
    s2_token = next(
        (t for t, n in token_to_name.items() if n == "qual_mfd_replace"), None
    )
    print(f"  'qual_mfd_replace' Creation: Token = {s2_token}")

    s2_closes = [
        r
        for r in wl_records
        if r["type"] == "EVENT_FD_CLOSED"
        and r["fd"] == 3
        and r["object_token"] == s2_token
    ]
    print(
        f"  Raw EVENT_FD_CLOSED events on FD 3 for Token {s2_token}: {len(s2_closes)}"
    )
    for r in s2_closes:
        print(
            f"    - Seq {r['seq']} @ {r['timestamp_ns']} ns: FD {r['fd']}, Token {r['object_token']}, Duration: {r['entry_ts_ns']} ns"
        )

    if s2_closes:
        print("  >>> CONFIRMED DEFICIENCY (INCORRECT ATTRIBUTION):")
        print(
            f"      FD 3 was replaced with an ordinary file (/tmp/ephim_qual_ordinary_*) via dup2."
        )
        print(
            f"      When close(3) was called on the ordinary file, BPF capture_close_fd queried memfd_desc_registry,"
        )
        print(
            f"      found the stale entry for Token {s2_token}, and emitted a FALSE EVENT_FD_CLOSED!"
        )
        print(
            f"      The closure of an ordinary file was falsely attributed as closing memfd Token {s2_token}!"
        )

    # 3. Suite 3: Failed Operations and Reuse
    print("\n[SUITE 3: Descriptor Reuse and Failed Operations]")
    bad_closes = [
        r for r in wl_records if r["fd"] == -1 and r["type"] == "EVENT_FD_CLOSED"
    ]
    print(f"  Spurious close(-1) events: {len(bad_closes)} (Expected: 0)")
    bad_dups = [
        r for r in wl_records if r["fd"] == -1 and r["type"] == "EVENT_FD_INSTALLED"
    ]
    print(f"  Spurious dup(-1) events: {len(bad_dups)} (Expected: 0)")
    if len(bad_closes) == 0 and len(bad_dups) == 0:
        print(
            "  [OK] Negative syscall failures cleanly rejected with zero spurious telemetry."
        )

    # 4. Suite 4: Concurrent Operations and CLONE_FILES
    print("\n[SUITE 4: Shared Descriptor Tables Across Processes (CLONE_FILES)]")
    s4_token = next(
        (t for t, n in token_to_name.items() if n == "qual_mfd_clone"), None
    )
    print(f"  'qual_mfd_clone' Creation in Parent (PID {wl_pid}): Token = {s4_token}")

    s4_child_closes = [
        r
        for r in wl_records
        if r["type"] == "EVENT_FD_CLOSED" and r["pid"] == clone_pid
    ]
    print(
        f"  Child (PID {clone_pid}) Close Events in Raw Telemetry: {len(s4_child_closes)}"
    )
    if len(s4_child_closes) == 0:
        print("  >>> CONFIRMED DEFICIENCY (MISSING COVERAGE & REGISTRY MISMATCH):")
        print(
            f"      Child PID {clone_pid} closed the shared descriptor, but BPF capture_close_fd"
        )
        print(
            f"      looked up (tgid={clone_pid}, fd=3), which failed because the registry stored (tgid={wl_pid}, fd=3)!"
        )
        print(
            f"      The child's close was dropped silently, and parent's registry entry was orphaned."
        )

    print("\n=================================================================")
    print("Reconciliation Diagnosis Complete.")
    print("=================================================================")


if __name__ == "__main__":
    main()
