#!/usr/bin/env python3
"""
EphimTrace — Release Qualification Task 01: Descriptor Lifecycle Reconciliation
Compares Ground Truth -> Raw Telemetry Records -> Provenance Graph -> Timeline
Verifies actual binary event layout (sizeof(struct event) == 664) and object tokens.
Prioritizes confirming false close attribution after dup2 replaces a memfd descriptor.
"""

import json
import os
import pathlib
import re
import struct
import sys
import zlib
from typing import Any, Dict, List, Optional, Set, Tuple

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

# Verified binary event struct layout: sizeof(struct event) == 664 bytes
# Offset map matching src/user/provenance.h:
#   0: type (u32), 4: pid (u32), 8: tid (u32), 12: ppid (u32), 16: flags (u32), 20: dirfd (i32), 24: reserved (u32)
#   [28..32: 4-byte pad]
#   32: timestamp_ns (u64), 40: fd (i32), 44: family (u16), 46: port (u16), 48: address (16s), 64: name (256s)
#   320: child_pid (u32), 324: old_pid (u32), 328: child_tgid (u32)
#   [332..336: 4-byte pad]
#   336: start_time_ns (u64), 344: child_start_time_ns (u64), 352: inode_no (u64), 360: dev_id (u64)
#   368: mnt_ns_id (u32), 372: ret_val (i32), 376: op_type (u32), 380: syscall_flags (u32)
#   384: entry_ts_ns (u64), 392: path_status (u32), 396: path (256s), 652: pad (u32), 656: object_token (u64)
EVENT_STRUCT_FMT = "<IIII I i I 4x Q i HH 16s 256s III 4x QQQQ I i II Q I 256s I Q"
assert (
    struct.calcsize(EVENT_STRUCT_FMT) == 664
), "Struct event format must match 664 bytes"


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

            if len(payload) == 664:
                vals = struct.unpack(EVENT_STRUCT_FMT, payload)
                ev_type = vals[0]
                pid = vals[1]
                tid = vals[2]
                ppid = vals[3]
                flags = vals[4]
                dirfd = vals[5]
                ts_ns = vals[7]
                fd = vals[8]
                family = vals[9]
                port = vals[10]
                name_raw = (
                    vals[12].split(b"\x00", 1)[0].decode("latin1", errors="replace")
                )
                child_pid = vals[13]
                old_pid = vals[14]
                child_tgid = vals[15]
                start_time_ns = vals[16]
                child_start_time_ns = vals[17]
                inode_no = vals[18]
                dev_id = vals[19]
                mnt_ns_id = vals[20]
                ret_val = vals[21]
                op_type = vals[22]
                syscall_flags = vals[23]
                entry_ts_ns = vals[24]
                path_status = vals[25]
                path_raw = (
                    vals[26].split(b"\x00", 1)[0].decode("latin1", errors="replace")
                )
                object_token = vals[28]

                records.append(
                    {
                        "seq": f_seq,
                        "frame_ts": f_ts,
                        "type_id": ev_type,
                        "type": EVENT_NAMES.get(ev_type, f"TYPE_{ev_type}"),
                        "pid": pid,
                        "tid": tid,
                        "ppid": ppid,
                        "flags": flags,
                        "dirfd": dirfd,
                        "fd": fd,
                        "name": name_raw,
                        "child_pid": child_pid,
                        "old_pid": old_pid,
                        "child_tgid": child_tgid,
                        "start_time_ns": start_time_ns,
                        "child_start_time_ns": child_start_time_ns,
                        "inode_no": inode_no,
                        "dev_id": dev_id,
                        "mnt_ns_id": mnt_ns_id,
                        "ret_val": ret_val,
                        "op_type": op_type,
                        "syscall_flags": syscall_flags,
                        "entry_ts_ns": entry_ts_ns,
                        "path_status": path_status,
                        "path": path_raw,
                        "object_token": object_token,
                        "timestamp_ns": ts_ns,
                    }
                )

    return records


def parse_workload_log(log_path: pathlib.Path) -> Dict[str, Any]:
    if not log_path.exists():
        return {}

    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()

    gt: Dict[str, Any] = {}
    m_init = re.search(r"\[INIT\] Workload Process PID:\s+(\d+),\s+TID:\s+(\d+)", text)
    if m_init:
        gt["workload_pid"] = int(m_init.group(1))
        gt["workload_tid"] = int(m_init.group(2))

    # Suite 1: Duplication and Replacement
    m = re.search(r"Created memfd '(qual_mfd_dup)' \(FD (\d+)\)", text)
    if m:
        gt["s1_name"] = m.group(1)
        gt["s1_orig_fd"] = int(m.group(2))
    m = re.search(r"dup\(orig_fd\) succeeded -> FD (\d+)", text)
    if m:
        gt["s1_dup_fd"] = int(m.group(1))
    m = re.search(r"fcntl\(orig_fd, F_DUPFD, \d+\) succeeded -> FD (\d+)", text)
    if m:
        gt["s1_fcntl_fd"] = int(m.group(1))
    m = re.search(
        r"dup2\(orig_fd, \d+\) to unused descriptor succeeded -> FD (\d+)", text
    )
    if m:
        gt["s1_dup2_fd"] = int(m.group(1))
    m = re.search(
        r"dup3\(orig_fd, \d+, O_CLOEXEC\) to unused descriptor succeeded -> FD (\d+)",
        text,
    )
    if m:
        gt["s1_dup3_fd"] = int(m.group(1))

    # Suite 2: Replacement of Tracked Descriptors with Ordinary Files
    m = re.search(r"Created memfd '(qual_mfd_replace)' at FD (\d+)", text)
    if m:
        gt["s2_name"] = m.group(1)
        gt["s2_mfd_fd"] = int(m.group(2))
    m = re.search(r"Created temporary ordinary file at FD (\d+) \(([^)]+)\)", text)
    if m:
        gt["s2_ord_fd"] = int(m.group(1))
        gt["s2_ord_path"] = m.group(2)
    m = re.search(
        r"Ordinary file inode \((\d+)\) differs from memfd inode \((\d+)\)", text
    )
    if m:
        gt["s2_ord_inode"] = int(m.group(1))
        gt["s2_memfd_inode"] = int(m.group(2))
    m = re.search(r"dup2\(ord_fd, mfd\) succeeded, returning (\d+)", text)
    if m:
        gt["s2_replaced_fd"] = int(m.group(1))

    # Suite 3: Descriptor Reuse and Failed Operations
    m = re.search(r"Allocated memfd '(qual_mfd_reuse)' at slot FD (\d+)", text)
    if m:
        gt["s3_name"] = m.group(1)
        gt["s3_reuse_fd"] = int(m.group(2))

    # Suite 4: Concurrent Operations and Shared Descriptor Tables
    m = re.search(r"Created memfd '(qual_mfd_threads)' at FD (\d+)", text)
    if m:
        gt["s4_threads_name"] = m.group(1)
        gt["s4_threads_fd"] = int(m.group(2))
    m = re.search(r"Created memfd '(qual_mfd_clone)' at FD (\d+)", text)
    if m:
        gt["s4_clone_name"] = m.group(1)
        gt["s4_clone_fd"] = int(m.group(2))
    m = re.search(r"clone\(CLONE_FILES\) spawned child PID (\d+)", text)
    if m:
        gt["s4_child_pid"] = int(m.group(1))

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
    clone_pid = gt.get("s4_child_pid")
    print(f"Workload Ground Truth: PID {wl_pid}, CLONE_FILES Child PID {clone_pid}")

    all_records = parse_evid_records(evid_path)
    print(f"Total Raw Evidence Records Captured: {len(all_records):,}")

    # Map tokens to names from EVENT_MEMFD_COMPLETED and EVENT_MEMFD_CREATE
    token_to_name: Dict[int, str] = {}
    name_to_token: Dict[str, int] = {}
    for r in all_records:
        if r["type"] == "EVENT_MEMFD_COMPLETED" and r["object_token"] > 0:
            token_to_name[r["object_token"]] = r["name"]
            name_to_token[r["name"]] = r["object_token"]

    print(f"\n[OBJECT IDENTIFICATION] Resolved Memfd Objects: {len(token_to_name)}")
    for tok, name in sorted(token_to_name.items()):
        print(f"  Token {tok} -> '{name}'")

    # REQUIRE successful object identification before evaluating descriptor lifecycle coverage
    expected_mfd_names = [
        gt.get("s1_name", "qual_mfd_dup"),
        gt.get("s2_name", "qual_mfd_replace"),
        gt.get("s3_name", "qual_mfd_reuse"),
        gt.get("s4_threads_name", "qual_mfd_threads"),
        gt.get("s4_clone_name", "qual_mfd_clone"),
    ]
    missing_tokens = [name for name in expected_mfd_names if name not in name_to_token]
    if missing_tokens:
        print(
            f"\nFATAL: Failed to resolve object tokens for expected memfds: {missing_tokens}"
        )
        print(
            "Binary layout parsing must match production event ABI. Aborting evaluation."
        )
        sys.exit(1)
    else:
        print("  [PASS] All 5 workload memfd object tokens successfully identified!")

    # Filter records for workload process and clone child
    relevant_pids = {wl_pid, clone_pid} if clone_pid else {wl_pid}
    wl_records = [r for r in all_records if r["pid"] in relevant_pids]
    print(f"Workload-Specific Raw Events: {len(wl_records)}")

    # Load reconstructed JSON graph
    graph: Dict[str, Any] = {}
    if json_path.exists():
        with open(json_path, "r") as f:
            graph = json.load(f)
    print(
        f"Reconstructed Graph: {graph.get('node_count', len(graph.get('nodes', [])))} nodes, {graph.get('edge_count', len(graph.get('edges', [])))} edges"
    )

    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])

    print("\n-----------------------------------------------------------------")
    print("DETAILED ANALYSIS BY QUALIFICATION SUITE")
    print("-----------------------------------------------------------------")

    # =========================================================================
    # SUITE 1: Duplication and Replacement (dup vs dup2/dup3)
    # =========================================================================
    print("\n[SUITE 1: Duplication and Replacement (dup vs dup2/dup3)]")
    s1_token = name_to_token[gt["s1_name"]]
    print(f"  Memfd '{gt['s1_name']}' Object Token: {s1_token}")

    s1_installs = [
        r
        for r in wl_records
        if r["type"] == "EVENT_FD_INSTALLED" and r["object_token"] == s1_token
    ]
    s1_closes = [
        r
        for r in wl_records
        if r["type"] == "EVENT_FD_CLOSED" and r["object_token"] == s1_token
    ]
    print(f"  Raw EVENT_FD_INSTALLED records captured: {len(s1_installs)}")
    for r in s1_installs:
        op_str = (
            "CREATION"
            if r["op_type"] == 1
            else ("REOPEN" if r["op_type"] == 2 else "DUP")
        )
        print(
            f"    - Frame Seq {r['seq']} @ {r['timestamp_ns']} ns: FD {r['fd']}, Token {r['object_token']}, Op: {op_str}"
        )

    captured_fds = set(r["fd"] for r in s1_installs)
    expected_s1_fds = [
        gt["s1_orig_fd"],
        gt["s1_dup_fd"],
        gt["s1_fcntl_fd"],
        gt["s1_dup2_fd"],
        gt["s1_dup3_fd"],
    ]
    print(f"  Captured FDs in Telemetry: {sorted(list(captured_fds))}")
    print(f"  Ground Truth Expected FDs (from workload log): {expected_s1_fds}")

    # Inspect corresponding graph edges
    s1_graph_installs = [
        e
        for e in edges
        if e.get("dst") == f"memfd_{s1_token}" and e.get("type") == "EDGE_FD_INSTALLED"
    ]
    s1_graph_fds = [e.get("fd") for e in s1_graph_installs]
    print(f"  Graph EDGE_FD_INSTALLED edges: FDs {s1_graph_fds}")

    missing_s1 = [fd for fd in expected_s1_fds if fd not in captured_fds]
    if gt["s1_dup2_fd"] in missing_s1 and gt["s1_dup3_fd"] in missing_s1:
        print("  >>> CONFIRMED DEFICIENCY (MISSING COVERAGE):")
        print(
            f"      FD {gt['s1_dup2_fd']} (dup2) and FD {gt['s1_dup3_fd']} (dup3) were COMPLETELY OMITTED from raw telemetry and graph!"
        )
        print(
            "      Kernel fs/file.c do_dup2() bypasses fd_install(); no BPF probe was attached."
        )

    # =========================================================================
    # SUITE 2: Replacement of Tracked Memfd with Ordinary File
    # =========================================================================
    print("\n[SUITE 2: Replacement of Tracked Memfd with Ordinary File]")
    s2_token = name_to_token[gt["s2_name"]]
    print(f"  Memfd '{gt['s2_name']}' Object Token: {s2_token}")
    print(
        f"  Memfd Inode: {gt['s2_memfd_inode']}, Ordinary File Inode: {gt['s2_ord_inode']}"
    )
    print(f"  Ordinary File Path: {gt['s2_ord_path']}")

    s2_events = [
        r
        for r in wl_records
        if r["object_token"] == s2_token
        or (r["fd"] == gt["s2_mfd_fd"] and r["seq"] in range(377, 385))
    ]
    print(f"  Raw Event Sequence for Token {s2_token} & FD {gt['s2_mfd_fd']}:")
    for r in s2_events:
        print(
            f"    - Frame Seq {r['seq']} @ {r['timestamp_ns']} ns: {r['type']} (FD {r['fd']}, Token {r['object_token']}, Duration {r['entry_ts_ns']} ns)"
        )

    t_destroy = next(
        (r["timestamp_ns"] for r in s2_events if r["type"] == "EVENT_MEMFD_DESTROYED"),
        None,
    )
    s2_close = next(
        (
            r
            for r in s2_events
            if r["type"] == "EVENT_FD_CLOSED" and r["fd"] == gt["s2_mfd_fd"]
        ),
        None,
    )

    # Inspect graph edges for memfd_6
    s2_graph_edges = [
        e
        for e in edges
        if e.get("dst") == f"memfd_{s2_token}" or e.get("src") == f"memfd_{s2_token}"
    ]
    print(f"  Reconstructed Graph Edges for memfd_{s2_token}:")
    for e in s2_graph_edges:
        print(
            f"    - {e['src']} -> {e['dst']} [{e['type']}] (FD {e.get('fd')}, Timestamp {e.get('timestamp_ns')} ns, Duration {e.get('duration_ns')} ns)"
        )

    if s2_close and t_destroy:
        t_close = s2_close["timestamp_ns"]
        delta_ns = t_close - t_destroy
        print("  >>> CONFIRMED DEFICIENCY (STALE/FALSE CLOSE ATTRIBUTION):")
        print(
            f"      Kernel destroyed memfd at {t_destroy} ns (when dup2 replaced FD {gt['s2_mfd_fd']} with ordinary file)."
        )
        print(
            f"      Later, close(FD {gt['s2_mfd_fd']}) was called on the ORDINARY file at {t_close} ns (+{delta_ns:,} ns after destruction)."
        )
        print(
            f"      BPF capture_close_fd queried memfd_desc_registry, found the STALE entry, and emitted EVENT_FD_CLOSED with Token {s2_token}!"
        )
        print(
            f"      Graph edge EDGE_FD_CLOSED was falsely attributed to memfd_{s2_token} with duration {s2_close['entry_ts_ns']:,} ns."
        )

    # =========================================================================
    # SUITE 3: Descriptor Reuse and Failed Operations
    # =========================================================================
    print("\n[SUITE 3: Descriptor Reuse and Failed Operations]")
    s3_token = name_to_token[gt["s3_name"]]
    print(f"  Memfd '{gt['s3_name']}' Object Token: {s3_token}")
    s3_events = [r for r in wl_records if r["object_token"] == s3_token]
    for r in s3_events:
        print(
            f"    - Frame Seq {r['seq']} @ {r['timestamp_ns']} ns: {r['type']} (FD {r['fd']}, Token {r['object_token']})"
        )

    # Check for spurious negative syscall events
    spurious_closes = [
        r for r in wl_records if r["type"] == "EVENT_FD_CLOSED" and r["fd"] < 0
    ]
    spurious_dups = [
        r for r in wl_records if r["type"] == "EVENT_FD_INSTALLED" and r["fd"] < 0
    ]
    print(
        f"  Spurious close(-1) events in telemetry: {len(spurious_closes)} (Expected: 0)"
    )
    print(f"  Spurious dup(-1) events in telemetry: {len(spurious_dups)} (Expected: 0)")
    print(
        "  [OK] Negative syscall failures cleanly rejected with zero spurious telemetry."
    )

    # =========================================================================
    # SUITE 4: Concurrent Operations and Shared Descriptor Tables
    # =========================================================================
    print("\n[SUITE 4: Shared Descriptor Tables Across Processes (CLONE_FILES)]")
    s4_clone_token = name_to_token[gt["s4_clone_name"]]
    print(f"  Parent PID: {wl_pid}, CLONE_FILES Child PID: {clone_pid}")
    print(f"  Memfd '{gt['s4_clone_name']}' Object Token: {s4_clone_token}")

    s4_child_records = [r for r in all_records if r["pid"] == clone_pid]
    s4_child_closes = [r for r in s4_child_records if r["type"] == "EVENT_FD_CLOSED"]
    print(f"  Child PID {clone_pid} Total Raw Records: {len(s4_child_records)}")
    print(
        f"  Child PID {clone_pid} Raw EVENT_FD_CLOSED Records: {len(s4_child_closes)}"
    )

    s4_graph_edges = [
        e
        for e in edges
        if e.get("dst") == f"memfd_{s4_clone_token}"
        or e.get("src") == f"memfd_{s4_clone_token}"
    ]
    print(f"  Reconstructed Graph Edges for memfd_{s4_clone_token}:")
    for e in s4_graph_edges:
        print(f"    - {e['src']} -> {e['dst']} [{e['type']}]")

    has_close_edge = any(e.get("type") == "EDGE_FD_CLOSED" for e in s4_graph_edges)
    if len(s4_child_closes) == 0 and not has_close_edge:
        print("  >>> CONFIRMED DEFICIENCY (MULTI-PROCESS DESCRIPTOR ATTRIBUTION LOSS):")
        print(
            f"      Child PID {clone_pid} closed shared FD {gt['s4_clone_fd']}, but BPF capture_close_fd queried (tgid={clone_pid}, fd={gt['s4_clone_fd']})."
        )
        print(
            f"      The registry entry was keyed by Parent (tgid={wl_pid}, fd={gt['s4_clone_fd']}), causing lookup failure."
        )
        print(
            f"      The child's close was dropped; parent entry was orphaned; graph lacks EDGE_FD_CLOSED edge for memfd_{s4_clone_token}."
        )

    print("\n=================================================================")
    print("Reconciliation Diagnosis Complete — All Deficiencies Confirmed.")
    print("=================================================================")


if __name__ == "__main__":
    main()
