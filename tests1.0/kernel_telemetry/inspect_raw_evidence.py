#!/usr/bin/env python3
"""
Read-only forensic evidence inspector.
Safely parses and extracts record sequence numbers, timestamps,
process IDs, object tokens, and event names from raw .evid files.
Does not modify files or change filesystem permissions.
"""

import sys
import struct
import zlib
import pathlib

def inspect_evidence(evid_path: pathlib.Path, target_pids=None, target_tokens=None):
    if not evid_path.exists():
        print(f"Error: {evid_path} does not exist", file=sys.stderr)
        sys.exit(1)

    file_size = evid_path.stat().st_size
    if file_size < 64:
        print(f"Error: {evid_path} too small ({file_size} bytes)", file=sys.stderr)
        sys.exit(1)

    with open(evid_path, "rb") as f:
        hdr_data = f.read(64)
        if len(hdr_data) < 64:
            print("Error: Incomplete header", file=sys.stderr)
            sys.exit(1)

        magic, ver, mode, pid, session_start, ev_size, hdr_size, max_b, max_rec, _, hdr_crc = struct.unpack("<IIIIQIIQQ12sI", hdr_data)
        if magic not in (0x45564944, 0x44495645) or ver != 1:
            print(f"Error: Invalid header magic 0x{magic:08x} or version {ver}", file=sys.stderr)
            sys.exit(1)

        print(f"[EVIDENCE HEADER] Magic: 0x{magic:08x}, Version: {ver}, Target PID: {pid}, File Size: {file_size} bytes")
        print(f"{'Seq':<6} | {'Timestamp (ns)':<16} | {'Type':<26} | {'PID':<7} | {'Token':<6} | {'Inode':<7} | {'Comm/Name':<24} | Details")
        print("-" * 115)

        event_names = {
            1: "EVENT_FORK",
            2: "EVENT_EXECVE",
            3: "EVENT_PROCESS_EXEC",
            4: "EVENT_PROCESS_EXIT",
            5: "EVENT_FD_INSTALLED",
            6: "EVENT_FD_CLOSED",
            7: "EVENT_MEMFD_CREATE",
            8: "EVENT_MEMFD_WRITE",
            9: "EVENT_MEMFD_COMPLETED",
            10: "EVENT_MEMFD_DESTROYED",
            11: "EVENT_MEMFD_EXEC_ATTEMPT",
            12: "EVENT_MEMFD_EXEC_SUCCESS",
            13: "EVENT_VFS_UNLINK_COMPLETED",
            14: "EVENT_VFS_RMDIR_COMPLETED",
            15: "EVENT_CONNECT"
        }

        # Struct format: 664 bytes
        ev_fmt = "=IIIIIiI4xQiHH16s256sIII4xQQQQIiiIQI256sIQ"
        seq = 0
        matched_count = 0

        while True:
            frame_data = f.read(32)
            if not frame_data:
                break
            if len(frame_data) < 32:
                print(f"[INCOMPLETE FRAME at seq {seq}]")
                break

            f_magic, f_flags, f_seq, f_ts, f_len, f_crc = struct.unpack("<IIQQII", frame_data)
            if f_magic not in (0x52454344, 0x44434552):
                print(f"[CORRUPT FRAME MAGIC 0x{f_magic:08x} at seq {seq}]")
                break

            payload = f.read(f_len)
            if len(payload) < f_len:
                print(f"[TRUNCATED PAYLOAD at seq {f_seq}]")
                break

            if (zlib.crc32(payload) & 0xFFFFFFFF) != f_crc:
                print(f"[CRC MISMATCH at seq {f_seq}]")
                break

            tup = struct.unpack(ev_fmt, payload)
            ev_type, ev_pid, ev_tid, ev_ppid, ev_flags = tup[0], tup[1], tup[2], tup[3], tup[4]
            ev_ts, ev_fd = tup[7], tup[8]
            ev_name = tup[12].split(b"\0", 1)[0].decode("utf-8", errors="replace")
            ev_child_pid = tup[13]
            ev_inode, ev_dev, ev_ret, ev_op, ev_entry_ts, ev_token = tup[18], tup[19], tup[21], tup[22], tup[24], tup[28]

            t_name = event_names.get(ev_type, f"TYPE_{ev_type}")

            match_pid = (target_pids is None) or (ev_pid in target_pids) or (ev_child_pid in target_pids)
            match_tok = (target_tokens is None) or (ev_token in target_tokens)

            if match_pid or match_tok:
                matched_count += 1
                details = f"ret={ev_ret}, fd={ev_fd}, op={ev_op}"
                if ev_type == 1: # FORK
                    details = f"child_pid={ev_child_pid}"
                elif ev_type == 8: # WRITE
                    details = f"bytes={ev_ret}, offset={ev_entry_ts}"
                elif ev_type in (11, 12): # EXEC_ATTEMPT / EXEC_SUCCESS
                    details = f"target={ev_name}, token={ev_token}"

                print(f"{f_seq:<6} | {ev_ts:<16} | {t_name:<26} | {ev_pid:<7} | {ev_token:<6} | {ev_inode:<7} | {ev_name:<24} | {details}")

            seq += 1

        print("-" * 115)
        print(f"Total records verified: {seq}, Filter matched records: {matched_count}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 inspect_raw_evidence.py <file.evid> [pid1,pid2...] [tok1,tok2...]")
        sys.exit(1)

    path = pathlib.Path(sys.argv[1])
    pids = [int(p) for p in sys.argv[2].split(",")] if len(sys.argv) > 2 and sys.argv[2] != "-" else None
    tokens = [int(t) for t in sys.argv[3].split(",")] if len(sys.argv) > 3 and sys.argv[3] != "-" else None

    inspect_evidence(path, pids, tokens)
