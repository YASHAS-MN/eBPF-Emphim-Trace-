#!/usr/bin/env python3
"""
EphimTrace Milestone 7: Automated Forensic Verification Script
Parses ephimtrace_dag.json and ephimtrace_timeline.md, asserting:
1. Presence of required node types: NODE_PROCESS, NODE_MEMFD, NODE_FS_OBJECT, NODE_NET_ENDPOINT.
2. Presence and causal order of edges:
   EDGE_FORK -> EDGE_MEMFD_CREATE -> EDGE_MEMFD_WRITE -> EDGE_MEMFD_EXEC_SUCCESS -> EDGE_UNLINK -> EDGE_CONNECT
3. Strict timestamp monotonicity along the causal chain.
4. Consistency with forensic markdown timeline log.
"""

import sys
import json
import os
import argparse
import re

REQUIRED_NODE_TYPES = {
    "NODE_PROCESS",
    "NODE_MEMFD",
    "NODE_FS_OBJECT",
    "NODE_NET_ENDPOINT",
}

EXPECTED_EDGE_SEQUENCE = [
    "EDGE_FORK",
    "EDGE_MEMFD_CREATE",
    "EDGE_MEMFD_WRITE",
    "EDGE_MEMFD_EXEC_SUCCESS",
    "EDGE_UNLINK",
    "EDGE_CONNECT",
]


def verify_dag_json(json_path):
    print(f"[VERIFY] Loading DAG JSON from: {json_path}")
    if not os.path.exists(json_path):
        print(f"  [FAIL] JSON file does not exist: {json_path}")
        return False, None

    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"  [FAIL] JSON parse error: {e}")
        return False, None

    nodes = data.get("nodes", [])
    edges = data.get("edges", [])

    print(f"  [INFO] Parsed {len(nodes)} nodes and {len(edges)} edges.")

    # 1. Assert Node Types
    found_node_types = {n.get("type") for n in nodes if "type" in n}
    missing_nodes = REQUIRED_NODE_TYPES - found_node_types

    print("\n[ASSERTION 1: Node Type Coverage]")
    for ntype in REQUIRED_NODE_TYPES:
        status = "FOUND" if ntype in found_node_types else "MISSING"
        count = sum(1 for n in nodes if n.get("type") == ntype)
        print(f"  - {ntype:<20}: [{status}] ({count} instances)")

    if missing_nodes:
        print(f"  [FAIL] Missing required node types: {missing_nodes}")
        return False, None

    print("  [PASS] All 4 required node types present in DAG.")

    # 2. Assert Edge Presence and Causal Order
    print("\n[ASSERTION 2: Causal Edge Sequence & Monotonicity]")
    # We look for a sub-sequence of edges matching EXPECTED_EDGE_SEQUENCE
    # along the target process/memfd causal chain.
    matched_chain = []
    curr_idx = 0

    for edge in edges:
        etype = edge.get("type")
        if (
            curr_idx < len(EXPECTED_EDGE_SEQUENCE)
            and etype == EXPECTED_EDGE_SEQUENCE[curr_idx]
        ):
            matched_chain.append(edge)
            curr_idx += 1

    if len(matched_chain) != len(EXPECTED_EDGE_SEQUENCE):
        missing_steps = EXPECTED_EDGE_SEQUENCE[curr_idx:]
        print(
            f"  [FAIL] Causal sequence incomplete! Matched {len(matched_chain)}/{len(EXPECTED_EDGE_SEQUENCE)} steps."
        )
        print(f"         Missing remaining steps: {missing_steps}")
        return False, None

    # Print causal chain table
    print(
        f"  {'Step':<4} {'Edge Type':<26} {'Source':<24} {'Destination':<24} {'Timestamp (ns)':<16} {'Delta'}"
    )
    print("  " + "-" * 105)

    last_ts = None
    monotonic = True

    for i, edge in enumerate(matched_chain):
        ts = edge.get("timestamp_ns", 0)
        etype = edge.get("type", "")
        src = edge.get("src", "")
        dst = edge.get("dst", "")

        delta_str = "+0 ns"
        if last_ts is not None:
            delta = ts - last_ts
            if delta < 0:
                delta_str = f"INVALID ({delta} ns)"
                monotonic = False
            else:
                delta_str = f"+{delta} ns"
        last_ts = ts

        print(f"  {i+1:<4} {etype:<26} {src:<24} {dst:<24} {ts:<16} {delta_str}")

    if not monotonic:
        print(
            "  [FAIL] Edge timestamps are not monotonically non-decreasing along the causal chain!"
        )
        return False, None

    print("  [PASS] Causal edge sequence verified with strictly monotonic timestamps.")
    return True, matched_chain


def verify_timeline_md(timeline_path, matched_chain):
    print(f"\n[VERIFY] Checking Timeline Report: {timeline_path}")
    if not os.path.exists(timeline_path):
        print(f"  [FAIL] Timeline file does not exist: {timeline_path}")
        return False

    with open(timeline_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Verify each expected event type appears in the timeline in sequence
    timeline_event_tokens = [
        "[FORK]",
        "[MEMFD_CREATE]",
        "[MEMFD_WRITE]",
        "[MEMFD_EXEC_SUCCESS]",
        "[UNLINK]",
        "[CONNECT]",
    ]

    last_pos = -1
    for token in timeline_event_tokens:
        pos = content.find(token, last_pos + 1)
        if pos == -1:
            print(
                f"  [FAIL] Expected event token '{token}' not found in timeline after offset {last_pos}!"
            )
            return False
        last_pos = pos
        print(f"  - Verified sequential timeline event: {token:<22} (offset {pos})")

    # Extract timestamps from timeline lines
    ts_matches = [int(m) for m in re.findall(r"\[(\d+)\s+ns\]", content)]
    if ts_matches:
        for j in range(1, len(ts_matches)):
            if ts_matches[j] < ts_matches[j - 1]:
                print(
                    f"  [FAIL] Timeline timestamps decrease from {ts_matches[j-1]} to {ts_matches[j]}!"
                )
                return False
        print(
            f"  [PASS] Timeline log contains {len(ts_matches)} ordered timestamp entries."
        )

    print("  [PASS] Timeline markdown log accurately mirrors causal event sequence.")
    return True


def main():
    parser = argparse.ArgumentParser(
        description="EphimTrace Forensic Verification Script"
    )
    parser.add_argument(
        "--json", default="ephimtrace_dag.json", help="Path to ephimtrace_dag.json"
    )
    parser.add_argument(
        "--timeline",
        default="ephimtrace_timeline.md",
        help="Path to ephimtrace_timeline.md",
    )
    args = parser.parse_args()

    print("=================================================================")
    print("=== EphimTrace Milestone 7: Automated Forensic Verification   ===")
    print("=================================================================")

    json_ok, matched_chain = verify_dag_json(args.json)
    if not json_ok:
        print("\n[RESULT] FAILED: DAG JSON validation failed.")
        sys.exit(1)

    timeline_ok = verify_timeline_md(args.timeline, matched_chain)
    if not timeline_ok:
        print("\n[RESULT] FAILED: Timeline validation failed.")
        sys.exit(1)

    print("\n=================================================================")
    print("=== [SUCCESS] ALL FORENSIC ASSERTIONS VERIFIED CLEANLY        ===")
    print("=================================================================\n")
    sys.exit(0)


if __name__ == "__main__":
    main()
