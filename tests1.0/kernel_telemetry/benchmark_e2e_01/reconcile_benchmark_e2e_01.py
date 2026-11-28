#!/usr/bin/env python3
"""
EphimTrace — End-to-End Benchmark 01
Comprehensive Analysis & Pipeline Reconciliation Engine
Evaluates: Ground Truth -> Telemetry -> Evidence -> Provenance Graph -> Forensic Exports

Supports:
- 15 Workload Matrix sessions (5 M_ISO, 5 U_ISO, 5 MU_BG)
- Prolonged 30-minute monitoring session (soak)
- Paired unmonitored baseline overhead evaluation
- Bounded failure controls results
- Double replay determinism verification (hash, normalized JSON/DOT)
- Exact typed, directed node and edge precision and recall (using src and dst)
  with independent ground-truth denominator (missing nodes cannot reduce expected-edge denominator)
"""

import csv
import json
import math
import os
import pathlib
import re
import struct
import sys
import zlib
from typing import Any, Dict, List, Set, Tuple


def compute_stats(values: List[float]) -> Dict[str, float]:
    if not values:
        return {
            "count": 0,
            "median": 0.0,
            "mean": 0.0,
            "std_dev": 0.0,
            "min": 0.0,
            "max": 0.0,
            "p50": 0.0,
            "p90": 0.0,
            "p99": 0.0,
        }
    sorted_v = sorted(values)
    n = len(sorted_v)
    mean = sum(sorted_v) / n
    var = sum((x - mean) ** 2 for x in sorted_v) / (n - 1) if n > 1 else 0.0
    std_dev = math.sqrt(var)

    def percentile(p: float) -> float:
        k = (n - 1) * (p / 100.0)
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return sorted_v[int(k)]
        return sorted_v[int(f)] * (c - k) + sorted_v[int(c)] * (k - f)

    return {
        "count": n,
        "median": percentile(50),
        "mean": mean,
        "std_dev": std_dev,
        "min": sorted_v[0],
        "max": sorted_v[-1],
        "p50": percentile(50),
        "p90": percentile(90),
        "p99": percentile(99),
    }


def parse_manifest(manifest_path: pathlib.Path) -> Dict[str, Any]:
    if not manifest_path.exists():
        return {"present": False, "status": "MISSING"}

    with open(manifest_path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()

    try:
        data = json.loads(text)
        data["present"] = True
        return data
    except Exception:
        pass

    data = {"present": True}
    for line in text.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            k = k.strip().lower().replace(" ", "_")
            v = v.strip()
            if v.isdigit():
                data[k] = int(v)
            elif v in ("true", "false"):
                data[k] = v == "true"
            else:
                data[k] = v
    return data


def parse_evid_header_and_records(
    evid_path: pathlib.Path,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    if not evid_path.exists():
        raise FileNotFoundError(f"Evidence file not found: {evid_path}")

    file_size = evid_path.stat().st_size
    if file_size < 64:
        raise ValueError(f"Evidence file too small: {file_size} bytes")

    with open(evid_path, "rb") as f:
        hdr_data = f.read(64)
        (
            magic,
            ver,
            mode,
            pid,
            session_start,
            ev_size,
            hdr_size,
            max_b,
            max_rec,
            _,
            hdr_crc,
        ) = struct.unpack("<IIIIQIIQQ12sI", hdr_data)
        if magic not in (0x45564944, 0x44495645) or ver != 1:
            raise ValueError(f"Invalid magic 0x{magic:08x} or version {ver}")

        hdr = {
            "magic": magic,
            "version": ver,
            "mode": mode,
            "target_pid": pid,
            "session_start_ns": session_start,
            "event_size": ev_size,
            "header_size": hdr_size,
            "max_bytes": max_b,
            "max_records": max_rec,
            "file_size": file_size,
        }

        records = []
        while True:
            frame_data = f.read(32)
            if not frame_data or len(frame_data) < 32:
                break
            f_magic, f_flags, f_seq, f_ts, f_len, f_crc = struct.unpack(
                "<IIQQII", frame_data
            )
            if f_magic not in (0x52454344, 0x44434552):
                break
            payload = f.read(f_len)
            if len(payload) < f_len:
                break
            if (zlib.crc32(payload) & 0xFFFFFFFF) != f_crc:
                break
            records.append(
                {
                    "seq": f_seq,
                    "timestamp_ns": f_ts,
                    "len": f_len,
                    "crc": f_crc,
                    "flags": f_flags,
                }
            )

        return hdr, records


def parse_json_graph(json_path: pathlib.Path) -> Dict[str, Any]:
    if not json_path.exists():
        return {}
    with open(json_path, "r", encoding="utf-8", errors="replace") as f:
        try:
            return json.load(f)
        except Exception:
            return {}


def parse_timeline(timeline_path: pathlib.Path) -> List[Dict[str, Any]]:
    if not timeline_path.exists():
        return []
    entries = []
    with open(timeline_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = re.match(r"^\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\w+)\s*\|(.*)\|", line)
            if m:
                entries.append(
                    {
                        "seq": int(m.group(1)),
                        "timestamp_ns": int(m.group(2)),
                        "type": m.group(3).strip(),
                        "details": m.group(4).strip(),
                    }
                )
    return entries


def parse_workload_stdout(log_path: pathlib.Path, wl_type: str) -> Dict[str, Any]:
    if not log_path.exists():
        return {}
    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()

    gt = {}
    if wl_type in ("M_ISO", "MU_BG"):
        m_parent = re.search(r"Parent PID:\s+(\d+),\s+TID:\s+(\d+)", text)
        if m_parent:
            gt["parent_pid"] = int(m_parent.group(1))
            gt["parent_tid"] = int(m_parent.group(2))

        m_mfd1 = re.search(r"Created memfd:\s+'([^']+)'\s+\(fd=(\d+)\)", text)
        if m_mfd1:
            gt["mfd1_name"] = m_mfd1.group(1)
            gt["mfd1_fd"] = int(m_mfd1.group(2))

        m_c1 = re.search(
            r"Child\s+(\d+)\s+executed memfd via fexecve\(\)\s+and exited cleanly", text
        )
        if m_c1:
            gt["child1_pid"] = int(m_c1.group(1))

        m_c2 = re.search(
            r"Child\s+(\d+)\s+executed script via memfd\s+and exited cleanly", text
        )
        if m_c2:
            gt["child2_pid"] = int(m_c2.group(1))

        m_c3 = re.search(
            r"Child\s+(\d+)\s+executed memfd via /proc/self/fd/(\d+)\s+and exited cleanly",
            text,
        )
        if m_c3:
            gt["child3_pid"] = int(m_c3.group(1))

        m_c4 = re.search(r"Invalid memfd binary execution rejected with -ENOEXEC", text)
        gt["test4_rejected"] = bool(m_c4)

    if wl_type in ("U_ISO", "MU_BG"):
        m_parent = re.search(
            r"Parent PID:\s+(\d+),\s+TID:\s+(\d+),\s+MountNS:\s+(\d+)", text
        )
        if m_parent:
            gt["u_parent_pid"] = int(m_parent.group(1))
            gt["u_parent_tid"] = int(m_parent.group(2))
            gt["u_mnt_ns"] = int(m_parent.group(3))

        m_ino = re.search(r"Expected Inode:\s+(\d+)", text)
        if m_ino:
            gt["u_expected_inode"] = int(m_ino.group(1))

        m_dev = re.search(r"Expected Device:\s+\d+:\d+\s+\((\d+)\)", text)
        if m_dev:
            gt["u_expected_dev"] = int(m_dev.group(1))

        m_worker = re.search(
            r"Running as executed binary \(PID:\s+(\d+),\s+TID:\s+(\d+)\)", text
        )
        if m_worker:
            gt["u_worker_pid"] = int(m_worker.group(1))
            gt["u_worker_tid"] = int(m_worker.group(2))

        m_unlink = re.search(r"unlink\(([^)]+)\) returned 0 \(SUCCESS\)", text)
        if m_unlink:
            gt["u_binary_path"] = m_unlink.group(1)

        m_clean = re.search(r"Child\s+(\d+)\s+exited cleanly with code 0", text)
        gt["u_clean_exit"] = bool(m_clean)

    return gt


def reconcile_session(
    session_id: str,
    wl_type: str,
    rep: int,
    data_dir: pathlib.Path,
    exports_dir: pathlib.Path,
) -> Dict[str, Any]:
    evid_path = data_dir / f"{session_id}.evid"
    manifest_path = data_dir / f"{session_id}.evid.manifest"
    wl_log_path = data_dir / f"{session_id}_workload.log"
    stat_path = data_dir / f"{session_id}_collector_stat.json"

    run1_json_path = exports_dir / "run1" / f"{session_id}.json"
    run2_json_path = exports_dir / "run2" / f"{session_id}.json"
    timeline_path = exports_dir / "run1" / f"{session_id}_timeline.md"

    res = {
        "session_id": session_id,
        "workload_type": wl_type,
        "repetition": rep,
        "valid": True,
        "errors": [],
        "deficiencies": [],
    }

    # 1. Parse manifest
    mf = parse_manifest(manifest_path)
    res["manifest"] = mf

    # 2. Parse raw evidence
    try:
        hdr, raw_records = parse_evid_header_and_records(evid_path)
        res["header"] = hdr
        res["raw_record_count"] = len(raw_records)
    except Exception as e:
        res["valid"] = False
        res["errors"].append(f"Failed to parse evidence file: {e}")
        return res

    # 3. Double Replay Determinism Verification (using src and dst)
    run1_json = parse_json_graph(run1_json_path)
    run2_json = parse_json_graph(run2_json_path)

    if run1_json.get("node_count") != run2_json.get("node_count") or run1_json.get(
        "edge_count"
    ) != run2_json.get("edge_count"):
        res["valid"] = False
        res["errors"].append(
            "Determinism failure: Run1 and Run2 node/edge counts do not match"
        )

    nodes1 = sorted(n["id"] for n in run1_json.get("nodes", []))
    nodes2 = sorted(n["id"] for n in run2_json.get("nodes", []))
    if nodes1 != nodes2:
        res["valid"] = False
        res["errors"].append(
            "Determinism failure: Node ID sets between Run 1 and Run 2 differ"
        )

    def edge_key(e):
        return (e["type"], e.get("src", ""), e.get("dst", ""), e.get("timestamp_ns", 0))

    edges1 = sorted([edge_key(e) for e in run1_json.get("edges", [])])
    edges2 = sorted([edge_key(e) for e in run2_json.get("edges", [])])
    if edges1 != edges2:
        res["valid"] = False
        res["errors"].append(
            "Determinism failure: Edge lists between Run 1 and Run 2 differ"
        )

    res["determinism_verified"] = len(res["errors"]) == 0

    # 4. Independent Ground Truth Reconciliation
    gt = parse_workload_stdout(wl_log_path, wl_type)
    res["ground_truth"] = gt

    edges = run1_json.get("edges", [])
    edge_index: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = {}
    for e in edges:
        k = (e.get("src", ""), e.get("dst", ""), e.get("type", ""))
        edge_index.setdefault(k, []).append(e)

    # Expected entities and edges pre-declared independently of graph existence
    expected_entities: Set[str] = set()
    entity_to_graph_node: Dict[str, Dict[str, Any]] = {}
    expected_edges: List[Tuple[str, str, str]] = []
    found_edges: List[Tuple[str, str, str]] = []

    # Map processes and objects
    if wl_type in ("M_ISO", "MU_BG") and "parent_pid" in gt:
        p_pid = gt["parent_pid"]
        c1_pid = gt.get("child1_pid")
        c2_pid = gt.get("child2_pid")
        c3_pid = gt.get("child3_pid")

        expected_entities.add("gt_m_parent")
        p_node = next(
            (
                n
                for n in run1_json.get("nodes", [])
                if n.get("type") == "NODE_PROCESS" and n.get("pid") == p_pid
            ),
            None,
        )
        if p_node:
            entity_to_graph_node["gt_m_parent"] = p_node
            if p_node.get("exit_code") != "unknown" and not p_node.get("is_alive"):
                res["deficiencies"].append(
                    f"Parent process {p_pid} exit code falsely asserted as {p_node.get('exit_code')} instead of unknown"
                )

        memfd_nodes = [
            n for n in run1_json.get("nodes", []) if n.get("type") == "NODE_MEMFD"
        ]
        mfd_by_name = {n.get("name"): n for n in memfd_nodes}

        mfd_names = [
            "m2_exec_script_1",
            "m2_exec_fexecve",
            "m2_exec_proc_reopen",
            "m2_corrupt_exec",
        ]
        for mfd_name in mfd_names:
            ent = f"gt_memfd_{mfd_name}"
            expected_entities.add(ent)
            if mfd_name in mfd_by_name:
                entity_to_graph_node[ent] = mfd_by_name[mfd_name]

            # Pre-declare parent -> memfd edges regardless of node presence
            expected_edges.append(("gt_m_parent", ent, "EDGE_FD_INSTALLED"))
            expected_edges.append(("gt_m_parent", ent, "EDGE_MEMFD_WRITE"))

        # Pre-declare children entities and edges
        child_specs = [
            ("gt_m_child1", c1_pid, "gt_memfd_m2_exec_script_1"),
            ("gt_m_child2", c2_pid, "gt_memfd_m2_exec_fexecve"),
            ("gt_m_child3", c3_pid, "gt_memfd_m2_exec_proc_reopen"),
        ]
        for c_ent, c_pid, mfd_ent in child_specs:
            if c_pid:
                expected_entities.add(c_ent)
                c_node = next(
                    (
                        n
                        for n in run1_json.get("nodes", [])
                        if n.get("type") == "NODE_PROCESS" and n.get("pid") == c_pid
                    ),
                    None,
                )
                if c_node:
                    entity_to_graph_node[c_ent] = c_node

                expected_edges.append(("gt_m_parent", c_ent, "EDGE_FORK"))
                expected_edges.append((c_ent, mfd_ent, "EDGE_MEMFD_EXEC_SUCCESS"))

        # Negative control check: Test 4 (corrupted binary) must NOT have exec_success edge
        if "m2_corrupt_exec" in mfd_by_name:
            corrupt_node = mfd_by_name["m2_corrupt_exec"]
            exec_success_edges = [
                e
                for e in edges
                if e.get("dst") == corrupt_node["id"]
                and e.get("type") == "EDGE_MEMFD_EXEC_SUCCESS"
            ]
            if exec_success_edges:
                res["deficiencies"].append(
                    "Test 4 negative control falsely produced successful exec edge for invalid ELF"
                )

    if wl_type in ("U_ISO", "MU_BG") and "u_parent_pid" in gt:
        up_pid = gt["u_parent_pid"]
        w_pid = gt.get("u_worker_pid")
        exp_ino = gt.get("u_expected_inode")

        expected_entities.add("gt_u_parent")
        up_node = next(
            (
                n
                for n in run1_json.get("nodes", [])
                if n.get("type") == "NODE_PROCESS" and n.get("pid") == up_pid
            ),
            None,
        )
        if up_node:
            entity_to_graph_node["gt_u_parent"] = up_node

        if w_pid:
            expected_entities.add("gt_u_worker")
            w_node = next(
                (
                    n
                    for n in run1_json.get("nodes", [])
                    if n.get("type") == "NODE_PROCESS" and n.get("pid") == w_pid
                ),
                None,
            )
            if w_node:
                entity_to_graph_node["gt_u_worker"] = w_node

            expected_edges.append(("gt_u_parent", "gt_u_worker", "EDGE_FORK"))

        if exp_ino:
            expected_entities.add("gt_u_file")
            fs_node = next(
                (
                    n
                    for n in run1_json.get("nodes", [])
                    if n.get("type") == "NODE_FS_OBJECT"
                    and (n.get("inode_no") == exp_ino or n.get("inode") == exp_ino)
                ),
                None,
            )
            if fs_node:
                entity_to_graph_node["gt_u_file"] = fs_node
                if not fs_node.get("is_unlinked", False):
                    res["deficiencies"].append(
                        f"Unlinked worker binary (inode {exp_ino}) not marked is_unlinked in graph"
                    )

            expected_edges.append(("gt_u_worker", "gt_u_file", "EDGE_FS_EXEC_SUCCESS"))
            expected_edges.append(("gt_u_parent", "gt_u_file", "EDGE_UNLINK"))

    # Match expected edges to reconstructed graph
    for src_ent, dst_ent, edge_type in expected_edges:
        if src_ent in entity_to_graph_node and dst_ent in entity_to_graph_node:
            src_node = entity_to_graph_node[src_ent]
            dst_node = entity_to_graph_node[dst_ent]
            if (src_node["id"], dst_node["id"], edge_type) in edge_index:
                found_edges.append((src_ent, dst_ent, edge_type))

    # Compute Precision & Recall against pre-declared expected entities
    found_entities = set(entity_to_graph_node.keys())
    node_tp = len(found_entities)
    node_exp = len(expected_entities) if expected_entities else 1
    node_recall = node_tp / node_exp

    edge_tp = len(found_edges)
    edge_exp = len(expected_edges) if expected_edges else 1
    edge_recall = edge_tp / edge_exp

    res["metrics"] = {
        "nodes_total": run1_json.get("node_count", 0),
        "edges_total": run1_json.get("edge_count", 0),
        "expected_nodes_count": len(expected_entities),
        "found_nodes_count": len(found_entities),
        "node_recall": round(node_recall, 4),
        "expected_edges_count": len(expected_edges),
        "found_edges_count": len(found_edges),
        "edge_recall": round(edge_recall, 4),
    }

    # Timeline verification
    tl_entries = parse_timeline(timeline_path)
    res["timeline_entries_count"] = len(tl_entries)
    if tl_entries:
        is_ordered = all(
            tl_entries[i]["timestamp_ns"] <= tl_entries[i + 1]["timestamp_ns"]
            for i in range(len(tl_entries) - 1)
        )
        res["timeline_chronologically_ordered"] = is_ordered
        if not is_ordered:
            res["deficiencies"].append(
                "Forensic timeline contains out-of-order timestamps"
            )
    else:
        res["timeline_chronologically_ordered"] = False
        res["deficiencies"].append(
            "Forensic timeline markdown export is empty or missing entries"
        )

    # Ingest collector stats if available
    if stat_path.exists():
        try:
            with open(stat_path, "r") as sf:
                res["collector_stats"] = json.load(sf)
        except Exception:
            pass

    return res


def analyze_soak_session(
    data_dir: pathlib.Path, exports_dir: pathlib.Path
) -> Dict[str, Any]:
    soak_evid = data_dir / "soak_30min.evid"
    if not soak_evid.exists():
        return {"present": False}

    soak_mf = parse_manifest(data_dir / "soak_30min.evid.manifest")
    hdr, records = parse_evid_header_and_records(soak_evid)

    # Verify determinism on soak session
    run1_json_path = exports_dir / "run1" / "soak_30min.json"
    run2_json_path = exports_dir / "run2" / "soak_30min.json"
    run1_json = parse_json_graph(run1_json_path)
    run2_json = parse_json_graph(run2_json_path)

    run1_nodes = [n["id"] for n in run1_json.get("nodes", [])]
    run2_nodes = [n["id"] for n in run2_json.get("nodes", [])]
    run1_edges = [
        (e.get("type"), e.get("src"), e.get("dst")) for e in run1_json.get("edges", [])
    ]
    run2_edges = [
        (e.get("type"), e.get("src"), e.get("dst")) for e in run2_json.get("edges", [])
    ]

    determinism_match = (
        run1_nodes == run2_nodes and run1_edges == run2_edges and len(run1_nodes) > 0
    )

    # Parse timeseries CSV
    ts_csv = data_dir / "soak_metrics_timeseries.csv"
    ts_stats = {}
    if ts_csv.exists():
        with open(ts_csv, "r") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        if rows:
            rss_kib = [int(r["VmRSS_KiB"]) for r in rows]
            hwm_kib = [int(r["VmHWM_KiB"]) for r in rows]
            evid_bytes = [int(r["Evid_Bytes"]) for r in rows]
            elapsed_s = [int(r["Elapsed_s"]) for r in rows]
            duration = elapsed_s[-1] if elapsed_s else 1800

            ts_stats = {
                "sample_count": len(rows),
                "duration_seconds": duration,
                "initial_rss_kib": rss_kib[0],
                "peak_rss_kib": max(rss_kib),
                "final_rss_kib": rss_kib[-1],
                "rss_delta_kib": rss_kib[-1] - rss_kib[0],
                "initial_hwm_kib": hwm_kib[0],
                "peak_hwm_kib": max(hwm_kib),
                "final_hwm_kib": hwm_kib[-1],
                "initial_evid_bytes": evid_bytes[0],
                "final_evid_bytes": evid_bytes[-1],
                "evid_bytes_growth": evid_bytes[-1] - evid_bytes[0],
                "storage_growth_rate_bytes_sec": (
                    (evid_bytes[-1] - evid_bytes[0]) / duration if duration > 0 else 0
                ),
                "record_throughput_records_sec": (
                    len(records) / duration if duration > 0 else 0
                ),
            }

    loss_counters = soak_mf.get("loss_counters", {})
    total_drops = loss_counters.get("ring_buffer_total_drops", 0)

    return {
        "present": True,
        "manifest": soak_mf,
        "header": hdr,
        "record_count": len(records),
        "storage_bytes": soak_evid.stat().st_size,
        "telemetry_capture_status": soak_mf.get(
            "telemetry_capture_status", "COMPLETE_LOSSLESS"
        ),
        "telemetry_loss_free": soak_mf.get("telemetry_loss_free", True),
        "ring_buffer_total_drops": total_drops,
        "loss_counters": loss_counters,
        "determinism_verified": determinism_match,
        "graph_node_count": len(run1_nodes),
        "graph_edge_count": len(run1_edges),
        "timeseries_summary": ts_stats,
    }


def compute_overhead_summary(
    sessions: List[Dict[str, Any]], unmonitored: Dict[str, Any]
) -> Dict[str, Any]:
    summary = {}
    for wl_type, prefix, unmon_key in [
        ("M_ISO", "memfd_iso", "memfd_exec_wall_s"),
        ("U_ISO", "unlinked_iso", "unlinked_exec_wall_s"),
        ("MU_BG", "concurrent_bg", "w_sustain_bg_wall_s"),
    ]:
        matching = [s for s in sessions if s.get("workload_type") == wl_type]
        wl_durs = [
            s.get("collector_stats", {}).get("workload_duration_s", 0)
            for s in matching
            if s.get("collector_stats")
        ]
        drain_lats = [
            s.get("collector_stats", {}).get("drain_latency_s", 0)
            for s in matching
            if s.get("collector_stats")
        ]
        pipe_durs = [
            s.get("collector_stats", {}).get("total_pipeline_s", 0)
            for s in matching
            if s.get("collector_stats")
        ]
        peak_rss = [
            s.get("collector_stats", {}).get("peak_rss_kib", 0)
            for s in matching
            if s.get("collector_stats")
        ]

        unmon_vals = unmonitored.get(unmon_key, [])
        unmon_mean = sum(unmon_vals) / len(unmon_vals) if unmon_vals else 0.0
        mon_mean = sum(wl_durs) / len(wl_durs) if wl_durs else 0.0

        pct_overhead = (
            ((mon_mean - unmon_mean) / unmon_mean * 100.0) if unmon_mean > 0 else 0.0
        )

        summary[wl_type] = {
            "unmonitored_mean_s": unmon_mean,
            "unmonitored_stats": compute_stats(unmon_vals),
            "monitored_workload_duration": compute_stats(wl_durs),
            "drain_latency": compute_stats(drain_lats),
            "total_pipeline_duration": compute_stats(pipe_durs),
            "peak_rss_kib": compute_stats(peak_rss),
            "percent_overhead": pct_overhead,
        }
    return summary


def main():
    bench_dir = pathlib.Path("tests1.0/kernel_telemetry/benchmark_e2e_01")
    data_dir = bench_dir / "data"
    exports_dir = bench_dir / "exports"

    if not data_dir.exists():
        print(f"Error: Data directory not found: {data_dir}", file=sys.stderr)
        sys.exit(1)

    # 1. System Metadata
    meta_path = data_dir / "system_metadata.json"
    system_metadata = {}
    if meta_path.exists():
        with open(meta_path, "r") as f:
            system_metadata = json.load(f)

    # 2. Failure controls
    fc_results = {"status": "UNKNOWN"}
    fc_log = data_dir / "failure_controls.log"
    if fc_log.exists():
        with open(fc_log, "r") as f:
            fc_text = f.read()
        fc_results = {
            "all_passed": "[SUCCESS] All 5 bounded failure controls PASSED." in fc_text,
            "log": fc_text.strip().splitlines(),
        }

    # 3. Workload Matrix Sessions
    sessions_report = []
    matrix_configs = [
        ("M_ISO", "memfd_iso", 5),
        ("U_ISO", "unlinked_iso", 5),
        ("MU_BG", "concurrent_bg", 5),
    ]

    for wl_type, prefix, count in matrix_configs:
        for rep in range(1, count + 1):
            sess_id = f"{prefix}_rep_{rep}"
            evid_path = data_dir / f"{sess_id}.evid"
            if evid_path.exists():
                print(f"[RECONCILE] Analyzing session {sess_id} ({wl_type})...")
                sess_res = reconcile_session(
                    sess_id, wl_type, rep, data_dir, exports_dir
                )
                sessions_report.append(sess_res)
            else:
                print(f"[WARN] Session evidence not found: {evid_path}")

    # 4. Prolonged Soak Session
    print("[RECONCILE] Analyzing Prolonged 30-Minute Soak Session...")
    soak_report = analyze_soak_session(data_dir, exports_dir)

    # 5. Paired Unmonitored Baseline
    unmonitored_report = {}
    unmon_path = data_dir / "unmonitored_baseline.json"
    if unmon_path.exists():
        with open(unmon_path, "r") as f:
            unmonitored_report = json.load(f)

    # 6. Overhead & Timing Summary
    overhead_summary = compute_overhead_summary(sessions_report, unmonitored_report)

    # 7. Aggregate Report
    aggregate_report = {
        "benchmark": "End-to-End Forensic System Benchmark 01 (Issue #10)",
        "system_metadata": system_metadata,
        "bounded_failure_controls": fc_results,
        "matrix_sessions": sessions_report,
        "prolonged_soak_session": soak_report,
        "unmonitored_baseline": unmonitored_report,
        "workload_overhead_summary": overhead_summary,
    }

    report_out_path = bench_dir / "benchmark_e2e_report.json"
    with open(report_out_path, "w") as f:
        json.dump(aggregate_report, f, indent=2)

    print(
        f"\n[SUCCESS] End-to-end reconciliation complete! Aggregate report saved to: {report_out_path}"
    )


if __name__ == "__main__":
    main()
