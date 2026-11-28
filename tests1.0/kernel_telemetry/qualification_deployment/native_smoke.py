#!/usr/bin/env python3
"""Run only on a trusted local test host via sudo; never overwrite a capture."""
import hashlib
import json
import os
import pathlib
import pwd
import re
import signal
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tests1.0/kernel_telemetry/qualification_descriptor"))
from reconcile_descriptor_qualification import parse_evid_records, parse_workload_log

def require(condition, label):
    if not condition:
        raise RuntimeError(label)
    print("[PASS]", label, flush=True)

def digest(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()

def text(path):
    return path.read_text(errors="replace")

if os.geteuid() != 0 or not os.environ.get("SUDO_UID") or int(os.environ["SUDO_UID"]) == 0:
    sys.exit("Run with sudo from the normal local test account.")
uid = int(os.environ["SUDO_UID"])
gid = int(os.environ["SUDO_GID"])
user = pwd.getpwuid(uid).pw_name
bins = [ROOT / "build" / x for x in ("loader", "replay", "monitor.bpf.o", "test_qualification_descriptor")]
for b in bins:
    require(b.is_file(), f"built artifact: {b.name}")
    print("SHA256", digest(b), b.name)
print("Commit:", subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip())
print("Kernel:", os.uname().release, os.uname().machine)
print("BTF:", pathlib.Path("/sys/kernel/btf/vmlinux").exists())
print("Online CPUs:", text(pathlib.Path("/sys/devices/system/cpu/online")).strip())
for cmd in (["cc", "--version"], ["clang-16", "--version"], ["pkg-config", "--modversion", "libbpf"]):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        print(cmd[0] + ":", result.stdout.splitlines()[0] if result.stdout else "not reported")
    except FileNotFoundError:
        print(cmd[0] + ": not found")
out = pathlib.Path(tempfile.mkdtemp(prefix="ephim_native_"))
print("Private artifacts:", out, flush=True)
evid = out / "descriptor_qual.evid"
manifest = out / "descriptor_qual.evid.manifest"
loader_log = out / "loader.log"
wl_log = out / "workload.log"
env = dict(os.environ)
for key in ("EPHIM_RING_BUFFER_MB", "EPHIM_LOW_MEMORY", "EPHIM_QUIET"):
    env.pop(key, None)
proc = None
try:
    with loader_log.open("wb") as log:
        proc = subprocess.Popen([str(bins[0]), "--ring-buffer-mb", "64",
                                 "-b", "2147483648", "-o", str(evid), "-v"],
                                cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 30
        while "STATUS: READY" not in text(loader_log):
            if proc.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError("Collector did not reach READY; see loader.log")
            time.sleep(0.1)
        require(proc.poll() is None, "collector READY and running")
        with wl_log.open("wb") as wl:
            subprocess.run(["runuser", "-u", user, "--", str(bins[3])],
                           cwd=ROOT, stdout=wl, stderr=subprocess.STDOUT,
                           check=True, timeout=30)
        require("28/28 Assertions Passed (0 Failed)" in text(wl_log), "native workload 28/28 assertions")
        time.sleep(1)
        require(proc.poll() is None, "collector remained running through workload")
        proc.send_signal(signal.SIGINT)
        require(proc.wait(timeout=30) == 0, "orderly collector shutdown")
finally:
    if proc is not None and proc.poll() is None:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    # Fresh private directory; only hand off the artifacts created by this run.
    for path in (evid, manifest, loader_log, wl_log):
        if path.is_file():
            os.chown(path, uid, gid)
            os.chmod(path, 0o600)
    os.chown(out, uid, gid)

# Replay without root. Preserve original session files and use fresh outputs.
for line in text(loader_log).splitlines():
    if line.startswith(("LOGICAL HOOKS ATTACHED:", "PER-CPU EVENTS ATTACHED:",
                        "Ring Buffer Total Drops:", "Kernel Registry Drops:",
                        "Kernel Token Errors:", "Kernel Token Mismatches:")):
        print(line)
require("LOGICAL HOOKS ATTACHED: 27/27" in text(loader_log), "all 27 logical hooks attached")
m = json.loads(text(manifest))
require(m["finalized"] and m["synchronized"], "finalized synchronized manifest")
before = {p: digest(p) for p in (evid, manifest)}
for run in (1, 2):
    subprocess.run(["runuser", "-u", user, "--", str(bins[1]), str(evid), "--strict",
                    "--dot", str(out / f"run{run}.dot"),
                    "--json", str(out / f"run{run}.json"),
                    "--timeline", str(out / f"run{run}.md"),
                    "--summary-json", str(out / f"run{run}_summary.json"), "-q"],
                   cwd=ROOT, check=True, timeout=30)
    summary = json.loads(text(out / f"run{run}_summary.json"))
    require(summary["status"] == "OK" and summary["manifest_verified"] and
            summary["persistence_verified"] and summary["records_verified"] ==
            summary["records_replayed"] == m["record_count"] and
            summary["records_verified"] > 0 and
            not any(summary[k] for k in ("corrupt_records", "seq_gaps", "incomplete_records")),
            f"strict replay {run}: verified/replayed {summary['records_verified']} records")
    require(summary["telemetry_loss_free"], f"run {run}: zero reported instrumented losses")
for suffix in ("dot", "json", "md"):
    require(digest(out / f"run1.{suffix}") == digest(out / f"run2.{suffix}"),
            f"byte-identical {suffix} exports")
require(all(digest(p) == h for p, h in before.items()), "evidence and manifest SHA256 unchanged")
for p, h in before.items():
    print("SHA256", h, p.name)

gt = parse_workload_log(wl_log)
pid, child = gt["workload_pid"], gt["s4_child_pid"]
records = parse_evid_records(evid)
require(len(records) == m["record_count"], "raw parser agrees with strict replay count")
graph = json.loads(text(out / "run1.json"))
edges = graph["edges"]
nodes = {n["id"] for n in graph["nodes"]}
def token(name):
    matches = {r["object_token"] for r in records if r["pid"] == pid and
               r["type_id"] == 12 and r["name"] == name and r["object_token"] > 0 and r["ret_val"] >= 0}
    require(len(matches) == 1, f"unique completed token for {name}")
    return next(iter(matches))
def select(tok, kind, actor=pid):
    return [r for r in records if r["object_token"] == tok and
            r["type_id"] == kind and r["pid"] == actor]
def edge_match(r, edge_type):
    src = f"proc_{r['pid']}_{r['start_time_ns']}"
    dst = f"memfd_{r['object_token']}"
    return src in nodes and dst in nodes and any(
        e["src"] == src and e["dst"] == dst and e["type"] == edge_type and
        e.get("fd") == r["fd"] and e["timestamp_ns"] == r["timestamp_ns"] for e in edges)
t1 = token(gt["s1_name"])
expected = sorted(gt[key] for key in ("s1_orig_fd", "s1_dup_fd", "s1_fcntl_fd", "s1_dup2_fd", "s1_dup3_fd"))
installs = select(t1, 15)
require(sorted(r["fd"] for r in installs) == expected and
        all(edge_match(r, "EDGE_FD_INSTALLED") for r in installs),
        f"duplication: exact raw and graph installs {expected}")
t2 = token(gt["s2_name"])
closes = select(t2, 16)
destroyed = select(t2, 13)
require(len(closes) == 1 and closes[0]["fd"] == gt["s2_mfd_fd"] and
        len(destroyed) == 1 and closes[0]["timestamp_ns"] <= destroyed[0]["timestamp_ns"] and
        edge_match(closes[0], "EDGE_FD_CLOSED"),
        "replacement: exactly one close before destruction, matching graph")
t3 = token(gt["s3_name"])
closes = select(t3, 16)
require(len(closes) == 1 and closes[0]["fd"] == gt["s3_reuse_fd"] and
        edge_match(closes[0], "EDGE_FD_CLOSED"), "descriptor reuse: exact tracked close")
token(gt["s4_threads_name"])
t4 = token(gt["s4_clone_name"])
closes = select(t4, 16, child)
require(len(closes) == 1 and closes[0]["fd"] == gt["s4_clone_fd"] and
        edge_match(closes[0], "EDGE_FD_CLOSED"),
        f"CLONE_FILES: raw and graph close attributed to child {child}")
require(not any(r["type_id"] in (15, 16) and r["fd"] < 0 and r["pid"] == pid for r in records),
        "no negative-FD installation/closure events")
print("Integrated native smoke passed. Artifacts preserved at", out)
