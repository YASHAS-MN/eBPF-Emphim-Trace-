#!/usr/bin/env python3
"""Bounded comparison: two existing benign workloads, one run per collector.
Run as sudo from the normal trusted test account. Raw records remain private."""
import collections
import hashlib
import json
import os
import pathlib
import pwd
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tests1.0/kernel_telemetry/qualification_descriptor"))
from reconcile_descriptor_qualification import parse_evid_records

def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")

def digest(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()

def read_jsonl(path):
    rows = []
    bad = 0
    for line in path.read_text(errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
            if isinstance(row, dict):
                rows.append(row)
            else:
                bad += 1
        except json.JSONDecodeError:
            bad += 1
    return rows, bad

if len(sys.argv) != 2 or os.geteuid() != 0 or not os.environ.get("SUDO_UID") or int(os.environ["SUDO_UID"]) == 0:
    sys.exit("Usage: sudo python3 run_comparison.py /absolute/path/to/tracee")
uid, gid = int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
user = pwd.getpwuid(uid).pw_name
tracee = pathlib.Path(sys.argv[1]).resolve(strict=True)
build = ROOT / "build"
fixtures = {"memfd": build / "test_m2_exec", "unlinked": build / "test_m2_unlinked_exec"}
binaries = [tracee, build / "loader", build / "replay", build / "monitor.bpf.o", *fixtures.values()]
for path in binaries:
    if not path.is_file():
        sys.exit(f"Missing built artifact: {path}")
if subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip() == "":
    sys.exit("Cannot identify source checkpoint")
os.umask(0o077)
out = pathlib.Path(tempfile.mkdtemp(prefix="ephim_compare_"))
print("Private capture directory:", out, flush=True)
env = dict(os.environ)
for key in ("EPHIM_RING_BUFFER_MB", "EPHIM_LOW_MEMORY", "EPHIM_QUIET"):
    env.pop(key, None)
def as_user(*args, **kwargs):
    return subprocess.run(["runuser", "-u", user, "--", *map(str, args)],
                          cwd=ROOT, env=env, **kwargs)
def handoff(d):
    # Only fresh files in private directories owned by this invocation.
    for p in d.iterdir():
        if p.is_file() and not p.is_symlink():
            os.chown(p, uid, gid)
            os.chmod(p, 0o600)
    os.chown(d, uid, gid)
def stop(proc):
    if proc.poll() is not None:
        return proc.returncode
    proc.send_signal(signal.SIGINT)
    try:
        return proc.wait(timeout=20)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        raise RuntimeError("Collector did not stop orderly")
def ready_marker():
    p = as_user("/bin/sh", "-c", "echo $$; exec /bin/true",
                capture_output=True, text=True, check=True, timeout=5)
    return int(p.stdout.strip())
def ready_tracee(proc, events):
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"Tracee exited during startup: {proc.returncode}")
        pid = ready_marker()
        time.sleep(0.6)
        rows, _ = read_jsonl(events)
        if any(r.get("eventName") == "sched_process_exec" and
               r.get("hostProcessId") == pid for r in rows):
            return
    raise RuntimeError("No Tracee exec readiness marker observed")
def ready_ephim(proc, log):
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"EphimTrace exited during startup: {proc.returncode}")
        if "STATUS: READY" in log.read_text(errors="replace"):
            return
        time.sleep(0.1)
    raise RuntimeError("EphimTrace did not reach READY")
def metrics(port, path):
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(f"http://127.0.0.1:{port}/metrics", timeout=3) as response:
            path.write_bytes(response.read())
        return True
    except Exception as e:
        path.write_text(f"Metrics unavailable: {e}\n")
        return False

report = {"kernel": os.uname().release, "arch": os.uname().machine,
          "commit": subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip(),
          "binary_sha256": {p.name: digest(p) for p in binaries},
          "tracee_version": subprocess.check_output([str(tracee), "version"], text=True).strip(),
          "scope": "system-wide collectors; evaluate workload PID/child relationships only; no throughput ranking",
          "sessions": []}
try:
    inventory = subprocess.run([str(tracee), "list"], cwd=tracee.parent,
                               capture_output=True, text=True, timeout=30, check=True)
    (out / "tracee_events.txt").write_text(inventory.stdout)
    (out / "tracee_inventory.log").write_text(inventory.stderr)
    names = set(re.findall(r"^\|\s*([A-Za-z0-9_]+)\s*\|", inventory.stdout, re.M))
    requested = ["memfd_create", "write", "writev", "vfs_write", "vfs_writev",
                 "open", "openat", "openat2", "close", "dup", "dup2", "dup3", "fcntl",
                 "execve", "execveat", "sched_process_fork", "sched_process_exec",
                 "sched_process_exit", "security_bprm_check", "process_execute_failed",
                 "unlink", "unlinkat", "security_inode_unlink", "rmdir",
                 "security_file_open", "file_modification"]
    selected = [n for n in requested if n in names]
    missing = [n for n in requested if n not in names]
    report.update(tracee_selected_events=selected, tracee_not_in_inventory=missing,
                  signature_note="Bundled signature plugin mismatch observed in preflight; raw event evaluation only")
    if not {"memfd_create", "sched_process_exec", "sched_process_fork", "sched_process_exit", "unlink"}.issubset(selected):
        raise RuntimeError("Required Tracee events missing from inventory")
    print("Tracee selected:", ",".join(selected), flush=True)
    print("Not listed:", ",".join(missing) or "none", flush=True)

    for collector in ("tracee", "ephimtrace"):
        for scenario, workload in fixtures.items():
            d = out / f"{collector}_{scenario}"
            d.mkdir()
            log = d / "collector.log"
            wl = d / "workload.log"
            events = d / "events.jsonl"
            evidence = d / "session.evid"
            manifest = d / "session.evid.manifest"
            entry = {"collector": collector, "scenario": scenario, "status": "STARTING"}
            report["sessions"].append(entry)
            print("\nStarting", d.name, flush=True)
            proc = None
            try:
                if collector == "tracee":
                    # Loopback only, select a currently unused port.
                    with socket.socket() as s:
                        s.bind(("127.0.0.1", 0))
                        port = s.getsockname()[1]
                    cmd = [str(tracee), "--events", ",".join(selected),
                           "--output", "json", "--output", "option:parse-arguments-fds",
                           "--output", "option:sort-events", "--proctree", "source=events",
                           "--server", f"http-address=127.0.0.1:{port}", "--server", "metrics"]
                    cwd = tracee.parent
                else:
                    cmd = [str(build / "loader"), "--ring-buffer-mb", "64",
                           "-b", "268435456", "-o", str(evidence), "-q"]
                    cwd = ROOT
                entry["command"] = cmd
                write_json(d / "command.json", cmd)
                with log.open("wb") as lf, events.open("wb") as ef:
                    proc = subprocess.Popen(cmd, cwd=cwd, env=env,
                                            stdout=ef if collector == "tracee" else lf,
                                            stderr=lf)
                    if collector == "tracee":
                        ready_tracee(proc, events)
                        entry["metrics_before_available"] = metrics(port, d / "metrics_before.txt")
                    else:
                        ready_ephim(proc, log)
                    print("[PASS] readiness confirmed", flush=True)
                    with wl.open("wb") as wf:
                        rc = as_user(workload, stdout=wf, stderr=subprocess.STDOUT, timeout=30).returncode
                    entry["workload_rc"] = rc
                    if rc != 0 or proc.poll() is not None:
                        raise RuntimeError("Workload failed or collector died")
                    time.sleep(2)
                    if collector == "tracee":
                        entry["metrics_after_available"] = metrics(port, d / "metrics_after.txt")
                    entry["collector_rc"] = stop(proc)
                    if entry["collector_rc"] != 0:
                        raise RuntimeError(f"Collector shutdown exit {entry['collector_rc']}")
                handoff(d)
                # The parent must be traversable by the normal account for replay.
                os.chown(out, uid, gid)
                gt = wl.read_text(errors="replace")
                match = re.search(r"\[INIT\] (?:Process|Parent) PID:\s*(\d+)", gt)
                if not match:
                    raise RuntimeError("Workload parent PID unavailable")
                parent = int(match.group(1))
                entry["parent_pid"] = parent
                entry["workload_log"] = gt
                if collector == "tracee":
                    rows, bad = read_jsonl(events)
                    entry.update(records=len(rows), invalid_json_lines=bad, evidence_sha256=digest(events))
                    if bad or not rows:
                        raise RuntimeError("Tracee JSON stream is empty or malformed")
                    related = {parent}
                    # Include direct workload children, including the failed exec child.
                    for row in rows:
                        if row.get("hostParentProcessId") == parent:
                            related.add(row.get("hostProcessId"))
                    related.discard(None)
                    filtered = [r for r in rows if r.get("hostProcessId") in related]
                    entry["workload_event_counts"] = dict(collections.Counter(r.get("eventName", "?") for r in filtered))
                    # Retain original rows privately; no claim of completeness.
                    write_json(d / "workload_events.json", filtered)
                    entry["related_pids"] = sorted(related)
                    if not filtered:
                        raise RuntimeError("No Tracee workload events")
                    if entry["metrics_after_available"]:
                        entry["loss_metric_lines"] = [line for line in (d / "metrics_after.txt").read_text().splitlines()
                                                      if not line.startswith("#") and re.search("lost|drop|error", line, re.I)]
                else:
                    before = {p.name: digest(p) for p in (evidence, manifest)}
                    with (d / "replay.log").open("wb") as rf:
                        as_user(build / "replay", evidence, "--strict", "--dot", d / "graph.dot",
                                "--json", d / "graph.json", "--timeline", d / "timeline.md",
                                "--summary-json", d / "summary.json", "-q",
                                stdout=rf, stderr=subprocess.STDOUT, check=True, timeout=30)
                    if before != {p.name: digest(p) for p in (evidence, manifest)}:
                        raise RuntimeError("EphimTrace input hashes changed")
                    entry["input_sha256"] = before
                    entry["replay_summary"] = json.loads((d / "summary.json").read_text())
                    rows = parse_evid_records(evidence)
                    if len(rows) != entry["replay_summary"]["records_verified"]:
                        raise RuntimeError("Raw parser and replay record counts differ")
                    related = {parent}
                    for row in rows:
                        if row["pid"] == parent and row["type_id"] == 6 and row["child_tgid"] > 0:
                            related.add(row["child_tgid"])
                    filtered = [r for r in rows if r["pid"] in related]
                    entry["workload_event_counts"] = dict(collections.Counter(r["type"] for r in filtered))
                    write_json(d / "workload_events.json", filtered)
                    entry["related_pids"] = sorted(related)
                entry["status"] = "CAPTURED"
                print("[PASS]", d.name, entry["workload_event_counts"], flush=True)
            except Exception as e:
                entry.update(status="FAILED", error=str(e))
                print("[FAIL]", d.name, str(e), flush=True)
                # Do not silently continue an invalid experiment.
                raise
            finally:
                if proc is not None and proc.poll() is None:
                    stop(proc)
                handoff(d)
                write_json(out / "comparison_report.json", report)
finally:
    handoff(out)
    print("Report:", out / "comparison_report.json", flush=True)

print("Four capture sessions completed; semantic evaluation still pending.", flush=True)
