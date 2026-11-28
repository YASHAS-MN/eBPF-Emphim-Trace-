#!/usr/bin/env python3
"""Disposable CLI checks; no kernel attachment or root required."""
import os
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[3]
LOADER = ROOT / "build/loader"
REPLAY = ROOT / "build/replay"
env = dict(os.environ)
for name in ("EPHIM_RING_BUFFER_MB", "EPHIM_LOW_MEMORY", "EPHIM_QUIET"):
    env.pop(name, None)

def run(args, extra=None):
    return subprocess.run([str(x) for x in args], cwd=ROOT,
                          env={**env, **(extra or {})}, capture_output=True,
                          text=True, timeout=10)

def reject(args, fragment, extra=None):
    p = run(args, extra)
    assert p.returncode == 1 and fragment in p.stderr, (
        args, p.returncode, p.stdout, p.stderr)
    print("[PASS]", fragment, ":", repr(str(args[-1]))[:100])

with tempfile.TemporaryDirectory(prefix="ephim_cli_") as tmp:
    d = pathlib.Path(tmp)
    evidence = d / "session.evid"
    base = [LOADER, "-o", evidence]
    for value in ("0", "3", "1025", "-1", "64junk", "4294967360", "", " 64"):
        reject(base + ["--ring-buffer-mb", value], "power of two")
    for value in ("0", "3", "-1", "64junk", "4294967360"):
        reject(base, "EPHIM_RING_BUFFER_MB", {"EPHIM_RING_BUFFER_MB": value})
    for value in ("0", "1", "-1", "1024junk", "9223372036854775808"):
        reject(base + ["--max-bytes", value], "requires an unsigned decimal")
    for value in ("-1", "4294967296", "12junk"):
        reject(base + ["--filter-pid", value], "invalid PID")
    for value in ("-1", "18446744073709551616", "1junk"):
        reject(base + ["--filter-token", value], "invalid object token")
    for value in ("", str(d / ("x" * 256)), str(d / 'quote"evid')):
        reject([LOADER, "-o", value], "evidence path")
    assert not list(d.iterdir()), "invalid capture arguments created files"

    sidecar = d / "session.evid.manifest"
    sidecar.write_bytes(b"preserve existing sidecar")
    reject(base, "manifest path already exists")
    assert not evidence.exists() and sidecar.read_bytes() == b"preserve existing sidecar"

    evidence.write_bytes(b"disposable sentinel")
    for flag, fragment, values in (
        ("--filter-pid", "invalid PID", ("-1", "4294967296", "12junk")),
        ("--filter-token", "invalid object token", ("-1", "18446744073709551616", "1junk")),
        ("--progress", "invalid progress interval", ("-1", "18446744073709551616", "1junk")),
    ):
        for value in values:
            reject([REPLAY, evidence, flag, value, "--dot", d / "out.dot"], fragment)
    reject([REPLAY, evidence, "--dot", ""], "invalid export path")
    reject([REPLAY, d / ("x" * 256)], "invalid evidence path")
    assert evidence.read_bytes() == b"disposable sentinel"
    assert sidecar.read_bytes() == b"preserve existing sidecar"
    assert not (d / "out.dot").exists()

    # Valid options reach help without touching the kernel or output path.
    for args in (
        [LOADER, "--ring-buffer-mb", "1", "--help"],
        [LOADER, "--ring-buffer-mb", "1024", "--help"],
        [LOADER, "--low-memory", "--help"],
        [LOADER, "--filter-pid", "4294967295", "--help"],
        [REPLAY, "--filter-token", "18446744073709551615", "--help"],
    ):
        p = run(args)
        assert p.returncode == 0 and "Usage:" in p.stdout, (args, p.stderr)
        print("[PASS] valid boundary:", " ".join(map(str, args[1:])))
print("All deployment CLI checks passed.")
