#!/usr/bin/env python3
"""EphimTrace diagnostic overlay: never edits production source files."""

import argparse
import csv
import hashlib
import json
import os
import pathlib
import re
import select
import shlex
import signal
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]  # tests1.0/kernel_telemetry -> repository root
BUILD = ROOT / "build" / "telemetry_lab"
EVENTS = {
    1: "EXECVE",
    2: "MEMFD_CREATE",
    3: "UNLINK",
    4: "UNLINKAT",
    5: "CONNECT",
    6: "FORK",
    7: "PROCESS_EXEC",
    8: "PROCESS_EXIT",
    9: "VFS_UNLINK_COMPLETED",
    10: "VFS_RMDIR_COMPLETED",
    11: "RMDIR",
    12: "MEMFD_COMPLETED",
    13: "MEMFD_DESTROYED",
    14: "MEMFD_FILE_RELEASED",
    15: "FD_INSTALLED",
    16: "FD_CLOSED",
    17: "MEMFD_WRITE",
    18: "MEMFD_EXEC_ATTEMPT",
    19: "MEMFD_EXEC_SUCCESS",
    99: "DEBUG",
}


def replace(s, a, b):
    if s.count(a) != 1:
        raise RuntimeError(
            f"Source layout changed: expected one occurrence of {a[:100]!r}, got {s.count(a)}"
        )
    return s.replace(a, b, 1)


MAPS = [
    "pending_memfd_map",
    "pending_syscall_map",
    "unlink_identity_map",
    "rmdir_identity_map",
    "pending_memfd_exec",
    "memfd_file_registry",
    "memfd_desc_registry",
    "memfd_inode_registry",
]


def build():
    BUILD.mkdir(parents=True, exist_ok=True)
    (BUILD / "build_info.json").unlink(missing_ok=True)
    bp = ROOT / "src/bpf/monitor.bpf.c"
    up = ROOT / "src/user/loader.c"
    pp = ROOT / "src/user/provenance.c"
    b = bp.read_text()
    u = up.read_text()
    p_src = pp.read_text()

    if not re.search(
        r"__uint\(type, BPF_MAP_TYPE_RINGBUF\);\s*__uint\(max_entries, 1 << 20\);", b
    ):
        raise RuntimeError("Ring-buffer definition changed; review baseline")

    # Replace calls before introducing the diagnostic submit wrapper.
    b, n = re.subn(r"\bbpf_ringbuf_submit\((\w+),\s*0\);", r"diag_submit(\1);", b)
    if n != 24:
        raise RuntimeError(f"Unexpected submit site count: {n}")
    if re.search(r"\bbpf_ringbuf_(submit|discard|output)\s*\(", b):
        raise RuntimeError("Uninstrumented transport operation")

    def map_call(m):
        op, name, args = m.groups()
        if name not in MAPS:
            raise RuntimeError(f"Unknown map mutation: {name}")
        base = 728 + MAPS.index(name) * 6 + (0 if op == "update" else 3)
        return f"DIAG_MAP_CALL({base}, bpf_map_{op}_elem(&{name},{args}))"

    b, nmap = re.subn(
        r"bpf_map_(update|delete)_elem\(&([a-zA-Z_][a-zA-Z0-9_]*),([^()]*?)\)",
        map_call,
        b,
    )
    if not nmap or len(re.findall(r"\bbpf_map_(?:update|delete)_elem\s*\(", b)) != nmap:
        raise RuntimeError("Map mutation coverage check failed")

    b = replace(
        b,
        "static __always_inline void inc_counter(__u32 idx)",
        (HERE / "bpf_probe.inc").read_text()
        + "\nstatic __always_inline void inc_counter(__u32 idx)",
    )
    b = replace(
        b,
        "    __u32 key = idx;\n",
        "    if (idx < 128 && diag_target()) diag_inc(600+idx);\n    __u32 key = idx;\n",
    )
    b = replace(
        b,
        "    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);\n    if (!e)\n        return NULL;",
        "    diag_event(type,0);\n    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);\n    if (!e) { diag_event(type,1); return NULL; }",
    )
    if len(re.findall(r"\bbpf_ringbuf_reserve\s*\(", b)) != 1:
        raise RuntimeError("Unexpected reserve site count")

    u = replace(
        u,
        "static int handle_event(void *ctx, void *data, size_t size)",
        (HERE / "user_probe.inc").read_text()
        + "\nstatic int handle_event(void *ctx, void *data, size_t size)",
    )

    marker = "static int parse_online_cpus("
    wrapper = """static int diag_receive(void *ctx, void *data, size_t size) {
    (void)ctx;
    uint64_t _t_enter = diag_time_now_ns();
    if (size != sizeof(struct event)) { diag_invalid++; return 0; }
    const struct event *e = data;
    if (!e->type || (e->type > 19 && e->type != 99)) { diag_other++; return 0; }
    diag_received[0][e->type]++;
    int cap_idx = -1;
    if (e->pid == diag_pid) {
        diag_received[1][e->type]++;
        if (e->type == 2 || e->type == 12) {
            if (diag_captured_count < DIAG_MAX_CAPTURED) {
                cap_idx = (int)diag_captured_count++;
                struct diag_captured_event *cap = &diag_captured_events[cap_idx];
                cap->type = e->type;
                cap->pid = e->pid;
                cap->tid = e->tid;
                cap->ret_val = e->ret_val;
                cap->fd = e->fd;
                cap->op_type = e->op_type;
                cap->flags = e->syscall_flags;
                cap->token = e->object_token;
                cap->inode_no = e->inode_no;
                cap->dev_id = e->dev_id;
                cap->entry_ts = e->entry_ts_ns;
                cap->ts = e->timestamp_ns;
                cap->p_status = P_STATUS_UNAVAILABLE;
                snprintf(cap->name, sizeof(cap->name), "%.63s", e->name);
            } else {
                diag_captured_overflow++;
            }
        }
    }
    uint64_t _t_rec = diag_time_now_ns();
    diag_timing_record(&g_diag_profile.reception, _t_rec - _t_enter);
    if (diag_delay) { struct timespec ts = {diag_delay / 1000000, (long)(diag_delay % 1000000) * 1000}; nanosleep(&ts, NULL); }

    if (event_queue_push(g_queue, e, cap_idx) < 0) {
        if (cap_idx >= 0) {
            diag_captured_events[cap_idx].p_status = P_STATUS_FAILED;
        }
    }
    return 0;
}

"""
    u = replace(u, marker, wrapper + marker)
    u = replace(
        u,
        "static inline void on_event_processed(int cap_idx, uint32_t pid) {\n    (void)cap_idx;\n    (void)pid;\n}",
        """static inline void on_event_processed(int cap_idx, uint32_t pid) {
    diag_record_global_event_ts();
    if (cap_idx >= 0) {
        diag_captured_events[cap_idx].p_status = diag_p_get_last_status();
        if (diag_last_processed_token != 0) {
            diag_captured_events[cap_idx].token = diag_last_processed_token;
        }
    }
    if (pid == diag_pid) {
        diag_record_target_event_ts();
    }
}""",
    )
    u = replace(
        u,
        "    libbpf_set_print(libbpf_print_fn);",
        """    diag_profile_init();
    const char *pid_env=getenv("EPHIM_DIAG_PID");
    if (!pid_env || !(diag_pid=(uint32_t)strtoul(pid_env,NULL,10))) return 2;
    diag_full=getenv("EPHIM_DIAG_FULL") && !strcmp(getenv("EPHIM_DIAG_FULL"),"1");
    if (getenv("EPHIM_DIAG_DELAY_US")) diag_delay=(unsigned)strtoul(getenv("EPHIM_DIAG_DELAY_US"),NULL,10);
    libbpf_set_print(libbpf_print_fn);""",
    )
    u = replace(
        u,
        "    if (prov_engine_init() != 0) {",
        "    if (diag_full && prov_engine_init() != 0) {",
    )
    u = replace(
        u,
        'bpf_object__open_file("build/monitor.bpf.o", NULL)',
        'bpf_object__open_file("build/telemetry_lab/monitor.diag.bpf.o", NULL)',
    )
    marker = "    if (current_log_level >= LOG_LEVEL_DEBUG) {\n        setup_diag_instance();"
    u = replace(
        u,
        marker,
        """    struct bpf_map *cfg=bpf_object__find_map_by_name(obj,"diag_cfg");
    uint32_t cfgkey=0;
    if (!cfg || bpf_map_update_elem(bpf_map__fd(cfg),&cfgkey,&diag_pid,BPF_ANY)) { perror("diag_cfg"); goto cleanup; }
    uint32_t fail_flags = 0;
    if (getenv("EPHIM_DIAG_FAIL_FILE_REG") && atoi(getenv("EPHIM_DIAG_FAIL_FILE_REG"))) fail_flags |= 0x1;
    if (getenv("EPHIM_DIAG_FAIL_DESC_REG") && atoi(getenv("EPHIM_DIAG_FAIL_DESC_REG"))) fail_flags |= 0x2;
    if (getenv("EPHIM_DIAG_FAIL_INODE_REG") && atoi(getenv("EPHIM_DIAG_FAIL_INODE_REG"))) fail_flags |= 0x4;
    const char *gen_fail = getenv("EPHIM_DIAG_FAIL_REG");
    if (gen_fail) {
        if (!strcmp(gen_fail, "file") || !strcmp(gen_fail, "1")) fail_flags |= 0x1;
        else if (!strcmp(gen_fail, "desc") || !strcmp(gen_fail, "2")) fail_flags |= 0x2;
        else if (!strcmp(gen_fail, "inode") || !strcmp(gen_fail, "4")) fail_flags |= 0x4;
        else if (!strcmp(gen_fail, "all")) fail_flags |= 0x7;
    }
    if (fail_flags) {
        uint32_t fk = 1;
        bpf_map_update_elem(bpf_map__fd(cfg), &fk, &fail_flags, BPF_ANY);
    }
    /* Reset measurement before attaching the existing hooks. */
""" + marker,
    )
    u = replace(
        u,
        "ring_buffer__new(bpf_map__fd(map), acquisition_callback, NULL, NULL)",
        "ring_buffer__new(bpf_map__fd(map), diag_receive, NULL, NULL)",
    )
    u = replace(
        u,
        "    time_t last_counter_print = time(NULL);",
        '    puts("DIAG_READY"); diag_record_baseline_rusage(); fflush(stdout);\n    time_t last_counter_print = time(NULL);',
    )

    u = replace(
        u,
        "    export_provenance_data(filter_pid, filter_token, timeline_filepath);\n\n    ret = 0;",
        """    if (diag_report(obj)) { log_error("Diagnostic counter read failed"); goto cleanup; }
    ret = 0;""",
    )
    u = replace(
        u,
        "    prov_engine_destroy();\n    cleanup_diag_instance();",
        "    if (diag_full) prov_engine_destroy();\n    cleanup_diag_instance();",
    )
    u = replace(
        u,
        """    update_process_state(e);
    prov_engine_process_event(e);

    if (size != sizeof(*e))
        return 0;

    if (quiet_mode)
        return 0;

    switch (e->type) {""",
        """    uint64_t _t_ps_start = diag_time_now_ns();
    update_process_state(e);
    uint64_t _t_ps_end = diag_time_now_ns();
    diag_timing_record(&g_diag_profile.process_state, _t_ps_end - _t_ps_start);

    uint64_t _t_prov_start = diag_time_now_ns();
    prov_engine_process_event(e);
    uint64_t _t_prov_end = diag_time_now_ns();
    diag_timing_record(&g_diag_profile.provenance, _t_prov_end - _t_prov_start);

    if (size != sizeof(*e))
        return 0;

    if (quiet_mode)
        return 0;

    uint64_t _t_log_start = diag_time_now_ns();
    switch (e->type) {""",
    )
    u = replace(
        u,
        """    fflush(stdout);
    return 0;
}""",
        """    fflush(stdout);
    uint64_t _t_log_end = diag_time_now_ns();
    diag_timing_record(&g_diag_profile.logging, _t_log_end - _t_log_start);
    return 0;
}""",
    )

    # Instrument provenance.c to generate provenance.diag.c (Checkpoint P)
    orig_memfd_block = """    case EVENT_MEMFD_CREATE: {
        struct prov_node *proc = prov_upsert_process(e->pid, e->start_time_ns, e->ppid, NULL);
        if (e->object_token != 0) {
            struct prov_node *memfd = prov_upsert_memfd(e->object_token, e->pid, e->start_time_ns,
                                                        e->name, e->inode_no, e->dev_id);
            struct prov_edge_attr attr = {
                .timestamp_ns = e->timestamp_ns,
                .fd = e->fd,
            };
            prov_add_edge(proc, memfd, EDGE_MEMFD_CREATE, &attr);
        }
        break;
    }

    case EVENT_MEMFD_COMPLETED: {
        if (e->op_type == 2 /* MEMFD_STATUS_SUCCESS_CORRELATED */ && e->object_token != 0) {
            struct prov_node *proc = prov_upsert_process(e->pid, e->start_time_ns, e->ppid, NULL);
            const char *name = e->name[0] ? e->name : (e->path[0] ? e->path : "memfd");
            struct prov_node *memfd = prov_upsert_memfd(e->object_token, e->pid, e->start_time_ns,
                                                        name, e->inode_no, e->dev_id);
            /* Check if creation edge already recorded */
            bool has_create_edge = false;
            if (proc) {
                struct prov_edge *edge = proc->out_edges;
                while (edge) {
                    if (edge->type == EDGE_MEMFD_CREATE && edge->dst == memfd) {
                        has_create_edge = true;
                        break;
                    }
                    edge = edge->next_out;
                }
            }
            if (!has_create_edge) {
                struct prov_edge_attr attr = {
                    .timestamp_ns = e->timestamp_ns,
                    .fd = e->fd,
                };
                prov_add_edge(proc, memfd, EDGE_MEMFD_CREATE, &attr);
            }
        }
        break;
    }"""

    diag_memfd_block = """    case EVENT_MEMFD_CREATE: {
        struct prov_node *proc = prov_upsert_process(e->pid, e->start_time_ns, e->ppid, NULL);
        if (e->object_token != 0) {
            struct prov_node *memfd = prov_upsert_memfd(e->object_token, e->pid, e->start_time_ns,
                                                        e->name, e->inode_no, e->dev_id);
            struct prov_edge_attr attr = {
                .timestamp_ns = e->timestamp_ns,
                .fd = e->fd,
            };
            prov_add_edge(proc, memfd, EDGE_MEMFD_CREATE, &attr);
            uint64_t _p_c_t1 = diag_p_time_now_ns();
            diag_record_p_outcome((proc && memfd) ? P_STATUS_SUCCESS : P_STATUS_FAILED);
            diag_p_record_timing(diag_p_time_now_ns() - _p_c_t1);
        } else {
            /* Intentional filtering: syscall-entry does not carry token, memfd node/edge not created */
            uint64_t _p_c_t1 = diag_p_time_now_ns();
            diag_record_p_outcome(proc ? P_STATUS_FILTERED : P_STATUS_FAILED);
            diag_p_record_timing(diag_p_time_now_ns() - _p_c_t1);
        }
        break;
    }

    case EVENT_MEMFD_COMPLETED: {
        if (diag_should_inject_p_fail()) {
            uint64_t _p_diag_t0 = diag_p_time_now_ns();
            diag_record_p_outcome(P_STATUS_FAILED);
            diag_p_record_timing(diag_p_time_now_ns() - _p_diag_t0);
            break;
        }
        if (e->op_type == 2 /* MEMFD_STATUS_SUCCESS_CORRELATED */ && e->object_token != 0) {
            uint64_t _p_diag_t0 = diag_p_time_now_ns();
            /* Pre-check: examine if memfd node or edge already exists before production processing */
            char memfd_id[128];
            snprintf(memfd_id, sizeof(memfd_id), "memfd_%llu", (unsigned long long)e->object_token);
            struct prov_node *pre_memfd = prov_find_node(memfd_id);

            char proc_id[128];
            if (e->start_time_ns != 0) {
                snprintf(proc_id, sizeof(proc_id), "proc_%u_%llu", e->pid, (unsigned long long)e->start_time_ns);
            } else {
                struct prov_node *act = find_active_proc(e->pid);
                if (act) snprintf(proc_id, sizeof(proc_id), "%s", act->id);
                else snprintf(proc_id, sizeof(proc_id), "proc_%u_0", e->pid);
            }
            struct prov_node *pre_proc = prov_find_node(proc_id);
            bool pre_edge_existed = false;
            if (pre_proc && pre_memfd) {
                for (struct prov_edge *ed = pre_proc->out_edges; ed; ed = ed->next_out) {
                    if (ed->type == EDGE_MEMFD_CREATE && ed->dst == pre_memfd) {
                        pre_edge_existed = true;
                        break;
                    }
                }
            }
            uint64_t _p_diag_t1 = diag_p_time_now_ns();

            /* Execute exact production logic */
            struct prov_node *proc = prov_upsert_process(e->pid, e->start_time_ns, e->ppid, NULL);
            const char *name = e->name[0] ? e->name : (e->path[0] ? e->path : "memfd");
            struct prov_node *memfd = prov_upsert_memfd(e->object_token, e->pid, e->start_time_ns,
                                                        name, e->inode_no, e->dev_id);
            if (diag_should_inject_p_fail()) {
                /* Simulate controlled allocation / processing failure in provenance engine */
                memfd = NULL;
            }
            bool has_create_edge = false;
            if (proc && memfd) {
                struct prov_edge *edge = proc->out_edges;
                while (edge) {
                    if (edge->type == EDGE_MEMFD_CREATE && edge->dst == memfd) {
                        has_create_edge = true;
                        break;
                    }
                    edge = edge->next_out;
                }
            }
            if (!has_create_edge && proc && memfd) {
                struct prov_edge_attr attr = {
                    .timestamp_ns = e->timestamp_ns,
                    .fd = e->fd,
                };
                prov_add_edge(proc, memfd, EDGE_MEMFD_CREATE, &attr);
            }

            /* Diagnostic Checkpoint P verification */
            uint64_t _p_diag_t2 = diag_p_time_now_ns();
            if (!proc || !memfd) {
                diag_record_p_outcome(P_STATUS_FAILED);
            } else if (pre_edge_existed) {
                diag_record_p_outcome(P_STATUS_EDGE_SUPPRESSED);
            } else {
                bool edge_verified = false;
                for (struct prov_edge *ed = proc->out_edges; ed; ed = ed->next_out) {
                    if (ed->type == EDGE_MEMFD_CREATE && ed->dst == memfd &&
                        ed->attr.fd == e->fd && ed->attr.timestamp_ns == e->timestamp_ns) {
                        edge_verified = true;
                        break;
                    }
                }
                diag_record_p_outcome(edge_verified ? P_STATUS_SUCCESS : P_STATUS_FAILED);
            }
            uint64_t _p_diag_t3 = diag_p_time_now_ns();
            diag_p_record_timing((_p_diag_t1 - _p_diag_t0) + (_p_diag_t3 - _p_diag_t2));
        } else if (e->op_type == 1 /* MEMFD_STATUS_FAILED */) {
            uint64_t _p_diag_t0 = diag_p_time_now_ns();
            diag_record_p_outcome(P_STATUS_FILTERED);
            diag_p_record_timing(diag_p_time_now_ns() - _p_diag_t0);
        } else {
            uint64_t _p_diag_t0 = diag_p_time_now_ns();
            diag_record_p_outcome(P_STATUS_CORRELATION_DEFICIENCY);
            diag_p_record_timing(diag_p_time_now_ns() - _p_diag_t0);
        }
        break;
    }"""

    p_src = (
        (HERE / "prov_probe.inc").read_text()
        + "\n"
        + replace(p_src, orig_memfd_block, diag_memfd_block)
    )

    (BUILD / "monitor.diag.bpf.c").write_text(b)
    (BUILD / "loader.diag.c").write_text(u)
    (BUILD / "provenance.diag.c").write_text(p_src)

    clang = shlex.split(os.environ.get("CLANG", "clang-16"))
    cc = shlex.split(os.environ.get("CC", "gcc"))
    flags = shlex.split(
        os.environ.get(
            "BPF_CFLAGS",
            "-O2 -g -target bpf -D__TARGET_ARCH_x86 -I src/bpf -I/usr/include/x86_64-linux-gnu -I/usr/include",
        )
    )

    def pkg(option):
        p = subprocess.run(
            ["pkg-config", option, "libbpf"], capture_output=True, text=True
        )
        return (
            shlex.split(p.stdout)
            if p.returncode == 0
            else (["-lbpf"] if option == "--libs" else [])
        )

    def run(cmd):
        subprocess.run(cmd, cwd=ROOT, check=True)

    run(
        clang
        + flags
        + [
            "-c",
            str(BUILD / "monitor.diag.bpf.c"),
            "-o",
            str(BUILD / "monitor.diag.bpf.o"),
        ]
    )
    run(
        cc
        + ["-O2", "-Wall", "-Wextra", "-pthread", "-I", "src/user", "-I", "."]
        + pkg("--cflags")
        + [
            str(BUILD / "loader.diag.c"),
            str(BUILD / "provenance.diag.c"),
            str(ROOT / "src/user/canonical_correlator.c"),
            "-o",
            str(BUILD / "loader.diag"),
        ]
        + pkg("--libs")
    )
    run(
        cc
        + [
            "-O2",
            "-Wall",
            "-Wextra",
            "-pthread",
            str(HERE / "workload.c"),
            "-o",
            str(BUILD / "workload"),
        ]
    )
    if (HERE / "test_prov_p.c").exists():
        run(
            cc
            + [
                "-O2",
                "-Wall",
                "-Wextra",
                "-I",
                "src/user",
                str(HERE / "test_prov_p.c"),
                str(BUILD / "provenance.diag.c"),
                "-o",
                str(BUILD / "test_prov_p"),
            ]
        )
    if (HERE / "test_registry_concurrency.c").exists():
        run(
            cc
            + [
                "-O2",
                "-Wall",
                "-Wextra",
                "-pthread",
                str(HERE / "test_registry_concurrency.c"),
                "-o",
                str(BUILD / "test_registry_concurrency"),
            ]
        )
    if (HERE / "test_async_queue.c").exists():
        run(
            cc
            + [
                "-O2",
                "-Wall",
                "-Wextra",
                "-pthread",
                "-I",
                "src/user",
                "-I",
                ".",
                str(HERE / "test_async_queue.c"),
                "-o",
                str(BUILD / "test_async_queue"),
            ]
        )
    if (HERE / "test_callback_equivalence.c").exists():
        run(
            cc
            + [
                "-O2",
                "-Wall",
                "-Wextra",
                "-I",
                "src/user",
                "-I",
                ".",
                str(HERE / "test_callback_equivalence.c"),
                str(BUILD / "provenance.diag.c"),
                str(ROOT / "src/user/canonical_correlator.c"),
                "-lbpf",
                "-o",
                str(BUILD / "test_callback_equivalence"),
            ]
        )
    info = {
        "bpf_sha256": hashlib.sha256(bp.read_bytes()).hexdigest(),
        "loader_sha256": hashlib.sha256(up.read_bytes()).hexdigest(),
        "provenance_sha256": hashlib.sha256(
            (ROOT / "src/user/provenance.c").read_bytes()
        ).hexdigest(),
        "header_sha256": hashlib.sha256(
            (ROOT / "src/user/provenance.h").read_bytes()
        ).hexdigest(),
        "submit_sites": n,
        "map_mutation_sites": nmap,
        "kernel": os.uname().release,
        "ring_bytes": 1048576,
    }
    (BUILD / "build_info.json").write_text(json.dumps(info, indent=2))
    print("Diagnostic build complete:", info, flush=True)


def line_with_timeout(stream, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        r, _, _ = select.select(
            [stream], [], [], min(1.0, max(0.05, deadline - time.monotonic()))
        )
        if r:
            line = stream.readline()
            if not line:
                raise RuntimeError("workload exited without response")
            return line.strip()
    raise TimeoutError("workload response timed out")


def wait_ready(p, log, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if p.poll() is not None:
            raise RuntimeError(f"loader exited {p.returncode}; inspect {log}")
        if b"\nDIAG_READY\n" in log.read_bytes():
            return
        time.sleep(0.03)
    raise TimeoutError(f"loader readiness timeout; inspect {log}")


def stopped(pid):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        status = pathlib.Path(f"/proc/{pid}/status").read_text()
        if re.search(r"^State:\s+T", status, re.M):
            return
        time.sleep(0.01)
    raise TimeoutError("consumer did not stop")


def get_result(log):
    with log.open() as f:
        lines = [x[len("DIAG_JSON ") :] for x in f if x.startswith("DIAG_JSON ")]
    if len(lines) != 1:
        raise RuntimeError("missing or duplicate diagnostic report")
    return json.loads(lines[0])


def reconcile_events(records, captured_events, p_available=False):
    """Reconciles individual captured events against ground-truth records using (pid, tid, name)."""
    events_by_type = {2: {}, 12: {}}
    unexpected = []
    gt_keys = {(r["pid"], r["tid"], r["name"]) for r in records}

    for e in captured_events:
        t = e.get("type")
        k = (e.get("pid"), e.get("tid"), e.get("name"))
        if k not in gt_keys:
            unexpected.append(e)
            continue
        if t in events_by_type:
            events_by_type[t].setdefault(k, []).append(e)
        else:
            unexpected.append(e)

    missing_create = []
    missing_complete = []
    duplicate_create = []
    duplicate_complete = []
    incorrect_outcome = []
    corrupted_events = []
    p_discrepancies = []

    reconstructed_records = []
    incomplete_records = []

    for r in records:
        k = (r["pid"], r["tid"], r["name"])
        op_has_flaw = False

        # Check EVENT_MEMFD_CREATE (type 2)
        c_events = events_by_type[2].get(k, [])
        if len(c_events) == 0:
            missing_create.append(r)
            op_has_flaw = True
        elif len(c_events) > 1:
            duplicate_create.append({"record": r, "events": c_events})
            op_has_flaw = True
        else:
            ce = c_events[0]
            is_corrupt = False
            # Detect uninitialized token contamination on enter
            if ce.get("token", 0) != 0:
                corrupted_events.append(
                    {
                        "record": r,
                        "event": ce,
                        "reason": f"Unexpected non-zero object_token on enter: {ce.get('token')} (hex 0x{ce.get('token',0):x})",
                    }
                )
                is_corrupt = True
                op_has_flaw = True
            elif ce.get("ret", 0) != 0 or ce.get("fd", -1) != -1:
                incorrect_outcome.append(
                    {
                        "record": r,
                        "event": ce,
                        "reason": "Invalid creation entry return/fd fields",
                    }
                )
                op_has_flaw = True

            if p_available:
                # Expected P for enter event is P_STATUS_FILTERED (2)
                # When token is corrupt, downstream provenance engine was misled into creating node/edge (p=1)
                if ce.get("p") != 2:
                    p_discrepancies.append(
                        {
                            "record": r,
                            "event": ce,
                            "expected_p": 2,
                            "observed_p": ce.get("p"),
                            "related_to_token_corruption": is_corrupt,
                        }
                    )
                    op_has_flaw = True

        # Check EVENT_MEMFD_COMPLETED (type 12)
        comp_events = events_by_type[12].get(k, [])
        if len(comp_events) == 0:
            missing_complete.append(r)
            op_has_flaw = True
        elif len(comp_events) > 1:
            duplicate_complete.append({"record": r, "events": comp_events})
            op_has_flaw = True
        else:
            ce = comp_events[0]
            if r["success"] == 1:
                if ce.get("op") != 2:
                    incorrect_outcome.append(
                        {
                            "record": r,
                            "event": ce,
                            "reason": f"Expected op=2, got {ce.get('op')}",
                        }
                    )
                    op_has_flaw = True
                elif ce.get("ret") != r["ret"]:
                    incorrect_outcome.append(
                        {
                            "record": r,
                            "event": ce,
                            "reason": f"Expected ret={r['ret']}, got {ce.get('ret')}",
                        }
                    )
                    op_has_flaw = True
                elif ce.get("fd") != r["ret"]:
                    incorrect_outcome.append(
                        {
                            "record": r,
                            "event": ce,
                            "reason": f"Expected fd={r['ret']}, got {ce.get('fd')}",
                        }
                    )
                    op_has_flaw = True
                elif ce.get("token", 0) == 0:
                    incorrect_outcome.append(
                        {
                            "record": r,
                            "event": ce,
                            "reason": "Zero object token on correlated success",
                        }
                    )
                    op_has_flaw = True

                if p_available:
                    # Expected P for correlated success is P_STATUS_SUCCESS (1)
                    if ce.get("p") != 1:
                        p_discrepancies.append(
                            {
                                "record": r,
                                "event": ce,
                                "expected_p": 1,
                                "observed_p": ce.get("p"),
                                "related_to_token_corruption": False,
                            }
                        )
                        op_has_flaw = True
            else:
                if ce.get("op") != 1:
                    incorrect_outcome.append(
                        {
                            "record": r,
                            "event": ce,
                            "reason": f"Expected op=1 (failed), got {ce.get('op')}",
                        }
                    )
                    op_has_flaw = True
                elif ce.get("ret") != -r["errno"]:
                    incorrect_outcome.append(
                        {
                            "record": r,
                            "event": ce,
                            "reason": f"Expected ret={-r['errno']}, got {ce.get('ret')}",
                        }
                    )
                    op_has_flaw = True
                elif ce.get("fd") != -1:
                    incorrect_outcome.append(
                        {
                            "record": r,
                            "event": ce,
                            "reason": f"Expected fd=-1, got {ce.get('fd')}",
                        }
                    )
                    op_has_flaw = True
                elif ce.get("token", 0) != 0:
                    incorrect_outcome.append(
                        {
                            "record": r,
                            "event": ce,
                            "reason": "Non-zero token on failed syscall",
                        }
                    )
                    op_has_flaw = True

                if p_available:
                    # Expected P for failed syscall is P_STATUS_FILTERED (2)
                    if ce.get("p") != 2:
                        p_discrepancies.append(
                            {
                                "record": r,
                                "event": ce,
                                "expected_p": 2,
                                "observed_p": ce.get("p"),
                                "related_to_token_corruption": False,
                            }
                        )
                        op_has_flaw = True

        if not op_has_flaw:
            reconstructed_records.append(r)
        else:
            incomplete_records.append(r)

    return {
        "reconstructed_count": len(reconstructed_records),
        "incomplete_count": len(incomplete_records),
        "reconstructed_records": reconstructed_records,
        "incomplete_records": incomplete_records,
        "missing_create": missing_create,
        "missing_complete": missing_complete,
        "duplicate_create": duplicate_create,
        "duplicate_complete": duplicate_complete,
        "unexpected": unexpected,
        "incorrect_outcome": incorrect_outcome,
        "corrupted_events": corrupted_events,
        "p_discrepancies": p_discrepancies,
    }


def analyse(d, w, timing=None):
    rows = {(r["scope"], r["type"]): r for r in d["events"]}
    t = lambda k: rows.get(
        (1, k), dict(attempted=0, reserve_failed=0, submitted=0, received=0)
    )

    measurement_issues = []
    backend_findings = {
        "generation_gaps": {},
        "reservation_drops": {},
        "missing_events": {},
        "corruption_findings": [],
        "processing_findings": [],
        "correlation_findings": {},
    }

    # 1. Measurement Infrastructure Reliability Checks
    if d.get("invalid", 0) > 0:
        measurement_issues.append("userspace received invalid-size records")
    if d.get("unknown_type", 0) > 0:
        measurement_issues.append("userspace received unknown-type records")
    if d.get("captured_overflow", 0) > 0:
        measurement_issues.append("userspace diagnostic event buffer overflow")

    for r in d["events"]:
        if r["attempted"] != r["reserve_failed"] + r["submitted"]:
            measurement_issues.append(
                f"reservation accounting mismatch scope={r['scope']} type={r['type']}: attempted ({r['attempted']}) != reserve_failed ({r['reserve_failed']}) + submitted ({r['submitted']})"
            )

    # Reception count check against captured records count
    expected_captured = t(2)["received"] + t(12)["received"]
    actual_captured = d.get("captured_count", len(d.get("captured_events", [])))
    if actual_captured != expected_captured:
        measurement_issues.append(
            f"captured count mismatch: recorded {actual_captured} != received {expected_captured}"
        )

    # Workload execution validity
    workload_valid = (
        w.get("status") == "VALID"
        and w.get("execution_failures", 0) == 0
        and w.get("create_attempts", 0)
        == w.get("create_successes", 0) + w.get("create_failures", 0)
    )
    if not workload_valid:
        measurement_issues.append("workload execution failure or invariant violation")

    measurement_valid = len(measurement_issues) == 0

    # 2. Reconcile Telemetry & Detect Backend Defects
    caps = d.get("captured_events", [])
    records = w.get("records", [])
    p_info = d.get("p_checkpoint", {})
    p_avail = p_info.get("available", False)

    rec = reconcile_events(records, caps, p_available=p_avail)

    c = d.get("target_counters", [0] * 128)
    checks = {
        "memfd_enter_hook": (w["calls"], c[60] if len(c) > 60 else 0),
        "memfd_exit_hook": (w["calls"], c[70] if len(c) > 70 else 0),
        "creation_attempt_records": (w["calls"], t(2)["attempted"]),
        "completion_attempt_records": (w["calls"], t(12)["attempted"]),
        "write_attempt_records": (w["writes"], t(17)["attempted"]),
        "close_attempt_records": (w["closes"], t(16)["attempted"]),
        "fd_install_attempt_records": (w["creates"], t(15)["attempted"]),
    }
    mismatches = {
        k: {"expected": a, "observed": b} for k, (a, b) in checks.items() if a != b
    }
    backend_findings["generation_gaps"] = mismatches

    target_drops = sum(r["reserve_failed"] for r in d["events"] if r["scope"] == 1)
    all_drops = sum(r["reserve_failed"] for r in d["events"] if r["scope"] == 0)
    backend_findings["reservation_drops"] = {
        "target_total": target_drops,
        "global_total": all_drops,
        "by_type": {
            r["type"]: r["reserve_failed"]
            for r in d["events"]
            if r["scope"] == 1 and r["reserve_failed"] > 0
        },
    }

    backend_findings["missing_events"] = {
        "missing_create_count": len(rec["missing_create"]),
        "missing_complete_count": len(rec["missing_complete"]),
        "unaccounted_create_loss": max(
            0, len(rec["missing_create"]) - t(2)["reserve_failed"]
        ),
        "unaccounted_complete_loss": max(
            0, len(rec["missing_complete"]) - t(12)["reserve_failed"]
        ),
    }

    backend_findings["corruption_findings"] = (
        rec["corrupted_events"] + rec["incorrect_outcome"]
    )
    backend_findings["processing_findings"] = rec["p_discrepancies"]
    backend_findings["correlation_findings"] = {
        "duplicate_create_count": len(rec["duplicate_create"]),
        "duplicate_complete_count": len(rec["duplicate_complete"]),
        "unexpected_count": len(rec["unexpected"]),
        "completion_uncorrelated": c[72],
    }

    # Telemetry Completeness: are any events missing or dropped?
    telemetry_complete = (
        target_drops == 0
        and len(rec["missing_create"]) == 0
        and len(rec["missing_complete"]) == 0
        and len(mismatches) == 0
    )

    # Telemetry Fidelity: are all delivered events uncorrupted, conforming to contract?
    # Note: Do not double-count related corruption and processing discrepancies as independent lost events.
    unrelated_p_disc = [
        p for p in rec["p_discrepancies"] if not p.get("related_to_token_corruption")
    ]
    telemetry_fidelity_valid = (
        len(rec["corrupted_events"]) == 0
        and len(rec["incorrect_outcome"]) == 0
        and len(rec["duplicate_complete"]) == 0
        and len(rec["unexpected"]) == 0
        and c[72] == 0
        and len(unrelated_p_disc) == 0
    )

    n_ops_attempted = w.get("create_attempts", len(w.get("records", [])))
    n_reconstructed = rec.get("reconstructed_count", 0)
    n_incomplete = rec.get("incomplete_count", 0)
    operation_residual = n_ops_attempted - (n_reconstructed + n_incomplete)

    c_e2e = (n_reconstructed / n_ops_attempted) if n_ops_attempted > 0 else 1.0
    f_incomplete = (n_incomplete / n_ops_attempted) if n_ops_attempted > 0 else 0.0

    # Independent stage-wise event conservation (Scope 1 = target workload)
    t_create = t(2)
    t_complete = t(12)
    ring_attempted = t_create["attempted"] + t_complete["attempted"]
    ring_reserve_failed = t_create["reserve_failed"] + t_complete["reserve_failed"]
    ring_submitted = t_create["submitted"] + t_complete["submitted"]
    ring_received = t_create["received"] + t_complete["received"]
    ring_residual = ring_attempted - (ring_submitted + ring_reserve_failed)
    transport_loss = ring_submitted - ring_received

    queue_info = d.get("queue", {})
    queue_drops = queue_info.get("drops", 0)
    queue_admission_attempts = queue_info.get("admission_attempts", ring_received)
    queue_enqueued = queue_info.get("enqueued", ring_received)
    queue_dequeued = queue_info.get("dequeued", ring_received)
    queue_residual = (queue_admission_attempts - (queue_enqueued + queue_drops)) if queue_admission_attempts > 0 else 0
    queue_drain_residual = (queue_enqueued - queue_dequeued) if queue_enqueued > 0 else 0

    gen_gap = len(backend_findings["generation_gaps"])
    corr_def = c[72] if len(c) > 72 else 0
    proc_fail = p_info.get("failed", 0) if p_avail else 0

    accounting_residual = (
        operation_residual
        + abs(ring_residual)
        + abs(queue_residual)
        + abs(queue_drain_residual)
    )

    thru = {}
    if timing:
        w_dur = timing.get("workload_duration_sec", 0.0)
        tot_dur = timing.get("total_duration_sec", 0.0)
        drain_s = timing.get("drain_latency_sec", 0.0)
        global_drain_s = timing.get("global_backlog_drain_sec", 0.0)
        thru["offered_throughput_ops_sec"] = (n_ops_attempted / w_dur) if w_dur > 0 else 0.0
        thru["useful_throughput_ops_sec"] = (n_reconstructed / tot_dur) if tot_dur > 0 else 0.0
        thru["drain_latency_ms"] = drain_s * 1000.0
        thru["global_backlog_drain_ms"] = global_drain_s * 1000.0
        thru["workload_duration_sec"] = w_dur
        thru["total_duration_sec"] = tot_dur

    loader_ru = d.get("rusage", {})
    loader_active_cpu_us = loader_ru.get("active_user_cpu_us", loader_ru.get("user_cpu_us", 0)) + loader_ru.get("active_sys_cpu_us", loader_ru.get("sys_cpu_us", 0))
    loader_total_cpu_us = loader_ru.get("total_user_cpu_us", loader_active_cpu_us) + loader_ru.get("total_sys_cpu_us", 0)
    loader_max_rss_kb = loader_ru.get("max_rss_kb", 0)
    workload_cpu_us = w.get("user_cpu_us", 0) + w.get("sys_cpu_us", 0)
    resources = {
        "workload_cpu_us": workload_cpu_us,
        "loader_active_cpu_us": loader_active_cpu_us,
        "loader_total_cpu_us": loader_total_cpu_us,
        "loader_cpu_us": loader_active_cpu_us,
        "loader_max_rss_kb": loader_max_rss_kb,
        "loader_max_rss_mib": round(loader_max_rss_kb / 1024.0, 2),
        "cpu_cost_attempted_us": (loader_active_cpu_us / n_ops_attempted) if n_ops_attempted > 0 else 0.0,
        "cpu_cost_reconstructed_us": (loader_active_cpu_us / n_reconstructed) if n_reconstructed > 0 else 0.0,
        "total_trial_cpu_cost_attempted_us": (loader_total_cpu_us / n_ops_attempted) if n_ops_attempted > 0 else 0.0,
    }

    pipeline_accounting = {
        "ops_attempted": n_ops_attempted,
        "reconstructed": n_reconstructed,
        "incomplete": n_incomplete,
        "operation_residual": operation_residual,
        "validated_create_completeness_c_e2e": c_e2e,
        "completeness_c_e2e": c_e2e,
        "incomplete_create_fraction_f": f_incomplete,
        "incomplete_fraction_f": f_incomplete,
        "evaluated_operation_scope": "memfd_create_intent_and_completion",
        "target_ring_attempted": ring_attempted,
        "target_ring_submitted": ring_submitted,
        "target_ring_loss": ring_reserve_failed,
        "ring_loss": ring_reserve_failed,
        "target_transport_loss": transport_loss,
        "global_queue_admission_attempts": queue_admission_attempts,
        "global_queue_enqueued": queue_enqueued,
        "global_queue_dequeued": queue_dequeued,
        "global_queue_loss": queue_drops,
        "queue_loss": queue_drops,
        "ring_residual": ring_residual,
        "queue_residual": queue_residual,
        "queue_drain_residual": queue_drain_residual,
        "gen_gap": gen_gap,
        "corr_def": corr_def,
        "proc_fail": proc_fail,
        "residual": accounting_residual,
    }

    return {
        "measurement_valid": measurement_valid,
        "telemetry_complete": telemetry_complete,
        "telemetry_fidelity_valid": telemetry_fidelity_valid,
        "measurement_issues": measurement_issues,
        "backend_findings": backend_findings,
        "pipeline_accounting": pipeline_accounting,
        "throughput": thru,
        "resources": resources,
        "queue": queue_info,
        "reconciliation": {
            "missing_create_count": len(rec["missing_create"]),
            "missing_complete_count": len(rec["missing_complete"]),
            "duplicate_create_count": len(rec["duplicate_create"]),
            "duplicate_complete_count": len(rec["duplicate_complete"]),
            "unexpected_count": len(rec["unexpected"]),
            "corrupted_events_count": len(rec["corrupted_events"]),
            "incorrect_outcome_count": len(rec["incorrect_outcome"]),
            "p_discrepancies_count": len(rec["p_discrepancies"]),
        },
        "target_reservation_failures": target_drops,
        "all_reservation_failures": all_drops,
        "p_checkpoint": p_info,
        "map_mutations": d.get("map_mutations", []),
        "target_map_update_failures": {
            r["map"]: r["other_error"] + r["enoent"]
            for r in d.get("map_mutations", [])
            if r["scope"] == 1
            and r["op"] == "update"
            and r["other_error"] + r["enoent"]
        },
        "completion_correlated": c[71] if len(c) > 71 else 0,
        "completion_uncorrelated": c[72] if len(c) > 72 else 0,
        "completion_failed_syscall": c[73] if len(c) > 73 else 0,
        "memfd_completion_rb_error": c[74] if len(c) > 74 else 0,
    }


def trial(
    out,
    name,
    iterations,
    workers,
    pace,
    full,
    stall,
    delay,
    hold,
    cpu=None,
    flags=None,
    quiet=False,
):
    log = out / (name + ".log")
    result = out / (name + ".json")
    truth_path = out / (name + "_ground_truth.json")
    cap_path = out / (name + "_captured_events.json")
    spec = dict(
        name=name,
        iterations_per_worker=iterations,
        workers=workers,
        pace_us=pace,
        full_callback=full,
        stall=stall,
        callback_delay_us=delay,
        hold_fds=hold,
        cpu=cpu,
        flags=flags,
        quiet=quiet,
    )
    p = w = None
    try:
        w_env = dict(os.environ, EPHIM_GROUND_TRUTH_FILE=str(truth_path))
        w_cmd = [
            str(BUILD / "workload"),
            str(iterations),
            str(workers),
            str(pace),
            str(int(hold)),
        ]
        if flags is not None:
            w_cmd.append(str(flags))

        w = subprocess.Popen(
            w_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=w_env,
        )
        if line_with_timeout(w.stdout, 5) != "WORKLOAD_READY":
            stderr_out = w.stderr.read() if w.stderr else ""
            raise RuntimeError(f"bad workload handshake: {stderr_out}")
        if cpu is not None:
            os.sched_setaffinity(w.pid, {cpu})
        env = dict(
            os.environ,
            EPHIM_DIAG_PID=str(w.pid),
            EPHIM_DIAG_FULL=str(int(full)),
            EPHIM_DIAG_DELAY_US=str(delay),
            EPHIM_CAPTURED_EVENTS_FILE=str(cap_path),
            EPHIM_QUIET="1" if quiet else "0",
        )
        loader_cmd = [str(BUILD / "loader.diag")]
        if quiet:
            loader_cmd.append("-q")
        with log.open("w") as f:
            p = subprocess.Popen(
                loader_cmd,
                cwd=ROOT,
                env=env,
                stdout=f,
                stderr=subprocess.STDOUT,
            )
            wait_ready(p, log)
            if stall:
                os.kill(p.pid, signal.SIGSTOP)
                stopped(p.pid)
            t_workload_start = time.monotonic()
            w.stdin.write("\n")
            w.stdin.flush()
            truth = json.loads(line_with_timeout(w.stdout, 180))
            t_workload_done = time.monotonic()
            if ("records" not in truth or not truth["records"]) and truth_path.exists():
                try:
                    truth["records"] = json.loads(truth_path.read_text()).get(
                        "records", []
                    )
                except Exception:
                    pass
            if stall:
                os.kill(p.pid, signal.SIGCONT)
            time.sleep(0.25)
            p.send_signal(signal.SIGINT)
            if p.wait(timeout=120) != 0:
                raise RuntimeError("loader returned failure")
            t_processing_complete = time.monotonic()

        d = get_result(log)
        meas_timing = d.get("timing", {})
        start_ts_ns = truth.get("start_ts_ns", 0)
        done_ts_ns = truth.get("done_ts_ns", 0)
        target_first_ts_ns = meas_timing.get("target_first_event_proc_ts_ns", meas_timing.get("first_event_proc_ts_ns", 0))
        target_last_ts_ns = meas_timing.get("target_last_event_proc_ts_ns", meas_timing.get("last_event_proc_ts_ns", 0))
        global_last_ts_ns = meas_timing.get("global_last_event_ts_ns", 0)

        if start_ts_ns and done_ts_ns and done_ts_ns >= start_ts_ns:
            workload_duration_sec = (done_ts_ns - start_ts_ns) / 1e9
        elif "seconds" in truth and truth["seconds"] > 0:
            workload_duration_sec = truth["seconds"]
        else:
            workload_duration_sec = max(0.0001, t_workload_done - t_workload_start)

        if target_last_ts_ns and done_ts_ns and target_last_ts_ns > done_ts_ns:
            drain_latency_sec = (target_last_ts_ns - done_ts_ns) / 1e9
        else:
            drain_latency_sec = 0.0

        if global_last_ts_ns and done_ts_ns and global_last_ts_ns > done_ts_ns:
            global_backlog_drain_sec = (global_last_ts_ns - done_ts_ns) / 1e9
        else:
            global_backlog_drain_sec = 0.0

        if target_last_ts_ns and start_ts_ns and target_last_ts_ns > start_ts_ns:
            total_duration_sec = max(workload_duration_sec, (target_last_ts_ns - start_ts_ns) / 1e9)
        else:
            total_duration_sec = workload_duration_sec + drain_latency_sec

        timing = {
            "workload_start_ns": start_ts_ns,
            "workload_done_ns": done_ts_ns,
            "target_first_event_proc_ts_ns": target_first_ts_ns,
            "target_last_event_proc_ts_ns": target_last_ts_ns,
            "first_event_proc_ts_ns": target_first_ts_ns,
            "last_event_proc_ts_ns": target_last_ts_ns,
            "global_last_event_ts_ns": global_last_ts_ns,
            "workload_duration_sec": workload_duration_sec,
            "drain_latency_sec": drain_latency_sec,
            "global_backlog_drain_sec": global_backlog_drain_sec,
            "total_duration_sec": total_duration_sec,
        }
        if d["pid"] != w.pid:
            raise RuntimeError("wrong target PID")
        if (
            "captured_events" not in d or not d["captured_events"]
        ) and cap_path.exists():
            try:
                d["captured_events"] = json.loads(cap_path.read_text())
            except Exception:
                pass
        analysis = analyse(d, truth, timing=timing)
        report = {
            "status": "VALID" if analysis["measurement_valid"] else "INVALID",
            "test": spec,
            "workload": truth,
            "measurement": d,
            "analysis": analysis,
        }
    except Exception as e:
        report = {"status": "INVALID", "test": spec, "error": str(e)}
    finally:
        if p is not None and p.poll() is None:
            p.send_signal(signal.SIGCONT)
            p.send_signal(signal.SIGINT)
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
        if w is not None:
            if w.poll() is None:
                try:
                    w.stdin.write("\n")
                    w.stdin.flush()
                    w.wait(timeout=3)
                except (OSError, subprocess.TimeoutExpired):
                    w.kill()
                    w.wait()
            if w.stdin:
                w.stdin.close()
            if w.stdout:
                w.stdout.close()
            if w.stderr:
                w.stderr.close()

    result.write_text(json.dumps(report, indent=2))
    if "measurement" in report:
        with (out / (name + ".csv")).open("w", newline="") as f:
            fields = [
                "scope",
                "type",
                "event",
                "attempted",
                "reserve_failed",
                "submitted",
                "received",
                "loss_pct",
            ]
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            for r in report["measurement"]["events"]:
                writer.writerow(
                    dict(
                        r,
                        event=EVENTS.get(r["type"], "UNKNOWN"),
                        loss_pct=(
                            round(100 * r["reserve_failed"] / r["attempted"], 4)
                            if r["attempted"]
                            else ""
                        ),
                    )
                )
        a = report["analysis"]
        rec = a["reconciliation"]
        pipe = a.get("pipeline_accounting", {})
        thru = a.get("throughput", {})
        res = a.get("resources", {})
        q_tag = " (quiet)" if spec.get("quiet") else ""
        c_pct = pipe.get("completeness_c_e2e", 1.0) * 100.0
        print(
            f"{name}{q_tag}: {report['status']} | complete={a['telemetry_complete']} (C_e2e={c_pct:.1f}%, drops={a['target_reservation_failures']}, q_drops={pipe.get('queue_loss', 0)}) | fidelity={a['telemetry_fidelity_valid']} (corrupt={rec['corrupted_events_count']}, p_disc={rec['p_discrepancies_count']}) | gaps={len(a['backend_findings']['generation_gaps'])} | offered={thru.get('offered_throughput_ops_sec', 0.0):.0f} op/s, useful={thru.get('useful_throughput_ops_sec', 0.0):.0f} op/s, drain={thru.get('drain_latency_ms', 0.0):.1f}ms, RSS={res.get('loader_max_rss_mib', 0.0)}MiB",
            flush=True,
        )
        if "profiling" in report["measurement"]:
            prof = report["measurement"]["profiling"]
            tot = prof.get("total_callback", {})
            ps = prof.get("process_state", {})
            prov = prof.get("provenance", {})
            prov_excl = prof.get("provenance_exclusive", {})
            logg = prof.get("logging", {})
            p_diag = prof.get("p_diag_overhead", {})
            q_flag = " [QUIET]" if prof.get("quiet_mode") else ""
            print(
                f"  [PROFILE]{q_flag} Callback: avg={tot.get('avg_ns', 0)}ns (total={tot.get('total_ns', 0)/1e6:.2f}ms) | PS={ps.get('avg_ns', 0)}ns | Prov={prov.get('avg_ns', 0)}ns (excl={prov_excl.get('avg_ns', 0)}ns) | Log={logg.get('avg_ns', 0)}ns | DiagP={p_diag.get('avg_ns', 0)}ns",
                flush=True,
            )
    else:
        print(name, report["status"], report.get("error", ""), flush=True)
    return report


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["build", "run"])
    ap.add_argument(
        "--suite", choices=["quick", "pressure", "map", "cpu", "benchmark"], default="quick"
    )
    ap.add_argument(
        "--quiet",
        action="store_true",
        help="Run loader in quiet mode (bypass presentation logging)",
    )
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--hold", type=int, default=10000)
    ap.add_argument("--iterations", type=int, default=5000)
    ap.add_argument("--workers", type=int, default=4)
    a = ap.parse_args()
    if a.action == "build":
        build()
        return 0
    if os.geteuid() != 0:
        ap.error("run on your local Linux host using sudo")
    if not (
        1 <= a.repeat <= 20
        and 1 <= a.workers <= 64
        and 1 <= a.iterations <= 1000000
        and 1 <= a.hold <= 100000
    ):
        ap.error("invalid bounds")
    info = json.loads((BUILD / "build_info.json").read_text())
    for key, path in [
        ("bpf_sha256", "src/bpf/monitor.bpf.c"),
        ("loader_sha256", "src/user/loader.c"),
        ("provenance_sha256", "src/user/provenance.c"),
        ("header_sha256", "src/user/provenance.h"),
    ]:
        if hashlib.sha256((ROOT / path).read_bytes()).hexdigest() != info[key]:
            ap.error("production source changed; rebuild first")
    out = HERE / "results" / time.strftime("%Y%m%d-%H%M%S")
    out.mkdir(parents=True, exist_ok=False)
    (out / "environment.json").write_text(
        json.dumps(
            dict(
                info,
                online_cpus=sorted(os.sched_getaffinity(0)),
                suite=a.suite,
                quiet=a.quiet,
            ),
            indent=2,
        )
    )
    # Quick suite includes single, paced fast, paced full (low-pressure P verification), fast, full, and stall.
    if a.suite == "quick":
        cases = [
            ("single", 1, 1, 1000, False, False, 0, False),
            ("paced", 100, 1, 1000, False, False, 0, False),
            ("paced_full", 100, 1, 1000, True, False, 0, False),
            ("fast", a.iterations, 1, 0, False, False, 0, False),
            ("full", a.iterations, 1, 0, True, False, 0, False),
            ("stall", a.iterations, 1, 0, False, True, 0, False),
        ]
    elif a.suite == "pressure":
        cases = [
            ("parallel_fast", a.iterations, a.workers, 0, False, False, 0, False),
            ("parallel_full", a.iterations, a.workers, 0, True, False, 0, False),
            ("slow", a.iterations, a.workers, 0, False, False, 100, False),
            ("parallel_stall", a.iterations, a.workers, 0, False, True, 0, False),
        ]
    elif a.suite == "map":
        cases = [("hold_paced", a.hold, 1, 100, False, False, 0, True)]
    elif a.suite == "benchmark":
        cases = [
            ("W_PACED", 500, 1, 1000, True, False, 0, False),
            ("W_BURST", 2500, 4, 0, True, False, 0, False),
            ("W_SUSTAIN", 15000, 4, 50, True, False, 0, False),
            ("W_CONTENTION", 5000, 8, 0, True, False, 0, False),
            ("W_REGISTRY", 10000, 1, 100, True, False, 0, True),
        ]
    else:
        cases = [
            (f"cpu_{c}", 100, 1, 1000, False, False, 0, False, c)
            for c in sorted(os.sched_getaffinity(0))
        ]
    reports = []
    for i in range(a.repeat):
        for case in cases:
            report = trial(out, case[0] + f"_{i+1}", *case[1:], quiet=a.quiet)
            reports.append(report)
            if report["status"] == "INVALID":
                break
        if reports[-1]["status"] == "INVALID":
            break
    (out / "summary.json").write_text(json.dumps(reports, indent=2))
    print("Results:", out)
    return 0 if all(r["status"] == "VALID" for r in reports) else 1


if __name__ == "__main__":
    sys.exit(main())
