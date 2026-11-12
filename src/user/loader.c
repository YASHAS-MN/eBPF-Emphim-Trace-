
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/sysmacros.h>
#include <sys/stat.h>
#include <time.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <ctype.h>
#include "provenance.h"

enum log_level {
    LOG_LEVEL_ERROR = 0,
    LOG_LEVEL_INFO  = 1,
    LOG_LEVEL_DEBUG = 2,
};

static enum log_level current_log_level = LOG_LEVEL_INFO;

#define log_error(fmt, ...) \
    do { \
        if (current_log_level >= LOG_LEVEL_ERROR) \
            fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__); \
    } while (0)

#define log_info(fmt, ...) \
    do { \
        if (current_log_level >= LOG_LEVEL_INFO) \
            fprintf(stdout, fmt "\n", ##__VA_ARGS__); \
    } while (0)

#define log_debug(fmt, ...) \
    do { \
        if (current_log_level >= LOG_LEVEL_DEBUG) \
            fprintf(stdout, "[DEBUG] " fmt "\n", ##__VA_ARGS__); \
    } while (0)

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG && current_log_level < LOG_LEVEL_DEBUG)
        return 0;
    if (level == LIBBPF_INFO && current_log_level < LOG_LEVEL_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

#define DEBUG_STAGE_SYSCALL_ENTRY 1
#define DEBUG_STAGE_VFS_ENTRY     2
#define DEBUG_STAGE_VFS_EXIT      3
#define DEBUG_STAGE_SYSCALL_EXIT  4

#define VFS_IDENTITY_INODE_VALID   (1 << 0)
#define VFS_IDENTITY_DEV_VALID     (1 << 1)
#define VFS_IDENTITY_MNT_VALID     (1 << 2)
#define VFS_IDENTITY_NAME_VALID    (1 << 3)
#define VFS_IDENTITY_SYSCALL_VALID (1 << 4)

#define PATH_VALID       1
#define PATH_TRUNCATED   2
#define PATH_UNAVAILABLE 3

#define MEMFD_STATUS_FAILED               1
#define MEMFD_STATUS_SUCCESS_CORRELATED   2
#define MEMFD_STATUS_SUCCESS_UNCORRELATED 3

static uint64_t next_memfd_instance_id = 1;

enum counter_idx {
    CNT_UNLINK_ENTER = 0,
    CNT_UNLINK_MAP_UPD_OK = 1,
    CNT_UNLINK_MAP_UPD_ERR = 2,
    CNT_UNLINK_RB_OK = 3,
    CNT_UNLINK_RB_SUBMIT = 4,

    CNT_UNLINKAT_ENTER = 10,
    CNT_UNLINKAT_MAP_UPD_OK = 11,
    CNT_UNLINKAT_MAP_UPD_ERR = 12,
    CNT_UNLINKAT_RB_OK = 13,
    CNT_UNLINKAT_RB_SUBMIT = 14,

    CNT_RMDIR_ENTER = 20,
    CNT_RMDIR_MAP_UPD_OK = 21,
    CNT_RMDIR_MAP_UPD_ERR = 22,
    CNT_RMDIR_RB_OK = 23,
    CNT_RMDIR_RB_SUBMIT = 24,

    CNT_VFS_UNLINK_ENTRY = 30,
    CNT_VFS_UNLINK_PENDING_FOUND = 31,
    CNT_VFS_UNLINK_PENDING_MISSING = 32,
    CNT_VFS_UNLINK_EXIT = 33,

    CNT_VFS_RMDIR_ENTRY = 40,
    CNT_VFS_RMDIR_PENDING_FOUND = 41,
    CNT_VFS_RMDIR_PENDING_MISSING = 42,
    CNT_VFS_RMDIR_EXIT = 43,

    CNT_UNLINK_EXIT = 50,
    CNT_UNLINK_EXIT_CLEANUP = 51,
    CNT_UNLINKAT_EXIT = 52,
    CNT_UNLINKAT_EXIT_CLEANUP = 53,
    CNT_RMDIR_EXIT = 54,
    CNT_RMDIR_EXIT_CLEANUP = 55,

    /* Memfd creation counters */
    CNT_MEMFD_ENTER = 60,
    CNT_MEMFD_MAP_UPD_OK = 61,
    CNT_MEMFD_MAP_UPD_ERR = 62,

    CNT_FD_INSTALL_TOTAL = 65,
    CNT_FD_INSTALL_MATCH = 66,
    CNT_FD_INSTALL_ERR = 67,

    CNT_MEMFD_EXIT = 70,
    CNT_MEMFD_CORRELATED = 71,
    CNT_MEMFD_UNCORRELATED = 72,
    CNT_MEMFD_FAILED = 73,
    CNT_MEMFD_RB_ERR = 74,

    /* M2.1 Registry counters */
    CNT_REG_INODE_INSERT_OK = 80,
    CNT_REG_INODE_INSERT_ERR = 81,
    CNT_REG_FILE_INSERT_OK = 82,
    CNT_REG_FILE_INSERT_ERR = 83,
    CNT_REG_COMMITTED = 84,
    CNT_REG_PROVISIONAL_DROPPED = 85,
    CNT_REG_RETIRED = 86,
    CNT_REG_REOPEN_MATCH = 87,
    CNT_REG_FILE_DELETE_OK = 88,
    CNT_REG_FILE_DELETE_ERR = 89,
    CNT_REG_INODE_ROLLBACK = 90,
    CNT_REG_TOKEN_ERR = 91,
    CNT_REG_MAP_FULL_DROP = 92,
    CNT_REG_INODE_DELETE_ERR = 93,
    CNT_REG_TOKEN_MISMATCH = 94,
    CNT_FD_CLOSED_MATCH = 95,
    CNT_MEMFD_WRITE_OPS = 96,
    CNT_MEMFD_WRITE_BYTES = 97,
    CNT_MEMFD_EXEC_ATTEMPT = 98,
    CNT_MEMFD_EXEC_SUCCESS = 99,
    CNT_MEMFD_EXEC_FAIL = 100,

    CNT_MAX_COUNTERS = 128
};

#define MAX_PROCESSES 4096
#define MAX_THREADS 8192

struct process_state {
    uint32_t pid;
    uint64_t start_time_ns;
    uint32_t parent_pid;
    uint32_t last_tid;
    uint32_t thread_count;
    uint32_t exec_count;
    int active;
    char executable[256];
};

struct thread_state {
    uint32_t tid;
    uint32_t tgid;
    uint64_t start_time_ns;
};

static struct process_state processes[MAX_PROCESSES];
static struct thread_state threads[MAX_THREADS];

static int process_count;
static int thread_count;

static struct process_state *find_process(uint32_t pid, uint64_t start_time_ns)
{
    /* Require a valid, non-zero start_time_ns for process resolution.
     * Never fall back to PID alone: an unknown or unavailable generation identity
     * must never cause an event to merge into an existing process record.
     */
    if (start_time_ns == 0)
        return NULL;

    for (int i = 0; i < process_count; i++) {
        if (processes[i].pid == pid && processes[i].start_time_ns == start_time_ns)
            return &processes[i];
    }

    return NULL;
}

static int find_thread(uint32_t tid, uint32_t tgid, uint64_t start_time_ns)
{
    for (int i = 0; i < thread_count; i++) {
        if (threads[i].tid == tid &&
            threads[i].tgid == tgid &&
            threads[i].start_time_ns == start_time_ns)
            return i;
    }

    return -1;
}

static struct process_state *create_process(
    uint32_t pid,
    uint64_t start_time_ns,
    uint32_t parent_pid,
    uint32_t tid
)
{
    /* Do not create or track process records if generation identifier is unknown (0) */
    if (start_time_ns == 0)
        return NULL;

    struct process_state *p = find_process(pid, start_time_ns);

    if (p) {
        if (p->active)
            return p;

        *p = (struct process_state){0};
    } else {
        if (process_count < MAX_PROCESSES) {
            p = &processes[process_count++];
            *p = (struct process_state){0};
        } else {
            /* Table full: reuse an inactive slot if available */
            for (int i = 0; i < MAX_PROCESSES; i++) {
                if (!processes[i].active && processes[i].thread_count == 0) {
                    p = &processes[i];
                    *p = (struct process_state){0};
                    break;
                }
            }
            if (!p)
                return NULL;
        }
    }

    p->pid = pid;
    p->start_time_ns = start_time_ns;
    p->parent_pid = parent_pid;
    p->last_tid = tid;
    p->active = 1;

    return p;
}

static struct process_state *get_process(
    uint32_t pid,
    uint64_t start_time_ns,
    uint32_t tid,
    uint32_t ppid
)
{
    if (start_time_ns == 0)
        return NULL;

    struct process_state *p = find_process(pid, start_time_ns);

    if (p && p->active)
        return p;

    return create_process(pid, start_time_ns, ppid, tid);
}

static void remember_thread(uint32_t tid, uint32_t tgid, uint64_t start_time_ns)
{
    if (start_time_ns == 0)
        return;

    /* Check if this thread entry for this exact (TID, TGID, start_time_ns) is already known */
    int idx = find_thread(tid, tgid, start_time_ns);
    if (idx >= 0)
        return;

    /* If this TID exists under an older generation or different TGID (e.g. TID reuse),
     * retire the old thread record first.
     */
    for (int i = 0; i < thread_count; i++) {
        if (threads[i].tid == tid) {
            struct process_state *old_p = find_process(threads[i].tgid, threads[i].start_time_ns);
            if (old_p && old_p->thread_count > 0)
                old_p->thread_count--;

            threads[i] = threads[--thread_count];
            break;
        }
    }

    if (thread_count < MAX_THREADS) {
        threads[thread_count].tid = tid;
        threads[thread_count].tgid = tgid;
        threads[thread_count].start_time_ns = start_time_ns;
        thread_count++;

        struct process_state *p = find_process(tgid, start_time_ns);
        if (p)
            p->thread_count++;
    }
}

static void remove_thread(uint32_t tid, uint32_t tgid, uint64_t start_time_ns)
{
    int idx = -1;

    if (start_time_ns != 0) {
        idx = find_thread(tid, tgid, start_time_ns);
    } else {
        /* Fallback if exit event lacks start_time_ns: match by TID and TGID */
        for (int i = 0; i < thread_count; i++) {
            if (threads[i].tid == tid && threads[i].tgid == tgid) {
                idx = i;
                break;
            }
        }
    }

    if (idx < 0)
        return;

    uint32_t thread_tgid = threads[idx].tgid;
    uint64_t thread_start_time = threads[idx].start_time_ns;

    struct process_state *p = find_process(thread_tgid, thread_start_time);
    if (p && p->thread_count > 0)
        p->thread_count--;

    threads[idx] = threads[--thread_count];
}

static void remove_process_threads(uint32_t tgid, uint64_t start_time_ns)
{
    for (int i = 0; i < thread_count;) {
        if (threads[i].tgid == tgid &&
            (start_time_ns == 0 || threads[i].start_time_ns == start_time_ns)) {
            threads[i] = threads[--thread_count];
        } else {
            i++;
        }
    }

    struct process_state *p = find_process(tgid, start_time_ns);
    if (p)
        p->thread_count = 0;
}

static void print_process_state(const struct process_state *p)
{
    if (!p)
        return;

    printf("[PROCESS_STATE]\n");
    printf("PID: %u\n", p->pid);
    printf("Start Time: %llu ns\n", (unsigned long long)p->start_time_ns);
    printf("PPID: %u\n", p->parent_pid);
    printf("Executable: %s\n", p->executable[0] ? p->executable : "<unavailable>");
    printf("Threads: %u\n", p->thread_count);
    printf("Exec count: %u\n", p->exec_count);
    printf("Active: %s\n", p->active ? "yes" : "no");
}

static void update_process_state(const struct event *e)
{
    if (e->type == EVENT_DEBUG)
        return;
    if (e->type == EVENT_FORK) {
        /* Ensure parent process record exists using parent's start_time_ns */
        get_process(e->pid, e->start_time_ns, e->tid, e->ppid);

        if (e->child_tgid != e->pid) {
            /* New process: create child process with child_start_time_ns */
            create_process(
                e->child_tgid,
                e->child_start_time_ns,
                e->pid,
                e->child_pid
            );
            remember_thread(e->child_pid, e->child_tgid, e->child_start_time_ns);
        } else {
            /* Thread clone in existing process: child shares parent's start_time_ns */
            remember_thread(e->child_pid, e->child_tgid, e->start_time_ns);
        }

        /* Register/confirm parent thread */
        remember_thread(e->tid, e->pid, e->start_time_ns);
        return;
    }

    struct process_state *p = get_process(
        e->pid, e->start_time_ns, e->tid, e->ppid
    );

    /* Register calling thread now that the process record is guaranteed to exist */
    remember_thread(e->tid, e->pid, e->start_time_ns);

    if (!p)
        return;

    p->last_tid = e->tid;

    if (e->type == EVENT_PROCESS_EXEC) {
        p->exec_count++;

        snprintf(
            p->executable,
            sizeof(p->executable),
            "%s",
            e->name
        );
    }

    if (e->type == EVENT_PROCESS_EXIT) {
        remove_thread(e->tid, e->pid, e->start_time_ns);

        if (e->reserved) {
            p->active = 0;
            remove_process_threads(e->pid, e->start_time_ns);
        }
    }
}

static volatile sig_atomic_t running = 1;
static volatile sig_atomic_t sigusr1_received = 0;
static volatile sig_atomic_t sigusr2_received = 0;

static void handle_sigint(int sig)
{
    (void)sig;
    running = 0;
}

static void handle_sigusr1(int sig)
{
    (void)sig;
    sigusr1_received = 1;
}

static void handle_sigusr2(int sig)
{
    (void)sig;
    sigusr2_received = 1;
}


static const char *diag_instance_dir = "/sys/kernel/tracing/instances/ephim_diag";
static int diag_instance_created = 0;

static int read_tracefs_int(const char *subpath)
{
    char path[256];
    snprintf(path, sizeof(path), "/sys/kernel/tracing/%s", subpath);
    FILE *f = fopen(path, "r");
    if (!f) {
        snprintf(path, sizeof(path), "/sys/kernel/debug/tracing/%s", subpath);
        f = fopen(path, "r");
    }
    if (!f) return -1;
    int val = -1;
    if (fscanf(f, "%d", &val) != 1) val = -1;
    fclose(f);
    return val;
}

static void print_tracefs_format(const char *category, const char *name)
{
    if (current_log_level < LOG_LEVEL_DEBUG)
        return;
    char path[256];
    snprintf(path, sizeof(path), "/sys/kernel/tracing/events/%s/%s/format", category, name);
    FILE *f = fopen(path, "r");
    if (!f) {
        snprintf(path, sizeof(path), "/sys/kernel/debug/tracing/events/%s/%s/format", category, name);
        f = fopen(path, "r");
    }
    if (!f) return;
    printf("[TRACEFS FORMAT] %s/%s:\n", category, name);
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        printf("    %s", line);
    }
    fclose(f);
}

static int write_tracefs_str(const char *subpath, const char *val)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", diag_instance_dir, subpath);
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fputs(val, f);
    fclose(f);
    return 0;
}

static void setup_diag_instance(void)
{
    if (mkdir(diag_instance_dir, 0755) != 0 && errno != EEXIST) {
        diag_instance_dir = "/sys/kernel/debug/tracing/instances/ephim_diag";
        if (mkdir(diag_instance_dir, 0755) != 0 && errno != EEXIST) {
            fprintf(stderr, "[DIAG_OBSERVER] Could not create tracefs instance %s: %s\n",
                    diag_instance_dir, strerror(errno));
            return;
        }
    }
    diag_instance_created = 1;
    write_tracefs_str("tracing_on", "0\n");
    write_tracefs_str("trace", "\n");
    write_tracefs_str("events/syscalls/sys_enter_unlink/enable", "1\n");
    write_tracefs_str("events/syscalls/sys_exit_unlink/enable", "1\n");
    write_tracefs_str("events/syscalls/sys_enter_unlinkat/enable", "1\n");
    write_tracefs_str("events/syscalls/sys_exit_unlinkat/enable", "1\n");
    write_tracefs_str("events/syscalls/sys_enter_rmdir/enable", "1\n");
    write_tracefs_str("events/syscalls/sys_exit_rmdir/enable", "1\n");
    write_tracefs_str("tracing_on", "1\n");
    log_debug("[DIAG_OBSERVER] Independent tracefs instance active at %s", diag_instance_dir);
}

static void dump_diag_instance(void)
{
    if (!diag_instance_created || current_log_level < LOG_LEVEL_DEBUG) return;
    char path[256];
    snprintf(path, sizeof(path), "%s/trace", diag_instance_dir);
    FILE *f = fopen(path, "r");
    if (!f) return;
    printf("\n================ [INDEPENDENT TRACEFS OBSERVER: RECORDED EVENTS] ================\n");
    char line[512];
    int count = 0;
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || strlen(line) < 10) continue;
        if (strstr(line, "sys_enter_unlink") || strstr(line, "sys_exit_unlink") ||
            strstr(line, "sys_enter_rmdir") || strstr(line, "sys_exit_rmdir")) {
            printf("  [TRACEFS] %s", line);
            count++;
        }
    }
    printf("  Total observed independent tracefs events: %d\n", count);
    printf("=================================================================================\n\n");
    fclose(f);
    fflush(stdout);
}

static void cleanup_diag_instance(void)
{
    if (!diag_instance_created) return;
    write_tracefs_str("tracing_on", "0\n");
    write_tracefs_str("events/enable", "0\n");
    rmdir(diag_instance_dir);
}

static void print_counters_table(int cnt_fd)
{
    if (cnt_fd < 0) return;

    uint64_t c[CNT_MAX_COUNTERS] = {0};
    for (uint32_t k = 0; k < CNT_MAX_COUNTERS; k++) {
        uint32_t key = k;
        uint64_t val = 0;
        if (bpf_map_lookup_elem(cnt_fd, &key, &val) == 0) {
            c[k] = val;
        }
    }

    printf("\n================ [BPF PROG EXECUTION COUNTERS] ================\n");
    printf("  [UNLINK]     sys_enter: %-6llu | map_ok: %-6llu | map_err: %-6llu | rb_ok: %-6llu | rb_submit: %-6llu\n",
           (unsigned long long)c[CNT_UNLINK_ENTER], (unsigned long long)c[CNT_UNLINK_MAP_UPD_OK],
           (unsigned long long)c[CNT_UNLINK_MAP_UPD_ERR], (unsigned long long)c[CNT_UNLINK_RB_OK],
           (unsigned long long)c[CNT_UNLINK_RB_SUBMIT]);
    printf("  [UNLINKAT]   sys_enter: %-6llu | map_ok: %-6llu | map_err: %-6llu | rb_ok: %-6llu | rb_submit: %-6llu\n",
           (unsigned long long)c[CNT_UNLINKAT_ENTER], (unsigned long long)c[CNT_UNLINKAT_MAP_UPD_OK],
           (unsigned long long)c[CNT_UNLINKAT_MAP_UPD_ERR], (unsigned long long)c[CNT_UNLINKAT_RB_OK],
           (unsigned long long)c[CNT_UNLINKAT_RB_SUBMIT]);
    printf("  [RMDIR]      sys_enter: %-6llu | map_ok: %-6llu | map_err: %-6llu | rb_ok: %-6llu | rb_submit: %-6llu\n",
           (unsigned long long)c[CNT_RMDIR_ENTER], (unsigned long long)c[CNT_RMDIR_MAP_UPD_OK],
           (unsigned long long)c[CNT_RMDIR_MAP_UPD_ERR], (unsigned long long)c[CNT_RMDIR_RB_OK],
           (unsigned long long)c[CNT_RMDIR_RB_SUBMIT]);
    printf("  --------------------------------------------------------------\n");
    printf("  [VFS_UNLINK] entry: %-6llu | pending_found: %-6llu | pending_missing: %-6llu | exit: %-6llu\n",
           (unsigned long long)c[CNT_VFS_UNLINK_ENTRY], (unsigned long long)c[CNT_VFS_UNLINK_PENDING_FOUND],
           (unsigned long long)c[CNT_VFS_UNLINK_PENDING_MISSING], (unsigned long long)c[CNT_VFS_UNLINK_EXIT]);
    printf("  [VFS_RMDIR]  entry: %-6llu | pending_found: %-6llu | pending_missing: %-6llu | exit: %-6llu\n",
           (unsigned long long)c[CNT_VFS_RMDIR_ENTRY], (unsigned long long)c[CNT_VFS_RMDIR_PENDING_FOUND],
           (unsigned long long)c[CNT_VFS_RMDIR_PENDING_MISSING], (unsigned long long)c[CNT_VFS_RMDIR_EXIT]);
    printf("  --------------------------------------------------------------\n");
    printf("  [SYS_EXIT]   unlink_exit: %-6llu (cleanup: %-6llu)\n",
           (unsigned long long)c[CNT_UNLINK_EXIT], (unsigned long long)c[CNT_UNLINK_EXIT_CLEANUP]);
    printf("               unlinkat_exit: %-6llu (cleanup: %-6llu)\n",
           (unsigned long long)c[CNT_UNLINKAT_EXIT], (unsigned long long)c[CNT_UNLINKAT_EXIT_CLEANUP]);
    printf("               rmdir_exit: %-6llu (cleanup: %-6llu)\n",
           (unsigned long long)c[CNT_RMDIR_EXIT], (unsigned long long)c[CNT_RMDIR_EXIT_CLEANUP]);
    printf("  --------------------------------------------------------------\n");
    printf("  [MEMFD]      sys_enter: %-6llu | map_ok: %-6llu | map_err: %-6llu\n",
           (unsigned long long)c[CNT_MEMFD_ENTER], (unsigned long long)c[CNT_MEMFD_MAP_UPD_OK],
           (unsigned long long)c[CNT_MEMFD_MAP_UPD_ERR]);
    printf("  [FD_INSTALL] total: %-6llu | match: %-6llu | err: %-6llu | closed_match: %-6llu\n",
           (unsigned long long)c[CNT_FD_INSTALL_TOTAL], (unsigned long long)c[CNT_FD_INSTALL_MATCH],
           (unsigned long long)c[CNT_FD_INSTALL_ERR], (unsigned long long)c[CNT_FD_CLOSED_MATCH]);
    printf("  [MEMFD_WRITE] ops: %-6llu | bytes: %-6llu\n",
           (unsigned long long)c[CNT_MEMFD_WRITE_OPS], (unsigned long long)c[CNT_MEMFD_WRITE_BYTES]);
    printf("  [MEMFD_EXEC]  attempt: %-6llu | success: %-6llu | fail: %-6llu\n",
           (unsigned long long)c[CNT_MEMFD_EXEC_ATTEMPT],
           (unsigned long long)c[CNT_MEMFD_EXEC_SUCCESS],
           (unsigned long long)c[CNT_MEMFD_EXEC_FAIL]);
    printf("  [MEMFD_EXIT] exit: %-6llu | correlated: %-6llu | uncorrelated: %-6llu | failed: %-6llu | rb_err: %-6llu\n",
           (unsigned long long)c[CNT_MEMFD_EXIT], (unsigned long long)c[CNT_MEMFD_CORRELATED],
           (unsigned long long)c[CNT_MEMFD_UNCORRELATED], (unsigned long long)c[CNT_MEMFD_FAILED],
           (unsigned long long)c[CNT_MEMFD_RB_ERR]);
    printf("  --------------------------------------------------------------\n");
    printf("  [REGISTRY]   inode_ok: %-6llu | inode_err: %-6llu | file_ok: %-6llu | file_err: %-6llu\n",
           (unsigned long long)c[CNT_REG_INODE_INSERT_OK], (unsigned long long)c[CNT_REG_INODE_INSERT_ERR],
           (unsigned long long)c[CNT_REG_FILE_INSERT_OK], (unsigned long long)c[CNT_REG_FILE_INSERT_ERR]);
    printf("               committed: %-6llu | prov_drop: %-6llu | retired: %-6llu | reopen_match: %-6llu\n",
           (unsigned long long)c[CNT_REG_COMMITTED], (unsigned long long)c[CNT_REG_PROVISIONAL_DROPPED],
           (unsigned long long)c[CNT_REG_RETIRED], (unsigned long long)c[CNT_REG_REOPEN_MATCH]);
    printf("               file_del_ok: %-6llu | file_del_err: %-6llu | ino_rollback: %-6llu | ino_del_err: %-6llu\n",
           (unsigned long long)c[CNT_REG_FILE_DELETE_OK], (unsigned long long)c[CNT_REG_FILE_DELETE_ERR],
           (unsigned long long)c[CNT_REG_INODE_ROLLBACK], (unsigned long long)c[CNT_REG_INODE_DELETE_ERR]);
    printf("               token_err: %-6llu | token_mismatch: %-6llu | map_full_drop: %-6llu\n",
           (unsigned long long)c[CNT_REG_TOKEN_ERR], (unsigned long long)c[CNT_REG_TOKEN_MISMATCH],
           (unsigned long long)c[CNT_REG_MAP_FULL_DROP]);
    printf("===============================================================\n\n");
    fflush(stdout);
    dump_diag_instance();
}

static int handle_event(void *ctx, void *data, size_t size)
{
    (void)ctx;

    const struct event *e = data;

    update_process_state(e);
    prov_engine_process_event(e);

    if (size != sizeof(*e))
        return 0;

    switch (e->type) {
    case EVENT_EXECVE:
        printf("[EXECVE] PID: %u PPID: %u Path: %s\n",
               e->pid, e->ppid, e->name);
        break;

    case EVENT_MEMFD_CREATE:
        printf("[MEMFD_CREATE] PID: %u PPID: %u Name: %s Flags: 0x%x\n",
               e->pid, e->ppid, e->name, e->flags);
        break;

    case EVENT_MEMFD_COMPLETED: {
        const char *status_str = "UNKNOWN";
        uint64_t instance_id = 0;
        char inode_buf[32] = "<unavailable>";
        char dev_buf[64] = "<unavailable>";
        char mnt_buf[32] = "<unavailable>";
        char id_buf[32] = "<none>";

        if (e->op_type == MEMFD_STATUS_FAILED) {
            status_str = "FAILED";
        } else if (e->op_type == MEMFD_STATUS_SUCCESS_CORRELATED) {
            status_str = "SUCCESS_CORRELATED";
            instance_id = e->object_token ? e->object_token : next_memfd_instance_id++;
            snprintf(id_buf, sizeof(id_buf), "%llu", (unsigned long long)instance_id);

            if ((e->flags & VFS_IDENTITY_INODE_VALID) && e->inode_no != 0)
                snprintf(inode_buf, sizeof(inode_buf), "%llu", (unsigned long long)e->inode_no);
            if (e->flags & VFS_IDENTITY_DEV_VALID)
                snprintf(dev_buf, sizeof(dev_buf), "%u:%u (%llu)", major(e->dev_id), minor(e->dev_id), (unsigned long long)e->dev_id);
            if (e->mnt_ns_id != 0)
                snprintf(mnt_buf, sizeof(mnt_buf), "%u", e->mnt_ns_id);
        } else if (e->op_type == MEMFD_STATUS_SUCCESS_UNCORRELATED) {
            status_str = "SUCCESS_UNCORRELATED";
        }

        const char *dentry_name_ptr = (e->flags & VFS_IDENTITY_NAME_VALID && e->path[0]) ? e->path : (e->path[0] ? e->path : "<unavailable>");

        printf("[MEMFD_COMPLETED] Status: %s InstanceID: %s PID: %u TID: %u PPID: %u StartTime: %llu ns Name: %s Flags: 0x%x RetVal: %d FD: %d Target: %s Inode: %s Device: %s MountNS: %s EntryTime: %llu ns CompletionTime: %llu ns\n",
               status_str,
               id_buf,
               e->pid,
               e->tid,
               e->ppid,
               (unsigned long long)e->start_time_ns,
               e->name[0] ? e->name : "<unavailable>",
               e->syscall_flags,
               e->ret_val,
               e->fd,
               dentry_name_ptr,
               inode_buf,
               dev_buf,
               mnt_buf,
               (unsigned long long)e->entry_ts_ns,
               (unsigned long long)e->timestamp_ns);
        break;
    }

    case EVENT_MEMFD_DESTROYED: {
        printf("[MEMFD_DESTROYED] Token: %llu Inode: %llu Device: %u:%u (%llu) Name: %s\n",
               (unsigned long long)e->object_token,
               (unsigned long long)e->inode_no,
               major(e->dev_id), minor(e->dev_id), (unsigned long long)e->dev_id,
               e->name[0] ? e->name : "<unavailable>");
        break;
    }

    case EVENT_MEMFD_FILE_RELEASED: {
        printf("[MEMFD_FILE_RELEASED] Token: %llu Inode: %llu\n",
               (unsigned long long)e->object_token,
               (unsigned long long)e->inode_no);
        break;
    }

    case EVENT_FD_INSTALLED: {
        if (current_log_level >= LOG_LEVEL_DEBUG) {
            const char *type_str = "UNKNOWN";
            if (e->op_type == 1) type_str = "CREATION";
            else if (e->op_type == 2) type_str = "REOPEN";
            else if (e->op_type == 3) type_str = "DUP";
            printf("[FD_INSTALLED] PID: %u FD: %d Token: %llu Type: %s\n",
                   e->pid, e->fd, (unsigned long long)e->object_token, type_str);
        }
        break;
    }

    case EVENT_FD_CLOSED: {
        if (current_log_level >= LOG_LEVEL_DEBUG) {
            printf("[FD_CLOSED]    PID: %u FD: %d Token: %llu\n",
                   e->pid, e->fd, (unsigned long long)e->object_token);
        }
        break;
    }

    case EVENT_MEMFD_WRITE: {
        if (current_log_level >= LOG_LEVEL_DEBUG) {
            printf("[MEMFD_WRITE] PID: %u Token: %llu Offset: %lld Bytes: %zu\n",
                   e->pid, (unsigned long long)e->object_token,
                   (long long)e->entry_ts_ns, (size_t)e->ret_val);
        }
        break;
    }

    case EVENT_MEMFD_EXEC_ATTEMPT: {
        if (current_log_level >= LOG_LEVEL_DEBUG) {
            printf("[MEMFD_EXEC_ATTEMPT] PID: %u TID: %u Token: %llu File: %s\n",
                   e->pid, e->tid, (unsigned long long)e->object_token,
                   e->name[0] ? e->name : "<unknown>");
        }
        break;
    }

    case EVENT_MEMFD_EXEC_SUCCESS: {
        if (current_log_level >= LOG_LEVEL_DEBUG) {
            printf("[MEMFD_EXEC_SUCCESS] PID: %u TID: %u Token: %llu Binary: %s\n",
                   e->pid, e->tid, (unsigned long long)e->object_token,
                   e->name[0] ? e->name : "<unknown>");
        }
        break;
    }

    case EVENT_UNLINK:
        printf("[UNLINK] PID: %u PPID: %u Path: %s\n",
               e->pid, e->ppid, e->name);
        break;

    case EVENT_UNLINKAT:
        printf("[UNLINKAT] PID: %u PPID: %u DirFD: %d Path: %s Flags: 0x%x\n",
               e->pid, e->ppid, e->dirfd, e->name, e->flags);
        break;

    case EVENT_CONNECT: {
        char ip[INET6_ADDRSTRLEN] = "<unsupported>";

        if (e->family == AF_INET)
            inet_ntop(AF_INET, e->address, ip, sizeof(ip));
        else if (e->family == AF_INET6)
            inet_ntop(AF_INET6, e->address, ip, sizeof(ip));

        printf("[CONNECT] PID: %u PPID: %u FD: %d Destination: %s:%u Family: %u\n",
               e->pid, e->ppid, e->fd, ip,
               ntohs(e->port), e->family);
        break;
    }

    case EVENT_FORK:
        printf("[FORK] Parent PID: %u Parent TID: %u Child PID: %u Child TID: %u Child: %s\n",
               e->pid, e->tid, e->child_tgid, e->child_pid, e->name);
        if (e->child_tgid != e->pid) {
            /* New process: output child's initial process state */
            print_process_state(find_process(e->child_tgid, e->child_start_time_ns));
        } else {
            /* Thread clone: output parent process's updated state */
            print_process_state(find_process(e->pid, e->start_time_ns));
        }
        break;

    case EVENT_PROCESS_EXEC:
        printf("[PROCESS_EXEC] PID/TID: %u Old PID/TID: %u Executable: %s\n",
               e->pid, e->old_pid, e->name);
        print_process_state(find_process(e->pid, e->start_time_ns));
        break;

    case EVENT_PROCESS_EXIT:
        printf("[PROCESS_EXIT] PID/TID: %u Process: %s Group dead: %s\n",
               e->pid, e->name, e->reserved ? "yes" : "no");
        print_process_state(find_process(e->pid, e->start_time_ns));
        break;

    case EVENT_RMDIR:
        printf("[RMDIR] PID: %u PPID: %u Path: %s\n",
               e->pid, e->ppid,
               e->path_status == PATH_TRUNCATED ? "[TRUNCATED]" : (e->path[0] ? e->path : (e->name[0] ? e->name : "<unavailable>")));
        break;

    case EVENT_VFS_UNLINK_COMPLETED: {
        char inode_buf[32] = "<unavailable>";
        char dev_buf[64] = "<unavailable>";
        char mnt_buf[32] = "<unavailable>";
        char syscall_buf[64] = "<unmatched>";
        char path_buf[300] = "<unavailable>";
        char dirfd_buf[32] = "<unavailable>";
        char flags_buf[32] = "<unavailable>";

        if ((e->flags & VFS_IDENTITY_INODE_VALID) && e->inode_no != 0)
            snprintf(inode_buf, sizeof(inode_buf), "%llu", (unsigned long long)e->inode_no);
        else if (e->inode_no != 0)
            snprintf(inode_buf, sizeof(inode_buf), "%llu", (unsigned long long)e->inode_no);

        if (e->flags & VFS_IDENTITY_DEV_VALID)
            snprintf(dev_buf, sizeof(dev_buf), "%u:%u (%llu)", major(e->dev_id), minor(e->dev_id), (unsigned long long)e->dev_id);
        else if (e->dev_id != 0)
            snprintf(dev_buf, sizeof(dev_buf), "%u:%u (%llu)", major(e->dev_id), minor(e->dev_id), (unsigned long long)e->dev_id);

        if ((e->flags & VFS_IDENTITY_MNT_VALID) && e->mnt_ns_id != 0)
            snprintf(mnt_buf, sizeof(mnt_buf), "%u", e->mnt_ns_id);
        else if (e->mnt_ns_id != 0)
            snprintf(mnt_buf, sizeof(mnt_buf), "%u", e->mnt_ns_id);

        if (e->flags & VFS_IDENTITY_SYSCALL_VALID) {
            if (e->op_type == EVENT_UNLINK)
                snprintf(syscall_buf, sizeof(syscall_buf), "unlink");
            else if (e->op_type == EVENT_UNLINKAT)
                snprintf(syscall_buf, sizeof(syscall_buf), "unlinkat");
            else if (e->op_type == EVENT_RMDIR)
                snprintf(syscall_buf, sizeof(syscall_buf), "rmdir");
            else
                snprintf(syscall_buf, sizeof(syscall_buf), "op_%u", e->op_type);

            if (e->dirfd == -100)
                snprintf(dirfd_buf, sizeof(dirfd_buf), "AT_FDCWD");
            else
                snprintf(dirfd_buf, sizeof(dirfd_buf), "%d", e->dirfd);

            snprintf(flags_buf, sizeof(flags_buf), "0x%x", e->syscall_flags);

            if (e->path_status == PATH_TRUNCATED)
                snprintf(path_buf, sizeof(path_buf), "[TRUNCATED] %s...", e->path);
            else if (e->path_status == PATH_VALID && e->path[0])
                snprintf(path_buf, sizeof(path_buf), "%s", e->path);
            else
                snprintf(path_buf, sizeof(path_buf), "<unavailable>");
        }

        const char *name_ptr = (e->flags & VFS_IDENTITY_NAME_VALID && e->name[0]) ? e->name : (e->name[0] ? e->name : "<unavailable>");

        printf("[VFS_UNLINK_COMPLETED] PID: %u TID: %u PPID: %u StartTime: %llu ns Syscall: %s Path: %s (status=%s) DirFD: %s SyscallFlags: %s Target: %s Inode: %s Device: %s MountNS: %s EntryTime: %llu ns CompletionTime: %llu ns Status: %s (ret=%d)\n",
               e->pid,
               e->tid,
               e->ppid,
               (unsigned long long)e->start_time_ns,
               syscall_buf,
               path_buf,
               (e->flags & VFS_IDENTITY_SYSCALL_VALID) ? (e->path_status == PATH_VALID ? "VALID" : (e->path_status == PATH_TRUNCATED ? "TRUNCATED" : "UNAVAILABLE")) : "UNMATCHED",
               dirfd_buf,
               flags_buf,
               name_ptr,
               inode_buf,
               dev_buf,
               mnt_buf,
               (unsigned long long)e->entry_ts_ns,
               (unsigned long long)e->timestamp_ns,
               e->ret_val == 0 ? "SUCCESS" : "FAILED",
               e->ret_val);
        break;
    }

    case EVENT_VFS_RMDIR_COMPLETED: {
        char inode_buf[32] = "<unavailable>";
        char dev_buf[64] = "<unavailable>";
        char mnt_buf[32] = "<unavailable>";
        char syscall_buf[64] = "<unmatched>";
        char path_buf[300] = "<unavailable>";
        char dirfd_buf[32] = "<unavailable>";
        char flags_buf[32] = "<unavailable>";

        if ((e->flags & VFS_IDENTITY_INODE_VALID) && e->inode_no != 0)
            snprintf(inode_buf, sizeof(inode_buf), "%llu", (unsigned long long)e->inode_no);
        else if (e->inode_no != 0)
            snprintf(inode_buf, sizeof(inode_buf), "%llu", (unsigned long long)e->inode_no);

        if (e->flags & VFS_IDENTITY_DEV_VALID)
            snprintf(dev_buf, sizeof(dev_buf), "%u:%u (%llu)", major(e->dev_id), minor(e->dev_id), (unsigned long long)e->dev_id);
        else if (e->dev_id != 0)
            snprintf(dev_buf, sizeof(dev_buf), "%u:%u (%llu)", major(e->dev_id), minor(e->dev_id), (unsigned long long)e->dev_id);

        if ((e->flags & VFS_IDENTITY_MNT_VALID) && e->mnt_ns_id != 0)
            snprintf(mnt_buf, sizeof(mnt_buf), "%u", e->mnt_ns_id);
        else if (e->mnt_ns_id != 0)
            snprintf(mnt_buf, sizeof(mnt_buf), "%u", e->mnt_ns_id);

        if (e->flags & VFS_IDENTITY_SYSCALL_VALID) {
            if (e->op_type == EVENT_UNLINK)
                snprintf(syscall_buf, sizeof(syscall_buf), "unlink");
            else if (e->op_type == EVENT_UNLINKAT)
                snprintf(syscall_buf, sizeof(syscall_buf), "unlinkat");
            else if (e->op_type == EVENT_RMDIR)
                snprintf(syscall_buf, sizeof(syscall_buf), "rmdir");
            else
                snprintf(syscall_buf, sizeof(syscall_buf), "op_%u", e->op_type);

            if (e->dirfd == -100)
                snprintf(dirfd_buf, sizeof(dirfd_buf), "AT_FDCWD");
            else
                snprintf(dirfd_buf, sizeof(dirfd_buf), "%d", e->dirfd);

            snprintf(flags_buf, sizeof(flags_buf), "0x%x", e->syscall_flags);

            if (e->path_status == PATH_TRUNCATED)
                snprintf(path_buf, sizeof(path_buf), "[TRUNCATED] %s...", e->path);
            else if (e->path_status == PATH_VALID && e->path[0])
                snprintf(path_buf, sizeof(path_buf), "%s", e->path);
            else
                snprintf(path_buf, sizeof(path_buf), "<unavailable>");
        }

        const char *name_ptr = (e->flags & VFS_IDENTITY_NAME_VALID && e->name[0]) ? e->name : (e->name[0] ? e->name : "<unavailable>");

        printf("[VFS_RMDIR_COMPLETED] PID: %u TID: %u PPID: %u StartTime: %llu ns Syscall: %s Path: %s (status=%s) DirFD: %s SyscallFlags: %s Target: %s Inode: %s Device: %s MountNS: %s EntryTime: %llu ns CompletionTime: %llu ns Status: %s (ret=%d)\n",
               e->pid,
               e->tid,
               e->ppid,
               (unsigned long long)e->start_time_ns,
               syscall_buf,
               path_buf,
               (e->flags & VFS_IDENTITY_SYSCALL_VALID) ? (e->path_status == PATH_VALID ? "VALID" : (e->path_status == PATH_TRUNCATED ? "TRUNCATED" : "UNAVAILABLE")) : "UNMATCHED",
               dirfd_buf,
               flags_buf,
               name_ptr,
               inode_buf,
               dev_buf,
               mnt_buf,
               (unsigned long long)e->entry_ts_ns,
               (unsigned long long)e->timestamp_ns,
               e->ret_val == 0 ? "SUCCESS" : "FAILED",
               e->ret_val);
        break;
    }

    case EVENT_DEBUG: {
        if (current_log_level < LOG_LEVEL_DEBUG)
            break;
        if (e->flags == DEBUG_STAGE_SYSCALL_ENTRY) {
            printf("[DIAG:SYSCALL_ENTRY] PID: %u TID: %u Op: %u StartTime: %llu ns MapUpdateRet: %d PathStatus: %u Path: %s Info: %s\n",
                   e->pid, e->tid, e->op_type, (unsigned long long)e->start_time_ns,
                   e->ret_val, e->path_status, e->path[0] ? e->path : "<none>", e->name);
        } else if (e->flags == DEBUG_STAGE_VFS_ENTRY) {
            const char *reason_str = "UNKNOWN";
            if (e->path_status == 0) reason_str = "ACCEPTED";
            else if (e->path_status == 1) reason_str = "REJECT_NO_PENDING_ENTRY";
            else if (e->path_status == 2) reason_str = "REJECT_TGID_MISMATCH";
            else if (e->path_status == 3) reason_str = "REJECT_START_TIME_MISMATCH";
            else if (e->path_status == 4) reason_str = "REJECT_OP_MISMATCH";

            printf("[DIAG:VFS_ENTRY] PID: %u TID: %u ExpectedOp: %u CurrentStartTime: %llu ns PendingFound: %d StoredTGID: %u StoredStartTime: %llu ns Reason: %s StoredPath: %s\n",
                   e->pid, e->tid, e->op_type, (unsigned long long)e->start_time_ns,
                   e->ret_val, e->child_tgid, (unsigned long long)e->child_start_time_ns,
                   reason_str, e->path[0] ? e->path : "<none>");
        } else if (e->flags == DEBUG_STAGE_VFS_EXIT) {
            printf("[DIAG:VFS_EXIT] PID: %u TID: %u SnapshotFound: %d SyscallValid: %d Target: %s Path: %s\n",
                   e->pid, e->tid, e->ret_val, e->reserved,
                   e->name[0] ? e->name : "<none>", e->path[0] ? e->path : "<none>");
        } else if (e->flags == DEBUG_STAGE_SYSCALL_EXIT) {
            printf("[DIAG:SYSCALL_EXIT] PID: %u TID: %u ExpectedOp: %u StoredEntryFound: %d Path: %s\n",
                   e->pid, e->tid, e->op_type, e->ret_val,
                   e->path[0] ? e->path : "<none>");
        }
        break;
    }
    }

    fflush(stdout);
    return 0;
}

static int parse_online_cpus(int **out_cpus, int *out_count)
{
    FILE *f = fopen("/sys/devices/system/cpu/online", "r");
    if (!f)
        return -1;

    char line[256];
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return -1;
    }
    fclose(f);

    /* Strip newline and trailing whitespace */
    char *end = line + strlen(line) - 1;
    while (end >= line && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }

    int capacity = 16;
    int count = 0;
    int *cpus = malloc(capacity * sizeof(int));
    if (!cpus)
        return -1;

    char *saveptr = NULL;
    char *token = strtok_r(line, ",", &saveptr);
    while (token) {
        char *dash = strchr(token, '-');
        if (dash) {
            *dash = '\0';
            int start = atoi(token);
            int stop = atoi(dash + 1);
            if (start > stop) {
                int tmp = start;
                start = stop;
                stop = tmp;
            }
            for (int cpu = start; cpu <= stop; cpu++) {
                if (count >= capacity) {
                    capacity *= 2;
                    int *tmp = realloc(cpus, capacity * sizeof(int));
                    if (!tmp) {
                        free(cpus);
                        return -1;
                    }
                    cpus = tmp;
                }
                cpus[count++] = cpu;
            }
        } else {
            int cpu = atoi(token);
            if (count >= capacity) {
                capacity *= 2;
                int *tmp = realloc(cpus, capacity * sizeof(int));
                if (!tmp) {
                    free(cpus);
                    return -1;
                }
                cpus = tmp;
            }
            cpus[count++] = cpu;
        }
        token = strtok_r(NULL, ",", &saveptr);
    }

    *out_cpus = cpus;
    *out_count = count;
    return 0;
}

enum hook_group {
    HOOK_GROUP_LIFECYCLE,
    HOOK_GROUP_SYSCALL_ENTRY,
    HOOK_GROUP_SYSCALL_EXIT,
    HOOK_GROUP_VFS,
    HOOK_GROUP_MAX
};

static const char *hook_group_titles[HOOK_GROUP_MAX] = {
    [HOOK_GROUP_LIFECYCLE]     = "Process lifecycle",
    [HOOK_GROUP_SYSCALL_ENTRY] = "Syscall entry",
    [HOOK_GROUP_SYSCALL_EXIT]  = "Syscall exit",
    [HOOK_GROUP_VFS]           = "VFS",
};

enum hook_type {
    HOOK_TYPE_TRACEPOINT,
    HOOK_TYPE_PER_CPU_TRACEPOINT,
    HOOK_TYPE_RAW_TRACEPOINT,
    HOOK_TYPE_TRAMPOLINE,
};

struct hook_spec {
    const char *prog_name;
    const char *category;
    const char *target;
    enum hook_group group;
    enum hook_type type;
};

static const struct hook_spec required_hooks[] = {
    /* Process lifecycle */
    {
        .prog_name = "capture_process_fork",
        .category  = "sched",
        .target    = "sched_process_fork",
        .group     = HOOK_GROUP_LIFECYCLE,
        .type      = HOOK_TYPE_RAW_TRACEPOINT,
    },
    {
        .prog_name = "capture_process_exec",
        .category  = "sched",
        .target    = "sched_process_exec",
        .group     = HOOK_GROUP_LIFECYCLE,
        .type      = HOOK_TYPE_TRACEPOINT,
    },
    {
        .prog_name = "capture_process_exit",
        .category  = "sched",
        .target    = "sched_process_exit",
        .group     = HOOK_GROUP_LIFECYCLE,
        .type      = HOOK_TYPE_TRACEPOINT,
    },

    /* Syscall entry: 5 per-CPU hooks for mayfault workaround */
    {
        .prog_name = "capture_execve",
        .category  = "syscalls",
        .target    = "sys_enter_execve",
        .group     = HOOK_GROUP_SYSCALL_ENTRY,
        .type      = HOOK_TYPE_PER_CPU_TRACEPOINT,
    },
    {
        .prog_name = "capture_memfd_create",
        .category  = "syscalls",
        .target    = "sys_enter_memfd_create",
        .group     = HOOK_GROUP_SYSCALL_ENTRY,
        .type      = HOOK_TYPE_PER_CPU_TRACEPOINT,
    },
    {
        .prog_name = "capture_unlink",
        .category  = "syscalls",
        .target    = "sys_enter_unlink",
        .group     = HOOK_GROUP_SYSCALL_ENTRY,
        .type      = HOOK_TYPE_PER_CPU_TRACEPOINT,
    },
    {
        .prog_name = "capture_unlinkat",
        .category  = "syscalls",
        .target    = "sys_enter_unlinkat",
        .group     = HOOK_GROUP_SYSCALL_ENTRY,
        .type      = HOOK_TYPE_PER_CPU_TRACEPOINT,
    },
    {
        .prog_name = "capture_rmdir",
        .category  = "syscalls",
        .target    = "sys_enter_rmdir",
        .group     = HOOK_GROUP_SYSCALL_ENTRY,
        .type      = HOOK_TYPE_PER_CPU_TRACEPOINT,
    },
    /* capture_connect retains single attachment (user_mask is 0) */
    {
        .prog_name = "capture_connect",
        .category  = "syscalls",
        .target    = "sys_enter_connect",
        .group     = HOOK_GROUP_SYSCALL_ENTRY,
        .type      = HOOK_TYPE_TRACEPOINT,
    },

    /* Syscall exit */
    {
        .prog_name = "capture_unlink_exit",
        .category  = "syscalls",
        .target    = "sys_exit_unlink",
        .group     = HOOK_GROUP_SYSCALL_EXIT,
        .type      = HOOK_TYPE_TRACEPOINT,
    },
    {
        .prog_name = "capture_unlinkat_exit",
        .category  = "syscalls",
        .target    = "sys_exit_unlinkat",
        .group     = HOOK_GROUP_SYSCALL_EXIT,
        .type      = HOOK_TYPE_TRACEPOINT,
    },
    {
        .prog_name = "capture_rmdir_exit",
        .category  = "syscalls",
        .target    = "sys_exit_rmdir",
        .group     = HOOK_GROUP_SYSCALL_EXIT,
        .type      = HOOK_TYPE_TRACEPOINT,
    },
    {
        .prog_name = "capture_memfd_create_exit",
        .category  = "syscalls",
        .target    = "sys_exit_memfd_create",
        .group     = HOOK_GROUP_SYSCALL_EXIT,
        .type      = HOOK_TYPE_TRACEPOINT,
    },

    /* VFS */
    {
        .prog_name = "capture_fd_install",
        .category  = "vfs",
        .target    = "fd_install",
        .group     = HOOK_GROUP_VFS,
        .type      = HOOK_TYPE_TRAMPOLINE,
    },
    {
        .prog_name = "capture_shmem_evict_inode",
        .category  = "vfs",
        .target    = "shmem_evict_inode",
        .group     = HOOK_GROUP_VFS,
        .type      = HOOK_TYPE_TRAMPOLINE,
    },
    {
        .prog_name = "capture_fput",
        .category  = "vfs",
        .target    = "__fput",
        .group     = HOOK_GROUP_VFS,
        .type      = HOOK_TYPE_TRAMPOLINE,
    },
    {
        .prog_name = "capture_shmem_write_iter",
        .category  = "vfs",
        .target    = "shmem_file_write_iter",
        .group     = HOOK_GROUP_VFS,
        .type      = HOOK_TYPE_TRAMPOLINE,
    },
    {
        .prog_name = "capture_close_fd",
        .category  = "vfs",
        .target    = "close_fd",
        .group     = HOOK_GROUP_VFS,
        .type      = HOOK_TYPE_TRAMPOLINE,
    },
    {
        .prog_name = "capture_bprm_check",
        .category  = "security",
        .target    = "security_bprm_check",
        .group     = HOOK_GROUP_VFS,
        .type      = HOOK_TYPE_TRAMPOLINE,
    },
    {
        .prog_name = "capture_execve_exit",
        .category  = "syscalls",
        .target    = "sys_exit_execve",
        .group     = HOOK_GROUP_SYSCALL_EXIT,
        .type      = HOOK_TYPE_TRACEPOINT,
    },
    {
        .prog_name = "capture_execveat_exit",
        .category  = "syscalls",
        .target    = "sys_exit_execveat",
        .group     = HOOK_GROUP_SYSCALL_EXIT,
        .type      = HOOK_TYPE_TRACEPOINT,
    },
    {
        .prog_name = "capture_vfs_unlink_entry",
        .category  = "vfs",
        .target    = "vfs_unlink",
        .group     = HOOK_GROUP_VFS,
        .type      = HOOK_TYPE_TRAMPOLINE,
    },
    {
        .prog_name = "capture_vfs_unlink_exit",
        .category  = "vfs",
        .target    = "vfs_unlink",
        .group     = HOOK_GROUP_VFS,
        .type      = HOOK_TYPE_TRAMPOLINE,
    },
    {
        .prog_name = "capture_vfs_rmdir_entry",
        .category  = "vfs",
        .target    = "vfs_rmdir",
        .group     = HOOK_GROUP_VFS,
        .type      = HOOK_TYPE_TRAMPOLINE,
    },
    {
        .prog_name = "capture_vfs_rmdir_exit",
        .category  = "vfs",
        .target    = "vfs_rmdir",
        .group     = HOOK_GROUP_VFS,
        .type      = HOOK_TYPE_TRAMPOLINE,
    },
};

#define NUM_REQUIRED_HOOKS (sizeof(required_hooks) / sizeof(required_hooks[0]))

struct cpu_attachment {
    int cpu_id;
    int perf_fd;
};

struct hook_status {
    const struct hook_spec *spec;
    int attached;
    int err;
    char err_msg[128];
    int prog_fd;
    int link_fd;
    int event_id;
    int tp_enable;

    int cpus_total;
    int cpus_attached;
    int failed_cpu_id;
    struct cpu_attachment *cpu_records;
};

static void close_cpu_attachments(struct cpu_attachment *records, int count)
{
    if (!records)
        return;
    for (int j = count - 1; j >= 0; j--) {
        if (records[j].perf_fd >= 0) {
            ioctl(records[j].perf_fd, PERF_EVENT_IOC_DISABLE, 0);
            close(records[j].perf_fd);
            records[j].perf_fd = -1;
        }
    }
}

static void print_startup_summary(const struct hook_status *statuses, size_t total,
                                  size_t attached_count, size_t total_percpu_attached,
                                  size_t total_percpu_expected)
{
    printf("\n=== EphimTrace Hook Attachment Summary ===\n");
    for (int g = 0; g < HOOK_GROUP_MAX; g++) {
        printf("\n[%s]\n", hook_group_titles[g]);
        for (size_t i = 0; i < total; i++) {
            if (statuses[i].spec->group != (enum hook_group)g)
                continue;

            if (statuses[i].spec->type == HOOK_TYPE_PER_CPU_TRACEPOINT) {
                if (statuses[i].attached) {
                    printf("  [OK]   %-24s (%s/%-22s) [CPUs: %d/%d]\n",
                           statuses[i].spec->prog_name,
                           statuses[i].spec->category,
                           statuses[i].spec->target,
                           statuses[i].cpus_attached,
                           statuses[i].cpus_total);
                } else {
                    if (statuses[i].failed_cpu_id >= 0) {
                        printf("  [FAIL] %-24s (%s/%-22s) [CPUs: %d/%d, failed on CPU %d: %s]\n",
                               statuses[i].spec->prog_name,
                               statuses[i].spec->category,
                               statuses[i].spec->target,
                               statuses[i].cpus_attached,
                               statuses[i].cpus_total,
                               statuses[i].failed_cpu_id,
                               statuses[i].err_msg[0] ? statuses[i].err_msg : "error");
                    } else {
                        printf("  [FAIL] %-24s (%s/%-22s) - error: %s\n",
                               statuses[i].spec->prog_name,
                               statuses[i].spec->category,
                               statuses[i].spec->target,
                               statuses[i].err_msg[0] ? statuses[i].err_msg : "error");
                    }
                }
            } else {
                if (statuses[i].attached) {
                    printf("  [OK]   %-24s (%s/%s)\n",
                           statuses[i].spec->prog_name,
                           statuses[i].spec->category,
                           statuses[i].spec->target);
                } else {
                    printf("  [FAIL] %-24s (%s/%s) - error: %s\n",
                           statuses[i].spec->prog_name,
                           statuses[i].spec->category,
                           statuses[i].spec->target,
                           statuses[i].err_msg[0] ? statuses[i].err_msg : "unknown error");
                }
            }
        }
    }

    printf("\nLOGICAL HOOKS ATTACHED: %zu/%zu\n", attached_count, total);
    if (total_percpu_expected > 0) {
        printf("PER-CPU EVENTS ATTACHED: %zu/%zu\n", total_percpu_attached, total_percpu_expected);
    }
    printf("ATTACHED: %zu/%zu\n", attached_count, total);

    if (attached_count == total && total > 0 &&
        total_percpu_attached == total_percpu_expected) {
        printf("STATUS: READY\n\n");
    } else {
        printf("STATUS: FAILED\n\n");
    }
    fflush(stdout);
}

static uint32_t filter_pid = 0;
static uint64_t filter_token = 0;
static const char *timeline_filepath = "ephimtrace_timeline.md";

static void export_provenance_data(uint32_t target_pid, uint64_t target_token, const char *timeline_path)
{
    prov_engine_export_dot("ephimtrace_dag.dot");
    prov_engine_export_json("ephimtrace_dag.json");
    size_t nc = 0, ec = 0;
    prov_engine_get_counts(&nc, &ec);
    printf("[PROVENANCE] Graph exported: %zu nodes, %zu edges\n", nc, ec);

    if (target_pid != 0 || target_token != 0) {
        prov_engine_export_filtered_dot("ephimtrace_filtered.dot", target_pid, target_token);
        prov_engine_export_filtered_json("ephimtrace_filtered.json", target_pid, target_token);
        printf("[PROVENANCE] Filtered graph exported (PID=%u, Token=%llu): ephimtrace_filtered.dot, ephimtrace_filtered.json\n",
               target_pid, (unsigned long long)target_token);
    }

    if (timeline_path && timeline_path[0]) {
        prov_engine_export_timeline(timeline_path, target_pid, target_token);
        printf("[PROVENANCE] Timeline exported: %s\n", timeline_path);
    }
    fflush(stdout);
}

int main(int argc, char **argv)
{
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            current_log_level = LOG_LEVEL_DEBUG;
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--filter-pid") == 0) {
            if (i + 1 < argc) {
                filter_pid = (uint32_t)strtoul(argv[++i], NULL, 10);
            } else {
                fprintf(stderr, "Error: %s requires a PID argument\n", argv[i]);
                return 1;
            }
        } else if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--filter-token") == 0) {
            if (i + 1 < argc) {
                filter_token = (uint64_t)strtoull(argv[++i], NULL, 10);
            } else {
                fprintf(stderr, "Error: %s requires a token argument\n", argv[i]);
                return 1;
            }
        } else if (strcmp(argv[i], "--timeline") == 0) {
            if (i + 1 < argc) {
                timeline_filepath = argv[++i];
            } else {
                fprintf(stderr, "Error: --timeline requires a filepath argument\n");
                return 1;
            }
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [OPTIONS]\n", argv[0]);
            printf("Options:\n");
            printf("  -v, --verbose               Enable verbose/debug logging\n");
            printf("  -p, --filter-pid <pid>      Set target PID for filtered export\n");
            printf("  -t, --filter-token <token>  Set target object token for filtered export\n");
            printf("  --timeline <filepath>       Path to write forensic timeline (default: ephimtrace_timeline.md)\n");
            printf("  -h, --help                  Show this help message\n");
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            fprintf(stderr, "Usage: %s [-v|--verbose] [-p|--filter-pid <pid>] [-t|--filter-token <token>] [--timeline <file>] [-h|--help]\n", argv[0]);
            return 1;
        }
    }

    libbpf_set_print(libbpf_print_fn);

    int *online_cpus = NULL;
    int online_cpu_count = 0;
    int cpus_parsed = parse_online_cpus(&online_cpus, &online_cpu_count);

    struct bpf_object *obj = NULL;
    struct bpf_link *links[NUM_REQUIRED_HOOKS] = {NULL};
    struct hook_status statuses[NUM_REQUIRED_HOOKS];
    struct ring_buffer *rb = NULL;
    size_t attached_count = 0;
    size_t total_percpu_attached = 0;
    size_t total_percpu_expected = 0;
    int ret = 1;

    for (size_t i = 0; i < NUM_REQUIRED_HOOKS; i++) {
        statuses[i].spec = &required_hooks[i];
        statuses[i].attached = 0;
        statuses[i].err = 0;
        statuses[i].err_msg[0] = '\0';
        statuses[i].prog_fd = -1;
        statuses[i].link_fd = -1;
        statuses[i].event_id = -1;
        statuses[i].tp_enable = -1;

        statuses[i].cpus_total = (required_hooks[i].type == HOOK_TYPE_PER_CPU_TRACEPOINT && cpus_parsed == 0) ? online_cpu_count : 0;
        statuses[i].cpus_attached = 0;
        statuses[i].failed_cpu_id = -1;
        statuses[i].cpu_records = NULL;

        if (required_hooks[i].type == HOOK_TYPE_PER_CPU_TRACEPOINT && cpus_parsed == 0) {
            total_percpu_expected += online_cpu_count;
        }
    }

    signal(SIGINT, handle_sigint);
    signal(SIGUSR1, handle_sigusr1);
    signal(SIGUSR2, handle_sigusr2);

    if (prov_engine_init() != 0) {
        log_error("Failed to initialize provenance engine");
        goto cleanup;
    }

    if (cpus_parsed != 0 || online_cpu_count <= 0) {
        log_error("Failed to parse online CPUs from sysfs");
        for (size_t i = 0; i < NUM_REQUIRED_HOOKS; i++) {
            if (statuses[i].spec->type == HOOK_TYPE_PER_CPU_TRACEPOINT) {
                statuses[i].err = ENOENT;
                snprintf(statuses[i].err_msg, sizeof(statuses[i].err_msg),
                         "Failed to enumerate online CPUs");
            }
        }
        print_startup_summary(statuses, NUM_REQUIRED_HOOKS, 0, 0, total_percpu_expected);
        goto cleanup;
    }

    obj = bpf_object__open_file("build/monitor.bpf.o", NULL);
    long open_err = libbpf_get_error(obj);
    if (open_err) {
        int ec = (int)open_err;
        log_error("Failed to open BPF object 'build/monitor.bpf.o': %d (%s)",
                  ec, strerror(ec < 0 ? -ec : ec));
        for (size_t i = 0; i < NUM_REQUIRED_HOOKS; i++) {
            statuses[i].err = ec;
            snprintf(statuses[i].err_msg, sizeof(statuses[i].err_msg),
                     "BPF object open failed: %s", strerror(ec < 0 ? -ec : ec));
        }
        print_startup_summary(statuses, NUM_REQUIRED_HOOKS, 0, 0, total_percpu_expected);
        if (online_cpus) free(online_cpus);
        return 1;
    }

    int load_err = bpf_object__load(obj);
    if (load_err) {
        log_error("Failed to load BPF object: %d (%s)",
                  load_err, strerror(load_err < 0 ? -load_err : load_err));
        for (size_t i = 0; i < NUM_REQUIRED_HOOKS; i++) {
            statuses[i].err = load_err;
            snprintf(statuses[i].err_msg, sizeof(statuses[i].err_msg),
                     "BPF object load failed: %s", strerror(load_err < 0 ? -load_err : load_err));
        }
        print_startup_summary(statuses, NUM_REQUIRED_HOOKS, 0, 0, total_percpu_expected);
        goto cleanup;
    }

    if (current_log_level >= LOG_LEVEL_DEBUG) {
        setup_diag_instance();
        print_tracefs_format("syscalls", "sys_enter_unlink");
        print_tracefs_format("syscalls", "sys_exit_unlink");
        print_tracefs_format("syscalls", "sys_enter_unlinkat");
        print_tracefs_format("syscalls", "sys_enter_rmdir");
    }

    for (size_t i = 0; i < NUM_REQUIRED_HOOKS; i++) {
        const struct hook_spec *hook = &required_hooks[i];
        struct bpf_program *program = bpf_object__find_program_by_name(obj, hook->prog_name);

        if (!program) {
            statuses[i].attached = 0;
            statuses[i].err = -ENOENT;
            snprintf(statuses[i].err_msg, sizeof(statuses[i].err_msg), "Program not found in BPF object");
            continue;
        }

        int prog_fd = bpf_program__fd(program);
        statuses[i].prog_fd = prog_fd;

        if (hook->type == HOOK_TYPE_PER_CPU_TRACEPOINT) {
            char sub_id[128] = {0};
            snprintf(sub_id, sizeof(sub_id), "events/%s/%s/id", hook->category, hook->target);
            int tp_id = read_tracefs_int(sub_id);
            if (tp_id <= 0) {
                statuses[i].attached = 0;
                statuses[i].err = ENOENT;
                snprintf(statuses[i].err_msg, sizeof(statuses[i].err_msg),
                         "Failed to read tracepoint ID (%s)", sub_id);
                continue;
            }

            statuses[i].event_id = tp_id;
            statuses[i].cpu_records = calloc(online_cpu_count, sizeof(struct cpu_attachment));
            if (!statuses[i].cpu_records) {
                statuses[i].attached = 0;
                statuses[i].err = ENOMEM;
                snprintf(statuses[i].err_msg, sizeof(statuses[i].err_msg),
                         "Memory allocation failed for CPU records");
                continue;
            }

            for (int j = 0; j < online_cpu_count; j++) {
                statuses[i].cpu_records[j].cpu_id = online_cpus[j];
                statuses[i].cpu_records[j].perf_fd = -1;
            }

            int hook_failed = 0;
            for (int j = 0; j < online_cpu_count; j++) {
                int target_cpu = online_cpus[j];
                struct perf_event_attr attr = {0};
                attr.type = PERF_TYPE_TRACEPOINT;
                attr.size = sizeof(attr);
                attr.config = tp_id;

                int pfd = (int)syscall(__NR_perf_event_open, &attr, -1, target_cpu, -1, PERF_FLAG_FD_CLOEXEC);
                if (pfd < 0) {
                    statuses[i].err = errno;
                    statuses[i].failed_cpu_id = target_cpu;
                    snprintf(statuses[i].err_msg, sizeof(statuses[i].err_msg),
                             "perf_event_open failed: %s", strerror(errno));
                    close_cpu_attachments(statuses[i].cpu_records, j);
                    total_percpu_attached -= statuses[i].cpus_attached;
                    statuses[i].cpus_attached = 0;
                    hook_failed = 1;
                    break;
                }

                /*
                 * Kernel tracepoint dispatch architecture:
                 * A tracepoint (trace_event_call) maintains a single global prog_array
                 * shared across all CPUs. When PERF_EVENT_IOC_SET_BPF is called, the BPF
                 * program is added to trace_event_call->prog_array. Calling IOC_SET_BPF
                 * more than once with the same program on the same tracepoint returns
                 * -EEXIST from bpf_prog_array_copy().
                 *
                 * To bypass the Ubuntu 7.0 kernel early-return regression:
                 *   if (hlist_empty(this_cpu_ptr(sys_data->enter_event->perf_events))) return;
                 * we attach the BPF program to the perf event on the first CPU (j == 0)
                 * via PERF_EVENT_IOC_SET_BPF, and open/enable an active perf event on every
                 * other online CPU (j > 0). This populates the per-CPU perf_events list on
                 * every CPU so that perf_syscall_enter() does not exit early. When the
                 * tracepoint triggers on any CPU, trace_call_bpf() dispatches the program
                 * from the tracepoint shared prog_array.
                 */
                if (j == 0) {
                    if (ioctl(pfd, PERF_EVENT_IOC_SET_BPF, prog_fd) < 0) {
                        statuses[i].err = errno;
                        statuses[i].failed_cpu_id = target_cpu;
                        snprintf(statuses[i].err_msg, sizeof(statuses[i].err_msg),
                                 "IOC_SET_BPF failed: %s", strerror(errno));
                        close(pfd);
                        close_cpu_attachments(statuses[i].cpu_records, j);
                        total_percpu_attached -= statuses[i].cpus_attached;
                        statuses[i].cpus_attached = 0;
                        hook_failed = 1;
                        break;
                    }
                }

                if (ioctl(pfd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
                    statuses[i].err = errno;
                    statuses[i].failed_cpu_id = target_cpu;
                    snprintf(statuses[i].err_msg, sizeof(statuses[i].err_msg),
                             "IOC_ENABLE failed: %s", strerror(errno));
                    ioctl(pfd, PERF_EVENT_IOC_DISABLE, 0);
                    close(pfd);
                    close_cpu_attachments(statuses[i].cpu_records, j);
                    total_percpu_attached -= statuses[i].cpus_attached;
                    statuses[i].cpus_attached = 0;
                    hook_failed = 1;
                    break;
                }

                statuses[i].cpu_records[j].perf_fd = pfd;
                statuses[i].cpus_attached++;
                total_percpu_attached++;
            }

            if (!hook_failed && statuses[i].cpus_attached == online_cpu_count) {
                statuses[i].attached = 1;
                attached_count++;
                log_debug("[ATTACHED PER-CPU] %-24s (%s/%-22s) | prog_fd: %-2d | %d CPUs attached",
                          hook->prog_name, hook->category, hook->target,
                          prog_fd, statuses[i].cpus_attached);
            }
            continue;
        }

        /* Single-link hooks */
        if (hook->type == HOOK_TYPE_RAW_TRACEPOINT) {
            links[i] = bpf_program__attach_raw_tracepoint(program, hook->target);
        } else if (hook->type == HOOK_TYPE_TRAMPOLINE) {
            links[i] = bpf_program__attach(program);
        } else {
            links[i] = bpf_program__attach_tracepoint(program, hook->category, hook->target);
        }

        long attach_err = libbpf_get_error(links[i]);
        if (!links[i] || attach_err) {
            int ec = attach_err ? (int)attach_err : (errno ? -errno : -EINVAL);
            statuses[i].attached = 0;
            statuses[i].err = ec;
            snprintf(statuses[i].err_msg, sizeof(statuses[i].err_msg),
                     "%s", strerror(ec < 0 ? -ec : ec));
            links[i] = NULL;
            continue;
        }

        statuses[i].attached = 1;
        attached_count++;
        statuses[i].link_fd = bpf_link__fd(links[i]);

        if (current_log_level >= LOG_LEVEL_DEBUG) {
            char sub_id[128] = {0}, sub_en[128] = {0};
            snprintf(sub_id, sizeof(sub_id), "events/%s/%s/id", hook->category, hook->target);
            snprintf(sub_en, sizeof(sub_en), "events/%s/%s/enable", hook->category, hook->target);
            statuses[i].event_id = read_tracefs_int(sub_id);
            statuses[i].tp_enable = read_tracefs_int(sub_en);

            log_debug("[ATTACHED] %-24s (%s/%-22s) | prog_fd: %-2d | link_fd: %-2d | event_id: %-5d | tracefs_en: %d",
                      hook->prog_name, hook->category, hook->target,
                      statuses[i].prog_fd, statuses[i].link_fd,
                      statuses[i].event_id, statuses[i].tp_enable);
        }
    }

    /* Requirement 4: Re-read online CPU list to verify topology hasn't changed */
    int *verify_cpus = NULL;
    int verify_cpu_count = 0;
    int topology_changed = 0;
    if (parse_online_cpus(&verify_cpus, &verify_cpu_count) < 0 || verify_cpu_count != online_cpu_count) {
        topology_changed = 1;
    } else {
        for (int k = 0; k < online_cpu_count; k++) {
            if (verify_cpus[k] != online_cpus[k]) {
                topology_changed = 1;
                break;
            }
        }
    }
    if (verify_cpus)
        free(verify_cpus);

    if (topology_changed) {
        log_error("CPU topology changed during initialization! Aborting to ensure safety.");
        for (size_t i = 0; i < NUM_REQUIRED_HOOKS; i++) {
            if (statuses[i].spec->type == HOOK_TYPE_PER_CPU_TRACEPOINT && statuses[i].attached) {
                statuses[i].attached = 0;
                attached_count--;
                statuses[i].err = EAGAIN;
                snprintf(statuses[i].err_msg, sizeof(statuses[i].err_msg),
                         "CPU topology changed during initialization");
                close_cpu_attachments(statuses[i].cpu_records, statuses[i].cpus_attached);
                total_percpu_attached -= statuses[i].cpus_attached;
                statuses[i].cpus_attached = 0;
            }
        }
    }

    print_startup_summary(statuses, NUM_REQUIRED_HOOKS, attached_count,
                          total_percpu_attached, total_percpu_expected);

    if (attached_count < NUM_REQUIRED_HOOKS || total_percpu_attached < total_percpu_expected) {
        for (size_t i = 0; i < NUM_REQUIRED_HOOKS; i++) {
            if (!statuses[i].attached) {
                log_error("Hook '%s' (%s/%s) failed to attach: %s",
                          statuses[i].spec->prog_name,
                          statuses[i].spec->category,
                          statuses[i].spec->target,
                          statuses[i].err_msg);
            }
        }
        goto cleanup;
    }

    struct bpf_map *map = bpf_object__find_map_by_name(obj, "events");
    if (!map) {
        log_error("Ring buffer map 'events' not found");
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(map), handle_event, NULL, NULL);
    long rb_err = libbpf_get_error(rb);
    if (!rb || rb_err) {
        int ec = rb_err ? (int)rb_err : (errno ? -errno : -EINVAL);
        rb = NULL;
        log_error("Ring buffer setup failed: %d (%s)", ec, strerror(ec < 0 ? -ec : ec));
        goto cleanup;
    }

    struct bpf_map *cnt_map = bpf_object__find_map_by_name(obj, "prog_counters");
    int cnt_fd = cnt_map ? bpf_map__fd(cnt_map) : -1;

    printf("EphimTrace: Monitoring syscall, VFS, and process lifecycle events. Press Ctrl+C to stop.\n");
    fflush(stdout);

    time_t last_counter_print = time(NULL);

    while (running) {
        int poll_err = ring_buffer__poll(rb, 250);

        if (sigusr1_received) {
            sigusr1_received = 0;
            print_counters_table(cnt_fd);
        }

        if (sigusr2_received) {
            sigusr2_received = 0;
            export_provenance_data(filter_pid, filter_token, timeline_filepath);
        }

        time_t now = time(NULL);
        if (current_log_level >= LOG_LEVEL_DEBUG && (now - last_counter_print >= 2)) {
            last_counter_print = now;
            print_counters_table(cnt_fd);
        }

        if (poll_err == -EINTR)
            continue;

        if (poll_err < 0) {
            log_error("Ring buffer polling failed: %d", poll_err);
            break;
        }
    }

    if (current_log_level >= LOG_LEVEL_DEBUG) {
        printf("\nFinal counter summary at exit:\n");
        print_counters_table(cnt_fd);
    }

    export_provenance_data(filter_pid, filter_token, timeline_filepath);

    ret = 0;

cleanup:
    prov_engine_destroy();
    cleanup_diag_instance();

    /* 1. Disable and close all per-CPU perf-event FDs first to stop event generation */
    for (size_t i = 0; i < NUM_REQUIRED_HOOKS; i++) {
        if (statuses[i].cpu_records) {
            close_cpu_attachments(statuses[i].cpu_records, statuses[i].cpus_total);
            free(statuses[i].cpu_records);
            statuses[i].cpu_records = NULL;
        }
    }

    /* 2. Destroy remaining libbpf links */
    for (size_t i = 0; i < NUM_REQUIRED_HOOKS; i++) {
        if (links[i]) {
            bpf_link__destroy(links[i]);
            links[i] = NULL;
        }
    }

    /* 3. Free the ring buffer */
    if (rb) {
        ring_buffer__free(rb);
        rb = NULL;
    }

    /* 4. Close the BPF object */
    if (obj) {
        bpf_object__close(obj);
        obj = NULL;
    }

    if (online_cpus) {
        free(online_cpus);
        online_cpus = NULL;
    }

    return ret;
}
