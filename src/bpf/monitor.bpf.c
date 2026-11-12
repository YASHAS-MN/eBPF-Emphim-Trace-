
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-declarations"
#include "vmlinux.h"
#pragma clang diagnostic pop

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

struct sys_enter_ctx {
    struct trace_entry ent;
    long id;
    unsigned long args[6];
};

struct sched_fork_ctx {
    struct trace_entry ent;
    __u32 parent_comm_loc;
    __s32 parent_pid;
    __u32 child_comm_loc;
    __s32 child_pid;
};

struct sched_exec_ctx {
    struct trace_entry ent;
    __u32 filename_loc;
    __s32 pid;
    __s32 old_pid;
};

struct sched_exit_ctx {
    struct trace_entry ent;
    char comm[16];
    __s32 pid;
    __s32 prio;
    __u8 group_dead;
};

enum event_type {
    EVENT_EXECVE = 1,
    EVENT_MEMFD_CREATE = 2,
    EVENT_UNLINK = 3,
    EVENT_UNLINKAT = 4,
    EVENT_CONNECT = 5,
    EVENT_FORK = 6,
    EVENT_PROCESS_EXEC = 7,
    EVENT_PROCESS_EXIT = 8,
    EVENT_VFS_UNLINK_COMPLETED = 9,
    EVENT_VFS_RMDIR_COMPLETED = 10,
    EVENT_RMDIR = 11,
    EVENT_MEMFD_COMPLETED = 12,
    EVENT_MEMFD_DESTROYED = 13,
    EVENT_MEMFD_FILE_RELEASED = 14,
    EVENT_FD_INSTALLED = 15,
    EVENT_FD_CLOSED = 16,
    EVENT_MEMFD_WRITE = 17,
    EVENT_MEMFD_EXEC_ATTEMPT = 18,
    EVENT_MEMFD_EXEC_SUCCESS = 19,
    EVENT_DEBUG = 99
};

#define DEBUG_STAGE_SYSCALL_ENTRY 1
#define DEBUG_STAGE_VFS_ENTRY     2
#define DEBUG_STAGE_VFS_EXIT      3
#define DEBUG_STAGE_SYSCALL_EXIT  4

#define REASON_ACCEPTED               0
#define REASON_NO_PENDING_ENTRY       1
#define REASON_TGID_MISMATCH          2
#define REASON_START_TIME_MISMATCH    3
#define REASON_OP_TYPE_MISMATCH       4

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

#define REG_STATE_PROVISIONAL 1
#define REG_STATE_COMMITTED   2

#define FD_INSTALL_OP_CREATION 1
#define FD_INSTALL_OP_REOPEN   2
#define FD_INSTALL_OP_DUP      3

struct event {
    __u32 type;
    __u32 pid;
    __u32 tid;
    __u32 ppid;
    __u32 flags;
    __s32 dirfd;
    __u32 reserved;
    __u64 timestamp_ns;
    __s32 fd;
    __u16 family;
    __u16 port;
    __u8 address[16];
    char name[256];
    __u32 child_pid;
    __u32 old_pid;
    __u32 child_tgid;
    __u64 start_time_ns;
    __u64 child_start_time_ns;
    __u64 inode_no;
    __u64 dev_id;
    __u32 mnt_ns_id;
    __s32 ret_val;
    __u32 op_type;
    __u32 syscall_flags;
    __u64 entry_ts_ns;
    __u32 path_status;
    char path[256];
    __u32 pad;
    __u64 object_token;
};

struct sockaddr_in_local {
    __u16 family;
    __u16 port;
    __u32 addr;
};

struct sockaddr_in6_local {
    __u16 family;
    __u16 port;
    __u32 flowinfo;
    __u8 addr[16];
    __u32 scope_id;
};

struct pending_memfd {
    __u32 tgid;
    __u32 tid;
    __u32 flags;
    __u64 start_time_ns;
    __u64 entry_ts_ns;
    __u32 path_status;
    char name[256];

    __u32 installed;
    __s32 captured_fd;
    __u64 file_cookie;
    __u64 file_ptr;
    __u64 inode_ptr;
    __u64 inode_no;
    __u64 dev_id;
    char dentry_name[256];
    __u32 identity_flags;
    __u32 install_count;
};

struct memfd_object_entry {
    __u64 object_token;
    __u64 inode_no;
    __u64 dev_id;
    __u32 creator_tgid;
    __u32 creator_tid;
    __u64 creator_start_time_ns;
    __u32 creation_flags;
    __u32 state;
    __u64 creation_ts_ns;
    char name[256];
};

/* Inode-anchored registry: struct inode * -> memfd_object_entry */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct memfd_object_entry);
} memfd_inode_registry SEC(".maps");

/* Open-file lookup registry: struct file * -> object_token */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, __u64);
} memfd_file_registry SEC(".maps");

struct descriptor_key {
    __u32 tgid;
    __s32 fd;
};

struct descriptor_entry {
    __u64 object_token;
    __u64 file_ptr;
    __u64 installed_ts_ns;
};

/* Descriptor registry: (tgid, fd) -> (object_token, file_ptr, installed_ts_ns) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct descriptor_key);
    __type(value, struct descriptor_entry);
} memfd_desc_registry SEC(".maps");

/* Pending memfd execution tracking: tid -> object_token */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} pending_memfd_exec SEC(".maps");


/* Monotonic token generator */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} memfd_token_generator SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct pending_memfd);
} pending_memfd_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct pending_memfd);
} memfd_heap SEC(".maps");


struct pending_syscall {
    __u32 op_type;
    __u32 tgid;
    __u32 tid;
    __s32 dirfd;
    __u32 flags;
    __u64 start_time_ns;
    __u64 entry_ts_ns;
    __u32 path_status;
    char path[256];
};

struct vfs_file_identity {
    __u64 inode_no;
    __u64 dev_id;
    __u32 mnt_ns_id;
    __u32 flags;
    char name[256];
    __u32 op_type;
    __u32 syscall_flags;
    __s32 dirfd;
    __u32 path_status;
    __u64 entry_ts_ns;
    char path[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

/* Bounded per-thread maps keyed by TID (__u32) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct pending_syscall);
} pending_syscall_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct vfs_file_identity);
} identity_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct vfs_file_identity);
} unlink_identity_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct vfs_file_identity);
} rmdir_identity_map SEC(".maps");

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

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, CNT_MAX_COUNTERS);
    __type(key, __u32);
    __type(value, __u64);
} prog_counters SEC(".maps");

static __always_inline void inc_counter(__u32 idx)
{
    __u32 key = idx;
    __u64 *val = bpf_map_lookup_elem(&prog_counters, &key);
    if (val)
        __sync_fetch_and_add(val, 1);
}

static __always_inline void fill_process_info(struct event *e)
{
    struct task_struct *task;
    struct task_struct *parent;
    struct task_struct *leader;

    __u64 pid_tgid = bpf_get_current_pid_tgid();

    e->pid = pid_tgid >> 32;
    e->tid = (__u32)pid_tgid;
    e->ppid = 0;
    e->start_time_ns = 0;

    task = (struct task_struct *)bpf_get_current_task_btf();
    if (!task)
        return;

    if (bpf_core_read(&parent, sizeof(parent), &task->real_parent) == 0 &&
        parent != NULL) {
        bpf_core_read(&e->ppid, sizeof(e->ppid), &parent->tgid);
    }

    /* Process identity strictly requires the process leader's start_boottime.
     * If reading the group_leader pointer or leader->start_boottime fails,
     * start_time_ns remains 0 (unavailable). Do NOT fall back to task->start_boottime.
     */
    if (bpf_core_read(&leader, sizeof(leader), &task->group_leader) == 0 &&
        leader != NULL) {
        bpf_core_read(&e->start_time_ns, sizeof(e->start_time_ns), &leader->start_boottime);
    }
}

static __always_inline struct event *new_event(__u32 type)
{
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return NULL;

    e->type = type;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->flags = 0;
    e->dirfd = -1;
    e->reserved = 0;
    e->fd = -1;
    e->family = 0;
    e->port = 0;
    e->child_pid = 0;
    e->old_pid = 0;
    e->child_tgid = 0;
    e->start_time_ns = 0;
    e->child_start_time_ns = 0;
    e->inode_no = 0;
    e->dev_id = 0;
    e->mnt_ns_id = 0;
    e->ret_val = 0;
    e->op_type = 0;
    e->syscall_flags = 0;
    e->entry_ts_ns = 0;
    e->path_status = PATH_UNAVAILABLE;
    e->pad = 0;

    __builtin_memset(e->address, 0, sizeof(e->address));
    __builtin_memset(e->name, 0, sizeof(e->name));
    __builtin_memset(e->path, 0, sizeof(e->path));

    fill_process_info(e);

    return e;
}

static __always_inline int submit_path_event(
    struct sys_enter_ctx *ctx,
    __u32 type,
    __u32 path_index,
    __s32 dirfd,
    __u32 flags
)
{
    struct event *e = new_event(type);

    if (!e)
        return 0;

    e->flags = flags;
    e->dirfd = dirfd;

    if (bpf_probe_read_user_str(
        e->name,
        sizeof(e->name),
        (const char *)ctx->args[path_index]
    ) < 0) {
        e->name[0] = '\0';
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* Existing syscall sensors */

SEC("tracepoint/syscalls/sys_enter_execve")
int capture_execve(struct sys_enter_ctx *ctx)
{
    return submit_path_event(ctx, EVENT_EXECVE, 0, -1, 0);
}

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int capture_memfd_create(struct sys_enter_ctx *ctx)
{
    inc_counter(CNT_MEMFD_ENTER);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u32 tgid = pid_tgid >> 32;

    __u32 zero = 0;
    struct pending_memfd *ps = bpf_map_lookup_elem(&memfd_heap, &zero);
    if (!ps)
        return 0;

    __builtin_memset(ps, 0, sizeof(*ps));

    ps->tgid = tgid;
    ps->tid = tid;
    ps->flags = (__u32)ctx->args[1];
    ps->entry_ts_ns = bpf_ktime_get_ns();
    ps->installed = 0;
    ps->captured_fd = -1;
    ps->file_cookie = 0;
    ps->inode_no = 0;
    ps->dev_id = 0;
    ps->identity_flags = 0;
    ps->install_count = 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    if (task) {
        struct task_struct *leader = NULL;
        if (bpf_core_read(&leader, sizeof(leader), &task->group_leader) == 0 && leader != NULL) {
            bpf_core_read(&ps->start_time_ns, sizeof(ps->start_time_ns), &leader->start_boottime);
        }
    }

    long len = bpf_probe_read_user_str(ps->name, sizeof(ps->name), (const char *)ctx->args[0]);
    if (len < 0) {
        ps->path_status = PATH_UNAVAILABLE;
        ps->name[0] = '\0';
    } else if (len == sizeof(ps->name)) {
        ps->path_status = PATH_TRUNCATED;
        ps->name[sizeof(ps->name) - 1] = '\0';
    } else {
        ps->path_status = PATH_VALID;
    }

    int map_upd_ret = bpf_map_update_elem(&pending_memfd_map, &tid, ps, BPF_ANY);
    if (map_upd_ret == 0)
        inc_counter(CNT_MEMFD_MAP_UPD_OK);
    else
        inc_counter(CNT_MEMFD_MAP_UPD_ERR);

    /* Submit existing syscall-attempt event */
    struct event *e = new_event(EVENT_MEMFD_CREATE);
    if (e) {
        e->flags = ps->flags;
        e->syscall_flags = ps->flags;
        e->entry_ts_ns = ps->entry_ts_ns;
        e->path_status = ps->path_status;
        __builtin_memcpy(e->name, ps->name, sizeof(e->name));
        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}

static __always_inline int is_diagnostic_target(const char *path, const char *d_name)
{
    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));

    /* Always trace test processes */
    if (comm[0] == 't' && comm[1] == 'e' && comm[2] == 's' && comm[3] == 't')
        return 1;

    /* Trace if path contains "ephim" */
    if (path) {
        #pragma unroll
        for (int i = 0; i < 32; i++) {
            if (path[i] == '\0')
                break;
            if (path[i] == 'e' && path[i+1] == 'p' && path[i+2] == 'h')
                return 1;
        }
    }

    /* Trace if dentry name contains "ephim" */
    if (d_name) {
        #pragma unroll
        for (int i = 0; i < 32; i++) {
            if (d_name[i] == '\0')
                break;
            if (d_name[i] == 'e' && d_name[i+1] == 'p' && d_name[i+2] == 'h')
                return 1;
        }
    }

    return 0;
}

static __always_inline void record_pending_syscall(
    __u32 op_type,
    __s32 dirfd,
    __u32 flags,
    const char *user_path
)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    struct pending_syscall ps;
    __builtin_memset(&ps, 0, sizeof(ps));

    ps.op_type = op_type;
    ps.tgid = pid_tgid >> 32;
    ps.tid = tid;
    ps.dirfd = dirfd;
    ps.flags = flags;
    ps.entry_ts_ns = bpf_ktime_get_ns();

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    if (task) {
        struct task_struct *leader = NULL;
        if (bpf_core_read(&leader, sizeof(leader), &task->group_leader) == 0 && leader != NULL) {
            bpf_core_read(&ps.start_time_ns, sizeof(ps.start_time_ns), &leader->start_boottime);
        }
    }

    long len = bpf_probe_read_user_str(ps.path, sizeof(ps.path), user_path);
    if (len < 0) {
        ps.path_status = PATH_UNAVAILABLE;
        ps.path[0] = '\0';
    } else if (len == sizeof(ps.path)) {
        ps.path_status = PATH_TRUNCATED;
        ps.path[sizeof(ps.path) - 1] = '\0';
    } else {
        ps.path_status = PATH_VALID;
    }

    int map_upd_ret = bpf_map_update_elem(&pending_syscall_map, &tid, &ps, BPF_ANY);

    if (op_type == EVENT_UNLINK) {
        if (map_upd_ret == 0) inc_counter(CNT_UNLINK_MAP_UPD_OK);
        else inc_counter(CNT_UNLINK_MAP_UPD_ERR);
    } else if (op_type == EVENT_UNLINKAT) {
        if (map_upd_ret == 0) inc_counter(CNT_UNLINKAT_MAP_UPD_OK);
        else inc_counter(CNT_UNLINKAT_MAP_UPD_ERR);
    } else if (op_type == EVENT_RMDIR) {
        if (map_upd_ret == 0) inc_counter(CNT_RMDIR_MAP_UPD_OK);
        else inc_counter(CNT_RMDIR_MAP_UPD_ERR);
    }

    if (is_diagnostic_target(ps.path, NULL)) {
        struct event *dbg = new_event(EVENT_DEBUG);
        if (dbg) {
            dbg->flags = DEBUG_STAGE_SYSCALL_ENTRY;
            dbg->op_type = op_type;
            dbg->pid = ps.tgid;
            dbg->tid = ps.tid;
            dbg->start_time_ns = ps.start_time_ns;
            dbg->path_status = ps.path_status;
            dbg->ret_val = map_upd_ret;
            dbg->entry_ts_ns = ps.entry_ts_ns;
            __builtin_memcpy(dbg->path, ps.path, sizeof(dbg->path));
            if (map_upd_ret == 0) {
                char msg[] = "MAP_UPD_OK";
                __builtin_memcpy(dbg->name, msg, sizeof(msg));
            } else {
                char msg[] = "MAP_UPD_ERR";
                __builtin_memcpy(dbg->name, msg, sizeof(msg));
            }
            bpf_ringbuf_submit(dbg, 0);
        }
    }

    /* Continue emitting the existing syscall-attempt event */
    struct event *e = new_event(op_type);
    if (e) {
        if (op_type == EVENT_UNLINK) inc_counter(CNT_UNLINK_RB_OK);
        else if (op_type == EVENT_UNLINKAT) inc_counter(CNT_UNLINKAT_RB_OK);
        else if (op_type == EVENT_RMDIR) inc_counter(CNT_RMDIR_RB_OK);

        e->dirfd = dirfd;
        e->flags = flags;
        e->op_type = op_type;
        e->syscall_flags = flags;
        e->entry_ts_ns = ps.entry_ts_ns;
        e->path_status = ps.path_status;
        __builtin_memcpy(e->path, ps.path, sizeof(e->path));
        __builtin_memcpy(e->name, ps.path, sizeof(e->name));
        bpf_ringbuf_submit(e, 0);

        if (op_type == EVENT_UNLINK) inc_counter(CNT_UNLINK_RB_SUBMIT);
        else if (op_type == EVENT_UNLINKAT) inc_counter(CNT_UNLINKAT_RB_SUBMIT);
        else if (op_type == EVENT_RMDIR) inc_counter(CNT_RMDIR_RB_SUBMIT);
    }
}

SEC("tracepoint/syscalls/sys_enter_unlink")
int capture_unlink(struct sys_enter_ctx *ctx)
{
    inc_counter(CNT_UNLINK_ENTER);
    record_pending_syscall(EVENT_UNLINK, -1, 0, (const char *)ctx->args[0]);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int capture_unlinkat(struct sys_enter_ctx *ctx)
{
    inc_counter(CNT_UNLINKAT_ENTER);
    record_pending_syscall(
        EVENT_UNLINKAT,
        (__s32)ctx->args[0],
        (__u32)ctx->args[2],
        (const char *)ctx->args[1]
    );
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rmdir")
int capture_rmdir(struct sys_enter_ctx *ctx)
{
    inc_counter(CNT_RMDIR_ENTER);
    record_pending_syscall(EVENT_RMDIR, -1, 0, (const char *)ctx->args[0]);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int capture_connect(struct sys_enter_ctx *ctx)
{
    struct event *e = new_event(EVENT_CONNECT);
    struct sockaddr_in_local addr4;
    struct sockaddr_in6_local addr6;
    void *user_addr = (void *)ctx->args[1];
    __u32 addrlen = (__u32)ctx->args[2];
    __u16 family = 0;

    if (!e)
        return 0;

    e->fd = (__s32)ctx->args[0];

    if (user_addr && addrlen >= sizeof(family) &&
        bpf_probe_read_user(&family, sizeof(family), user_addr) == 0) {

        e->family = family;

        if (family == 2 && addrlen >= sizeof(addr4)) {
            if (bpf_probe_read_user(&addr4, sizeof(addr4), user_addr) == 0) {
                e->port = addr4.port;
                __builtin_memcpy(
                    e->address, &addr4.addr, sizeof(addr4.addr)
                );
            }
        } else if (family == 10 && addrlen >= sizeof(addr6)) {
            if (bpf_probe_read_user(&addr6, sizeof(addr6), user_addr) == 0) {
                e->port = addr6.port;
                __builtin_memcpy(
                    e->address, addr6.addr, sizeof(addr6.addr)
                );
            }
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

static __always_inline __u64 encode_user_dev(__u32 kdev)
{
    unsigned int maj = kdev >> 20;
    unsigned int min = kdev & 0xfffff;

    return ((__u64)(maj & 0xfff) << 8) |
           ((__u64)(maj & ~0xfff) << 32) |
           ((__u64)(min & 0xff)) |
           ((__u64)(min & ~0xff) << 12);
}

/* Helper to capture resolved dentry file identity and mount namespace before VFS operation */
static __always_inline void capture_dentry_identity(struct dentry *dentry, struct vfs_file_identity *id)
{
    struct inode *inode = NULL;
    struct super_block *sb = NULL;
    struct task_struct *task = NULL;
    struct nsproxy *nsproxy = NULL;
    struct mnt_namespace *mnt_ns = NULL;
    const unsigned char *d_name_ptr = NULL;

    id->inode_no = 0;
    id->dev_id = 0;
    id->mnt_ns_id = 0;
    id->flags = 0;
    __builtin_memset(id->name, 0, sizeof(id->name));

    /* Extract resolved target inode and device ID */
    if (bpf_core_read(&inode, sizeof(inode), &dentry->d_inode) == 0 && inode != NULL) {
        if (bpf_core_read(&id->inode_no, sizeof(id->inode_no), &inode->i_ino) == 0 && id->inode_no != 0) {
            id->flags |= VFS_IDENTITY_INODE_VALID;
        }

        if (bpf_core_read(&sb, sizeof(sb), &inode->i_sb) == 0 && sb != NULL) {
            __u32 kdev = 0;
            if (bpf_core_read(&kdev, sizeof(kdev), &sb->s_dev) == 0) {
                id->dev_id = encode_user_dev(kdev);
                id->flags |= VFS_IDENTITY_DEV_VALID;
            }
        }
    }

    /* Extract filename from resolved dentry */
    if (bpf_core_read(&d_name_ptr, sizeof(d_name_ptr), &dentry->d_name.name) == 0 && d_name_ptr != NULL) {
        if (bpf_probe_read_kernel_str(id->name, sizeof(id->name), d_name_ptr) > 0) {
            id->flags |= VFS_IDENTITY_NAME_VALID;
        }
    }

    /* Extract mount namespace identifier from current task's nsproxy */
    task = (struct task_struct *)bpf_get_current_task_btf();
    if (task) {
        if (bpf_core_read(&nsproxy, sizeof(nsproxy), &task->nsproxy) == 0 && nsproxy != NULL) {
            if (bpf_core_read(&mnt_ns, sizeof(mnt_ns), &nsproxy->mnt_ns) == 0 && mnt_ns != NULL) {
                if (bpf_core_read(&id->mnt_ns_id, sizeof(id->mnt_ns_id), &mnt_ns->ns.inum) == 0 && id->mnt_ns_id != 0) {
                    id->flags |= VFS_IDENTITY_MNT_VALID;
                }
            }
        }
    }
}

/* VFS entry/exit sensors for unlink */

SEC("fentry/vfs_unlink")
int BPF_PROG(capture_vfs_unlink_entry, struct mnt_idmap *idmap, struct inode *dir, struct dentry *dentry, struct inode **delegated_inode)
{
    inc_counter(CNT_VFS_UNLINK_ENTRY);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u32 tgid = pid_tgid >> 32;
    struct vfs_file_identity *id;
    struct pending_syscall *ps;
    __u32 zero = 0;

    id = bpf_map_lookup_elem(&identity_heap, &zero);
    if (!id)
        return 0;

    capture_dentry_identity(dentry, id);

    id->op_type = 0;
    id->syscall_flags = 0;
    id->dirfd = -1;
    id->path_status = PATH_UNAVAILABLE;
    id->entry_ts_ns = 0;
    id->path[0] = '\0';

    ps = bpf_map_lookup_elem(&pending_syscall_map, &tid);
    __u32 reject_reason = REASON_ACCEPTED;
    __u64 cur_start_time = 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    if (task) {
        struct task_struct *leader = NULL;
        if (bpf_core_read(&leader, sizeof(leader), &task->group_leader) == 0 && leader != NULL) {
            bpf_core_read(&cur_start_time, sizeof(cur_start_time), &leader->start_boottime);
        }
    }

    if (!ps) {
        inc_counter(CNT_VFS_UNLINK_PENDING_MISSING);
        reject_reason = REASON_NO_PENDING_ENTRY;
    } else {
        inc_counter(CNT_VFS_UNLINK_PENDING_FOUND);
        if (ps->tgid != tgid) {
            reject_reason = REASON_TGID_MISMATCH;
        } else if (ps->start_time_ns != 0 && cur_start_time != 0 && ps->start_time_ns != cur_start_time) {
            reject_reason = REASON_START_TIME_MISMATCH;
        } else if (!(ps->op_type == EVENT_UNLINK ||
                    (ps->op_type == EVENT_UNLINKAT && !(ps->flags & 0x200 /* AT_REMOVEDIR */)))) {
            reject_reason = REASON_OP_TYPE_MISMATCH;
        } else {
            id->op_type = ps->op_type;
            id->syscall_flags = ps->flags;
            id->dirfd = ps->dirfd;
            id->path_status = ps->path_status;
            id->entry_ts_ns = ps->entry_ts_ns;
            __builtin_memcpy(id->path, ps->path, sizeof(id->path));
            id->flags |= VFS_IDENTITY_SYSCALL_VALID;
        }
    }

    if (is_diagnostic_target(ps ? ps->path : NULL, id->name)) {
        struct event *dbg = new_event(EVENT_DEBUG);
        if (dbg) {
            dbg->flags = DEBUG_STAGE_VFS_ENTRY;
            dbg->op_type = EVENT_UNLINK;
            dbg->pid = tgid;
            dbg->tid = tid;
            dbg->start_time_ns = cur_start_time;
            dbg->path_status = reject_reason;
            dbg->ret_val = (ps != NULL) ? 1 : 0;
            dbg->child_tgid = ps ? ps->tgid : 0;
            dbg->child_start_time_ns = ps ? ps->start_time_ns : 0;
            dbg->entry_ts_ns = ps ? ps->entry_ts_ns : 0;
            if (ps) {
                __builtin_memcpy(dbg->path, ps->path, sizeof(dbg->path));
            }
            if (reject_reason == REASON_ACCEPTED) {
                char msg[] = "VFS_ENTRY_ACCEPTED";
                __builtin_memcpy(dbg->name, msg, sizeof(msg));
            } else if (reject_reason == REASON_NO_PENDING_ENTRY) {
                char msg[] = "REJECT_NO_PENDING_ENTRY";
                __builtin_memcpy(dbg->name, msg, sizeof(msg));
            } else if (reject_reason == REASON_TGID_MISMATCH) {
                char msg[] = "REJECT_TGID_MISMATCH";
                __builtin_memcpy(dbg->name, msg, sizeof(msg));
            } else if (reject_reason == REASON_START_TIME_MISMATCH) {
                char msg[] = "REJECT_START_TIME_MISMATCH";
                __builtin_memcpy(dbg->name, msg, sizeof(msg));
            } else {
                char msg[] = "REJECT_OP_MISMATCH";
                __builtin_memcpy(dbg->name, msg, sizeof(msg));
            }
            bpf_ringbuf_submit(dbg, 0);
        }
    }

    bpf_map_update_elem(&unlink_identity_map, &tid, id, BPF_ANY);
    return 0;
}

SEC("fexit/vfs_unlink")
int BPF_PROG(capture_vfs_unlink_exit, struct mnt_idmap *idmap, struct inode *dir, struct dentry *dentry, struct inode **delegated_inode, int ret)
{
    inc_counter(CNT_VFS_UNLINK_EXIT);
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct vfs_file_identity *id_entry;
    struct event *e = new_event(EVENT_VFS_UNLINK_COMPLETED);

    if (!e) {
        bpf_map_delete_elem(&unlink_identity_map, &tid);
        bpf_map_delete_elem(&pending_syscall_map, &tid);
    bpf_map_delete_elem(&pending_memfd_map, &tid);
    bpf_map_delete_elem(&pending_memfd_exec, &tid);
        return 0;
    }

    e->ret_val = ret;

    /* Retrieve file identity and syscall context captured at entry */
    id_entry = bpf_map_lookup_elem(&unlink_identity_map, &tid);
    if (id_entry) {
        e->inode_no = id_entry->inode_no;
        e->dev_id = id_entry->dev_id;
        e->mnt_ns_id = id_entry->mnt_ns_id;
        e->flags = id_entry->flags;
        __builtin_memcpy(e->name, id_entry->name, sizeof(e->name));

        if (id_entry->flags & VFS_IDENTITY_SYSCALL_VALID) {
            e->op_type = id_entry->op_type;
            e->syscall_flags = id_entry->syscall_flags;
            e->dirfd = id_entry->dirfd;
            e->path_status = id_entry->path_status;
            e->entry_ts_ns = id_entry->entry_ts_ns;
            __builtin_memcpy(e->path, id_entry->path, sizeof(e->path));
            bpf_map_delete_elem(&pending_syscall_map, &tid);
    bpf_map_delete_elem(&pending_memfd_map, &tid);
    bpf_map_delete_elem(&pending_memfd_exec, &tid);
        } else {
            e->op_type = 0;
            e->syscall_flags = 0;
            e->dirfd = -1;
            e->path_status = PATH_UNAVAILABLE;
            e->entry_ts_ns = 0;
            e->path[0] = '\0';
        }
        bpf_map_delete_elem(&unlink_identity_map, &tid);
    } else {
        /* Missing identity or syscall context represented explicitly as unavailable */
        e->flags = 0;
        e->inode_no = 0;
        e->dev_id = 0;
        e->mnt_ns_id = 0;
        e->name[0] = '\0';
        e->op_type = 0;
        e->syscall_flags = 0;
        e->dirfd = -1;
        e->path_status = PATH_UNAVAILABLE;
        e->entry_ts_ns = 0;
        e->path[0] = '\0';
    }

    if (is_diagnostic_target(id_entry ? id_entry->path : NULL, id_entry ? id_entry->name : NULL)) {
        struct event *dbg = new_event(EVENT_DEBUG);
        if (dbg) {
            dbg->flags = DEBUG_STAGE_VFS_EXIT;
            dbg->op_type = id_entry ? id_entry->op_type : 0;
            dbg->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
            dbg->tid = tid;
            dbg->path_status = id_entry ? id_entry->path_status : PATH_UNAVAILABLE;
            dbg->ret_val = (id_entry != NULL) ? 1 : 0;
            dbg->reserved = (id_entry && (id_entry->flags & VFS_IDENTITY_SYSCALL_VALID)) ? 1 : 0;
            if (id_entry) {
                __builtin_memcpy(dbg->path, id_entry->path, sizeof(dbg->path));
                __builtin_memcpy(dbg->name, id_entry->name, sizeof(dbg->name));
            }
            bpf_ringbuf_submit(dbg, 0);
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* VFS entry/exit sensors for rmdir */

SEC("fentry/vfs_rmdir")
int BPF_PROG(capture_vfs_rmdir_entry, struct mnt_idmap *idmap, struct inode *dir, struct dentry *dentry, struct inode **delegated_inode)
{
    inc_counter(CNT_VFS_RMDIR_ENTRY);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u32 tgid = pid_tgid >> 32;
    struct vfs_file_identity *id;
    struct pending_syscall *ps;
    __u32 zero = 0;

    id = bpf_map_lookup_elem(&identity_heap, &zero);
    if (!id)
        return 0;

    capture_dentry_identity(dentry, id);

    id->op_type = 0;
    id->syscall_flags = 0;
    id->dirfd = -1;
    id->path_status = PATH_UNAVAILABLE;
    id->entry_ts_ns = 0;
    id->path[0] = '\0';

    ps = bpf_map_lookup_elem(&pending_syscall_map, &tid);
    __u32 reject_reason = REASON_ACCEPTED;
    __u64 cur_start_time = 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    if (task) {
        struct task_struct *leader = NULL;
        if (bpf_core_read(&leader, sizeof(leader), &task->group_leader) == 0 && leader != NULL) {
            bpf_core_read(&cur_start_time, sizeof(cur_start_time), &leader->start_boottime);
        }
    }

    if (!ps) {
        inc_counter(CNT_VFS_RMDIR_PENDING_MISSING);
        reject_reason = REASON_NO_PENDING_ENTRY;
    } else {
        inc_counter(CNT_VFS_RMDIR_PENDING_FOUND);
        if (ps->tgid != tgid) {
            reject_reason = REASON_TGID_MISMATCH;
        } else if (ps->start_time_ns != 0 && cur_start_time != 0 && ps->start_time_ns != cur_start_time) {
            reject_reason = REASON_START_TIME_MISMATCH;
        } else if (!(ps->op_type == EVENT_RMDIR ||
                    (ps->op_type == EVENT_UNLINKAT && (ps->flags & 0x200 /* AT_REMOVEDIR */)))) {
            reject_reason = REASON_OP_TYPE_MISMATCH;
        } else {
            id->op_type = ps->op_type;
            id->syscall_flags = ps->flags;
            id->dirfd = ps->dirfd;
            id->path_status = ps->path_status;
            id->entry_ts_ns = ps->entry_ts_ns;
            __builtin_memcpy(id->path, ps->path, sizeof(id->path));
            id->flags |= VFS_IDENTITY_SYSCALL_VALID;
        }
    }

    if (is_diagnostic_target(ps ? ps->path : NULL, id->name)) {
        struct event *dbg = new_event(EVENT_DEBUG);
        if (dbg) {
            dbg->flags = DEBUG_STAGE_VFS_ENTRY;
            dbg->op_type = EVENT_RMDIR;
            dbg->pid = tgid;
            dbg->tid = tid;
            dbg->start_time_ns = cur_start_time;
            dbg->path_status = reject_reason;
            dbg->ret_val = (ps != NULL) ? 1 : 0;
            dbg->child_tgid = ps ? ps->tgid : 0;
            dbg->child_start_time_ns = ps ? ps->start_time_ns : 0;
            dbg->entry_ts_ns = ps ? ps->entry_ts_ns : 0;
            if (ps) {
                __builtin_memcpy(dbg->path, ps->path, sizeof(dbg->path));
            }
            if (reject_reason == REASON_ACCEPTED) {
                char msg[] = "VFS_ENTRY_ACCEPTED";
                __builtin_memcpy(dbg->name, msg, sizeof(msg));
            } else if (reject_reason == REASON_NO_PENDING_ENTRY) {
                char msg[] = "REJECT_NO_PENDING_ENTRY";
                __builtin_memcpy(dbg->name, msg, sizeof(msg));
            } else if (reject_reason == REASON_TGID_MISMATCH) {
                char msg[] = "REJECT_TGID_MISMATCH";
                __builtin_memcpy(dbg->name, msg, sizeof(msg));
            } else if (reject_reason == REASON_START_TIME_MISMATCH) {
                char msg[] = "REJECT_START_TIME_MISMATCH";
                __builtin_memcpy(dbg->name, msg, sizeof(msg));
            } else {
                char msg[] = "REJECT_OP_MISMATCH";
                __builtin_memcpy(dbg->name, msg, sizeof(msg));
            }
            bpf_ringbuf_submit(dbg, 0);
        }
    }

    bpf_map_update_elem(&rmdir_identity_map, &tid, id, BPF_ANY);
    return 0;
}

SEC("fexit/vfs_rmdir")
int BPF_PROG(capture_vfs_rmdir_exit, struct mnt_idmap *idmap, struct inode *dir, struct dentry *dentry, struct inode **delegated_inode, int ret)
{
    inc_counter(CNT_VFS_RMDIR_EXIT);
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct vfs_file_identity *id_entry;
    struct event *e = new_event(EVENT_VFS_RMDIR_COMPLETED);

    if (!e) {
        bpf_map_delete_elem(&rmdir_identity_map, &tid);
        bpf_map_delete_elem(&pending_syscall_map, &tid);
    bpf_map_delete_elem(&pending_memfd_map, &tid);
    bpf_map_delete_elem(&pending_memfd_exec, &tid);
        return 0;
    }

    e->ret_val = ret;

    /* Retrieve directory identity and syscall context captured at entry */
    id_entry = bpf_map_lookup_elem(&rmdir_identity_map, &tid);
    if (id_entry) {
        e->inode_no = id_entry->inode_no;
        e->dev_id = id_entry->dev_id;
        e->mnt_ns_id = id_entry->mnt_ns_id;
        e->flags = id_entry->flags;
        __builtin_memcpy(e->name, id_entry->name, sizeof(e->name));

        if (id_entry->flags & VFS_IDENTITY_SYSCALL_VALID) {
            e->op_type = id_entry->op_type;
            e->syscall_flags = id_entry->syscall_flags;
            e->dirfd = id_entry->dirfd;
            e->path_status = id_entry->path_status;
            e->entry_ts_ns = id_entry->entry_ts_ns;
            __builtin_memcpy(e->path, id_entry->path, sizeof(e->path));
            bpf_map_delete_elem(&pending_syscall_map, &tid);
    bpf_map_delete_elem(&pending_memfd_map, &tid);
    bpf_map_delete_elem(&pending_memfd_exec, &tid);
        } else {
            e->op_type = 0;
            e->syscall_flags = 0;
            e->dirfd = -1;
            e->path_status = PATH_UNAVAILABLE;
            e->entry_ts_ns = 0;
            e->path[0] = '\0';
        }
        bpf_map_delete_elem(&rmdir_identity_map, &tid);
    } else {
        /* Missing identity or syscall context represented explicitly as unavailable */
        e->flags = 0;
        e->inode_no = 0;
        e->dev_id = 0;
        e->mnt_ns_id = 0;
        e->name[0] = '\0';
        e->op_type = 0;
        e->syscall_flags = 0;
        e->dirfd = -1;
        e->path_status = PATH_UNAVAILABLE;
        e->entry_ts_ns = 0;
        e->path[0] = '\0';
    }

    if (is_diagnostic_target(id_entry ? id_entry->path : NULL, id_entry ? id_entry->name : NULL)) {
        struct event *dbg = new_event(EVENT_DEBUG);
        if (dbg) {
            dbg->flags = DEBUG_STAGE_VFS_EXIT;
            dbg->op_type = id_entry ? id_entry->op_type : 0;
            dbg->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
            dbg->tid = tid;
            dbg->path_status = id_entry ? id_entry->path_status : PATH_UNAVAILABLE;
            dbg->ret_val = (id_entry != NULL) ? 1 : 0;
            dbg->reserved = (id_entry && (id_entry->flags & VFS_IDENTITY_SYSCALL_VALID)) ? 1 : 0;
            if (id_entry) {
                __builtin_memcpy(dbg->path, id_entry->path, sizeof(dbg->path));
                __builtin_memcpy(dbg->name, id_entry->name, sizeof(dbg->name));
            }
            bpf_ringbuf_submit(dbg, 0);
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* Syscall exit cleanup handlers for operations that fail before reaching VFS */

struct sys_exit_ctx {
    struct trace_entry ent;
    long id;
    long ret;
};

static __always_inline void cleanup_pending_syscall(__u32 expected_op)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u32 tgid = pid_tgid >> 32;

    struct pending_syscall *ps = bpf_map_lookup_elem(&pending_syscall_map, &tid);
    if (ps) {
        if (ps->op_type == expected_op && ps->tgid == tgid) {
            __u64 cur_start_time = 0;
            struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
            if (task) {
                struct task_struct *leader = NULL;
                if (bpf_core_read(&leader, sizeof(leader), &task->group_leader) == 0 && leader != NULL) {
                    bpf_core_read(&cur_start_time, sizeof(cur_start_time), &leader->start_boottime);
                }
            }

            if (ps->start_time_ns == 0 || cur_start_time == 0 || ps->start_time_ns == cur_start_time) {
                bpf_map_delete_elem(&pending_syscall_map, &tid);
    bpf_map_delete_elem(&pending_memfd_map, &tid);
    bpf_map_delete_elem(&pending_memfd_exec, &tid);
                if (expected_op == EVENT_UNLINK) inc_counter(CNT_UNLINK_EXIT_CLEANUP);
                else if (expected_op == EVENT_UNLINKAT) inc_counter(CNT_UNLINKAT_EXIT_CLEANUP);
                else if (expected_op == EVENT_RMDIR) inc_counter(CNT_RMDIR_EXIT_CLEANUP);
            }
        }
        if (is_diagnostic_target(ps->path, NULL)) {
            struct event *dbg = new_event(EVENT_DEBUG);
            if (dbg) {
                dbg->flags = DEBUG_STAGE_SYSCALL_EXIT;
                dbg->op_type = expected_op;
                dbg->pid = tgid;
                dbg->tid = tid;
                dbg->ret_val = 1; /* Found abandoned */
                __builtin_memcpy(dbg->path, ps->path, sizeof(dbg->path));
                char msg[] = "CLEANUP_PENDING_FOUND";
                __builtin_memcpy(dbg->name, msg, sizeof(msg));
                bpf_ringbuf_submit(dbg, 0);
            }
        }
    }
}

SEC("tracepoint/syscalls/sys_exit_unlink")
int capture_unlink_exit(struct sys_exit_ctx *ctx)
{
    inc_counter(CNT_UNLINK_EXIT);
    cleanup_pending_syscall(EVENT_UNLINK);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_unlinkat")
int capture_unlinkat_exit(struct sys_exit_ctx *ctx)
{
    inc_counter(CNT_UNLINKAT_EXIT);
    cleanup_pending_syscall(EVENT_UNLINKAT);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_rmdir")
int capture_rmdir_exit(struct sys_exit_ctx *ctx)
{
    inc_counter(CNT_RMDIR_EXIT);
    cleanup_pending_syscall(EVENT_RMDIR);
    return 0;
}

SEC("fentry/fd_install")
int BPF_PROG(capture_fd_install, unsigned int fd, struct file *file)
{
    inc_counter(CNT_FD_INSTALL_TOTAL);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;

    struct pending_memfd *ps = bpf_map_lookup_elem(&pending_memfd_map, &tid);
    if (!ps) {
        /* Not in memfd_create: check if this file references an already tracked memfd inode */
        if (file) {
            struct inode *inode = NULL;
            bpf_core_read(&inode, sizeof(inode), &file->f_inode);
            if (inode) {
                __u64 inode_key = (__u64)inode;
                struct memfd_object_entry *obj = bpf_map_lookup_elem(&memfd_inode_registry, &inode_key);
                if (obj && obj->state == REG_STATE_COMMITTED) {
                    __u64 file_key = (__u64)file;
                    __u32 op_type = 0;
                    int res_fil = bpf_map_update_elem(&memfd_file_registry, &file_key, &obj->object_token, BPF_NOEXIST);
                    if (res_fil == 0) {
                        inc_counter(CNT_REG_REOPEN_MATCH);
                        inc_counter(CNT_REG_FILE_INSERT_OK);
                        op_type = FD_INSTALL_OP_REOPEN;
                    } else if (res_fil == -17 /* -EEXIST */) {
                        __u64 *existing_tok = bpf_map_lookup_elem(&memfd_file_registry, &file_key);
                        if (existing_tok) {
                            if (*existing_tok != obj->object_token) {
                                inc_counter(CNT_REG_TOKEN_MISMATCH);
                                return 0;
                            }
                        }
                        op_type = FD_INSTALL_OP_DUP;
                    } else {
                        inc_counter(CNT_REG_FILE_INSERT_ERR);
                        inc_counter(CNT_REG_MAP_FULL_DROP);
                        return 0;
                    }

                    /* Track descriptor slot */
                    __u32 tgid_val = (__u32)(pid_tgid >> 32);
                    struct descriptor_key dk;
                    dk.tgid = tgid_val;
                    dk.fd = (__s32)fd;

                    struct descriptor_entry de;
                    __builtin_memset(&de, 0, sizeof(de));
                    de.object_token = obj->object_token;
                    de.file_ptr = file_key;
                    de.installed_ts_ns = bpf_ktime_get_ns();
                    bpf_map_update_elem(&memfd_desc_registry, &dk, &de, BPF_ANY);

                    struct event *e = new_event(EVENT_FD_INSTALLED);
                    if (e) {
                        e->fd = (__s32)fd;
                        e->object_token = obj->object_token;
                        e->op_type = op_type;
                        bpf_ringbuf_submit(e, 0);
                    }
                }
            }
        }
        return 0;
    }

    __u32 tgid = pid_tgid >> 32;
    if (ps->tgid != tgid)
        return 0;

    __u64 cur_start_time = 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    if (task) {
        struct task_struct *leader = NULL;
        if (bpf_core_read(&leader, sizeof(leader), &task->group_leader) == 0 && leader != NULL) {
            bpf_core_read(&cur_start_time, sizeof(cur_start_time), &leader->start_boottime);
        }
    }
    if (ps->start_time_ns != 0 && cur_start_time != 0 && ps->start_time_ns != cur_start_time)
        return 0;

    inc_counter(CNT_FD_INSTALL_MATCH);

    ps->install_count++;
    if (ps->installed) {
        /* Unexpected repeated matching fd_install for the same pending syscall */
        inc_counter(CNT_FD_INSTALL_ERR);
        return 0;
    }

    ps->installed = 1;
    ps->captured_fd = (__s32)fd;
    ps->file_ptr = (__u64)file;

    struct dentry *dentry = NULL;
    struct inode *inode = NULL;
    struct super_block *sb = NULL;
    const unsigned char *d_name_ptr = NULL;

    if (file) {
        bpf_core_read(&dentry, sizeof(dentry), &file->f_path.dentry);
        bpf_core_read(&inode, sizeof(inode), &file->f_inode);

        if (!inode && dentry) {
            bpf_core_read(&inode, sizeof(inode), &dentry->d_inode);
        }

        if (inode) {
            ps->inode_ptr = (__u64)inode;
            __u64 ino = 0;
            if (bpf_core_read(&ino, sizeof(ino), &inode->i_ino) == 0 && ino != 0) {
                ps->inode_no = ino;
                ps->identity_flags |= VFS_IDENTITY_INODE_VALID;
            }

            if (bpf_core_read(&sb, sizeof(sb), &inode->i_sb) == 0 && sb != NULL) {
                __u32 kdev = 0;
                if (bpf_core_read(&kdev, sizeof(kdev), &sb->s_dev) == 0) {
                    ps->dev_id = encode_user_dev(kdev);
                    ps->identity_flags |= VFS_IDENTITY_DEV_VALID;
                }
            }
        }

        if (dentry) {
            if (bpf_core_read(&d_name_ptr, sizeof(d_name_ptr), &dentry->d_name.name) == 0 && d_name_ptr != NULL) {
                if (bpf_probe_read_kernel_str(ps->dentry_name, sizeof(ps->dentry_name), d_name_ptr) > 0) {
                    ps->identity_flags |= VFS_IDENTITY_NAME_VALID;
                }
            }
        }
    }

    /* Allocate session-unique object token */
    __u32 zero = 0;
    __u64 *tok_ptr = bpf_map_lookup_elem(&memfd_token_generator, &zero);
    __u64 token = 0;
    if (tok_ptr) {
        token = __sync_fetch_and_add(tok_ptr, 1) + 1;
    }
    if (token == 0) {
        inc_counter(CNT_REG_TOKEN_ERR);
        ps->file_cookie = 0;
        return 0;
    }
    ps->file_cookie = token; /* Store assigned token */

    /* Register provisional entry in inode registry */
    if (inode) {
        __u64 inode_key = (__u64)inode;
        struct memfd_object_entry entry;
        __builtin_memset(&entry, 0, sizeof(entry));
        entry.object_token = token;
        entry.inode_no = ps->inode_no;
        entry.dev_id = ps->dev_id;
        entry.creator_tgid = ps->tgid;
        entry.creator_tid = ps->tid;
        entry.creator_start_time_ns = ps->start_time_ns;
        entry.creation_flags = ps->flags;
        entry.state = REG_STATE_PROVISIONAL;
        entry.creation_ts_ns = ps->entry_ts_ns;
        __builtin_memcpy(entry.name, ps->dentry_name, sizeof(entry.name));

        int res_ino = bpf_map_update_elem(&memfd_inode_registry, &inode_key, &entry, BPF_ANY);
        if (res_ino == 0) {
            inc_counter(CNT_REG_INODE_INSERT_OK);
        } else {
            inc_counter(CNT_REG_INODE_INSERT_ERR);
            inc_counter(CNT_REG_MAP_FULL_DROP);
            ps->file_cookie = 0;
            return 0;
        }
    } else {
        inc_counter(CNT_REG_INODE_INSERT_ERR);
        ps->file_cookie = 0;
        return 0;
    }

    /* Register provisional entry in open-file registry */
    if (file) {
        __u64 file_key = (__u64)file;
        int res_fil = bpf_map_update_elem(&memfd_file_registry, &file_key, &token, BPF_NOEXIST);
        if (res_fil == 0) {
            inc_counter(CNT_REG_FILE_INSERT_OK);

            /* Track descriptor slot */
            struct descriptor_key dk;
            dk.tgid = tgid;
            dk.fd = (__s32)fd;

            struct descriptor_entry de;
            __builtin_memset(&de, 0, sizeof(de));
            de.object_token = token;
            de.file_ptr = file_key;
            de.installed_ts_ns = bpf_ktime_get_ns();
            bpf_map_update_elem(&memfd_desc_registry, &dk, &de, BPF_ANY);

            struct event *e = new_event(EVENT_FD_INSTALLED);
            if (e) {
                e->fd = (__s32)fd;
                e->object_token = token;
                e->op_type = FD_INSTALL_OP_CREATION;
                bpf_ringbuf_submit(e, 0);
            }
        } else {
            inc_counter(CNT_REG_FILE_INSERT_ERR);
            inc_counter(CNT_REG_MAP_FULL_DROP);
            /* Atomic rollback: remove provisional entry from inode registry */
            if (ps->inode_ptr) {
                __u64 inode_key = ps->inode_ptr;
                int del_res = bpf_map_delete_elem(&memfd_inode_registry, &inode_key);
                if (del_res == 0)
                    inc_counter(CNT_REG_INODE_ROLLBACK);
                else
                    inc_counter(CNT_REG_INODE_DELETE_ERR);
            }
            ps->file_cookie = 0;
            return 0;
        }
    } else {
        inc_counter(CNT_REG_FILE_INSERT_ERR);
        if (ps->inode_ptr) {
            __u64 inode_key = ps->inode_ptr;
            int del_res = bpf_map_delete_elem(&memfd_inode_registry, &inode_key);
            if (del_res == 0)
                inc_counter(CNT_REG_INODE_ROLLBACK);
            else
                inc_counter(CNT_REG_INODE_DELETE_ERR);
        }
        ps->file_cookie = 0;
        return 0;
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_memfd_create")
int capture_memfd_create_exit(struct sys_exit_ctx *ctx)
{
    inc_counter(CNT_MEMFD_EXIT);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u32 tgid = pid_tgid >> 32;

    struct pending_memfd *ps = bpf_map_lookup_elem(&pending_memfd_map, &tid);
    if (!ps)
        return 0;

    if (ps->tgid != tgid) {
        bpf_map_delete_elem(&pending_memfd_map, &tid);
        return 0;
    }

    __u64 cur_start_time = 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    if (task) {
        struct task_struct *leader = NULL;
        if (bpf_core_read(&leader, sizeof(leader), &task->group_leader) == 0 && leader != NULL) {
            bpf_core_read(&cur_start_time, sizeof(cur_start_time), &leader->start_boottime);
        }
    }
    if (ps->start_time_ns != 0 && cur_start_time != 0 && ps->start_time_ns != cur_start_time) {
        bpf_map_delete_elem(&pending_memfd_map, &tid);
        return 0;
    }

    struct event *e = new_event(EVENT_MEMFD_COMPLETED);
    if (!e) {
        inc_counter(CNT_MEMFD_RB_ERR);
        bpf_map_delete_elem(&pending_memfd_map, &tid);
        return 0;
    }

    long ret = ctx->ret;
    e->ret_val = (__s32)ret;
    e->syscall_flags = ps->flags;
    e->entry_ts_ns = ps->entry_ts_ns;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->path_status = ps->path_status;
    __builtin_memcpy(e->name, ps->name, sizeof(e->name));

    if (ret < 0) {
        /* Syscall failed: negative errno. Purge provisional registry entries */
        if (ps->installed) {
            if (ps->captured_fd >= 0) {
                struct descriptor_key dk = { .tgid = ps->tgid, .fd = ps->captured_fd };
                bpf_map_delete_elem(&memfd_desc_registry, &dk);
            }
            if (ps->inode_ptr) {
                __u64 ino_key = ps->inode_ptr;
                int res = bpf_map_delete_elem(&memfd_inode_registry, &ino_key);
                if (res != 0)
                    inc_counter(CNT_REG_INODE_DELETE_ERR);
            }
            if (ps->file_ptr) {
                __u64 fil_key = ps->file_ptr;
                int res = bpf_map_delete_elem(&memfd_file_registry, &fil_key);
                if (res != 0)
                    inc_counter(CNT_REG_FILE_DELETE_ERR);
            }
            inc_counter(CNT_REG_PROVISIONAL_DROPPED);
        }
        e->op_type = MEMFD_STATUS_FAILED;
        e->fd = -1;
        e->flags = 0;
        e->inode_no = 0;
        e->dev_id = 0;
        e->mnt_ns_id = 0;
        e->path[0] = '\0';
        inc_counter(CNT_MEMFD_FAILED);
    } else {
        /* Syscall returned success (ret >= 0) */
        if (ps->installed && ps->captured_fd == (__s32)ret && ps->install_count == 1) {
            /* Validated correlation */
            e->op_type = MEMFD_STATUS_SUCCESS_CORRELATED;
            e->fd = (__s32)ret;
            e->flags = ps->identity_flags;
            e->inode_no = ps->inode_no;
            e->dev_id = ps->dev_id;
            e->mnt_ns_id = 0;
            e->object_token = ps->file_cookie;
            __builtin_memcpy(e->path, ps->dentry_name, sizeof(e->path));
            inc_counter(CNT_MEMFD_CORRELATED);

            /* Commit provisional entry in inode registry */
            if (ps->inode_ptr) {
                __u64 ino_key = ps->inode_ptr;
                struct memfd_object_entry *obj = bpf_map_lookup_elem(&memfd_inode_registry, &ino_key);
                if (obj) {
                    obj->state = REG_STATE_COMMITTED;
                    inc_counter(CNT_REG_COMMITTED);
                }
            }
        } else {
            /* Syscall succeeded but installation missing, inconsistent, or duplicate: purge provisional */
            if (ps->installed) {
                if (ps->captured_fd >= 0) {
                    struct descriptor_key dk = { .tgid = ps->tgid, .fd = ps->captured_fd };
                    bpf_map_delete_elem(&memfd_desc_registry, &dk);
                }
                if (ps->inode_ptr) {
                    __u64 ino_key = ps->inode_ptr;
                    int res = bpf_map_delete_elem(&memfd_inode_registry, &ino_key);
                    if (res != 0)
                        inc_counter(CNT_REG_INODE_DELETE_ERR);
                }
                if (ps->file_ptr) {
                    __u64 fil_key = ps->file_ptr;
                    int res = bpf_map_delete_elem(&memfd_file_registry, &fil_key);
                    if (res != 0)
                        inc_counter(CNT_REG_FILE_DELETE_ERR);
                }
                inc_counter(CNT_REG_PROVISIONAL_DROPPED);
            }
            e->op_type = MEMFD_STATUS_SUCCESS_UNCORRELATED;
            e->fd = (__s32)ret;
            e->flags = 0;
            e->inode_no = 0;
            e->dev_id = 0;
            e->mnt_ns_id = 0;
            e->path[0] = '\0';
            inc_counter(CNT_MEMFD_UNCORRELATED);
        }
    }

    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&pending_memfd_map, &tid);
    return 0;
}

SEC("fentry/shmem_evict_inode")
int BPF_PROG(capture_shmem_evict_inode, struct inode *inode)
{
    if (!inode)
        return 0;

    __u64 inode_key = (__u64)inode;
    struct memfd_object_entry *obj = bpf_map_lookup_elem(&memfd_inode_registry, &inode_key);
    if (!obj)
        return 0;

    inc_counter(CNT_REG_RETIRED);

    struct event *e = new_event(EVENT_MEMFD_DESTROYED);
    if (e) {
        e->inode_no = obj->inode_no;
        e->dev_id = obj->dev_id;
        e->object_token = obj->object_token;
        e->entry_ts_ns = obj->creation_ts_ns;
        e->timestamp_ns = bpf_ktime_get_ns();
        __builtin_memcpy(e->name, obj->name, sizeof(e->name));
        bpf_ringbuf_submit(e, 0);
    }

    int del_res = bpf_map_delete_elem(&memfd_inode_registry, &inode_key);
    if (del_res != 0)
        inc_counter(CNT_REG_INODE_DELETE_ERR);

    return 0;
}

SEC("fentry/__fput")
int BPF_PROG(capture_fput, struct file *file)
{
    if (!file)
        return 0;

    __u64 file_key = (__u64)file;
    __u64 *token_ptr = bpf_map_lookup_elem(&memfd_file_registry, &file_key);
    if (!token_ptr)
        return 0;

    __u64 token = *token_ptr;
    int res = bpf_map_delete_elem(&memfd_file_registry, &file_key);
    if (res == 0) {
        inc_counter(CNT_REG_FILE_DELETE_OK);
    } else {
        inc_counter(CNT_REG_FILE_DELETE_ERR);
    }

    struct event *e = new_event(EVENT_MEMFD_FILE_RELEASED);
    if (e) {
        struct inode *inode = NULL;
        bpf_core_read(&inode, sizeof(inode), &file->f_inode);
        if (inode) {
            __u64 ino = 0;
            bpf_core_read(&ino, sizeof(ino), &inode->i_ino);
            e->inode_no = ino;
        }
        e->object_token = token;
        e->timestamp_ns = bpf_ktime_get_ns();
        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}

SEC("fentry/shmem_file_write_iter")
int BPF_PROG(capture_shmem_write_iter, struct kiocb *iocb, struct iov_iter *from)
{
    if (!iocb || !from)
        return 0;

    struct file *file = NULL;
    bpf_core_read(&file, sizeof(file), &iocb->ki_filp);
    if (!file)
        return 0;

    __u64 file_key = (__u64)file;
    __u64 *token_ptr = bpf_map_lookup_elem(&memfd_file_registry, &file_key);
    if (!token_ptr)
        return 0;

    __u64 token = *token_ptr;
    loff_t pos = 0;
    bpf_core_read(&pos, sizeof(pos), &iocb->ki_pos);
    size_t count = 0;
    bpf_core_read(&count, sizeof(count), &from->count);
    int ki_flags = 0;
    bpf_core_read(&ki_flags, sizeof(ki_flags), &iocb->ki_flags);

    inc_counter(CNT_MEMFD_WRITE_OPS);
    __u32 cnt_bytes_idx = CNT_MEMFD_WRITE_BYTES;
    __u64 *bytes_val = bpf_map_lookup_elem(&prog_counters, &cnt_bytes_idx);
    if (bytes_val)
        __sync_fetch_and_add(bytes_val, count);

    struct event *e = new_event(EVENT_MEMFD_WRITE);
    if (e) {
        e->fd = -1;
        e->object_token = token;
        e->entry_ts_ns = (__u64)pos;
        e->ret_val = (__s32)count;
        e->flags = (__u32)ki_flags;
        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}

SEC("fentry/close_fd")
int BPF_PROG(capture_close_fd, unsigned int fd)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    struct descriptor_key dk;
    dk.tgid = tgid;
    dk.fd = (__s32)fd;

    struct descriptor_entry *de = bpf_map_lookup_elem(&memfd_desc_registry, &dk);
    if (!de)
        return 0;

    __u64 now = bpf_ktime_get_ns();
    __u64 duration_ns = (now >= de->installed_ts_ns) ? (now - de->installed_ts_ns) : 0;
    __u64 token = de->object_token;

    bpf_map_delete_elem(&memfd_desc_registry, &dk);
    inc_counter(CNT_FD_CLOSED_MATCH);

    struct event *e = new_event(EVENT_FD_CLOSED);
    if (e) {
        e->fd = (__s32)fd;
        e->object_token = token;
        e->entry_ts_ns = duration_ns;
        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}

SEC("fentry/security_bprm_check")
int BPF_PROG(capture_bprm_check, struct linux_binprm *bprm)
{
    if (!bprm)
        return 0;

    struct file *file = NULL;
    bpf_core_read(&file, sizeof(file), &bprm->file);
    if (!file)
        return 0;

    __u64 file_key = (__u64)file;
    __u64 *token_ptr = bpf_map_lookup_elem(&memfd_file_registry, &file_key);
    __u64 token = 0;
    if (token_ptr) {
        token = *token_ptr;
    } else {
        struct inode *inode = NULL;
        bpf_core_read(&inode, sizeof(inode), &file->f_inode);
        if (inode) {
            __u64 inode_key = (__u64)inode;
            struct memfd_object_entry *obj = bpf_map_lookup_elem(&memfd_inode_registry, &inode_key);
            if (obj && obj->state == REG_STATE_COMMITTED) {
                token = obj->object_token;
            }
        }
    }

    if (token == 0)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;

    bpf_map_update_elem(&pending_memfd_exec, &tid, &token, BPF_ANY);
    inc_counter(CNT_MEMFD_EXEC_ATTEMPT);

    struct event *e = new_event(EVENT_MEMFD_EXEC_ATTEMPT);
    if (e) {
        e->object_token = token;
        const char *filename_ptr = NULL;
        bpf_core_read(&filename_ptr, sizeof(filename_ptr), &bprm->filename);
        if (filename_ptr) {
            bpf_probe_read_kernel_str(e->name, sizeof(e->name), filename_ptr);
        }
        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}

/* Process lifecycle sensors */

SEC("raw_tracepoint/sched_process_fork")
int capture_process_fork(void *ctx)
{
    __u64 *args = ctx;

    struct task_struct *parent = (void *)args[0];
    struct task_struct *child = (void *)args[1];
    struct task_struct *parent_leader = NULL;
    struct task_struct *child_leader = NULL;

    struct event *e = new_event(EVENT_FORK);

    if (!e)
        return 0;

    bpf_core_read(&e->pid, sizeof(e->pid), &parent->tgid);
    bpf_core_read(&e->tid, sizeof(e->tid), &parent->pid);

    bpf_core_read(&e->child_tgid, sizeof(e->child_tgid),
                  &child->tgid);

    bpf_core_read(&e->child_pid, sizeof(e->child_pid),
                  &child->pid);

    /* Read parent process-generation start time strictly from group_leader.
     * Stays 0 if unreadable.
     */
    e->start_time_ns = 0;
    if (bpf_core_read(&parent_leader, sizeof(parent_leader), &parent->group_leader) == 0 &&
        parent_leader != NULL) {
        bpf_core_read(&e->start_time_ns, sizeof(e->start_time_ns), &parent_leader->start_boottime);
    }

    /* Read child process-generation start time strictly from group_leader.
     * Stays 0 if unreadable.
     */
    e->child_start_time_ns = 0;
    if (bpf_core_read(&child_leader, sizeof(child_leader), &child->group_leader) == 0 &&
        child_leader != NULL) {
        bpf_core_read(&e->child_start_time_ns, sizeof(e->child_start_time_ns), &child_leader->start_boottime);
    }

    bpf_probe_read_kernel_str(
        e->name, sizeof(e->name), child->comm
    );

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int capture_process_exec(struct sched_exec_ctx *ctx)
{
    struct event *e = new_event(EVENT_PROCESS_EXEC);
    __u32 offset;
    const char *filename;

    if (!e)
        return 0;

    e->old_pid = (__u32)ctx->old_pid;

    offset = ctx->filename_loc & 0xFFFF;
    filename = (const char *)ctx + offset;

    bpf_probe_read_kernel_str(
        e->name, sizeof(e->name), filename
    );

    bpf_ringbuf_submit(e, 0);

    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u64 *token_ptr = bpf_map_lookup_elem(&pending_memfd_exec, &tid);
    if (token_ptr) {
        __u64 token = *token_ptr;
        bpf_map_delete_elem(&pending_memfd_exec, &tid);
        inc_counter(CNT_MEMFD_EXEC_SUCCESS);

        struct event *e_succ = new_event(EVENT_MEMFD_EXEC_SUCCESS);
        if (e_succ) {
            e_succ->object_token = token;
            bpf_probe_read_kernel_str(e_succ->name, sizeof(e_succ->name), filename);
            bpf_ringbuf_submit(e_succ, 0);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int capture_execve_exit(struct sys_exit_ctx *ctx)
{
    if (ctx->ret < 0) {
        __u32 tid = (__u32)bpf_get_current_pid_tgid();
        __u64 *token_ptr = bpf_map_lookup_elem(&pending_memfd_exec, &tid);
        if (token_ptr) {
            bpf_map_delete_elem(&pending_memfd_exec, &tid);
            inc_counter(CNT_MEMFD_EXEC_FAIL);
        }
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execveat")
int capture_execveat_exit(struct sys_exit_ctx *ctx)
{
    if (ctx->ret < 0) {
        __u32 tid = (__u32)bpf_get_current_pid_tgid();
        __u64 *token_ptr = bpf_map_lookup_elem(&pending_memfd_exec, &tid);
        if (token_ptr) {
            bpf_map_delete_elem(&pending_memfd_exec, &tid);
            inc_counter(CNT_MEMFD_EXEC_FAIL);
        }
    }
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int capture_process_exit(struct sched_exit_ctx *ctx)
{
    /* Clean up any abandoned pending VFS identity and syscall map entries for this exiting thread */
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&unlink_identity_map, &tid);
    bpf_map_delete_elem(&rmdir_identity_map, &tid);
    bpf_map_delete_elem(&pending_syscall_map, &tid);
    bpf_map_delete_elem(&pending_memfd_map, &tid);
    bpf_map_delete_elem(&pending_memfd_exec, &tid);

    struct event *e = new_event(EVENT_PROCESS_EXIT);

    if (!e)
        return 0;

    e->reserved = (__u32)ctx->group_dead;

    bpf_probe_read_kernel_str(
        e->name, sizeof(e->name), ctx->comm
    );

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
