
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

    CNT_MAX_COUNTERS = 64
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
    return submit_path_event(
        ctx, EVENT_MEMFD_CREATE, 0, -1, (__u32)ctx->args[1]
    );
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
