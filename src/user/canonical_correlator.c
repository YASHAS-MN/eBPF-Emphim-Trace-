#include "canonical_correlator.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CORRELATOR_HASH_BUCKETS 4096
#define PENDING_ENTRY_BUCKETS 1024

struct correlator_obj {
    uint64_t object_token;
    uint64_t dev_id;
    uint64_t inode_no;
    uint64_t birth_ts_ns;
    uint32_t creator_tgid;
    uint64_t creator_start_time_ns;
    bool is_released;
    bool is_evicted;
    char name[64];
    char path[128];
    struct correlator_obj *next;
};

struct correlator_desc {
    uint32_t tgid;
    uint64_t start_time_ns;
    int32_t fd;
    uint64_t object_token;
    uint64_t dev_id;
    uint64_t inode_no;
    uint64_t installed_ts_ns;
    struct correlator_desc *next;
};

struct pending_entry {
    uint32_t pid;
    uint32_t tid;
    uint64_t entry_ts_ns;
    struct pending_entry *next;
};

static struct correlator_obj *g_object_table[CORRELATOR_HASH_BUCKETS];
static struct correlator_desc *g_desc_table[CORRELATOR_HASH_BUCKETS];
static struct pending_entry *g_pending_entry_table[PENDING_ENTRY_BUCKETS];
static uint32_t g_pending_entry_count = 0;

static uint64_t g_next_object_token = 1;
static struct correlator_stats g_stats;
uint64_t diag_last_processed_token = 0;

static inline uint32_t hash_ino_dev(uint64_t dev, uint64_t ino) {
    uint64_t h = (dev ^ (ino * 0x517cc1b727220a95ULL));
    return (uint32_t)(h % CORRELATOR_HASH_BUCKETS);
}

static inline uint32_t hash_desc(uint32_t tgid, int32_t fd) {
    uint64_t h = ((uint64_t)tgid ^ ((uint64_t)(uint32_t)fd * 0x517cc1b727220a95ULL));
    return (uint32_t)(h % CORRELATOR_HASH_BUCKETS);
}

static inline uint32_t hash_pid_tid(uint32_t pid, uint32_t tid) {
    return (pid ^ (tid * 31ULL)) % PENDING_ENTRY_BUCKETS;
}

void canonical_correlator_init(void) {
    memset(g_object_table, 0, sizeof(g_object_table));
    memset(g_desc_table, 0, sizeof(g_desc_table));
    memset(g_pending_entry_table, 0, sizeof(g_pending_entry_table));
    memset(&g_stats, 0, sizeof(g_stats));
    g_pending_entry_count = 0;
    g_next_object_token = 1;
    diag_last_processed_token = 0;
}

void canonical_correlator_destroy(void) {
    for (int i = 0; i < CORRELATOR_HASH_BUCKETS; i++) {
        struct correlator_obj *curr_obj = g_object_table[i];
        while (curr_obj) {
            struct correlator_obj *to_free = curr_obj;
            curr_obj = curr_obj->next;
            free(to_free);
        }
        g_object_table[i] = NULL;

        struct correlator_desc *curr_desc = g_desc_table[i];
        while (curr_desc) {
            struct correlator_desc *to_free = curr_desc;
            curr_desc = curr_desc->next;
            free(to_free);
        }
        g_desc_table[i] = NULL;
    }

    for (int i = 0; i < PENDING_ENTRY_BUCKETS; i++) {
        struct pending_entry *curr = g_pending_entry_table[i];
        while (curr) {
            struct pending_entry *to_free = curr;
            curr = curr->next;
            free(to_free);
        }
        g_pending_entry_table[i] = NULL;
    }
    g_pending_entry_count = 0;
    memset(&g_stats, 0, sizeof(g_stats));
}

static void record_pending_entry(uint32_t pid, uint32_t tid, uint64_t ts) {
    uint32_t idx = hash_pid_tid(pid, tid);
    struct pending_entry *curr = g_pending_entry_table[idx];
    while (curr) {
        if (curr->pid == pid && curr->tid == tid) {
            curr->entry_ts_ns = ts;
            return;
        }
        curr = curr->next;
    }
    if (g_pending_entry_count >= 4096)
        return;

    struct pending_entry *entry = (struct pending_entry *)calloc(1, sizeof(*entry));
    if (!entry) return;
    entry->pid = pid;
    entry->tid = tid;
    entry->entry_ts_ns = ts;
    entry->next = g_pending_entry_table[idx];
    g_pending_entry_table[idx] = entry;
    g_pending_entry_count++;
}

static bool check_and_clear_pending_entry(uint32_t pid, uint32_t tid) {
    uint32_t idx = hash_pid_tid(pid, tid);
    struct pending_entry **curr = &g_pending_entry_table[idx];
    while (*curr) {
        if ((*curr)->pid == pid && (*curr)->tid == tid) {
            struct pending_entry *to_free = *curr;
            *curr = to_free->next;
            free(to_free);
            if (g_pending_entry_count > 0)
                g_pending_entry_count--;
            return true;
        }
        curr = &(*curr)->next;
    }
    return false;
}

static struct correlator_obj *find_object(uint64_t dev, uint64_t ino) {
    if (dev == 0 && ino == 0)
        return NULL;
    uint32_t idx = hash_ino_dev(dev, ino);
    struct correlator_obj *curr = g_object_table[idx];
    while (curr) {
        if (curr->dev_id == dev && curr->inode_no == ino && !curr->is_evicted)
            return curr;
        curr = curr->next;
    }
    return NULL;
}

static int reap_evicted_objects(void) {
    int reaped = 0;
    for (int i = 0; i < CORRELATOR_HASH_BUCKETS; i++) {
        struct correlator_obj **curr = &g_object_table[i];
        while (*curr) {
            if ((*curr)->is_evicted) {
                struct correlator_obj *to_free = *curr;
                *curr = to_free->next;
                free(to_free);
                g_stats.retired_objects_count++;
                reaped++;
            } else {
                curr = &(*curr)->next;
            }
        }
    }
    return reaped;
}

static struct correlator_obj *upsert_object(uint64_t dev, uint64_t ino, uint64_t birth_ts,
                                            uint32_t creator_tgid, uint64_t creator_start_time,
                                            const char *name, const char *path) {
    if (dev == 0 && ino == 0)
        return NULL;

    uint32_t idx = hash_ino_dev(dev, ino);
    struct correlator_obj *obj = g_object_table[idx];
    while (obj) {
        if (obj->dev_id == dev && obj->inode_no == ino)
            break;
        obj = obj->next;
    }

    if (obj) {
        /* Inode reuse detection:
         * 1. Object was previously evicted/destroyed.
         * 2. Or birth timestamps differ.
         */
        if (obj->is_evicted ||
            (birth_ts != 0 && obj->birth_ts_ns != 0 && birth_ts != obj->birth_ts_ns)) {
            g_stats.inode_reuses_detected++;
            obj->object_token = g_next_object_token++;
            obj->birth_ts_ns = birth_ts;
            obj->creator_tgid = creator_tgid;
            obj->creator_start_time_ns = creator_start_time;
            if (obj->is_evicted) {
                obj->is_evicted = false;
                g_stats.active_objects_count++;
            }
            obj->is_released = false;
            if (name && name[0])
                snprintf(obj->name, sizeof(obj->name), "%s", name);
            if (path && path[0])
                snprintf(obj->path, sizeof(obj->path), "%s", path);
            return obj;
        }
        if (name && name[0] && (!obj->name[0]))
            snprintf(obj->name, sizeof(obj->name), "%s", name);
        if (path && path[0] && (!obj->path[0]))
            snprintf(obj->path, sizeof(obj->path), "%s", path);
        return obj;
    }

    /* Bounded state check: enforce max active objects */
    if (g_stats.active_objects_count >= CORRELATOR_MAX_OBJECTS) {
        g_stats.allocation_failures++;
        return NULL;
    }

    /* Reap evicted objects if table capacity is approached */
    reap_evicted_objects();

    obj = (struct correlator_obj *)calloc(1, sizeof(*obj));
    if (!obj) {
        g_stats.allocation_failures++;
        return NULL;
    }
    obj->object_token = g_next_object_token++;
    obj->dev_id = dev;
    obj->inode_no = ino;
    obj->birth_ts_ns = birth_ts;
    obj->creator_tgid = creator_tgid;
    obj->creator_start_time_ns = creator_start_time;
    if (name)
        snprintf(obj->name, sizeof(obj->name), "%s", name);
    if (path)
        snprintf(obj->path, sizeof(obj->path), "%s", path);

    obj->next = g_object_table[idx];
    g_object_table[idx] = obj;
    g_stats.active_objects_count++;
    return obj;
}

static struct correlator_desc *find_desc(uint32_t tgid, uint64_t start_time, int32_t fd) {
    if (fd < 0)
        return NULL;
    uint32_t idx = hash_desc(tgid, fd);
    struct correlator_desc *curr = g_desc_table[idx];

    if (start_time != 0) {
        while (curr) {
            if (curr->tgid == tgid && curr->fd == fd &&
                (curr->start_time_ns == start_time || curr->start_time_ns == 0))
                return curr;
            curr = curr->next;
        }
        return NULL;
    }

    /* start_time == 0: incoming event lacks process start time */
    struct correlator_desc *match = NULL;
    int match_count = 0;
    while (curr) {
        if (curr->tgid == tgid && curr->fd == fd) {
            match = curr;
            match_count++;
        }
        curr = curr->next;
    }

    if (match_count == 1) {
        return match;
    } else if (match_count > 1) {
        /* Ambiguity across multiple generations of recycled PID: preserve uncertainty */
        g_stats.uncertain_correlation_count++;
        return NULL;
    }
    return NULL;
}

static int set_desc(uint32_t tgid, uint64_t start_time, int32_t fd,
                    uint64_t token, uint64_t dev, uint64_t ino, uint64_t install_ts) {
    if (fd < 0)
        return -1;
    struct correlator_desc *desc = find_desc(tgid, start_time, fd);
    if (desc) {
        /* Descriptor reassignment without prior close */
        g_stats.fd_reuses_without_close++;
        desc->object_token = token;
        desc->dev_id = dev;
        desc->inode_no = ino;
        desc->installed_ts_ns = install_ts;
        if (start_time != 0)
            desc->start_time_ns = start_time;
        return 0;
    }

    /* Bounded state check */
    if (g_stats.active_descriptors_count >= CORRELATOR_MAX_DESCRIPTORS) {
        g_stats.allocation_failures++;
        return -1;
    }

    uint32_t idx = hash_desc(tgid, fd);
    desc = (struct correlator_desc *)calloc(1, sizeof(*desc));
    if (!desc) {
        g_stats.allocation_failures++;
        return -1;
    }
    desc->tgid = tgid;
    desc->start_time_ns = start_time;
    desc->fd = fd;
    desc->object_token = token;
    desc->dev_id = dev;
    desc->inode_no = ino;
    desc->installed_ts_ns = install_ts;

    desc->next = g_desc_table[idx];
    g_desc_table[idx] = desc;
    g_stats.active_descriptors_count++;
    return 0;
}

static void remove_desc(uint32_t tgid, uint64_t start_time, int32_t fd) {
    if (fd < 0)
        return;
    uint32_t idx = hash_desc(tgid, fd);
    struct correlator_desc **curr = &g_desc_table[idx];
    while (*curr) {
        if ((*curr)->tgid == tgid && (*curr)->fd == fd &&
            (start_time == 0 || (*curr)->start_time_ns == 0 || (*curr)->start_time_ns == start_time)) {
            struct correlator_desc *to_free = *curr;
            *curr = to_free->next;
            free(to_free);
            if (g_stats.active_descriptors_count > 0)
                g_stats.active_descriptors_count--;
            return;
        }
        curr = &(*curr)->next;
    }
}

int canonical_correlator_process_event(struct event *e) {
    if (!e)
        return -1;

    g_stats.raw_events_in++;
    diag_last_processed_token = 0;

    switch (e->type) {
    case EVENT_MEMFD_CREATE: {
        /* Syscall attempt: tokens are never allocated on entry */
        e->object_token = 0;
        record_pending_entry(e->pid, e->tid, e->entry_ts_ns ? e->entry_ts_ns : e->timestamp_ns);
        break;
    }

    case EVENT_FD_INSTALLED: {
        /* File descriptor install */
        uint64_t tok = 0;
        if (e->inode_no != 0) {
            struct correlator_obj *obj = upsert_object(e->dev_id, e->inode_no, e->entry_ts_ns,
                                                       e->pid, e->start_time_ns, e->name, e->path);
            if (obj)
                tok = obj->object_token;
        }
        if (tok != 0) {
            e->object_token = tok;
            set_desc(e->pid, e->start_time_ns, e->fd, tok, e->dev_id, e->inode_no, e->timestamp_ns);
        } else {
            e->object_token = 0;
            g_stats.uncertain_correlation_count++;
        }
        break;
    }

    case EVENT_MEMFD_COMPLETED: {
        bool had_entry = check_and_clear_pending_entry(e->pid, e->tid);
        if (!had_entry && e->entry_ts_ns == 0) {
            g_stats.missing_entry_count++;
        } else if (!had_entry) {
            /* Entry event was not received in userspace */
            g_stats.missing_entry_count++;
        }

        if (e->ret_val < 0) {
            /* Syscall failed: use named constant MEMFD_STATUS_FAILED (1) */
            e->op_type = MEMFD_STATUS_FAILED;
            e->object_token = 0;
            g_stats.failed_creations++;
            if (e->fd >= 0)
                remove_desc(e->pid, e->start_time_ns, e->fd);
        } else {
            /* Missing install observation check */
            struct correlator_desc *desc = find_desc(e->pid, e->start_time_ns, e->ret_val);
            if (!desc || desc->object_token == 0) {
                g_stats.missing_install_count++;
            }

            /* Syscall succeeded */
            if (e->op_type == MEMFD_STATUS_SUCCESS_CORRELATED &&
                (e->flags & 0x01 /* VFS_IDENTITY_INODE_VALID */) && e->inode_no != 0) {
                struct correlator_obj *obj = upsert_object(e->dev_id, e->inode_no, e->entry_ts_ns,
                                                           e->pid, e->start_time_ns, e->name, e->path);
                if (obj) {
                    e->object_token = obj->object_token;
                    e->op_type = MEMFD_STATUS_SUCCESS_CORRELATED;
                    set_desc(e->pid, e->start_time_ns, e->fd, obj->object_token, e->dev_id, e->inode_no, e->timestamp_ns);
                    g_stats.correlated_creations++;
                } else {
                    /* State allocation failure: classify truthfully as uncorrelated */
                    e->object_token = 0;
                    e->op_type = MEMFD_STATUS_SUCCESS_UNCORRELATED;
                    g_stats.uncorrelated_creations++;
                }
            } else {
                /* Missing or invalid identity: classify truthfully as uncorrelated */
                e->object_token = 0;
                e->op_type = MEMFD_STATUS_SUCCESS_UNCORRELATED;
                g_stats.uncorrelated_creations++;
            }
        }
        break;
    }

    case EVENT_FD_CLOSED: {
        struct correlator_desc *desc = find_desc(e->pid, e->start_time_ns, e->fd);
        if (desc && desc->object_token != 0) {
            e->object_token = desc->object_token;
            e->inode_no = desc->inode_no;
            e->dev_id = desc->dev_id;
            if (e->start_time_ns == 0 && desc->start_time_ns != 0)
                e->start_time_ns = desc->start_time_ns;
            remove_desc(e->pid, e->start_time_ns, e->fd);
        } else {
            e->object_token = 0;
            g_stats.untracked_closes++;
            g_stats.uncertain_correlation_count++;
        }
        break;
    }

    case EVENT_MEMFD_WRITE: {
        struct correlator_desc *desc = find_desc(e->pid, e->start_time_ns, e->fd);
        if (desc && desc->object_token != 0) {
            e->object_token = desc->object_token;
            if (e->start_time_ns == 0 && desc->start_time_ns != 0)
                e->start_time_ns = desc->start_time_ns;
        } else {
            struct correlator_obj *obj = find_object(e->dev_id, e->inode_no);
            if (obj) {
                e->object_token = obj->object_token;
            } else {
                e->object_token = 0;
                g_stats.uncertain_correlation_count++;
            }
        }
        break;
    }

    case EVENT_MEMFD_FILE_RELEASED: {
        struct correlator_obj *obj = find_object(e->dev_id, e->inode_no);
        if (obj) {
            e->object_token = obj->object_token;
            obj->is_released = true;
        } else {
            e->object_token = 0;
            g_stats.uncertain_correlation_count++;
        }
        break;
    }

    case EVENT_MEMFD_DESTROYED: {
        struct correlator_obj *obj = find_object(e->dev_id, e->inode_no);
        if (obj) {
            e->object_token = obj->object_token;
            obj->is_evicted = true;
            if (g_stats.active_objects_count > 0)
                g_stats.active_objects_count--;
        } else {
            e->object_token = 0;
            g_stats.uncertain_correlation_count++;
        }
        break;
    }

    case EVENT_MEMFD_EXEC_ATTEMPT:
    case EVENT_MEMFD_EXEC_SUCCESS: {
        struct correlator_obj *obj = find_object(e->dev_id, e->inode_no);
        if (obj) {
            e->object_token = obj->object_token;
        } else {
            e->object_token = 0;
            g_stats.uncertain_correlation_count++;
        }
        break;
    }

    default:
        /* Unrelated hooks pass through unaffected */
        break;
    }

    diag_last_processed_token = e->object_token;
    g_stats.canonical_events_out++;
    return 0;
}

int canonical_correlator_process_event_canonical(const struct event *raw, struct canonical_event *canon) {
    if (!raw || !canon)
        return -1;
    struct event temp = *raw;
    int rc = canonical_correlator_process_event(&temp);
    if (rc != 0)
        return rc;

    canon->type = temp.type;
    canon->pid = temp.pid;
    canon->tid = temp.tid;
    canon->start_time_ns = temp.start_time_ns;
    canon->fd = temp.fd;
    canon->object_token = temp.object_token;
    canon->inode_no = temp.inode_no;
    canon->dev_id = temp.dev_id;
    canon->op_type = temp.op_type;
    canon->timestamp_ns = temp.timestamp_ns;
    canon->creator_tgid = 0;
    canon->creator_start_time_ns = 0;

    /* Propagate creator lifetime identity consistently */
    if (canon->inode_no != 0) {
        struct correlator_obj *obj = find_object(canon->dev_id, canon->inode_no);
        if (obj) {
            canon->creator_tgid = obj->creator_tgid;
            canon->creator_start_time_ns = obj->creator_start_time_ns;
        }
    }

    return 0;
}

void canonical_correlator_get_stats(struct correlator_stats *out) {
    if (out)
        *out = g_stats;
}

void canonical_correlator_reset_stats(void) {
    uint64_t act_obj = g_stats.active_objects_count;
    uint64_t act_desc = g_stats.active_descriptors_count;
    memset(&g_stats, 0, sizeof(g_stats));
    g_stats.active_objects_count = act_obj;
    g_stats.active_descriptors_count = act_desc;
}

int diag_get_correlator_stats(struct correlator_stats *cs) {
    if (cs)
        canonical_correlator_get_stats(cs);
    return 0;
}
