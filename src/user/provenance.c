#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/sysmacros.h>

#include "provenance.h"

#define PROV_HASH_SIZE 16384
#define PID_HASH_SIZE  4096

struct active_proc_entry {
    uint32_t pid;
    struct prov_node *node;
    struct active_proc_entry *next;
};

static struct prov_node **g_node_buckets = NULL;
static struct active_proc_entry **g_active_pid_buckets = NULL;

static struct prov_node *g_nodes_head = NULL;
static struct prov_node *g_nodes_tail = NULL;
static size_t g_node_count = 0;

static struct prov_edge *g_edges_head = NULL;
static struct prov_edge *g_edges_tail = NULL;
static size_t g_edge_count = 0;

/* FNV-1a hash function */
static inline uint32_t hash_str(const char *str)
{
    uint32_t hash = 2166136261u;
    while (*str) {
        hash ^= (uint8_t)*str++;
        hash *= 16777619u;
    }
    return hash % PROV_HASH_SIZE;
}

static inline uint32_t hash_pid(uint32_t pid)
{
    return (pid * 2654435761u) % PID_HASH_SIZE;
}

static void register_active_proc(uint32_t pid, struct prov_node *node)
{
    if (!g_active_pid_buckets)
        return;
    uint32_t bucket = hash_pid(pid);
    struct active_proc_entry *entry = g_active_pid_buckets[bucket];
    while (entry) {
        if (entry->pid == pid) {
            entry->node = node;
            return;
        }
        entry = entry->next;
    }
    entry = calloc(1, sizeof(*entry));
    if (!entry)
        return;
    entry->pid = pid;
    entry->node = node;
    entry->next = g_active_pid_buckets[bucket];
    g_active_pid_buckets[bucket] = entry;
}

static struct prov_node *find_active_proc(uint32_t pid)
{
    if (!g_active_pid_buckets)
        return NULL;
    uint32_t bucket = hash_pid(pid);
    struct active_proc_entry *entry = g_active_pid_buckets[bucket];
    while (entry) {
        if (entry->pid == pid && entry->node && entry->node->proc.is_alive)
            return entry->node;
        entry = entry->next;
    }
    return NULL;
}

static void unregister_active_proc(uint32_t pid)
{
    if (!g_active_pid_buckets)
        return;
    uint32_t bucket = hash_pid(pid);
    struct active_proc_entry **curr = &g_active_pid_buckets[bucket];
    while (*curr) {
        if ((*curr)->pid == pid) {
            struct active_proc_entry *to_free = *curr;
            *curr = (*curr)->next;
            free(to_free);
            return;
        }
        curr = &(*curr)->next;
    }
}

int prov_engine_init(void)
{
    g_node_buckets = calloc(PROV_HASH_SIZE, sizeof(struct prov_node *));
    if (!g_node_buckets)
        return -ENOMEM;

    g_active_pid_buckets = calloc(PID_HASH_SIZE, sizeof(struct active_proc_entry *));
    if (!g_active_pid_buckets) {
        free(g_node_buckets);
        g_node_buckets = NULL;
        return -ENOMEM;
    }

    g_nodes_head = NULL;
    g_nodes_tail = NULL;
    g_node_count = 0;

    g_edges_head = NULL;
    g_edges_tail = NULL;
    g_edge_count = 0;

    return 0;
}

void prov_engine_get_counts(size_t *node_count, size_t *edge_count)
{
    if (node_count)
        *node_count = g_node_count;
    if (edge_count)
        *edge_count = g_edge_count;
}

struct prov_node *prov_find_node(const char *id)
{
    if (!g_node_buckets || !id || !id[0])
        return NULL;

    uint32_t bucket = hash_str(id);
    struct prov_node *curr = g_node_buckets[bucket];
    while (curr) {
        if (strcmp(curr->id, id) == 0)
            return curr;
        curr = curr->next_hash;
    }
    return NULL;
}

static struct prov_node *allocate_and_insert_node(const char *id, enum prov_node_type type)
{
    struct prov_node *node = calloc(1, sizeof(*node));
    if (!node)
        return NULL;

    node->type = type;
    snprintf(node->id, sizeof(node->id), "%s", id);
    node->filter_marked = false;

    uint32_t bucket = hash_str(id);
    node->next_hash = g_node_buckets[bucket];
    g_node_buckets[bucket] = node;

    if (!g_nodes_head) {
        g_nodes_head = node;
        g_nodes_tail = node;
    } else {
        g_nodes_tail->next_global = node;
        g_nodes_tail = node;
    }
    g_node_count++;

    return node;
}

struct prov_node *prov_upsert_process(uint32_t pid, uint64_t start_time_ns, uint32_t ppid, const char *comm)
{
    char id[128];
    struct prov_node *node = NULL;

    if (start_time_ns == 0) {
        node = find_active_proc(pid);
        if (node) {
            if (comm && comm[0] && node->proc.comm[0] == '\0')
                snprintf(node->proc.comm, sizeof(node->proc.comm), "%s", comm);
            if (ppid != 0 && node->proc.ppid == 0)
                node->proc.ppid = ppid;
            return node;
        }
        snprintf(id, sizeof(id), "proc_%u_0", pid);
    } else {
        snprintf(id, sizeof(id), "proc_%u_%llu", pid, (unsigned long long)start_time_ns);
    }

    node = prov_find_node(id);
    if (node) {
        if (comm && comm[0] && (node->proc.comm[0] == '\0' || strcmp(node->proc.comm, "<unknown>") == 0))
            snprintf(node->proc.comm, sizeof(node->proc.comm), "%s", comm);
        if (ppid != 0 && node->proc.ppid == 0)
            node->proc.ppid = ppid;
        return node;
    }

    node = allocate_and_insert_node(id, NODE_PROCESS);
    if (!node)
        return NULL;

    node->proc.pid = pid;
    node->proc.ppid = ppid;
    node->proc.start_time_ns = start_time_ns;
    if (comm && comm[0])
        snprintf(node->proc.comm, sizeof(node->proc.comm), "%s", comm);
    else
        snprintf(node->proc.comm, sizeof(node->proc.comm), "<unknown>");
    node->proc.is_alive = true;
    node->proc.exit_code = 0;

    register_active_proc(pid, node);

    return node;
}

struct prov_node *prov_upsert_memfd(uint64_t object_token, uint32_t creator_pid, uint64_t creator_start_time,
                                   const char *name, uint64_t inode_no, uint64_t dev_id)
{
    if (object_token == 0)
        return NULL;

    char id[128];
    snprintf(id, sizeof(id), "memfd_%llu", (unsigned long long)object_token);

    struct prov_node *node = prov_find_node(id);
    if (node) {
        if (name && name[0] && (node->memfd.name[0] == '\0' || strcmp(node->memfd.name, "<unknown>") == 0))
            snprintf(node->memfd.name, sizeof(node->memfd.name), "%s", name);
        if (inode_no != 0 && node->memfd.inode_no == 0)
            node->memfd.inode_no = inode_no;
        if (dev_id != 0 && node->memfd.dev_id == 0)
            node->memfd.dev_id = dev_id;
        if (creator_pid != 0 && node->memfd.creator_pid == 0) {
            node->memfd.creator_pid = creator_pid;
            node->memfd.creator_start_time = creator_start_time;
        }
        return node;
    }

    node = allocate_and_insert_node(id, NODE_MEMFD);
    if (!node)
        return NULL;

    node->memfd.object_token = object_token;
    node->memfd.creator_pid = creator_pid;
    node->memfd.creator_start_time = creator_start_time;
    if (name && name[0])
        snprintf(node->memfd.name, sizeof(node->memfd.name), "%s", name);
    else
        snprintf(node->memfd.name, sizeof(node->memfd.name), "<unknown>");
    node->memfd.inode_no = inode_no;
    node->memfd.dev_id = dev_id;
    node->memfd.is_destroyed = false;

    return node;
}

struct prov_node *prov_upsert_fs(uint64_t inode_no, uint64_t dev_id, uint32_t mnt_ns_id, const char *path)
{
    char id[128];
    snprintf(id, sizeof(id), "fs_%llu_%llu", (unsigned long long)dev_id, (unsigned long long)inode_no);

    struct prov_node *node = prov_find_node(id);
    if (node) {
        if (path && path[0] && (node->fs.path[0] == '\0' || strcmp(node->fs.path, "<unavailable>") == 0))
            snprintf(node->fs.path, sizeof(node->fs.path), "%s", path);
        if (mnt_ns_id != 0 && node->fs.mnt_ns_id == 0)
            node->fs.mnt_ns_id = mnt_ns_id;
        return node;
    }

    node = allocate_and_insert_node(id, NODE_FS_OBJECT);
    if (!node)
        return NULL;

    node->fs.inode_no = inode_no;
    node->fs.dev_id = dev_id;
    node->fs.mnt_ns_id = mnt_ns_id;
    if (path && path[0])
        snprintf(node->fs.path, sizeof(node->fs.path), "%s", path);
    else
        snprintf(node->fs.path, sizeof(node->fs.path), "<unavailable>");
    node->fs.is_unlinked = false;

    return node;
}

struct prov_node *prov_upsert_net(uint16_t family, const char *ip_str, uint16_t port)
{
    char id[128];
    snprintf(id, sizeof(id), "net_%u_%s_%u", family, ip_str ? ip_str : "unknown", port);

    struct prov_node *node = prov_find_node(id);
    if (node)
        return node;

    node = allocate_and_insert_node(id, NODE_NET_ENDPOINT);
    if (!node)
        return NULL;

    node->net.family = family;
    snprintf(node->net.ip_str, sizeof(node->net.ip_str), "%s", ip_str ? ip_str : "unknown");
    node->net.port = port;

    return node;
}

struct prov_edge *prov_add_edge(struct prov_node *src, struct prov_node *dst, enum prov_edge_type type, const struct prov_edge_attr *attr)
{
    if (!src || !dst)
        return NULL;

    struct prov_edge *edge = calloc(1, sizeof(*edge));
    if (!edge)
        return NULL;

    edge->type = type;
    edge->src = src;
    edge->dst = dst;
    if (attr)
        edge->attr = *attr;

    /* Add to source's outbound adjacency list */
    edge->next_out = src->out_edges;
    src->out_edges = edge;

    /* Add to destination's inbound adjacency list */
    edge->next_in = dst->in_edges;
    dst->in_edges = edge;

    /* Append to global edge list for chronological iteration */
    if (!g_edges_head) {
        g_edges_head = edge;
        g_edges_tail = edge;
    } else {
        g_edges_tail->next_global = edge;
        g_edges_tail = edge;
    }
    g_edge_count++;

    return edge;
}

void prov_engine_process_event(const struct event *e)
{
    if (!e || e->type == EVENT_DEBUG)
        return;

    switch (e->type) {
    case EVENT_FORK: {
        struct prov_node *src = prov_upsert_process(e->pid, e->start_time_ns, e->ppid, NULL);
        struct prov_node *dst = prov_upsert_process(e->child_tgid, e->child_start_time_ns, e->pid, e->name);

        if (e->child_tgid != e->pid && src && dst) {
            struct prov_edge_attr attr = {
                .timestamp_ns = e->timestamp_ns,
                .fd = -1,
            };
            prov_add_edge(src, dst, EDGE_FORK, &attr);
        }
        break;
    }

    case EVENT_PROCESS_EXEC: {
        struct prov_node *proc = prov_upsert_process(e->pid, e->start_time_ns, e->ppid, e->name);
        if (proc && e->name[0]) {
            snprintf(proc->proc.comm, sizeof(proc->proc.comm), "%s", e->name);
        }
        break;
    }

    case EVENT_PROCESS_EXIT: {
        struct prov_node *proc = prov_upsert_process(e->pid, e->start_time_ns, e->ppid, e->name);
        if (proc && e->reserved) {
            proc->proc.is_alive = false;
            proc->proc.exit_code = e->ret_val;
            unregister_active_proc(e->pid);
        }
        break;
    }

    case EVENT_MEMFD_CREATE: {
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
    }

    case EVENT_FD_INSTALLED: {
        if (e->object_token != 0) {
            struct prov_node *proc = prov_upsert_process(e->pid, e->start_time_ns, e->ppid, NULL);
            struct prov_node *memfd = prov_upsert_memfd(e->object_token, e->pid, e->start_time_ns, "", 0, 0);
            struct prov_edge_attr attr = {
                .timestamp_ns = e->timestamp_ns,
                .fd = e->fd,
            };
            if (e->op_type == 1)
                snprintf(attr.fd_installed.install_type, sizeof(attr.fd_installed.install_type), "CREATION");
            else if (e->op_type == 2)
                snprintf(attr.fd_installed.install_type, sizeof(attr.fd_installed.install_type), "REOPEN");
            else if (e->op_type == 3)
                snprintf(attr.fd_installed.install_type, sizeof(attr.fd_installed.install_type), "DUP");
            else
                snprintf(attr.fd_installed.install_type, sizeof(attr.fd_installed.install_type), "INSTALL");

            prov_add_edge(proc, memfd, EDGE_FD_INSTALLED, &attr);
        }
        break;
    }

    case EVENT_FD_CLOSED: {
        if (e->object_token != 0) {
            struct prov_node *proc = prov_upsert_process(e->pid, e->start_time_ns, e->ppid, NULL);
            struct prov_node *memfd = prov_upsert_memfd(e->object_token, e->pid, e->start_time_ns, "", 0, 0);
            struct prov_edge_attr attr = {
                .timestamp_ns = e->timestamp_ns,
                .fd = e->fd,
            };
            attr.fd_closed.duration_ns = e->entry_ts_ns;
            prov_add_edge(proc, memfd, EDGE_FD_CLOSED, &attr);
        }
        break;
    }

    case EVENT_MEMFD_WRITE: {
        if (e->object_token != 0) {
            struct prov_node *proc = prov_upsert_process(e->pid, e->start_time_ns, e->ppid, NULL);
            struct prov_node *memfd = prov_upsert_memfd(e->object_token, e->pid, e->start_time_ns, "", 0, 0);
            struct prov_edge_attr attr = {
                .timestamp_ns = e->timestamp_ns,
                .fd = -1,
            };
            attr.write.offset = (int64_t)e->entry_ts_ns;
            attr.write.bytes = (uint64_t)e->ret_val;
            prov_add_edge(proc, memfd, EDGE_MEMFD_WRITE, &attr);
        }
        break;
    }

    case EVENT_MEMFD_EXEC_ATTEMPT: {
        if (e->object_token != 0) {
            struct prov_node *proc = prov_upsert_process(e->pid, e->start_time_ns, e->ppid, NULL);
            struct prov_node *memfd = prov_upsert_memfd(e->object_token, e->pid, e->start_time_ns, "", 0, 0);
            struct prov_edge_attr attr = {
                .timestamp_ns = e->timestamp_ns,
                .fd = -1,
            };
            snprintf(attr.exec_attempt.filename, sizeof(attr.exec_attempt.filename), "%s",
                     e->name[0] ? e->name : "<unknown>");
            prov_add_edge(proc, memfd, EDGE_MEMFD_EXEC_ATTEMPT, &attr);
        }
        break;
    }

    case EVENT_MEMFD_EXEC_SUCCESS: {
        if (e->object_token != 0) {
            struct prov_node *proc = prov_upsert_process(e->pid, e->start_time_ns, e->ppid, e->name);
            struct prov_node *memfd = prov_upsert_memfd(e->object_token, e->pid, e->start_time_ns, "", 0, 0);
            if (proc && e->name[0]) {
                snprintf(proc->proc.comm, sizeof(proc->proc.comm), "%s", e->name);
            }
            struct prov_edge_attr attr = {
                .timestamp_ns = e->timestamp_ns,
                .fd = -1,
            };
            snprintf(attr.exec_success.binary_comm, sizeof(attr.exec_success.binary_comm), "%s",
                     e->name[0] ? e->name : "<unknown>");
            prov_add_edge(proc, memfd, EDGE_MEMFD_EXEC_SUCCESS, &attr);
        }
        break;
    }

    case EVENT_MEMFD_DESTROYED: {
        if (e->object_token != 0) {
            struct prov_node *memfd = prov_upsert_memfd(e->object_token, e->pid, e->start_time_ns,
                                                        e->name, e->inode_no, e->dev_id);
            if (memfd)
                memfd->memfd.is_destroyed = true;
        }
        break;
    }

    case EVENT_VFS_UNLINK_COMPLETED:
    case EVENT_VFS_RMDIR_COMPLETED: {
        struct prov_node *proc = prov_upsert_process(e->pid, e->start_time_ns, e->ppid, NULL);
        const char *path = e->path[0] ? e->path : (e->name[0] ? e->name : "<unknown>");
        struct prov_node *fs = prov_upsert_fs(e->inode_no, e->dev_id, e->mnt_ns_id, path);
        if (fs && e->ret_val == 0)
            fs->fs.is_unlinked = true;

        struct prov_edge_attr attr = {
            .timestamp_ns = e->timestamp_ns,
            .fd = e->dirfd,
        };
        snprintf(attr.unlink.path, sizeof(attr.unlink.path), "%s", path);
        snprintf(attr.unlink.status, sizeof(attr.unlink.status), "%s", (e->ret_val == 0) ? "SUCCESS" : "FAILED");
        prov_add_edge(proc, fs, EDGE_UNLINK, &attr);
        break;
    }

    case EVENT_CONNECT: {
        struct prov_node *proc = prov_upsert_process(e->pid, e->start_time_ns, e->ppid, NULL);
        char ip_str[INET6_ADDRSTRLEN] = "<unsupported>";
        if (e->family == AF_INET)
            inet_ntop(AF_INET, e->address, ip_str, sizeof(ip_str));
        else if (e->family == AF_INET6)
            inet_ntop(AF_INET6, e->address, ip_str, sizeof(ip_str));

        uint16_t port = ntohs(e->port);
        struct prov_node *net = prov_upsert_net(e->family, ip_str, port);

        struct prov_edge_attr attr = {
            .timestamp_ns = e->timestamp_ns,
            .fd = e->fd,
        };
        attr.connect.result = e->ret_val;
        prov_add_edge(proc, net, EDGE_CONNECT, &attr);
        break;
    }

    default:
        break;
    }
}

/* Helpers for DOT and JSON escaping */
static void escape_string(const char *in, char *out, size_t out_sz)
{
    size_t j = 0;
    for (size_t i = 0; in && in[i] && j + 2 < out_sz; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"' || c == '\\') {
            out[j++] = '\\';
            out[j++] = c;
        } else if (c == '\n') {
            out[j++] = '\\';
            out[j++] = 'n';
        } else if (c == '\r') {
            out[j++] = '\\';
            out[j++] = 'r';
        } else if (c == '\t') {
            out[j++] = '\\';
            out[j++] = 't';
        } else if (c >= 32 && c < 127) {
            out[j++] = c;
        } else {
            out[j++] = '?';
        }
    }
    out[j] = '\0';
}

/* Milestone 6 Phase 2: Filtering Engine */
int prov_engine_filter_subgraph(uint32_t target_pid, uint64_t target_token, struct prov_graph *out_filtered)
{
    if (!out_filtered)
        return -EINVAL;

    memset(out_filtered, 0, sizeof(*out_filtered));

    /* Reset filter flags on all nodes */
    struct prov_node *node = g_nodes_head;
    while (node) {
        node->filter_marked = false;
        node = node->next_global;
    }

    /* If neither filter is active, export the whole graph */
    if (target_pid == 0 && target_token == 0) {
        size_t n_nodes = g_node_count;
        size_t n_edges = g_edge_count;

        out_filtered->nodes = calloc(n_nodes > 0 ? n_nodes : 1, sizeof(struct prov_node *));
        out_filtered->edges = calloc(n_edges > 0 ? n_edges : 1, sizeof(struct prov_edge *));
        if (!out_filtered->nodes || !out_filtered->edges) {
            prov_graph_free(out_filtered);
            return -ENOMEM;
        }

        size_t ni = 0;
        node = g_nodes_head;
        while (node) {
            out_filtered->nodes[ni++] = node;
            node = node->next_global;
        }
        out_filtered->node_count = ni;

        size_t ei = 0;
        struct prov_edge *edge = g_edges_head;
        while (edge) {
            out_filtered->edges[ei++] = edge;
            edge = edge->next_global;
        }
        out_filtered->edge_count = ei;
        return 0;
    }

    /* Allocate BFS queue */
    size_t max_nodes = g_node_count > 0 ? g_node_count : 16;
    struct prov_node **queue = calloc(max_nodes, sizeof(struct prov_node *));
    if (!queue)
        return -ENOMEM;

    size_t q_head = 0;
    size_t q_tail = 0;

    /* 1. Seed identification */
    node = g_nodes_head;
    while (node) {
        bool is_seed = false;
        if (target_pid != 0 && node->type == NODE_PROCESS && node->proc.pid == target_pid) {
            is_seed = true;
        }
        if (target_token != 0 && node->type == NODE_MEMFD && node->memfd.object_token == target_token) {
            is_seed = true;
        }

        if (is_seed && !node->filter_marked) {
            node->filter_marked = true;
            queue[q_tail++] = node;
        }
        node = node->next_global;
    }

    /* 2. Traverse connected components */
    while (q_head < q_tail) {
        struct prov_node *curr = queue[q_head++];

        if (curr->type == NODE_PROCESS) {
            /* Outbound edges from process to:
             * - Child processes (EDGE_FORK)
             * - Memfds (EDGE_MEMFD_*, EDGE_FD_*)
             * - FS Objects (EDGE_UNLINK)
             * - Net Endpoints (EDGE_CONNECT)
             */
            struct prov_edge *e = curr->out_edges;
            while (e) {
                if (e->dst && !e->dst->filter_marked) {
                    e->dst->filter_marked = true;
                    if (q_tail < max_nodes)
                        queue[q_tail++] = e->dst;
                }
                e = e->next_out;
            }
        } else if (curr->type == NODE_MEMFD) {
            /* Inbound edges from processes that created/wrote/executed this memfd */
            struct prov_edge *e = curr->in_edges;
            while (e) {
                if (e->src && !e->src->filter_marked) {
                    /* If target_pid was specified, only traverse to that target process or its descendants */
                    if (target_pid == 0 || e->src->proc.pid == target_pid) {
                        e->src->filter_marked = true;
                        if (q_tail < max_nodes)
                            queue[q_tail++] = e->src;
                    }
                }
                e = e->next_in;
            }
        }
    }

    free(queue);

    /* 3. Collect matched nodes */
    size_t n_matched = 0;
    node = g_nodes_head;
    while (node) {
        if (node->filter_marked)
            n_matched++;
        node = node->next_global;
    }

    /* 4. Collect matched edges (both source and destination in subgraph) */
    size_t e_matched = 0;
    struct prov_edge *edge = g_edges_head;
    while (edge) {
        if (edge->src && edge->dst && edge->src->filter_marked && edge->dst->filter_marked)
            e_matched++;
        edge = edge->next_global;
    }

    out_filtered->nodes = calloc(n_matched > 0 ? n_matched : 1, sizeof(struct prov_node *));
    out_filtered->edges = calloc(e_matched > 0 ? e_matched : 1, sizeof(struct prov_edge *));
    if (!out_filtered->nodes || !out_filtered->edges) {
        prov_graph_free(out_filtered);
        return -ENOMEM;
    }

    size_t ni = 0;
    node = g_nodes_head;
    while (node) {
        if (node->filter_marked)
            out_filtered->nodes[ni++] = node;
        node = node->next_global;
    }
    out_filtered->node_count = ni;

    size_t ei = 0;
    edge = g_edges_head;
    while (edge) {
        if (edge->src && edge->dst && edge->src->filter_marked && edge->dst->filter_marked)
            out_filtered->edges[ei++] = edge;
        edge = edge->next_global;
    }
    out_filtered->edge_count = ei;

    return 0;
}

void prov_graph_free(struct prov_graph *graph)
{
    if (!graph)
        return;
    if (graph->nodes) {
        free(graph->nodes);
        graph->nodes = NULL;
    }
    if (graph->edges) {
        free(graph->edges);
        graph->edges = NULL;
    }
    graph->node_count = 0;
    graph->edge_count = 0;
}

/* Helper to render graph to DOT stream */
static int render_graph_dot(FILE *f, const struct prov_graph *g)
{
    if (!f || !g)
        return -EINVAL;

    fprintf(f, "digraph EphimTraceDAG {\n");
    fprintf(f, "    rankdir=LR;\n");
    fprintf(f, "    compound=true;\n");
    fprintf(f, "    node [fontsize=10, fontname=\"Helvetica\"];\n");
    fprintf(f, "    edge [fontsize=8, fontname=\"Helvetica\"];\n\n");

    /* Export Nodes */
    fprintf(f, "    /* --- Nodes --- */\n");
    char esc_buf1[512];
    char esc_buf2[512];

    for (size_t i = 0; i < g->node_count; i++) {
        struct prov_node *node = g->nodes[i];
        switch (node->type) {
        case NODE_PROCESS:
            escape_string(node->proc.comm, esc_buf1, sizeof(esc_buf1));
            fprintf(f, "    \"%s\" [shape=box, style=\"filled,rounded\", fillcolor=\"#E0F7FA\", "
                       "color=\"#00838F\", fontcolor=\"#006064\", "
                       "label=\"Process\\nPID: %u (PPID: %u)\\nComm: %s\\nStart: %llu ns\\n[%s]\"];\n",
                    node->id, node->proc.pid, node->proc.ppid, esc_buf1,
                    (unsigned long long)node->proc.start_time_ns,
                    node->proc.is_alive ? "ALIVE" : "DEAD");
            break;

        case NODE_MEMFD:
            escape_string(node->memfd.name, esc_buf1, sizeof(esc_buf1));
            fprintf(f, "    \"%s\" [shape=hexagon, style=\"filled\", fillcolor=\"#FFF3E0\", "
                       "color=\"#E65100\", fontcolor=\"#BF360C\", "
                       "label=\"Memfd Object\\nToken: %llu\\nName: %s\\nInode: %llu\\nDev: %llu\\n[%s]\"];\n",
                    node->id, (unsigned long long)node->memfd.object_token, esc_buf1,
                    (unsigned long long)node->memfd.inode_no,
                    (unsigned long long)node->memfd.dev_id,
                    node->memfd.is_destroyed ? "DESTROYED" : "ACTIVE");
            break;

        case NODE_FS_OBJECT:
            escape_string(node->fs.path, esc_buf1, sizeof(esc_buf1));
            fprintf(f, "    \"%s\" [shape=folder, style=\"filled\", fillcolor=\"#E8F5E9\", "
                       "color=\"#2E7D32\", fontcolor=\"#1B5E20\", "
                       "label=\"FS Object\\nPath: %s\\nInode: %llu\\nDev: %llu\\n[%s]\"];\n",
                    node->id, esc_buf1,
                    (unsigned long long)node->fs.inode_no,
                    (unsigned long long)node->fs.dev_id,
                    node->fs.is_unlinked ? "UNLINKED" : "ACTIVE");
            break;

        case NODE_NET_ENDPOINT:
            escape_string(node->net.ip_str, esc_buf1, sizeof(esc_buf1));
            fprintf(f, "    \"%s\" [shape=component, style=\"filled\", fillcolor=\"#F3E5F5\", "
                       "color=\"#6A1B9A\", fontcolor=\"#4A148C\", "
                       "label=\"Net Endpoint\\n%s:%u\\nFamily: %u\"];\n",
                    node->id, esc_buf1, node->net.port, node->net.family);
            break;
        }
    }

    /* Export Edges */
    fprintf(f, "\n    /* --- Edges --- */\n");
    for (size_t i = 0; i < g->edge_count; i++) {
        struct prov_edge *edge = g->edges[i];
        if (edge->src && edge->dst) {
            switch (edge->type) {
            case EDGE_FORK:
                fprintf(f, "    \"%s\" -> \"%s\" [label=\"fork()\\n@%llu ns\", color=\"#0288D1\", fontcolor=\"#0288D1\"];\n",
                        edge->src->id, edge->dst->id, (unsigned long long)edge->attr.timestamp_ns);
                break;

            case EDGE_MEMFD_CREATE:
                fprintf(f, "    \"%s\" -> \"%s\" [label=\"memfd_create(fd=%d)\\n@%llu ns\", color=\"#F57C00\", fontcolor=\"#F57C00\"];\n",
                        edge->src->id, edge->dst->id, edge->attr.fd, (unsigned long long)edge->attr.timestamp_ns);
                break;

            case EDGE_FD_INSTALLED:
                escape_string(edge->attr.fd_installed.install_type, esc_buf1, sizeof(esc_buf1));
                fprintf(f, "    \"%s\" -> \"%s\" [label=\"fd_install(fd=%d, %s)\\n@%llu ns\", color=\"#FB8C00\", fontcolor=\"#FB8C00\"];\n",
                        edge->src->id, edge->dst->id, edge->attr.fd, esc_buf1, (unsigned long long)edge->attr.timestamp_ns);
                break;

            case EDGE_FD_CLOSED:
                fprintf(f, "    \"%s\" -> \"%s\" [label=\"close_fd(fd=%d, dur=%llu ns)\\n@%llu ns\", color=\"#757575\", fontcolor=\"#616161\"];\n",
                        edge->src->id, edge->dst->id, edge->attr.fd,
                        (unsigned long long)edge->attr.fd_closed.duration_ns,
                        (unsigned long long)edge->attr.timestamp_ns);
                break;

            case EDGE_MEMFD_WRITE:
                fprintf(f, "    \"%s\" -> \"%s\" [label=\"write(off=%lld, bytes=%llu)\\n@%llu ns\", color=\"#D84315\", fontcolor=\"#D84315\"];\n",
                        edge->src->id, edge->dst->id,
                        (long long)edge->attr.write.offset,
                        (unsigned long long)edge->attr.write.bytes,
                        (unsigned long long)edge->attr.timestamp_ns);
                break;

            case EDGE_MEMFD_EXEC_ATTEMPT:
                escape_string(edge->attr.exec_attempt.filename, esc_buf1, sizeof(esc_buf1));
                fprintf(f, "    \"%s\" -> \"%s\" [label=\"exec_attempt(%s)\\n@%llu ns\", color=\"#C2185B\", fontcolor=\"#C2185B\"];\n",
                        edge->src->id, edge->dst->id, esc_buf1, (unsigned long long)edge->attr.timestamp_ns);
                break;

            case EDGE_MEMFD_EXEC_SUCCESS:
                escape_string(edge->attr.exec_success.binary_comm, esc_buf1, sizeof(esc_buf1));
                fprintf(f, "    \"%s\" -> \"%s\" [label=\"exec_success(%s)\\n@%llu ns\", color=\"#7B1FA2\", fontcolor=\"#7B1FA2\"];\n",
                        edge->src->id, edge->dst->id, esc_buf1, (unsigned long long)edge->attr.timestamp_ns);
                break;

            case EDGE_UNLINK:
                escape_string(edge->attr.unlink.path, esc_buf1, sizeof(esc_buf1));
                escape_string(edge->attr.unlink.status, esc_buf2, sizeof(esc_buf2));
                fprintf(f, "    \"%s\" -> \"%s\" [label=\"unlink(%s, %s)\\n@%llu ns\", color=\"#388E3C\", fontcolor=\"#388E3C\"];\n",
                        edge->src->id, edge->dst->id, esc_buf1, esc_buf2, (unsigned long long)edge->attr.timestamp_ns);
                break;

            case EDGE_CONNECT:
                fprintf(f, "    \"%s\" -> \"%s\" [label=\"connect(fd=%d, res=%d)\\n@%llu ns\", color=\"#512DA8\", fontcolor=\"#512DA8\"];\n",
                        edge->src->id, edge->dst->id, edge->attr.fd, edge->attr.connect.result,
                        (unsigned long long)edge->attr.timestamp_ns);
                break;
            }
        }
    }

    fprintf(f, "}\n");
    return 0;
}

/* Helper to render graph to JSON stream */
static int render_graph_json(FILE *f, const struct prov_graph *g)
{
    if (!f || !g)
        return -EINVAL;

    fprintf(f, "{\n");
    fprintf(f, "  \"version\": \"1.0\",\n");
    fprintf(f, "  \"node_count\": %zu,\n", g->node_count);
    fprintf(f, "  \"edge_count\": %zu,\n", g->edge_count);

    /* Export Nodes array */
    fprintf(f, "  \"nodes\": [\n");
    char esc_buf1[512];
    char esc_buf2[512];

    for (size_t i = 0; i < g->node_count; i++) {
        struct prov_node *node = g->nodes[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"id\": \"%s\",\n", node->id);
        switch (node->type) {
        case NODE_PROCESS:
            escape_string(node->proc.comm, esc_buf1, sizeof(esc_buf1));
            fprintf(f, "      \"type\": \"NODE_PROCESS\",\n");
            fprintf(f, "      \"pid\": %u,\n", node->proc.pid);
            fprintf(f, "      \"ppid\": %u,\n", node->proc.ppid);
            fprintf(f, "      \"comm\": \"%s\",\n", esc_buf1);
            fprintf(f, "      \"start_time_ns\": %llu,\n", (unsigned long long)node->proc.start_time_ns);
            fprintf(f, "      \"exit_code\": %d,\n", node->proc.exit_code);
            fprintf(f, "      \"is_alive\": %s\n", node->proc.is_alive ? "true" : "false");
            break;

        case NODE_MEMFD:
            escape_string(node->memfd.name, esc_buf1, sizeof(esc_buf1));
            fprintf(f, "      \"type\": \"NODE_MEMFD\",\n");
            fprintf(f, "      \"object_token\": %llu,\n", (unsigned long long)node->memfd.object_token);
            fprintf(f, "      \"creator_pid\": %u,\n", node->memfd.creator_pid);
            fprintf(f, "      \"creator_start_time\": %llu,\n", (unsigned long long)node->memfd.creator_start_time);
            fprintf(f, "      \"name\": \"%s\",\n", esc_buf1);
            fprintf(f, "      \"inode_no\": %llu,\n", (unsigned long long)node->memfd.inode_no);
            fprintf(f, "      \"dev_id\": %llu,\n", (unsigned long long)node->memfd.dev_id);
            fprintf(f, "      \"is_destroyed\": %s\n", node->memfd.is_destroyed ? "true" : "false");
            break;

        case NODE_FS_OBJECT:
            escape_string(node->fs.path, esc_buf1, sizeof(esc_buf1));
            fprintf(f, "      \"type\": \"NODE_FS_OBJECT\",\n");
            fprintf(f, "      \"inode_no\": %llu,\n", (unsigned long long)node->fs.inode_no);
            fprintf(f, "      \"dev_id\": %llu,\n", (unsigned long long)node->fs.dev_id);
            fprintf(f, "      \"mnt_ns_id\": %u,\n", node->fs.mnt_ns_id);
            fprintf(f, "      \"path\": \"%s\",\n", esc_buf1);
            fprintf(f, "      \"is_unlinked\": %s\n", node->fs.is_unlinked ? "true" : "false");
            break;

        case NODE_NET_ENDPOINT:
            escape_string(node->net.ip_str, esc_buf1, sizeof(esc_buf1));
            fprintf(f, "      \"type\": \"NODE_NET_ENDPOINT\",\n");
            fprintf(f, "      \"family\": %u,\n", node->net.family);
            fprintf(f, "      \"ip_str\": \"%s\",\n", esc_buf1);
            fprintf(f, "      \"port\": %u\n", node->net.port);
            break;
        }
        fprintf(f, "    }%s\n", (i + 1 < g->node_count) ? "," : "");
    }
    fprintf(f, "  ],\n");

    /* Export Edges array */
    fprintf(f, "  \"edges\": [\n");
    for (size_t i = 0; i < g->edge_count; i++) {
        struct prov_edge *edge = g->edges[i];
        if (edge->src && edge->dst) {
            fprintf(f, "    {\n");
            fprintf(f, "      \"src\": \"%s\",\n", edge->src->id);
            fprintf(f, "      \"dst\": \"%s\",\n", edge->dst->id);
            fprintf(f, "      \"timestamp_ns\": %llu,\n", (unsigned long long)edge->attr.timestamp_ns);

            switch (edge->type) {
            case EDGE_FORK:
                fprintf(f, "      \"type\": \"EDGE_FORK\"\n");
                break;

            case EDGE_MEMFD_CREATE:
                fprintf(f, "      \"type\": \"EDGE_MEMFD_CREATE\",\n");
                fprintf(f, "      \"fd\": %d\n", edge->attr.fd);
                break;

            case EDGE_FD_INSTALLED:
                escape_string(edge->attr.fd_installed.install_type, esc_buf1, sizeof(esc_buf1));
                fprintf(f, "      \"type\": \"EDGE_FD_INSTALLED\",\n");
                fprintf(f, "      \"fd\": %d,\n", edge->attr.fd);
                fprintf(f, "      \"install_type\": \"%s\"\n", esc_buf1);
                break;

            case EDGE_FD_CLOSED:
                fprintf(f, "      \"type\": \"EDGE_FD_CLOSED\",\n");
                fprintf(f, "      \"fd\": %d,\n", edge->attr.fd);
                fprintf(f, "      \"duration_ns\": %llu\n", (unsigned long long)edge->attr.fd_closed.duration_ns);
                break;

            case EDGE_MEMFD_WRITE:
                fprintf(f, "      \"type\": \"EDGE_MEMFD_WRITE\",\n");
                fprintf(f, "      \"offset\": %lld,\n", (long long)edge->attr.write.offset);
                fprintf(f, "      \"bytes\": %llu\n", (unsigned long long)edge->attr.write.bytes);
                break;

            case EDGE_MEMFD_EXEC_ATTEMPT:
                escape_string(edge->attr.exec_attempt.filename, esc_buf1, sizeof(esc_buf1));
                fprintf(f, "      \"type\": \"EDGE_MEMFD_EXEC_ATTEMPT\",\n");
                fprintf(f, "      \"filename\": \"%s\"\n", esc_buf1);
                break;

            case EDGE_MEMFD_EXEC_SUCCESS:
                escape_string(edge->attr.exec_success.binary_comm, esc_buf1, sizeof(esc_buf1));
                fprintf(f, "      \"type\": \"EDGE_MEMFD_EXEC_SUCCESS\",\n");
                fprintf(f, "      \"binary_comm\": \"%s\"\n", esc_buf1);
                break;

            case EDGE_UNLINK:
                escape_string(edge->attr.unlink.path, esc_buf1, sizeof(esc_buf1));
                escape_string(edge->attr.unlink.status, esc_buf2, sizeof(esc_buf2));
                fprintf(f, "      \"type\": \"EDGE_UNLINK\",\n");
                fprintf(f, "      \"path\": \"%s\",\n", esc_buf1);
                fprintf(f, "      \"status\": \"%s\"\n", esc_buf2);
                break;

            case EDGE_CONNECT:
                fprintf(f, "      \"type\": \"EDGE_CONNECT\",\n");
                fprintf(f, "      \"fd\": %d,\n", edge->attr.fd);
                fprintf(f, "      \"result\": %d\n", edge->attr.connect.result);
                break;
            }
            fprintf(f, "    }%s\n", (i + 1 < g->edge_count) ? "," : "");
        }
    }
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");

    return 0;
}

int prov_engine_export_dot(const char *filepath)
{
    if (!filepath)
        return -EINVAL;

    struct prov_graph full_graph = {0};
    int rc = prov_engine_filter_subgraph(0, 0, &full_graph);
    if (rc != 0)
        return rc;

    FILE *f = fopen(filepath, "w");
    if (!f) {
        prov_graph_free(&full_graph);
        return -errno;
    }

    render_graph_dot(f, &full_graph);
    fclose(f);
    prov_graph_free(&full_graph);
    return 0;
}

int prov_engine_export_json(const char *filepath)
{
    if (!filepath)
        return -EINVAL;

    struct prov_graph full_graph = {0};
    int rc = prov_engine_filter_subgraph(0, 0, &full_graph);
    if (rc != 0)
        return rc;

    FILE *f = fopen(filepath, "w");
    if (!f) {
        prov_graph_free(&full_graph);
        return -errno;
    }

    render_graph_json(f, &full_graph);
    fclose(f);
    prov_graph_free(&full_graph);
    return 0;
}

int prov_engine_export_filtered_dot(const char *filepath, uint32_t target_pid, uint64_t target_token)
{
    if (!filepath)
        return -EINVAL;

    struct prov_graph filtered = {0};
    int rc = prov_engine_filter_subgraph(target_pid, target_token, &filtered);
    if (rc != 0)
        return rc;

    FILE *f = fopen(filepath, "w");
    if (!f) {
        prov_graph_free(&filtered);
        return -errno;
    }

    render_graph_dot(f, &filtered);
    fclose(f);
    prov_graph_free(&filtered);
    return 0;
}

int prov_engine_export_filtered_json(const char *filepath, uint32_t target_pid, uint64_t target_token)
{
    if (!filepath)
        return -EINVAL;

    struct prov_graph filtered = {0};
    int rc = prov_engine_filter_subgraph(target_pid, target_token, &filtered);
    if (rc != 0)
        return rc;

    FILE *f = fopen(filepath, "w");
    if (!f) {
        prov_graph_free(&filtered);
        return -errno;
    }

    render_graph_json(f, &filtered);
    fclose(f);
    prov_graph_free(&filtered);
    return 0;
}

static int compare_edge_timestamps(const void *a, const void *b)
{
    const struct prov_edge *const *ea = a;
    const struct prov_edge *const *eb = b;
    if ((*ea)->attr.timestamp_ns < (*eb)->attr.timestamp_ns)
        return -1;
    if ((*ea)->attr.timestamp_ns > (*eb)->attr.timestamp_ns)
        return 1;
    return 0;
}

int prov_engine_export_timeline(const char *filepath, uint32_t target_pid, uint64_t target_token)
{
    if (!filepath)
        return -EINVAL;

    struct prov_graph filtered = {0};
    int rc = prov_engine_filter_subgraph(target_pid, target_token, &filtered);
    if (rc != 0)
        return rc;

    /* Sort edges by timestamp ascending */
    if (filtered.edge_count > 1) {
        qsort(filtered.edges, filtered.edge_count, sizeof(struct prov_edge *), compare_edge_timestamps);
    }

    FILE *f = fopen(filepath, "w");
    if (!f) {
        prov_graph_free(&filtered);
        return -errno;
    }

    fprintf(f, "# EphimTrace Forensic Timeline Report\n\n");
    fprintf(f, "- **Target PID Filter**: %u\n", target_pid);
    fprintf(f, "- **Target Token Filter**: %llu\n", (unsigned long long)target_token);
    fprintf(f, "- **Correlated Nodes**: %zu\n", filtered.node_count);
    fprintf(f, "- **Chronological Events**: %zu\n\n", filtered.edge_count);

    fprintf(f, "## Chronological Event Log\n\n");

    char esc_buf1[512];
    char esc_buf2[512];

    for (size_t i = 0; i < filtered.edge_count; i++) {
        struct prov_edge *edge = filtered.edges[i];
        if (!edge->src || !edge->dst)
            continue;

        uint64_t ts = edge->attr.timestamp_ns;
        const char *src_comm = (edge->src->type == NODE_PROCESS) ? edge->src->proc.comm : edge->src->id;
        uint32_t src_pid = (edge->src->type == NODE_PROCESS) ? edge->src->proc.pid : 0;

        switch (edge->type) {
        case EDGE_FORK:
            fprintf(f, "- `[%llu ns]` `[FORK]` Process %u (%s) -> fork() -> Child Process %u\n",
                    (unsigned long long)ts, src_pid, src_comm, edge->dst->proc.pid);
            break;

        case EDGE_MEMFD_CREATE:
            escape_string(edge->dst->memfd.name, esc_buf1, sizeof(esc_buf1));
            fprintf(f, "- `[%llu ns]` `[MEMFD_CREATE]` Process %u (%s) -> memfd_create() -> Memfd '%s' (Token: %llu, FD: %d)\n",
                    (unsigned long long)ts, src_pid, src_comm, esc_buf1,
                    (unsigned long long)edge->dst->memfd.object_token, edge->attr.fd);
            break;

        case EDGE_FD_INSTALLED:
            escape_string(edge->attr.fd_installed.install_type, esc_buf1, sizeof(esc_buf1));
            escape_string(edge->dst->memfd.name, esc_buf2, sizeof(esc_buf2));
            fprintf(f, "- `[%llu ns]` `[FD_INSTALLED]` Process %u (%s) -> fd_install(%s) -> Memfd '%s' (Token: %llu, FD: %d)\n",
                    (unsigned long long)ts, src_pid, src_comm, esc_buf1, esc_buf2,
                    (unsigned long long)edge->dst->memfd.object_token, edge->attr.fd);
            break;

        case EDGE_FD_CLOSED:
            escape_string(edge->dst->memfd.name, esc_buf1, sizeof(esc_buf1));
            fprintf(f, "- `[%llu ns]` `[FD_CLOSED]` Process %u (%s) -> close_fd() -> Memfd '%s' (Token: %llu, FD: %d, Duration: %llu ns)\n",
                    (unsigned long long)ts, src_pid, src_comm, esc_buf1,
                    (unsigned long long)edge->dst->memfd.object_token, edge->attr.fd,
                    (unsigned long long)edge->attr.fd_closed.duration_ns);
            break;

        case EDGE_MEMFD_WRITE:
            escape_string(edge->dst->memfd.name, esc_buf1, sizeof(esc_buf1));
            fprintf(f, "- `[%llu ns]` `[MEMFD_WRITE]` Process %u (%s) -> write() -> Memfd '%s' (Token: %llu, Offset: %lld, Bytes: %llu)\n",
                    (unsigned long long)ts, src_pid, src_comm, esc_buf1,
                    (unsigned long long)edge->dst->memfd.object_token,
                    (long long)edge->attr.write.offset,
                    (unsigned long long)edge->attr.write.bytes);
            break;

        case EDGE_MEMFD_EXEC_ATTEMPT:
            escape_string(edge->attr.exec_attempt.filename, esc_buf1, sizeof(esc_buf1));
            escape_string(edge->dst->memfd.name, esc_buf2, sizeof(esc_buf2));
            fprintf(f, "- `[%llu ns]` `[MEMFD_EXEC_ATTEMPT]` Process %u (%s) -> execveat() -> Memfd '%s' (Token: %llu, Target: %s)\n",
                    (unsigned long long)ts, src_pid, src_comm, esc_buf2,
                    (unsigned long long)edge->dst->memfd.object_token, esc_buf1);
            break;

        case EDGE_MEMFD_EXEC_SUCCESS:
            escape_string(edge->attr.exec_success.binary_comm, esc_buf1, sizeof(esc_buf1));
            escape_string(edge->dst->memfd.name, esc_buf2, sizeof(esc_buf2));
            fprintf(f, "- `[%llu ns]` `[MEMFD_EXEC_SUCCESS]` Process %u (%s) -> exec_success() -> Memfd '%s' (Token: %llu, Binary: %s)\n",
                    (unsigned long long)ts, src_pid, src_comm, esc_buf2,
                    (unsigned long long)edge->dst->memfd.object_token, esc_buf1);
            break;

        case EDGE_UNLINK:
            escape_string(edge->attr.unlink.path, esc_buf1, sizeof(esc_buf1));
            escape_string(edge->attr.unlink.status, esc_buf2, sizeof(esc_buf2));
            fprintf(f, "- `[%llu ns]` `[UNLINK]` Process %u (%s) -> unlink() -> FS Object '%s' (Status: %s)\n",
                    (unsigned long long)ts, src_pid, src_comm, esc_buf1, esc_buf2);
            break;

        case EDGE_CONNECT:
            escape_string(edge->dst->net.ip_str, esc_buf1, sizeof(esc_buf1));
            fprintf(f, "- `[%llu ns]` `[CONNECT]` Process %u (%s) -> connect() -> Net '%s:%u' (FD: %d, Result: %d)\n",
                    (unsigned long long)ts, src_pid, src_comm, esc_buf1, edge->dst->net.port,
                    edge->attr.fd, edge->attr.connect.result);
            break;
        }
    }

    fprintf(f, "\n## Structured Event Table\n\n");
    fprintf(f, "| Timestamp (ns) | Event Type | Source Entity | Action | Target Entity | Details |\n");
    fprintf(f, "|---|---|---|---|---|---|\n");

    for (size_t i = 0; i < filtered.edge_count; i++) {
        struct prov_edge *edge = filtered.edges[i];
        if (!edge->src || !edge->dst)
            continue;

        uint64_t ts = edge->attr.timestamp_ns;
        const char *src_comm = (edge->src->type == NODE_PROCESS) ? edge->src->proc.comm : edge->src->id;
        uint32_t src_pid = (edge->src->type == NODE_PROCESS) ? edge->src->proc.pid : 0;

        switch (edge->type) {
        case EDGE_FORK:
            fprintf(f, "| %llu | FORK | Process %u (%s) | fork() | Process %u | Child PID: %u |\n",
                    (unsigned long long)ts, src_pid, src_comm, edge->dst->proc.pid, edge->dst->proc.pid);
            break;

        case EDGE_MEMFD_CREATE:
            escape_string(edge->dst->memfd.name, esc_buf1, sizeof(esc_buf1));
            fprintf(f, "| %llu | MEMFD_CREATE | Process %u (%s) | memfd_create() | Memfd %llu | Name: %s, FD: %d |\n",
                    (unsigned long long)ts, src_pid, src_comm,
                    (unsigned long long)edge->dst->memfd.object_token, esc_buf1, edge->attr.fd);
            break;

        case EDGE_FD_INSTALLED:
            escape_string(edge->attr.fd_installed.install_type, esc_buf1, sizeof(esc_buf1));
            escape_string(edge->dst->memfd.name, esc_buf2, sizeof(esc_buf2));
            fprintf(f, "| %llu | FD_INSTALLED | Process %u (%s) | fd_install() | Memfd %llu | Type: %s, Name: %s, FD: %d |\n",
                    (unsigned long long)ts, src_pid, src_comm,
                    (unsigned long long)edge->dst->memfd.object_token, esc_buf1, esc_buf2, edge->attr.fd);
            break;

        case EDGE_FD_CLOSED:
            escape_string(edge->dst->memfd.name, esc_buf1, sizeof(esc_buf1));
            fprintf(f, "| %llu | FD_CLOSED | Process %u (%s) | close_fd() | Memfd %llu | Name: %s, FD: %d, Duration: %llu ns |\n",
                    (unsigned long long)ts, src_pid, src_comm,
                    (unsigned long long)edge->dst->memfd.object_token, esc_buf1, edge->attr.fd,
                    (unsigned long long)edge->attr.fd_closed.duration_ns);
            break;

        case EDGE_MEMFD_WRITE:
            escape_string(edge->dst->memfd.name, esc_buf1, sizeof(esc_buf1));
            fprintf(f, "| %llu | MEMFD_WRITE | Process %u (%s) | write() | Memfd %llu | Name: %s, Offset: %lld, Bytes: %llu |\n",
                    (unsigned long long)ts, src_pid, src_comm,
                    (unsigned long long)edge->dst->memfd.object_token, esc_buf1,
                    (long long)edge->attr.write.offset,
                    (unsigned long long)edge->attr.write.bytes);
            break;

        case EDGE_MEMFD_EXEC_ATTEMPT:
            escape_string(edge->attr.exec_attempt.filename, esc_buf1, sizeof(esc_buf1));
            escape_string(edge->dst->memfd.name, esc_buf2, sizeof(esc_buf2));
            fprintf(f, "| %llu | MEMFD_EXEC_ATTEMPT | Process %u (%s) | execveat() | Memfd %llu | Target: %s, Name: %s |\n",
                    (unsigned long long)ts, src_pid, src_comm,
                    (unsigned long long)edge->dst->memfd.object_token, esc_buf1, esc_buf2);
            break;

        case EDGE_MEMFD_EXEC_SUCCESS:
            escape_string(edge->attr.exec_success.binary_comm, esc_buf1, sizeof(esc_buf1));
            escape_string(edge->dst->memfd.name, esc_buf2, sizeof(esc_buf2));
            fprintf(f, "| %llu | MEMFD_EXEC_SUCCESS | Process %u (%s) | exec_success() | Memfd %llu | Binary: %s, Name: %s |\n",
                    (unsigned long long)ts, src_pid, src_comm,
                    (unsigned long long)edge->dst->memfd.object_token, esc_buf1, esc_buf2);
            break;

        case EDGE_UNLINK:
            escape_string(edge->attr.unlink.path, esc_buf1, sizeof(esc_buf1));
            escape_string(edge->attr.unlink.status, esc_buf2, sizeof(esc_buf2));
            fprintf(f, "| %llu | UNLINK | Process %u (%s) | unlink() | FS Object %llu | Path: %s, Status: %s |\n",
                    (unsigned long long)ts, src_pid, src_comm,
                    (unsigned long long)edge->dst->fs.inode_no, esc_buf1, esc_buf2);
            break;

        case EDGE_CONNECT:
            escape_string(edge->dst->net.ip_str, esc_buf1, sizeof(esc_buf1));
            fprintf(f, "| %llu | CONNECT | Process %u (%s) | connect() | Net Endpoint | Destination: %s:%u, FD: %d, Result: %d |\n",
                    (unsigned long long)ts, src_pid, src_comm, esc_buf1,
                    edge->dst->net.port, edge->attr.fd, edge->attr.connect.result);
            break;
        }
    }

    fclose(f);
    prov_graph_free(&filtered);
    return 0;
}

void prov_engine_destroy(void)
{
    /* Free edges */
    struct prov_edge *edge = g_edges_head;
    while (edge) {
        struct prov_edge *next = edge->next_global;
        free(edge);
        edge = next;
    }
    g_edges_head = NULL;
    g_edges_tail = NULL;
    g_edge_count = 0;

    /* Free nodes */
    struct prov_node *node = g_nodes_head;
    while (node) {
        struct prov_node *next = node->next_global;
        free(node);
        node = next;
    }
    g_nodes_head = NULL;
    g_nodes_tail = NULL;
    g_node_count = 0;

    /* Free active pid entries */
    if (g_active_pid_buckets) {
        for (int i = 0; i < PID_HASH_SIZE; i++) {
            struct active_proc_entry *entry = g_active_pid_buckets[i];
            while (entry) {
                struct active_proc_entry *next = entry->next;
                free(entry);
                entry = next;
            }
        }
        free(g_active_pid_buckets);
        g_active_pid_buckets = NULL;
    }

    /* Free node hash buckets */
    if (g_node_buckets) {
        free(g_node_buckets);
        g_node_buckets = NULL;
    }
}
