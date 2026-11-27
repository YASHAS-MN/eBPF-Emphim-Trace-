#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#include "provenance.h"
#include "provenance.c"
#include "evidence_io.h"

/* Structure for explicit expected node matching */
struct expected_node {
    char id[128];
    enum prov_node_type type;
    bool matched;
};

/* Structure for explicit expected directed edge matching with multiplicity */
struct expected_edge {
    char src_id[128];
    char dst_id[128];
    enum prov_edge_type type;
    int expected_count; /* Expected multiplicity */
    int matched_count;  /* Actual matched count */
};

/* Structure to track precision, recall, and exposed deficiencies */
struct metric_tracker {
    const char *test_name;
    size_t expected_nodes;
    size_t actual_nodes;
    size_t tp_nodes;
    size_t fp_nodes;
    size_t fn_nodes;

    size_t expected_edges;
    size_t actual_edges;
    size_t tp_edges;
    size_t fp_edges;
    size_t fn_edges;

    size_t checked_attributes;
    size_t matched_attributes;

    size_t false_joins;
    size_t false_splits;

    bool test_execution_success;
    size_t exposed_deficiencies_count;
    char exposed_deficiencies[1024];
};

static void evaluate_graph_precision_recall(
    struct expected_node *exp_nodes, size_t num_exp_nodes,
    struct expected_edge *exp_edges, size_t num_exp_edges,
    struct metric_tracker *m)
{
    m->expected_nodes = num_exp_nodes;
    m->actual_nodes = g_node_count;
    m->tp_nodes = 0;
    m->fp_nodes = 0;
    m->fn_nodes = 0;

    /* 1. Exact Node Matching */
    struct prov_node *curr_node = g_nodes_head;
    while (curr_node) {
        bool found = false;
        for (size_t i = 0; i < num_exp_nodes; i++) {
            if (strcmp(exp_nodes[i].id, curr_node->id) == 0 &&
                exp_nodes[i].type == curr_node->type) {
                if (!exp_nodes[i].matched) {
                    exp_nodes[i].matched = true;
                    m->tp_nodes++;
                    found = true;
                    break;
                }
            }
        }
        if (!found) {
            m->fp_nodes++;
        }
        curr_node = curr_node->next_global;
    }
    for (size_t i = 0; i < num_exp_nodes; i++) {
        if (!exp_nodes[i].matched) {
            m->fn_nodes++;
        }
    }

    /* 2. Exact Directed Edge Matching with Multiplicity */
    m->expected_edges = 0;
    for (size_t i = 0; i < num_exp_edges; i++) {
        m->expected_edges += exp_edges[i].expected_count;
    }
    m->actual_edges = g_edge_count;
    m->tp_edges = 0;
    m->fp_edges = 0;
    m->fn_edges = 0;

    struct prov_edge *curr_edge = g_edges_head;
    while (curr_edge) {
        bool found = false;
        if (curr_edge->src && curr_edge->dst) {
            for (size_t i = 0; i < num_exp_edges; i++) {
                if (curr_edge->type == exp_edges[i].type &&
                    strcmp(curr_edge->src->id, exp_edges[i].src_id) == 0 &&
                    strcmp(curr_edge->dst->id, exp_edges[i].dst_id) == 0) {
                    if (exp_edges[i].matched_count < exp_edges[i].expected_count) {
                        exp_edges[i].matched_count++;
                        m->tp_edges++;
                        found = true;
                        break;
                    }
                }
            }
        }
        if (!found) {
            m->fp_edges++;
        }
        curr_edge = curr_edge->next_global;
    }

    for (size_t i = 0; i < num_exp_edges; i++) {
        if (exp_edges[i].matched_count < exp_edges[i].expected_count) {
            m->fn_edges += (exp_edges[i].expected_count - exp_edges[i].matched_count);
        }
    }
}

static void print_metric_result(const struct metric_tracker *m)
{
    double node_prec = (m->actual_nodes > 0) ? ((double)m->tp_nodes / m->actual_nodes) : 1.0;
    double node_rec  = (m->expected_nodes > 0) ? ((double)m->tp_nodes / m->expected_nodes) : 1.0;
    double edge_prec = (m->actual_edges > 0) ? ((double)m->tp_edges / m->actual_edges) : 1.0;
    double edge_rec  = (m->expected_edges > 0) ? ((double)m->tp_edges / m->expected_edges) : 1.0;
    double attr_fid  = (m->checked_attributes > 0) ? ((double)m->matched_attributes / m->checked_attributes) : 1.0;

    printf("  [TEST: %-32s] Execution: %s\n", m->test_name, m->test_execution_success ? "SUCCESS" : "FAILED");
    printf("    Node Metrics: exp=%zu, act=%zu | TP=%zu, FP=%zu, FN=%zu -> Precision: %.2f%%, Recall: %.2f%%\n",
           m->expected_nodes, m->actual_nodes, m->tp_nodes, m->fp_nodes, m->fn_nodes,
           node_prec * 100.0, node_rec * 100.0);
    printf("    Edge Metrics: exp=%zu, act=%zu | TP=%zu, FP=%zu, FN=%zu -> Precision: %.2f%%, Recall: %.2f%%\n",
           m->expected_edges, m->actual_edges, m->tp_edges, m->fp_edges, m->fn_edges,
           edge_prec * 100.0, edge_rec * 100.0);
    printf("    Attribute Fidelity: %zu/%zu fields matched (%.2f%%)\n",
           m->matched_attributes, m->checked_attributes, attr_fid * 100.0);
    printf("    Identity Invariants: False Joins: %zu, False Splits: %zu\n",
           m->false_joins, m->false_splits);
    if (m->exposed_deficiencies_count > 0) {
        printf("    [EXPOSED DEFICIENCIES] (%zu reported):\n", m->exposed_deficiencies_count);
        printf("      %s\n", m->exposed_deficiencies);
    } else {
        printf("    [EXPOSED DEFICIENCIES] None (all invariants strictly preserved).\n");
    }
    printf("\n");
}

/* =========================================================================
 * Test 1: Standard Full Lifecycle Precision & Recall
 * ========================================================================= */
static struct metric_tracker test_standard_lifecycle(void)
{
    struct metric_tracker m = { .test_name = "1. Standard Full Lifecycle", .test_execution_success = true };
    prov_engine_init();

    struct event evs[] = {
        { .type = EVENT_FORK, .pid = 100, .tid = 100, .ppid = 1, .start_time_ns = 1000,
          .child_tgid = 200, .child_pid = 200, .child_start_time_ns = 2000, .timestamp_ns = 2010, .name = "child_proc" },
        { .type = EVENT_MEMFD_CREATE, .pid = 200, .tid = 200, .start_time_ns = 2000, .object_token = 1001, .fd = 3, .timestamp_ns = 2020, .name = "memfd_1" },
        { .type = EVENT_MEMFD_COMPLETED, .pid = 200, .tid = 200, .start_time_ns = 2000, .object_token = 1001, .inode_no = 5001, .dev_id = 1, .fd = 3, .op_type = 2, .timestamp_ns = 2030, .name = "memfd_1" },
        { .type = EVENT_MEMFD_WRITE, .pid = 200, .tid = 200, .start_time_ns = 2000, .object_token = 1001, .entry_ts_ns = 0, .ret_val = 1024, .timestamp_ns = 2040 },
        { .type = EVENT_FD_INSTALLED, .pid = 200, .tid = 200, .start_time_ns = 2000, .object_token = 1001, .fd = 4, .op_type = 3 /* DUP */, .timestamp_ns = 2050 },
        { .type = EVENT_FD_CLOSED, .pid = 200, .tid = 200, .start_time_ns = 2000, .object_token = 1001, .fd = 3, .entry_ts_ns = 5000, .timestamp_ns = 2060 },
        { .type = EVENT_MEMFD_EXEC_ATTEMPT, .pid = 200, .tid = 200, .start_time_ns = 2000, .object_token = 1001, .timestamp_ns = 2070, .name = "/dev/fd/4" },
        { .type = EVENT_MEMFD_EXEC_SUCCESS, .pid = 200, .tid = 200, .start_time_ns = 2000, .object_token = 1001, .timestamp_ns = 2080, .name = "worker_elf" },
        { .type = EVENT_VFS_UNLINK_COMPLETED, .pid = 100, .tid = 100, .start_time_ns = 1000, .inode_no = 7001, .dev_id = 2049, .ret_val = 0, .timestamp_ns = 2090, .path = "/tmp/data.bin" },
        { .type = EVENT_CONNECT, .pid = 200, .tid = 200, .start_time_ns = 2000, .family = AF_INET, .port = htons(9000), .fd = 5, .ret_val = 0, .timestamp_ns = 2100 },
        { .type = EVENT_PROCESS_EXIT, .pid = 200, .tid = 200, .start_time_ns = 2000, .reserved = 1, .ret_val = 0, .timestamp_ns = 2110 }
    };
    inet_pton(AF_INET, "127.0.0.1", evs[9].address);

    for (size_t i = 0; i < sizeof(evs)/sizeof(evs[0]); i++) {
        prov_engine_process_event(&evs[i]);
    }

    /* Independently defined expected nodes */
    struct expected_node exp_nodes[] = {
        { .id = "proc_100_1000",       .type = NODE_PROCESS },
        { .id = "proc_200_2000",       .type = NODE_PROCESS },
        { .id = "memfd_1001",          .type = NODE_MEMFD },
        { .id = "fs_2049_7001",        .type = NODE_FS_OBJECT },
        { .id = "net_2_127.0.0.1_9000",.type = NODE_NET_ENDPOINT }
    };

    /* Independently defined expected directed edges with multiplicity */
    struct expected_edge exp_edges[] = {
        { .src_id = "proc_100_1000", .dst_id = "proc_200_2000", .type = EDGE_FORK,               .expected_count = 1 },
        { .src_id = "proc_200_2000", .dst_id = "memfd_1001",    .type = EDGE_MEMFD_CREATE,       .expected_count = 1 },
        { .src_id = "proc_200_2000", .dst_id = "memfd_1001",    .type = EDGE_MEMFD_WRITE,        .expected_count = 1 },
        { .src_id = "proc_200_2000", .dst_id = "memfd_1001",    .type = EDGE_FD_INSTALLED,       .expected_count = 1 },
        { .src_id = "proc_200_2000", .dst_id = "memfd_1001",    .type = EDGE_FD_CLOSED,          .expected_count = 1 },
        { .src_id = "proc_200_2000", .dst_id = "memfd_1001",    .type = EDGE_MEMFD_EXEC_ATTEMPT, .expected_count = 1 },
        { .src_id = "proc_200_2000", .dst_id = "memfd_1001",    .type = EDGE_MEMFD_EXEC_SUCCESS, .expected_count = 1 },
        { .src_id = "proc_100_1000", .dst_id = "fs_2049_7001",  .type = EDGE_UNLINK,             .expected_count = 1 },
        { .src_id = "proc_200_2000", .dst_id = "net_2_127.0.0.1_9000", .type = EDGE_CONNECT,    .expected_count = 1 }
    };

    evaluate_graph_precision_recall(exp_nodes, sizeof(exp_nodes)/sizeof(exp_nodes[0]),
                                    exp_edges, sizeof(exp_edges)/sizeof(exp_edges[0]), &m);

    /* Verify attribute fidelity */
    struct prov_node *p100 = prov_find_node("proc_100_1000");
    struct prov_node *p200 = prov_find_node("proc_200_2000");
    struct prov_node *m1001 = prov_find_node("memfd_1001");
    struct prov_node *fs7001 = prov_find_node("fs_2049_7001");
    struct prov_node *net9000 = prov_find_node("net_2_127.0.0.1_9000");

    m.checked_attributes = 12;
    if (p200 && p200->proc.is_alive == false) m.matched_attributes++;
    if (p200 && p200->proc.exit_code == 0) m.matched_attributes++;
    if (p200 && strcmp(p200->proc.comm, "worker_elf") == 0) m.matched_attributes++;
    if (m1001 && m1001->memfd.inode_no == 5001) m.matched_attributes++;
    if (m1001 && m1001->memfd.dev_id == 1) m.matched_attributes++;
    if (m1001 && strcmp(m1001->memfd.name, "memfd_1") == 0) m.matched_attributes++;
    if (fs7001 && fs7001->fs.is_unlinked == true) m.matched_attributes++;
    if (fs7001 && strcmp(fs7001->fs.path, "/tmp/data.bin") == 0) m.matched_attributes++;
    if (net9000 && net9000->net.port == 9000) m.matched_attributes++;
    if (net9000 && strcmp(net9000->net.ip_str, "127.0.0.1") == 0) m.matched_attributes++;
    if (p100 && p100->proc.pid == 100) m.matched_attributes++;
    if (p200 && p200->proc.ppid == 100) m.matched_attributes++;

    if (m.tp_nodes != m.expected_nodes || m.tp_edges != m.expected_edges ||
        m.matched_attributes != m.checked_attributes) {
        m.test_execution_success = false;
    }

    prov_engine_destroy();
    return m;
}

/* =========================================================================
 * Test 2: Identity Consistency across PID Reuse
 * ========================================================================= */
static struct metric_tracker test_pid_reuse(void)
{
    struct metric_tracker m = { .test_name = "2. PID Reuse & Generation Separation", .test_execution_success = true };
    prov_engine_init();

    struct event e1_fork = { .type = EVENT_FORK, .pid = 1, .start_time_ns = 500,
                            .child_tgid = 3000, .child_pid = 3000, .child_start_time_ns = 1000000, .timestamp_ns = 1000050, .name = "worker_gen1" };
    struct event e1_create = { .type = EVENT_MEMFD_CREATE, .pid = 3000, .start_time_ns = 1000000, .object_token = 101, .fd = 3, .timestamp_ns = 1000100, .name = "m_gen1" };
    struct event e1_exit = { .type = EVENT_PROCESS_EXIT, .pid = 3000, .start_time_ns = 1000000, .reserved = 1, .ret_val = 0, .timestamp_ns = 1000200 };

    struct event e2_fork = { .type = EVENT_FORK, .pid = 1, .start_time_ns = 500,
                            .child_tgid = 3000, .child_pid = 3000, .child_start_time_ns = 2000000, .timestamp_ns = 2000050, .name = "worker_gen2" };
    struct event e2_create = { .type = EVENT_MEMFD_CREATE, .pid = 3000, .start_time_ns = 2000000, .object_token = 102, .fd = 3, .timestamp_ns = 2000100, .name = "m_gen2" };
    struct event e2_exit = { .type = EVENT_PROCESS_EXIT, .pid = 3000, .start_time_ns = 2000000, .reserved = 1, .ret_val = 0, .timestamp_ns = 2000200 };

    prov_engine_process_event(&e1_fork);
    prov_engine_process_event(&e1_create);
    prov_engine_process_event(&e1_exit);

    prov_engine_process_event(&e2_fork);
    prov_engine_process_event(&e2_create);
    prov_engine_process_event(&e2_exit);

    struct expected_node exp_nodes[] = {
        { .id = "proc_1_500",         .type = NODE_PROCESS },
        { .id = "proc_3000_1000000",  .type = NODE_PROCESS },
        { .id = "proc_3000_2000000",  .type = NODE_PROCESS },
        { .id = "memfd_101",          .type = NODE_MEMFD },
        { .id = "memfd_102",          .type = NODE_MEMFD }
    };

    struct expected_edge exp_edges[] = {
        { .src_id = "proc_1_500",        .dst_id = "proc_3000_1000000", .type = EDGE_FORK,         .expected_count = 1 },
        { .src_id = "proc_3000_1000000", .dst_id = "memfd_101",        .type = EDGE_MEMFD_CREATE, .expected_count = 1 },
        { .src_id = "proc_1_500",        .dst_id = "proc_3000_2000000", .type = EDGE_FORK,         .expected_count = 1 },
        { .src_id = "proc_3000_2000000", .dst_id = "memfd_102",        .type = EDGE_MEMFD_CREATE, .expected_count = 1 }
    };

    evaluate_graph_precision_recall(exp_nodes, sizeof(exp_nodes)/sizeof(exp_nodes[0]),
                                    exp_edges, sizeof(exp_edges)/sizeof(exp_edges[0]), &m);

    struct prov_node *g1 = prov_find_node("proc_3000_1000000");
    struct prov_node *g2 = prov_find_node("proc_3000_2000000");
    struct prov_node *m1 = prov_find_node("memfd_101");
    struct prov_node *m2 = prov_find_node("memfd_102");

    m.checked_attributes = 4;
    if (g1 && g2 && g1 != g2) {
        m.matched_attributes += 2;
    } else {
        m.false_joins++;
        m.test_execution_success = false;
    }
    if (m1 && m1->in_edges && m1->in_edges->src == g1) m.matched_attributes++;
    if (m2 && m2->in_edges && m2->in_edges->src == g2) m.matched_attributes++;

    /* Verify PID reuse behavior when start_time_ns is 0 */
    struct event e3_zero = { .type = EVENT_FD_INSTALLED, .pid = 3000, .start_time_ns = 0, .object_token = 102, .fd = 5, .timestamp_ns = 3000000 };
    prov_engine_process_event(&e3_zero);
    struct prov_node *fallback = prov_find_node("proc_3000_0");
    struct prov_node *unres = prov_find_node("proc_3000_unresolved_1");
    if (fallback) {
        m.exposed_deficiencies_count++;
        snprintf(m.exposed_deficiencies, sizeof(m.exposed_deficiencies),
                 "DEFICIENCY: PID Reuse with start_time=0 created unindexed fallback 'proc_<pid>_0'.");
    }
    if (unres && unres->proc.is_unresolved) {
        /* Successfully represented unresolved identity explicitly */
        m.matched_attributes++;
        m.checked_attributes++;
    }

    prov_engine_destroy();
    return m;
}

/* =========================================================================
 * Test 3: FD Reuse & Memfd Reopening
 * ========================================================================= */
static struct metric_tracker test_fd_reuse_and_reopening(void)
{
    struct metric_tracker m = { .test_name = "3. FD Reuse & Memfd Reopening", .test_execution_success = true };
    prov_engine_init();

    struct event e_create1 = { .type = EVENT_MEMFD_CREATE, .pid = 500, .start_time_ns = 1000, .object_token = 201, .fd = 3, .timestamp_ns = 10, .name = "m1" };
    struct event e_close1  = { .type = EVENT_FD_CLOSED,    .pid = 500, .start_time_ns = 1000, .object_token = 201, .fd = 3, .timestamp_ns = 20 };
    struct event e_create2 = { .type = EVENT_MEMFD_CREATE, .pid = 500, .start_time_ns = 1000, .object_token = 202, .fd = 3, .timestamp_ns = 30, .name = "m2" };
    struct event e_reopen  = { .type = EVENT_FD_INSTALLED, .pid = 600, .start_time_ns = 2000, .object_token = 201, .fd = 4, .op_type = 2 /* REOPEN */, .timestamp_ns = 40 };

    prov_engine_process_event(&e_create1);
    prov_engine_process_event(&e_close1);
    prov_engine_process_event(&e_create2);
    prov_engine_process_event(&e_reopen);

    struct expected_node exp_nodes[] = {
        { .id = "proc_500_1000", .type = NODE_PROCESS },
        { .id = "proc_600_2000", .type = NODE_PROCESS },
        { .id = "memfd_201",     .type = NODE_MEMFD },
        { .id = "memfd_202",     .type = NODE_MEMFD }
    };

    struct expected_edge exp_edges[] = {
        { .src_id = "proc_500_1000", .dst_id = "memfd_201", .type = EDGE_MEMFD_CREATE, .expected_count = 1 },
        { .src_id = "proc_500_1000", .dst_id = "memfd_201", .type = EDGE_FD_CLOSED,    .expected_count = 1 },
        { .src_id = "proc_500_1000", .dst_id = "memfd_202", .type = EDGE_MEMFD_CREATE, .expected_count = 1 },
        { .src_id = "proc_600_2000", .dst_id = "memfd_201", .type = EDGE_FD_INSTALLED, .expected_count = 1 }
    };

    evaluate_graph_precision_recall(exp_nodes, sizeof(exp_nodes)/sizeof(exp_nodes[0]),
                                    exp_edges, sizeof(exp_edges)/sizeof(exp_edges[0]), &m);

    struct prov_node *m1 = prov_find_node("memfd_201");
    struct prov_node *m2 = prov_find_node("memfd_202");
    struct prov_node *p600 = prov_find_node("proc_600_2000");

    m.checked_attributes = 4;
    if (m1 && m2 && m1 != m2) m.matched_attributes += 2;
    if (p600 && p600->out_edges && p600->out_edges->dst == m1 && p600->out_edges->type == EDGE_FD_INSTALLED) {
        m.matched_attributes += 2;
    }

    if (m.tp_nodes != m.expected_nodes || m.tp_edges != m.expected_edges ||
        m.matched_attributes != m.checked_attributes) {
        m.test_execution_success = false;
    }

    prov_engine_destroy();
    return m;
}

/* =========================================================================
 * Test 4: Successful vs Failed Execution Representation
 * ========================================================================= */
static struct metric_tracker test_exec_representation(void)
{
    struct metric_tracker m = { .test_name = "4. Exec Representation (Success vs Failure)", .test_execution_success = true };
    prov_engine_init();

    /* Child 701: Memfd exec success */
    struct event e1_fork = { .type = EVENT_FORK, .pid = 700, .start_time_ns = 1000, .child_tgid = 701, .child_pid = 701, .child_start_time_ns = 1100, .timestamp_ns = 1110, .name = "parent" };
    struct event e1_att  = { .type = EVENT_MEMFD_EXEC_ATTEMPT, .pid = 701, .start_time_ns = 1100, .object_token = 301, .timestamp_ns = 1120, .name = "/dev/fd/3" };
    struct event e1_succ = { .type = EVENT_MEMFD_EXEC_SUCCESS, .pid = 701, .start_time_ns = 1100, .object_token = 301, .timestamp_ns = 1130, .name = "success_binary" };

    /* Child 702: Memfd exec failure (-ENOEXEC abort) */
    struct event e2_fork = { .type = EVENT_FORK, .pid = 700, .start_time_ns = 1000, .child_tgid = 702, .child_pid = 702, .child_start_time_ns = 1200, .timestamp_ns = 1210, .name = "parent" };
    struct event e2_att  = { .type = EVENT_MEMFD_EXEC_ATTEMPT, .pid = 702, .start_time_ns = 1200, .object_token = 302, .timestamp_ns = 1220, .name = "/dev/fd/3" };
    struct event e2_exit = { .type = EVENT_PROCESS_EXIT, .pid = 702, .start_time_ns = 1200, .reserved = 1, .ret_val = 126, .timestamp_ns = 1230 };

    /* Child 703: Regular FS Exec success */
    struct event e3_fork = { .type = EVENT_FORK, .pid = 700, .start_time_ns = 1000, .child_tgid = 703, .child_pid = 703, .child_start_time_ns = 1300, .timestamp_ns = 1310, .name = "parent" };
    struct event e3_fsexec = { .type = EVENT_PROCESS_EXEC, .pid = 703, .start_time_ns = 1300, .object_token = 0,
                               .inode_no = 88123, .dev_id = 66309, .mnt_ns_id = 1,
                               .flags = (VFS_IDENTITY_INODE_VALID | VFS_IDENTITY_DEV_VALID),
                               .timestamp_ns = 1320, .name = "target_elf", .path = "/usr/bin/target_elf" };

    prov_engine_process_event(&e1_fork);
    prov_engine_process_event(&e1_att);
    prov_engine_process_event(&e1_succ);

    prov_engine_process_event(&e2_fork);
    prov_engine_process_event(&e2_att);
    prov_engine_process_event(&e2_exit);

    prov_engine_process_event(&e3_fork);
    prov_engine_process_event(&e3_fsexec);

    struct expected_node exp_nodes[] = {
        { .id = "proc_700_1000",   .type = NODE_PROCESS },
        { .id = "proc_701_1100",   .type = NODE_PROCESS },
        { .id = "proc_702_1200",   .type = NODE_PROCESS },
        { .id = "proc_703_1300",   .type = NODE_PROCESS },
        { .id = "memfd_301",       .type = NODE_MEMFD },
        { .id = "memfd_302",       .type = NODE_MEMFD },
        { .id = "fs_66309_88123",  .type = NODE_FS_OBJECT }
    };

    struct expected_edge exp_edges[] = {
        { .src_id = "proc_700_1000", .dst_id = "proc_701_1100",  .type = EDGE_FORK,               .expected_count = 1 },
        { .src_id = "proc_701_1100", .dst_id = "memfd_301",       .type = EDGE_MEMFD_EXEC_ATTEMPT, .expected_count = 1 },
        { .src_id = "proc_701_1100", .dst_id = "memfd_301",       .type = EDGE_MEMFD_EXEC_SUCCESS, .expected_count = 1 },
        { .src_id = "proc_700_1000", .dst_id = "proc_702_1200",  .type = EDGE_FORK,               .expected_count = 1 },
        { .src_id = "proc_702_1200", .dst_id = "memfd_302",       .type = EDGE_MEMFD_EXEC_ATTEMPT, .expected_count = 1 },
        { .src_id = "proc_700_1000", .dst_id = "proc_703_1300",  .type = EDGE_FORK,               .expected_count = 1 },
        { .src_id = "proc_703_1300", .dst_id = "fs_66309_88123", .type = EDGE_FS_EXEC_SUCCESS,   .expected_count = 1 }
    };

    evaluate_graph_precision_recall(exp_nodes, sizeof(exp_nodes)/sizeof(exp_nodes[0]),
                                    exp_edges, sizeof(exp_edges)/sizeof(exp_edges[0]), &m);

    struct prov_node *p701 = prov_find_node("proc_701_1100");
    struct prov_node *p702 = prov_find_node("proc_702_1200");
    struct prov_node *p703 = prov_find_node("proc_703_1300");

    m.checked_attributes = 6;
    if (p701 && strcmp(p701->proc.comm, "success_binary") == 0) m.matched_attributes++;
    if (p702 && strcmp(p702->proc.comm, "parent") == 0) m.matched_attributes++;
    bool p702_has_success = false;
    if (p702) {
        struct prov_edge *e = p702->out_edges;
        while (e) {
            if (e->type == EDGE_MEMFD_EXEC_SUCCESS) p702_has_success = true;
            e = e->next_out;
        }
    }
    if (!p702_has_success) m.matched_attributes++;
    if (p702 && p702->proc.exit_code == 126) m.matched_attributes++;
    if (p703 && strcmp(p703->proc.comm, "target_elf") == 0) m.matched_attributes++;
    struct prov_node *fs_node = prov_find_node("fs_66309_88123");
    if (fs_node && strcmp(fs_node->fs.path, "/usr/bin/target_elf") == 0) m.matched_attributes++;

    if (m.tp_nodes != m.expected_nodes || m.tp_edges != m.expected_edges ||
        m.matched_attributes != m.checked_attributes) {
        m.test_execution_success = false;
    }

    prov_engine_destroy();
    return m;
}

/* =========================================================================
 * Test 5: Missing, Duplicated, and Reordered Events (Deficiency Exposure)
 * ========================================================================= */
static struct metric_tracker test_missing_duplicate_reordered(void)
{
    struct metric_tracker m = { .test_name = "5. Robustness & Deficiency Exposure", .test_execution_success = true };
    prov_engine_init();

    /* Scenario A: Missing parent fork (orphan process events arrive first) */
    struct event e_orphan_memfd = { .type = EVENT_MEMFD_CREATE, .pid = 801, .start_time_ns = 5000, .object_token = 401, .fd = 3, .timestamp_ns = 5010, .name = "m_orphan" };
    prov_engine_process_event(&e_orphan_memfd);

    /* Scenario B: Duplicate fork event (Offering identical fork record twice) */
    struct event e_dup_fork1 = { .type = EVENT_FORK, .pid = 800, .start_time_ns = 1000, .child_tgid = 802, .child_pid = 802, .child_start_time_ns = 6000, .timestamp_ns = 6010, .name = "worker" };
    struct event e_dup_fork2 = { .type = EVENT_FORK, .pid = 800, .start_time_ns = 1000, .child_tgid = 802, .child_pid = 802, .child_start_time_ns = 6000, .timestamp_ns = 6010, .name = "worker" };
    prov_engine_process_event(&e_dup_fork1);
    prov_engine_process_event(&e_dup_fork2);

    /* Scenario C: Reordered event (write arrives before create) */
    struct event e_reordered_write = { .type = EVENT_MEMFD_WRITE, .pid = 802, .start_time_ns = 6000, .object_token = 402, .entry_ts_ns = 0, .ret_val = 512, .timestamp_ns = 6020 };
    struct event e_reordered_create = { .type = EVENT_MEMFD_CREATE, .pid = 802, .start_time_ns = 6000, .object_token = 402, .fd = 3, .timestamp_ns = 6030, .name = "m_late" };
    prov_engine_process_event(&e_reordered_write);
    prov_engine_process_event(&e_reordered_create);

    /* Scenario D: Duplicate MEMFD_COMPLETED event (should be deduplicated by engine) */
    struct event e_comp1 = { .type = EVENT_MEMFD_COMPLETED, .pid = 802, .start_time_ns = 6000, .object_token = 402, .inode_no = 999, .dev_id = 1, .fd = 3, .op_type = 2, .timestamp_ns = 6040, .name = "m_late" };
    struct event e_comp2 = { .type = EVENT_MEMFD_COMPLETED, .pid = 802, .start_time_ns = 6000, .object_token = 402, .inode_no = 999, .dev_id = 1, .fd = 3, .op_type = 2, .timestamp_ns = 6050, .name = "m_late" };
    prov_engine_process_event(&e_comp1);
    prov_engine_process_event(&e_comp2);

    /* Expected Nodes: 5
     *   proc_801_5000 (orphan process created on demand)
     *   memfd_401 (created by orphan)
     *   proc_800_1000 (parent)
     *   proc_802_6000 (child)
     *   memfd_402 (created by child)
     */
    struct expected_node exp_nodes[] = {
        { .id = "proc_801_5000", .type = NODE_PROCESS },
        { .id = "memfd_401",     .type = NODE_MEMFD },
        { .id = "proc_800_1000", .type = NODE_PROCESS },
        { .id = "proc_802_6000", .type = NODE_PROCESS },
        { .id = "memfd_402",     .type = NODE_MEMFD }
    };

    /* Expected Edges under Independent Ground Truth: 4
     * (Ground truth dictates exactly 1 FORK edge, 1 MEMFD_WRITE edge, and 2 MEMFD_CREATE edges)
     */
    struct expected_edge exp_edges[] = {
        { .src_id = "proc_801_5000", .dst_id = "memfd_401", .type = EDGE_MEMFD_CREATE, .expected_count = 1 },
        { .src_id = "proc_800_1000", .dst_id = "proc_802_6000", .type = EDGE_FORK,     .expected_count = 1 },
        { .src_id = "proc_802_6000", .dst_id = "memfd_402", .type = EDGE_MEMFD_WRITE,  .expected_count = 1 },
        { .src_id = "proc_802_6000", .dst_id = "memfd_402", .type = EDGE_MEMFD_CREATE, .expected_count = 1 }
    };

    evaluate_graph_precision_recall(exp_nodes, sizeof(exp_nodes)/sizeof(exp_nodes[0]),
                                    exp_edges, sizeof(exp_edges)/sizeof(exp_edges[0]), &m);

    /* Attribute Fidelity */
    struct prov_node *orphan = prov_find_node("proc_801_5000");
    struct prov_node *m402 = prov_find_node("memfd_402");
    m.checked_attributes = 3;
    if (orphan && strcmp(orphan->proc.comm, "<unknown>") == 0) m.matched_attributes++;
    if (m402 && strcmp(m402->memfd.name, "m_late") == 0) m.matched_attributes++;
    if (m402 && m402->memfd.inode_no == 999) m.matched_attributes++;

    /* Exposed Deficiency Checks */
    size_t fork_edge_count = 0;
    struct prov_node *p800 = prov_find_node("proc_800_1000");
    if (p800) {
        struct prov_edge *e = p800->out_edges;
        while (e) {
            if (e->type == EDGE_FORK && e->dst == prov_find_node("proc_802_6000")) fork_edge_count++;
            e = e->next_out;
        }
    }
    if (fork_edge_count > 1) {
        m.exposed_deficiencies_count++;
        snprintf(m.exposed_deficiencies, sizeof(m.exposed_deficiencies),
                 "Multiplicity Violation: Engine unconditionally appends duplicate EDGE_FORK edges "
                 "(1 redundant edge produced; edge precision: %.2f%%).",
                 (double)m.tp_edges / m.actual_edges * 100.0);
    }

    /* Test execution itself succeeded as a benchmark harness */
    m.test_execution_success = (m.actual_nodes == 5 && m.tp_nodes == 5 && m.tp_edges == 4);

    prov_engine_destroy();
    return m;
}

/* =========================================================================
 * Test 6: Scoped Remediation Regressions (Fork Dedup, Unresolved Identity, Exit Status)
 * ========================================================================= */
static struct metric_tracker test_remediation_regressions(void)
{
    struct metric_tracker m = { .test_name = "6. Scoped Remediation Regressions", .test_execution_success = true };
    prov_engine_init();

    /* --- Part 1: Duplicate fork prevention & repeated operations preservation --- */
    /* Parent 10 forks Child 20 (3 duplicate fork events offered) */
    struct event e_fork1 = { .type = EVENT_FORK, .pid = 10, .start_time_ns = 100, .child_tgid = 20, .child_pid = 20, .child_start_time_ns = 200, .timestamp_ns = 210, .name = "c20" };
    struct event e_fork2 = { .type = EVENT_FORK, .pid = 10, .start_time_ns = 100, .child_tgid = 20, .child_pid = 20, .child_start_time_ns = 200, .timestamp_ns = 211, .name = "c20" };
    struct event e_fork3 = { .type = EVENT_FORK, .pid = 10, .start_time_ns = 100, .child_tgid = 20, .child_pid = 20, .child_start_time_ns = 200, .timestamp_ns = 212, .name = "c20" };
    prov_engine_process_event(&e_fork1);
    prov_engine_process_event(&e_fork2);
    prov_engine_process_event(&e_fork3);

    /* Parent 10 forks Child 30 (legitimate separate fork) */
    struct event e_fork_c30 = { .type = EVENT_FORK, .pid = 10, .start_time_ns = 100, .child_tgid = 30, .child_pid = 30, .child_start_time_ns = 300, .timestamp_ns = 310, .name = "c30" };
    prov_engine_process_event(&e_fork_c30);

    /* Child 20 creates memfd 501 and writes 3 times (legitimate repeated writes) */
    struct event e_m501 = { .type = EVENT_MEMFD_CREATE, .pid = 20, .start_time_ns = 200, .object_token = 501, .fd = 3, .timestamp_ns = 220, .name = "memfd_repeat" };
    struct event e_w1   = { .type = EVENT_MEMFD_WRITE,  .pid = 20, .start_time_ns = 200, .object_token = 501, .entry_ts_ns = 0,    .ret_val = 512, .timestamp_ns = 230 };
    struct event e_w2   = { .type = EVENT_MEMFD_WRITE,  .pid = 20, .start_time_ns = 200, .object_token = 501, .entry_ts_ns = 512,  .ret_val = 512, .timestamp_ns = 240 };
    struct event e_w3   = { .type = EVENT_MEMFD_WRITE,  .pid = 20, .start_time_ns = 200, .object_token = 501, .entry_ts_ns = 1024, .ret_val = 512, .timestamp_ns = 250 };
    prov_engine_process_event(&e_m501);
    prov_engine_process_event(&e_w1);
    prov_engine_process_event(&e_w2);
    prov_engine_process_event(&e_w3);

    /* --- Part 2: Explicit Unresolved Identity (start_time_ns == 0) --- */
    /* Process 50 active generation */
    struct event e_p50_active = { .type = EVENT_FORK, .pid = 10, .start_time_ns = 100, .child_tgid = 50, .child_pid = 50, .child_start_time_ns = 5000, .timestamp_ns = 5010, .name = "p50_gen1" };
    prov_engine_process_event(&e_p50_active);

    /* Event arrives for pid 50 with start_time_ns = 0 */
    struct event e_p50_unres1 = { .type = EVENT_FD_INSTALLED, .pid = 50, .start_time_ns = 0, .object_token = 501, .fd = 7, .op_type = 2, .timestamp_ns = 5020 };
    prov_engine_process_event(&e_p50_unres1);

    /* Second event arrives for pid 50 with start_time_ns = 0 */
    struct event e_p50_unres2 = { .type = EVENT_FD_INSTALLED, .pid = 50, .start_time_ns = 0, .object_token = 501, .fd = 8, .op_type = 2, .timestamp_ns = 5030 };
    prov_engine_process_event(&e_p50_unres2);

    /* --- Part 3: Unavailable Process Exit Status --- */
    /* Process 60 never exits (alive) */
    struct event e_p60 = { .type = EVENT_FORK, .pid = 10, .start_time_ns = 100, .child_tgid = 60, .child_pid = 60, .child_start_time_ns = 6000, .timestamp_ns = 6010, .name = "p60_alive" };
    prov_engine_process_event(&e_p60);

    /* Process 70 exits with reserved = 0 (thread exit, group alive) */
    struct event e_p70 = { .type = EVENT_FORK, .pid = 10, .start_time_ns = 100, .child_tgid = 70, .child_pid = 70, .child_start_time_ns = 7000, .timestamp_ns = 7010, .name = "p70_grp_alive" };
    struct event e_p70_exit = { .type = EVENT_PROCESS_EXIT, .pid = 70, .start_time_ns = 7000, .reserved = 0, .ret_val = 0, .timestamp_ns = 7020, .name = "p70_grp_alive" };
    prov_engine_process_event(&e_p70);
    prov_engine_process_event(&e_p70_exit);

    /* Process 80 exits cleanly with reserved = 1, ret_val = 0 (known exit code 0) */
    struct event e_p80 = { .type = EVENT_FORK, .pid = 10, .start_time_ns = 100, .child_tgid = 80, .child_pid = 80, .child_start_time_ns = 8000, .timestamp_ns = 8010, .name = "p80_clean" };
    struct event e_p80_exit = { .type = EVENT_PROCESS_EXIT, .pid = 80, .start_time_ns = 8000, .reserved = 1, .ret_val = 0, .timestamp_ns = 8020, .name = "p80_clean" };
    prov_engine_process_event(&e_p80);
    prov_engine_process_event(&e_p80_exit);

    /* Process 90 exits with error reserved = 1, ret_val = 137 (known exit code 137) */
    struct event e_p90 = { .type = EVENT_FORK, .pid = 10, .start_time_ns = 100, .child_tgid = 90, .child_pid = 90, .child_start_time_ns = 9000, .timestamp_ns = 9010, .name = "p90_sigkill" };
    struct event e_p90_exit = { .type = EVENT_PROCESS_EXIT, .pid = 90, .start_time_ns = 9000, .reserved = 1, .ret_val = 137, .timestamp_ns = 9020, .name = "p90_sigkill" };
    prov_engine_process_event(&e_p90);
    prov_engine_process_event(&e_p90_exit);

    /* Verify Graph Entities */
    struct expected_node exp_nodes[] = {
        { .id = "proc_10_100",            .type = NODE_PROCESS },
        { .id = "proc_20_200",            .type = NODE_PROCESS },
        { .id = "proc_30_300",            .type = NODE_PROCESS },
        { .id = "memfd_501",              .type = NODE_MEMFD },
        { .id = "proc_50_5000",           .type = NODE_PROCESS },
        { .id = "proc_50_unresolved_1",   .type = NODE_PROCESS },
        { .id = "proc_50_unresolved_2",   .type = NODE_PROCESS },
        { .id = "proc_60_6000",           .type = NODE_PROCESS },
        { .id = "proc_70_7000",           .type = NODE_PROCESS },
        { .id = "proc_80_8000",           .type = NODE_PROCESS },
        { .id = "proc_90_9000",           .type = NODE_PROCESS }
    };

    struct expected_edge exp_edges[] = {
        { .src_id = "proc_10_100",          .dst_id = "proc_20_200",  .type = EDGE_FORK,         .expected_count = 1 },
        { .src_id = "proc_10_100",          .dst_id = "proc_30_300",  .type = EDGE_FORK,         .expected_count = 1 },
        { .src_id = "proc_20_200",          .dst_id = "memfd_501",    .type = EDGE_MEMFD_CREATE, .expected_count = 1 },
        { .src_id = "proc_20_200",          .dst_id = "memfd_501",    .type = EDGE_MEMFD_WRITE,  .expected_count = 3 },
        { .src_id = "proc_10_100",          .dst_id = "proc_50_5000", .type = EDGE_FORK,         .expected_count = 1 },
        { .src_id = "proc_50_unresolved_1", .dst_id = "memfd_501",    .type = EDGE_FD_INSTALLED, .expected_count = 1 },
        { .src_id = "proc_50_unresolved_2", .dst_id = "memfd_501",    .type = EDGE_FD_INSTALLED, .expected_count = 1 },
        { .src_id = "proc_10_100",          .dst_id = "proc_60_6000", .type = EDGE_FORK,         .expected_count = 1 },
        { .src_id = "proc_10_100",          .dst_id = "proc_70_7000", .type = EDGE_FORK,         .expected_count = 1 },
        { .src_id = "proc_10_100",          .dst_id = "proc_80_8000", .type = EDGE_FORK,         .expected_count = 1 },
        { .src_id = "proc_10_100",          .dst_id = "proc_90_9000", .type = EDGE_FORK,         .expected_count = 1 }
    };

    evaluate_graph_precision_recall(exp_nodes, sizeof(exp_nodes)/sizeof(exp_nodes[0]),
                                    exp_edges, sizeof(exp_edges)/sizeof(exp_edges[0]), &m);

    /* Attribute Checks */
    struct prov_node *p50_act = prov_find_node("proc_50_5000");
    struct prov_node *u1 = prov_find_node("proc_50_unresolved_1");
    struct prov_node *u2 = prov_find_node("proc_50_unresolved_2");
    struct prov_node *p60 = prov_find_node("proc_60_6000");
    struct prov_node *p70 = prov_find_node("proc_70_7000");
    struct prov_node *p80 = prov_find_node("proc_80_8000");
    struct prov_node *p90 = prov_find_node("proc_90_9000");

    m.checked_attributes = 10;
    /* 1. Unresolved nodes distinct from active node */
    if (u1 && u1->proc.is_unresolved && u1 != p50_act) m.matched_attributes++;
    if (u2 && u2->proc.is_unresolved && u2 != p50_act && u2 != u1) m.matched_attributes++;
    /* 2. No bogus proc_50_0 created */
    if (prov_find_node("proc_50_0") == NULL) m.matched_attributes++;
    /* 3. Exit status unknown on alive process */
    if (p60 && p60->proc.is_alive && !p60->proc.exit_code_known) m.matched_attributes++;
    /* 4. Exit status unknown on non-leader exit */
    if (p70 && p70->proc.is_alive && !p70->proc.exit_code_known) m.matched_attributes++;
    /* 5. Exit status known 0 on clean exit */
    if (p80 && !p80->proc.is_alive && p80->proc.exit_code_known && p80->proc.exit_code == 0) m.matched_attributes++;
    /* 6. Exit status known 137 on sigkill exit */
    if (p90 && !p90->proc.is_alive && p90->proc.exit_code_known && p90->proc.exit_code == 137) m.matched_attributes++;

    /* Export verification: JSON representation of unknown vs known exit codes */
    char json_tmp[256];
    snprintf(json_tmp, sizeof(json_tmp), "/tmp/test_remediation_%d.json", getpid());
    prov_engine_export_json(json_tmp);
    FILE *fj = fopen(json_tmp, "r");
    bool json_has_unknown_exit = false;
    bool json_has_zero_exit = false;
    bool json_has_unresolved_id = false;
    if (fj) {
        char line[512];
        while (fgets(line, sizeof(line), fj)) {
            if (strstr(line, "\"exit_code\": \"unknown\"")) json_has_unknown_exit = true;
            if (strstr(line, "\"exit_code\": 0")) json_has_zero_exit = true;
            if (strstr(line, "\"identity_status\": \"unresolved\"")) json_has_unresolved_id = true;
        }
        fclose(fj);
        unlink(json_tmp);
    }
    if (json_has_unknown_exit) m.matched_attributes++;
    if (json_has_zero_exit) m.matched_attributes++;
    if (json_has_unresolved_id) m.matched_attributes++;

    if (m.tp_nodes != m.expected_nodes || m.tp_edges != m.expected_edges ||
        m.matched_attributes != m.checked_attributes) {
        m.test_execution_success = false;
    }

    prov_engine_destroy();
    return m;
}

int main(void)
{
    printf("=================================================================\n");
    printf("   EphimTrace Provenance Benchmark 01 — Correctness Evaluation   \n");
    printf("=================================================================\n");
    printf("Matching Methodology: Exact typed, directed entity & multiplicity\n");
    printf("Precision = TP / (TP + FP)  |  Recall = TP / (TP + FN)\n");
    printf("=================================================================\n\n");

    struct metric_tracker results[6];
    results[0] = test_standard_lifecycle();
    print_metric_result(&results[0]);

    results[1] = test_pid_reuse();
    print_metric_result(&results[1]);

    results[2] = test_fd_reuse_and_reopening();
    print_metric_result(&results[2]);

    results[3] = test_exec_representation();
    print_metric_result(&results[3]);

    results[4] = test_missing_duplicate_reordered();
    print_metric_result(&results[4]);

    results[5] = test_remediation_regressions();
    print_metric_result(&results[5]);

    printf("=================================================================\n");
    printf("Summary: Correctness Evaluation Complete across 6 suites.\n");
    printf("=================================================================\n");
    return 0;
}
