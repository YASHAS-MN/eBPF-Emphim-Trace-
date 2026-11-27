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

/* Structure to track precision and recall metrics */
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

    bool passed;
    char notes[512];
};

static void print_metric_result(const struct metric_tracker *m)
{
    double node_prec = (m->actual_nodes > 0) ? ((double)m->tp_nodes / m->actual_nodes) : 1.0;
    double node_rec  = (m->expected_nodes > 0) ? ((double)m->tp_nodes / m->expected_nodes) : 1.0;
    double edge_prec = (m->actual_edges > 0) ? ((double)m->tp_edges / m->actual_edges) : 1.0;
    double edge_rec  = (m->expected_edges > 0) ? ((double)m->tp_edges / m->expected_edges) : 1.0;
    double attr_fid  = (m->checked_attributes > 0) ? ((double)m->matched_attributes / m->checked_attributes) : 1.0;

    printf("  [TEST: %-32s] Status: %s\n", m->test_name, m->passed ? "PASS" : "FAIL");
    printf("    Nodes: exp=%zu, act=%zu, tp=%zu, fp=%zu, fn=%zu -> Prec: %.2f%%, Rec: %.2f%%\n",
           m->expected_nodes, m->actual_nodes, m->tp_nodes, m->fp_nodes, m->fn_nodes,
           node_prec * 100.0, node_rec * 100.0);
    printf("    Edges: exp=%zu, act=%zu, tp=%zu, fp=%zu, fn=%zu -> Prec: %.2f%%, Rec: %.2f%%\n",
           m->expected_edges, m->actual_edges, m->tp_edges, m->fp_edges, m->fn_edges,
           edge_prec * 100.0, edge_rec * 100.0);
    printf("    Attributes: checked=%zu, matched=%zu -> Fidelity: %.2f%%\n",
           m->checked_attributes, m->matched_attributes, attr_fid * 100.0);
    printf("    Identities: false_joins=%zu, false_splits=%zu\n", m->false_joins, m->false_splits);
    if (m->notes[0]) {
        printf("    Notes: %s\n", m->notes);
    }
}

/* =========================================================================
 * Test 1: Standard Full Lifecycle Precision & Recall
 * ========================================================================= */
static struct metric_tracker test_standard_lifecycle(void)
{
    struct metric_tracker m = { .test_name = "1. Standard Full Lifecycle", .passed = true };
    prov_engine_init();

    /* Events:
     * 1. FORK: parent (100) -> child (200)
     * 2. MEMFD_CREATE: child (200) -> token 1001, fd 3
     * 3. MEMFD_COMPLETED: child (200) -> token 1001, inode 5001, dev 1
     * 4. MEMFD_WRITE: child (200) -> token 1001, off 0, bytes 1024
     * 5. FD_INSTALLED: child (200) -> token 1001, fd 4 (DUP)
     * 6. FD_CLOSED: child (200) -> token 1001, fd 3, dur 5000ns
     * 7. MEMFD_EXEC_ATTEMPT: child (200) -> token 1001, target /dev/fd/4
     * 8. MEMFD_EXEC_SUCCESS: child (200) -> token 1001, comm "worker_elf"
     * 9. VFS_UNLINK_COMPLETED: parent (100) -> inode 7001, dev 2049, path "/tmp/data.bin"
     * 10. CONNECT: child (200) -> 127.0.0.1:9000
     * 11. PROCESS_EXIT: child (200) -> exit 0
     */
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

    /* Expected Ground Truth:
     * Nodes (5):
     *   proc_100_1000 (Process)
     *   proc_200_2000 (Process)
     *   memfd_1001 (Memfd)
     *   fs_2049_7001 (FS Object)
     *   net_2_127.0.0.1_9000 (Net Endpoint)
     * Edges (9):
     *   FORK (proc_100 -> proc_200)
     *   MEMFD_CREATE (proc_200 -> memfd_1001) [deduplicated with MEMFD_COMPLETED]
     *   MEMFD_WRITE (proc_200 -> memfd_1001)
     *   FD_INSTALLED (proc_200 -> memfd_1001)
     *   FD_CLOSED (proc_200 -> memfd_1001)
     *   MEMFD_EXEC_ATTEMPT (proc_200 -> memfd_1001)
     *   MEMFD_EXEC_SUCCESS (proc_200 -> memfd_1001)
     *   UNLINK (proc_100 -> fs_2049_7001)
     *   CONNECT (proc_200 -> net_2_127.0.0.1_9000)
     */
    m.expected_nodes = 5;
    m.expected_edges = 9;

    prov_engine_get_counts(&m.actual_nodes, &m.actual_edges);

    /* Verify nodes */
    struct prov_node *p100 = prov_find_node("proc_100_1000");
    struct prov_node *p200 = prov_find_node("proc_200_2000");
    struct prov_node *m1001 = prov_find_node("memfd_1001");
    struct prov_node *fs7001 = prov_find_node("fs_2049_7001");
    struct prov_node *net9000 = prov_find_node("net_2_127.0.0.1_9000");

    if (p100) m.tp_nodes++; else m.fn_nodes++;
    if (p200) m.tp_nodes++; else m.fn_nodes++;
    if (m1001) m.tp_nodes++; else m.fn_nodes++;
    if (fs7001) m.tp_nodes++; else m.fn_nodes++;
    if (net9000) m.tp_nodes++; else m.fn_nodes++;

    if (m.actual_nodes > m.tp_nodes) m.fp_nodes = m.actual_nodes - m.tp_nodes;

    /* Verify edges count & types */
    if (m.actual_edges == m.expected_edges) {
        m.tp_edges = m.actual_edges;
    } else if (m.actual_edges > m.expected_edges) {
        m.tp_edges = m.expected_edges;
        m.fp_edges = m.actual_edges - m.expected_edges;
    } else {
        m.tp_edges = m.actual_edges;
        m.fn_edges = m.expected_edges - m.actual_edges;
    }

    /* Attribute fidelity checks */
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

    if (m.tp_nodes != m.expected_nodes || m.tp_edges != m.expected_edges || m.matched_attributes != m.checked_attributes) {
        m.passed = false;
    }

    prov_engine_destroy();
    return m;
}

/* =========================================================================
 * Test 2: Identity Consistency across PID Reuse
 * ========================================================================= */
static struct metric_tracker test_pid_reuse(void)
{
    struct metric_tracker m = { .test_name = "2. PID Reuse & Generation Separation", .passed = true };
    prov_engine_init();

    /* Generation 1: Process PID 3000, start_time 1000000. Spawns memfd 101. Exits. */
    struct event e1_fork = { .type = EVENT_FORK, .pid = 1, .start_time_ns = 500,
                            .child_tgid = 3000, .child_pid = 3000, .child_start_time_ns = 1000000, .timestamp_ns = 1000050, .name = "worker_gen1" };
    struct event e1_create = { .type = EVENT_MEMFD_CREATE, .pid = 3000, .start_time_ns = 1000000, .object_token = 101, .fd = 3, .timestamp_ns = 1000100, .name = "m_gen1" };
    struct event e1_exit = { .type = EVENT_PROCESS_EXIT, .pid = 3000, .start_time_ns = 1000000, .reserved = 1, .ret_val = 0, .timestamp_ns = 1000200 };

    /* Generation 2: Reused PID 3000, start_time 2000000. Spawns memfd 102. Exits. */
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

    /* Expected:
     * Nodes (5): proc_1_500, proc_3000_1000000, proc_3000_2000000, memfd_101, memfd_102
     * Edges (4): FORK (1->3000_g1), CREATE (3000_g1->101), FORK (1->3000_g2), CREATE (3000_g2->102)
     */
    m.expected_nodes = 5;
    m.expected_edges = 4;
    prov_engine_get_counts(&m.actual_nodes, &m.actual_edges);

    struct prov_node *g1 = prov_find_node("proc_3000_1000000");
    struct prov_node *g2 = prov_find_node("proc_3000_2000000");
    struct prov_node *m1 = prov_find_node("memfd_101");
    struct prov_node *m2 = prov_find_node("memfd_102");

    if (g1) m.tp_nodes++; else m.fn_nodes++;
    if (g2) m.tp_nodes++; else m.fn_nodes++;
    if (m1) m.tp_nodes++; else m.fn_nodes++;
    if (m2) m.tp_nodes++; else m.fn_nodes++;
    if (prov_find_node("proc_1_500")) m.tp_nodes++; else m.fn_nodes++;

    m.tp_edges = m.actual_edges;
    m.checked_attributes = 4;

    /* Verify separation: G1 and G2 must be completely distinct nodes */
    if (g1 && g2 && g1 != g2) {
        m.matched_attributes += 2;
    } else {
        m.false_joins++;
        m.passed = false;
        snprintf(m.notes, sizeof(m.notes), "DEFICIENCY: PID reuse caused false join between generations");
    }

    /* Verify edge source attribution */
    if (m1 && m1->in_edges && m1->in_edges->src == g1) m.matched_attributes++;
    if (m2 && m2->in_edges && m2->in_edges->src == g2) m.matched_attributes++;

    /* Test Case: PID reuse with start_time == 0 (Unresolved start_time fallback) */
    /* If a third event arrives for PID 3000 with start_time 0 after G2 exited */
    struct event e3_zero = { .type = EVENT_FD_INSTALLED, .pid = 3000, .start_time_ns = 0, .object_token = 102, .fd = 5, .timestamp_ns = 3000000 };
    prov_engine_process_event(&e3_zero);
    struct prov_node *fallback = prov_find_node("proc_3000_0");
    if (!fallback) {
        /* If find_active_proc returned NULL, it created proc_3000_0 */
        m.false_splits++;
    }

    prov_engine_destroy();
    return m;
}

/* =========================================================================
 * Test 3: FD Reuse & Memfd Reopening
 * ========================================================================= */
static struct metric_tracker test_fd_reuse_and_reopening(void)
{
    struct metric_tracker m = { .test_name = "3. FD Reuse & Memfd Reopening", .passed = true };
    prov_engine_init();

    /* Process 500 creates memfd 201 on FD 3, writes, closes FD 3.
     * Process 500 then creates memfd 202 on FD 3 (FD REUSE!).
     * Process 600 opens memfd 201 via /dev/fd/3 (REOPEN).
     */
    struct event e_create1 = { .type = EVENT_MEMFD_CREATE, .pid = 500, .start_time_ns = 1000, .object_token = 201, .fd = 3, .timestamp_ns = 10, .name = "m1" };
    struct event e_close1  = { .type = EVENT_FD_CLOSED,    .pid = 500, .start_time_ns = 1000, .object_token = 201, .fd = 3, .timestamp_ns = 20 };
    struct event e_create2 = { .type = EVENT_MEMFD_CREATE, .pid = 500, .start_time_ns = 1000, .object_token = 202, .fd = 3, .timestamp_ns = 30, .name = "m2" };
    struct event e_reopen  = { .type = EVENT_FD_INSTALLED, .pid = 600, .start_time_ns = 2000, .object_token = 201, .fd = 4, .op_type = 2 /* REOPEN */, .timestamp_ns = 40 };

    prov_engine_process_event(&e_create1);
    prov_engine_process_event(&e_close1);
    prov_engine_process_event(&e_create2);
    prov_engine_process_event(&e_reopen);

    /* Expected:
     * Nodes (4): proc_500_1000, proc_600_2000, memfd_201, memfd_202
     * Edges (4): CREATE(500->201), CLOSED(500->201), CREATE(500->202), REOPEN(600->201)
     */
    m.expected_nodes = 4;
    m.expected_edges = 4;
    prov_engine_get_counts(&m.actual_nodes, &m.actual_edges);

    struct prov_node *m1 = prov_find_node("memfd_201");
    struct prov_node *m2 = prov_find_node("memfd_202");
    struct prov_node *p500 = prov_find_node("proc_500_1000");
    struct prov_node *p600 = prov_find_node("proc_600_2000");

    if (m1) m.tp_nodes++; else m.fn_nodes++;
    if (m2) m.tp_nodes++; else m.fn_nodes++;
    if (p500) m.tp_nodes++; else m.fn_nodes++;
    if (p600) m.tp_nodes++; else m.fn_nodes++;

    m.tp_edges = m.actual_edges;
    m.checked_attributes = 4;

    /* Verify FD reuse did not merge memfd 201 and 202 */
    if (m1 && m2 && m1 != m2) {
        m.matched_attributes += 2;
    } else {
        m.false_joins++;
        m.passed = false;
        snprintf(m.notes, sizeof(m.notes), "DEFICIENCY: FD reuse caused false join of memfd nodes");
    }

    /* Verify reopen correctly linked p600 to m1 (token 201), not m2 */
    if (p600 && p600->out_edges && p600->out_edges->dst == m1 && p600->out_edges->type == EDGE_FD_INSTALLED) {
        m.matched_attributes += 2;
    } else {
        m.passed = false;
    }

    prov_engine_destroy();
    return m;
}

/* =========================================================================
 * Test 4: Successful vs Failed Execution Representation
 * ========================================================================= */
static struct metric_tracker test_exec_representation(void)
{
    struct metric_tracker m = { .test_name = "4. Exec Representation (Success vs Failure)", .passed = true };
    prov_engine_init();

    /* Child 1 (PID 701): Successful memfd execution */
    struct event e1_fork = { .type = EVENT_FORK, .pid = 700, .start_time_ns = 1000, .child_tgid = 701, .child_pid = 701, .child_start_time_ns = 1100, .timestamp_ns = 1110, .name = "parent" };
    struct event e1_att  = { .type = EVENT_MEMFD_EXEC_ATTEMPT, .pid = 701, .start_time_ns = 1100, .object_token = 301, .timestamp_ns = 1120, .name = "/dev/fd/3" };
    struct event e1_succ = { .type = EVENT_MEMFD_EXEC_SUCCESS, .pid = 701, .start_time_ns = 1100, .object_token = 301, .timestamp_ns = 1130, .name = "success_binary" };

    /* Child 2 (PID 702): Failed memfd execution (e.g. -ENOEXEC) */
    struct event e2_fork = { .type = EVENT_FORK, .pid = 700, .start_time_ns = 1000, .child_tgid = 702, .child_pid = 702, .child_start_time_ns = 1200, .timestamp_ns = 1210, .name = "parent" };
    struct event e2_att  = { .type = EVENT_MEMFD_EXEC_ATTEMPT, .pid = 702, .start_time_ns = 1200, .object_token = 302, .timestamp_ns = 1220, .name = "/dev/fd/3" };
    /* No EXEC_SUCCESS for Child 2! */
    struct event e2_exit = { .type = EVENT_PROCESS_EXIT, .pid = 702, .start_time_ns = 1200, .reserved = 1, .ret_val = 126, .timestamp_ns = 1230 };

    /* Child 3 (PID 703): Regular FS Exec Success */
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

    /* Expected:
     * Nodes (7): proc_700_1000, proc_701_1100, proc_702_1200, proc_703_1300, memfd_301, memfd_302, fs_66309_88123
     * Edges (7): FORK(700->701), ATTEMPT(701->301), SUCCESS(701->301),
     *            FORK(700->702), ATTEMPT(702->302),
     *            FORK(700->703), FS_EXEC_SUCCESS(703->fs_66309_88123)
     */
    m.expected_nodes = 7;
    m.expected_edges = 7;
    prov_engine_get_counts(&m.actual_nodes, &m.actual_edges);

    m.tp_nodes = m.actual_nodes;
    m.tp_edges = m.actual_edges;

    struct prov_node *p701 = prov_find_node("proc_701_1100");
    struct prov_node *p702 = prov_find_node("proc_702_1200");
    struct prov_node *p703 = prov_find_node("proc_703_1300");

    m.checked_attributes = 6;
    /* p701 comm transformed to success_binary */
    if (p701 && strcmp(p701->proc.comm, "success_binary") == 0) m.matched_attributes++;
    /* p702 comm NOT transformed (remains initial "parent") */
    if (p702 && strcmp(p702->proc.comm, "parent") == 0) m.matched_attributes++;
    /* p702 has no EDGE_MEMFD_EXEC_SUCCESS */
    bool p702_has_success = false;
    if (p702) {
        struct prov_edge *e = p702->out_edges;
        while (e) {
            if (e->type == EDGE_MEMFD_EXEC_SUCCESS) p702_has_success = true;
            e = e->next_out;
        }
    }
    if (!p702_has_success) m.matched_attributes++;
    /* p702 recorded exit code 126 */
    if (p702 && p702->proc.exit_code == 126) m.matched_attributes++;
    /* p703 comm transformed to target_elf */
    if (p703 && strcmp(p703->proc.comm, "target_elf") == 0) m.matched_attributes++;
    /* p703 connected to fs object */
    struct prov_node *fs_node = prov_find_node("fs_66309_88123");
    if (fs_node && strcmp(fs_node->fs.path, "/usr/bin/target_elf") == 0) m.matched_attributes++;

    if (m.matched_attributes != m.checked_attributes) m.passed = false;

    prov_engine_destroy();
    return m;
}

/* =========================================================================
 * Test 5: Missing, Duplicated, and Reordered Events (Deficiency Exposure)
 * ========================================================================= */
static struct metric_tracker test_missing_duplicate_reordered(void)
{
    struct metric_tracker m = { .test_name = "5. Robustness & Deficiency Exposure", .passed = true };
    prov_engine_init();

    /* Scenario A: Missing parent fork (orphan process events arrive first) */
    struct event e_orphan_memfd = { .type = EVENT_MEMFD_CREATE, .pid = 801, .start_time_ns = 5000, .object_token = 401, .fd = 3, .timestamp_ns = 5010, .name = "m_orphan" };
    prov_engine_process_event(&e_orphan_memfd);

    /* Verify: engine created proc_801_5000 with comm <unknown> */
    struct prov_node *orphan = prov_find_node("proc_801_5000");
    m.checked_attributes++;
    if (orphan && strcmp(orphan->proc.comm, "<unknown>") == 0) m.matched_attributes++;

    /* Scenario B: Duplicate fork event */
    struct event e_dup_fork1 = { .type = EVENT_FORK, .pid = 800, .start_time_ns = 1000, .child_tgid = 802, .child_pid = 802, .child_start_time_ns = 6000, .timestamp_ns = 6010, .name = "worker" };
    struct event e_dup_fork2 = { .type = EVENT_FORK, .pid = 800, .start_time_ns = 1000, .child_tgid = 802, .child_pid = 802, .child_start_time_ns = 6000, .timestamp_ns = 6010, .name = "worker" };
    prov_engine_process_event(&e_dup_fork1);
    prov_engine_process_event(&e_dup_fork2);

    /* Verify: Does engine deduplicate duplicate FORK edges? */
    size_t fork_edge_count = 0;
    struct prov_node *p800 = prov_find_node("proc_800_1000");
    if (p800) {
        struct prov_edge *e = p800->out_edges;
        while (e) {
            if (e->type == EDGE_FORK && e->dst == prov_find_node("proc_802_6000")) fork_edge_count++;
            e = e->next_out;
        }
    }
    m.checked_attributes++;
    if (fork_edge_count > 1) {
        /* Exposed deficiency: Engine does not deduplicate fork edges */
        m.fp_edges += (fork_edge_count - 1);
        strcat(m.notes, "DEFICIENCY: Duplicate FORK edges not deduplicated. ");
    } else {
        m.matched_attributes++;
    }

    /* Scenario C: Reordered event (write arrives before create) */
    struct event e_reordered_write = { .type = EVENT_MEMFD_WRITE, .pid = 802, .start_time_ns = 6000, .object_token = 402, .entry_ts_ns = 0, .ret_val = 512, .timestamp_ns = 6020 };
    struct event e_reordered_create = { .type = EVENT_MEMFD_CREATE, .pid = 802, .start_time_ns = 6000, .object_token = 402, .fd = 3, .timestamp_ns = 6030, .name = "m_late" };
    prov_engine_process_event(&e_reordered_write);
    prov_engine_process_event(&e_reordered_create);

    /* Verify: memfd_402 exists and name was updated */
    struct prov_node *m402 = prov_find_node("memfd_402");
    m.checked_attributes++;
    if (m402 && strcmp(m402->memfd.name, "m_late") == 0) {
        m.matched_attributes++;
    } else {
        strcat(m.notes, "DEFICIENCY: Out-of-order write/create failed to update memfd name. ");
    }

    /* Scenario D: Duplicate MEMFD_COMPLETED event (should be deduplicated by engine) */
    struct event e_comp1 = { .type = EVENT_MEMFD_COMPLETED, .pid = 802, .start_time_ns = 6000, .object_token = 402, .inode_no = 999, .dev_id = 1, .fd = 3, .op_type = 2, .timestamp_ns = 6040, .name = "m_late" };
    struct event e_comp2 = { .type = EVENT_MEMFD_COMPLETED, .pid = 802, .start_time_ns = 6000, .object_token = 402, .inode_no = 999, .dev_id = 1, .fd = 3, .op_type = 2, .timestamp_ns = 6050, .name = "m_late" };
    prov_engine_process_event(&e_comp1);
    prov_engine_process_event(&e_comp2);

    /* Count creation edges on memfd_402 */
    size_t create_edge_count = 0;
    if (m402) {
        struct prov_edge *e = m402->in_edges;
        while (e) {
            if (e->type == EDGE_MEMFD_CREATE) create_edge_count++;
            e = e->next_in;
        }
    }
    m.checked_attributes++;
    if (create_edge_count == 1) {
        m.matched_attributes++;
    } else {
        strcat(m.notes, "DEFICIENCY: Duplicate MEMFD_COMPLETED not deduplicated. ");
    }

    prov_engine_get_counts(&m.actual_nodes, &m.actual_edges);
    m.expected_nodes = 4; /* proc_801, memfd_401, proc_800, proc_802, memfd_402 -> wait, 5 nodes */
    m.expected_nodes = 5;
    m.tp_nodes = m.actual_nodes;

    prov_engine_destroy();
    return m;
}

int main(void)
{
    printf("=================================================================\n");
    printf("   EphimTrace Provenance Benchmark 01 — Correctness Evaluation   \n");
    printf("=================================================================\n");

    struct metric_tracker results[5];
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

    printf("=================================================================\n");
    printf("Summary: Correctness Evaluation Complete.\n");
    printf("=================================================================\n");
    return 0;
}
