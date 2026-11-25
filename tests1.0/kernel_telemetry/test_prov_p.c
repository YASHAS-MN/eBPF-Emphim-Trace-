#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "provenance.h"

enum diag_p_status {
    P_STATUS_UNAVAILABLE = 0,
    P_STATUS_SUCCESS = 1,
    P_STATUS_FILTERED = 2,
    P_STATUS_CORRELATION_DEFICIENCY = 3,
    P_STATUS_EDGE_SUPPRESSED = 4,
    P_STATUS_FAILED = 5
};

struct diag_p_stats {
    uint64_t success;
    uint64_t filtered;
    uint64_t correlation_deficiency;
    uint64_t edge_suppressed;
    uint64_t failed;
};

extern uint32_t diag_p_get_last_status(void);
extern void diag_p_get_stats(struct diag_p_stats *out);
extern void diag_p_reset(void);
extern void diag_p_set_inject_fail(int fail);
extern int diag_p_should_inject_fail(void);

int main(void) {
    printf("=== Testing Diagnostic Checkpoint P In-Memory Provenance Processing ===\n");
    assert(prov_engine_init() == 0);
    diag_p_reset();

    /* 1. Test EVENT_MEMFD_CREATE (intentional filtering) */
    struct event e1;
    memset(&e1, 0, sizeof(e1));
    e1.type = EVENT_MEMFD_CREATE;
    e1.pid = 1234;
    e1.tid = 1234;
    e1.start_time_ns = 100000;
    e1.timestamp_ns = 100500;
    e1.object_token = 0; /* Token is always 0 on enter */
    snprintf(e1.name, sizeof(e1.name), "test_memfd");

    prov_engine_process_event(&e1);
    uint32_t st1 = diag_p_get_last_status();
    printf("  [TEST 1] EVENT_MEMFD_CREATE p_status: %u (expected %u = FILTERED)\n", st1, P_STATUS_FILTERED);
    assert(st1 == P_STATUS_FILTERED);

    /* 2. Test Successful EVENT_MEMFD_COMPLETED */
    struct event e2;
    memset(&e2, 0, sizeof(e2));
    e2.type = EVENT_MEMFD_COMPLETED;
    e2.pid = 1234;
    e2.tid = 1234;
    e2.start_time_ns = 100000;
    e2.timestamp_ns = 101000;
    e2.op_type = 2; /* MEMFD_STATUS_SUCCESS_CORRELATED */
    e2.object_token = 8888;
    e2.ret_val = 5;
    e2.fd = 5;
    snprintf(e2.name, sizeof(e2.name), "test_memfd");

    prov_engine_process_event(&e2);
    uint32_t st2 = diag_p_get_last_status();
    printf("  [TEST 2] EVENT_MEMFD_COMPLETED success p_status: %u (expected %u = SUCCESS)\n", st2, P_STATUS_SUCCESS);
    assert(st2 == P_STATUS_SUCCESS);

    /* Verify node and edge exist */
    struct prov_node *memfd = prov_find_node("memfd_8888");
    assert(memfd != NULL);
    struct prov_node *proc = prov_find_node("proc_1234_100000");
    assert(proc != NULL);
    assert(proc->out_edges != NULL);
    assert(proc->out_edges->type == EDGE_MEMFD_CREATE);
    assert(proc->out_edges->dst == memfd);
    assert(proc->out_edges->attr.fd == 5);
    assert(proc->out_edges->attr.timestamp_ns == 101000);
    printf("  [TEST 2 PASS] Verified memfd_8888, proc_1234_100000 and EDGE_MEMFD_CREATE attributes\n");

    /* 3. Test Pre-existing Edge Suppression */
    prov_engine_process_event(&e2);
    uint32_t st3 = diag_p_get_last_status();
    printf("  [TEST 3] Duplicate event p_status: %u (expected %u = EDGE_SUPPRESSED)\n", st3, P_STATUS_EDGE_SUPPRESSED);
    assert(st3 == P_STATUS_EDGE_SUPPRESSED);

    /* 4. Test Intentional Filtering of Failed Syscall */
    struct event e4;
    memset(&e4, 0, sizeof(e4));
    e4.type = EVENT_MEMFD_COMPLETED;
    e4.pid = 1234;
    e4.tid = 1234;
    e4.start_time_ns = 100000;
    e4.timestamp_ns = 102000;
    e4.op_type = 1; /* MEMFD_STATUS_FAILED */
    e4.ret_val = -22;
    e4.fd = -1;
    e4.object_token = 0;
    snprintf(e4.name, sizeof(e4.name), "failed_memfd");

    prov_engine_process_event(&e4);
    uint32_t st4 = diag_p_get_last_status();
    printf("  [TEST 4] Failed syscall p_status: %u (expected %u = FILTERED)\n", st4, P_STATUS_FILTERED);
    assert(st4 == P_STATUS_FILTERED);

    /* 5. Test Correlation Deficiency */
    struct event e5;
    memset(&e5, 0, sizeof(e5));
    e5.type = EVENT_MEMFD_COMPLETED;
    e5.pid = 1234;
    e5.tid = 1234;
    e5.start_time_ns = 100000;
    e5.timestamp_ns = 103000;
    e5.op_type = 3; /* MEMFD_STATUS_SUCCESS_UNCORRELATED */
    e5.ret_val = 6;
    e5.fd = 6;
    e5.object_token = 0;
    snprintf(e5.name, sizeof(e5.name), "uncorr_memfd");

    prov_engine_process_event(&e5);
    uint32_t st5 = diag_p_get_last_status();
    printf("  [TEST 5] Uncorrelated p_status: %u (expected %u = CORRELATION_DEFICIENCY)\n", st5, P_STATUS_CORRELATION_DEFICIENCY);
    assert(st5 == P_STATUS_CORRELATION_DEFICIENCY);

    /* 6. Test Controlled Userspace Processing Failure (Simulated allocation failure) */
    diag_p_set_inject_fail(1);
    struct event e6;
    memset(&e6, 0, sizeof(e6));
    e6.type = EVENT_MEMFD_COMPLETED;
    e6.pid = 1234;
    e6.tid = 1234;
    e6.start_time_ns = 100000;
    e6.timestamp_ns = 104000;
    e6.op_type = 2; /* MEMFD_STATUS_SUCCESS_CORRELATED */
    e6.object_token = 9999;
    e6.ret_val = 7;
    e6.fd = 7;
    snprintf(e6.name, sizeof(e6.name), "fail_inject_memfd");

    prov_engine_process_event(&e6);
    uint32_t st6 = diag_p_get_last_status();
    printf("  [TEST 6] Injected failure p_status: %u (expected %u = FAILED)\n", st6, P_STATUS_FAILED);
    assert(st6 == P_STATUS_FAILED);
    diag_p_set_inject_fail(0);

    /* Check stats */
    struct diag_p_stats pst;
    diag_p_get_stats(&pst);
    printf("  Summary stats: success=%llu, filtered=%llu, uncorr=%llu, suppr=%llu, failed=%llu\n",
           (unsigned long long)pst.success, (unsigned long long)pst.filtered,
           (unsigned long long)pst.correlation_deficiency, (unsigned long long)pst.edge_suppressed,
           (unsigned long long)pst.failed);
    assert(pst.success == 1);
    assert(pst.filtered == 2);
    assert(pst.correlation_deficiency == 1);
    assert(pst.edge_suppressed == 1);
    assert(pst.failed == 1);

    prov_engine_destroy();
    printf("=== [PASS] All Checkpoint P Unit Tests Succeeded Cleanly ===\n");
    return 0;
}
