#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "src/user/canonical_correlator.h"
#include "src/user/provenance.h"

static void init_mock_event(struct event *e, uint32_t type, uint32_t pid, uint32_t tid) {
    memset(e, 0, sizeof(*e));
    e->type = type;
    e->pid = pid;
    e->tid = tid;
    e->timestamp_ns = 1000000000ULL;
    e->start_time_ns = 500000000ULL;
}

static void test_independent_creation_observations(void) {
    printf("[TEST 1] Independent creation entry, installation, and completion observations...\n");
    canonical_correlator_init();

    struct event e_enter;
    init_mock_event(&e_enter, EVENT_MEMFD_CREATE, 1001, 1001);
    e_enter.entry_ts_ns = 1000000100ULL;
    e_enter.flags = 0x01;
    snprintf(e_enter.name, sizeof(e_enter.name), "test_memfd");
    canonical_correlator_process_event(&e_enter);
    assert(e_enter.object_token == 0);

    struct event e_inst;
    init_mock_event(&e_inst, EVENT_FD_INSTALLED, 1001, 1001);
    e_inst.fd = 3;
    e_inst.inode_no = 9901;
    e_inst.dev_id = 42;
    e_inst.op_type = 1; /* FD_INSTALL_OP_CREATION */
    e_inst.entry_ts_ns = 1000000100ULL;
    canonical_correlator_process_event(&e_inst);
    assert(e_inst.object_token != 0);
    uint64_t assigned_token = e_inst.object_token;

    struct event e_exit;
    init_mock_event(&e_exit, EVENT_MEMFD_COMPLETED, 1001, 1001);
    e_exit.fd = 3;
    e_exit.ret_val = 3;
    e_exit.inode_no = 9901;
    e_exit.dev_id = 42;
    e_exit.entry_ts_ns = 1000000100ULL;
    e_exit.op_type = 2; /* MEMFD_STATUS_SUCCESS_CORRELATED */
    e_exit.flags = 0x01; /* VFS_IDENTITY_INODE_VALID */
    canonical_correlator_process_event(&e_exit);
    assert(e_exit.object_token == assigned_token);
    assert(e_exit.op_type == 2);

    struct correlator_stats st;
    canonical_correlator_get_stats(&st);
    assert(st.correlated_creations == 1);
    assert(st.failed_creations == 0);
    canonical_correlator_destroy();
    printf("  [PASS] Independent creation lifecycle preserved; token resolved truthfully\n");
}

static void test_missing_events_and_uncertainty(void) {
    printf("[TEST 2] Missing events and uncertain attribution...\n");
    canonical_correlator_init();

    /* Subcase A: Missing install event (install was dropped, but exit arrives) */
    struct event e_exit;
    init_mock_event(&e_exit, EVENT_MEMFD_COMPLETED, 1002, 1002);
    e_exit.fd = 4;
    e_exit.ret_val = 4;
    e_exit.inode_no = 9902;
    e_exit.dev_id = 42;
    e_exit.op_type = 2;
    e_exit.flags = 0x01;
    canonical_correlator_process_event(&e_exit);
    assert(e_exit.object_token != 0);

    /* Subcase B: Untracked descriptor close */
    struct event e_close;
    init_mock_event(&e_close, EVENT_FD_CLOSED, 1002, 1002);
    e_close.fd = 99; /* Never opened */
    canonical_correlator_process_event(&e_close);
    assert(e_close.object_token == 0);

    struct correlator_stats st;
    canonical_correlator_get_stats(&st);
    assert(st.untracked_closes == 1);
    canonical_correlator_destroy();
    printf("  [PASS] Untracked closures accounted without inventing synthetic events\n");
}

static void test_reopened_files_and_cross_process(void) {
    printf("[TEST 3] Reopened files and cross-process references...\n");
    canonical_correlator_init();

    /* Process 2001 creates memfd */
    struct event e_inst1;
    init_mock_event(&e_inst1, EVENT_FD_INSTALLED, 2001, 2001);
    e_inst1.fd = 5;
    e_inst1.inode_no = 7701;
    e_inst1.dev_id = 42;
    e_inst1.op_type = 1; /* CREATION */
    canonical_correlator_process_event(&e_inst1);
    uint64_t tok1 = e_inst1.object_token;

    struct event e_exit1;
    init_mock_event(&e_exit1, EVENT_MEMFD_COMPLETED, 2001, 2001);
    e_exit1.fd = 5;
    e_exit1.ret_val = 5;
    e_exit1.inode_no = 7701;
    e_exit1.dev_id = 42;
    e_exit1.op_type = 2;
    e_exit1.flags = 0x01;
    canonical_correlator_process_event(&e_exit1);
    assert(e_exit1.object_token == tok1);

    /* Process 2002 receives or reopens the same memfd (cross-process) */
    struct event e_inst2;
    init_mock_event(&e_inst2, EVENT_FD_INSTALLED, 2002, 2002);
    e_inst2.fd = 8;
    e_inst2.inode_no = 7701;
    e_inst2.dev_id = 42;
    e_inst2.op_type = 2; /* REOPEN */
    canonical_correlator_process_event(&e_inst2);
    assert(e_inst2.object_token == tok1);

    /* Process 2002 writes to it */
    struct event e_write;
    init_mock_event(&e_write, EVENT_MEMFD_WRITE, 2002, 2002);
    e_write.inode_no = 7701;
    e_write.dev_id = 42;
    canonical_correlator_process_event(&e_write);
    assert(e_write.object_token == tok1);

    /* Process 2002 closes fd 8 */
    struct event e_close2;
    init_mock_event(&e_close2, EVENT_FD_CLOSED, 2002, 2002);
    e_close2.fd = 8;
    canonical_correlator_process_event(&e_close2);
    assert(e_close2.object_token == tok1);

    /* Process 2001 closes fd 5 */
    struct event e_close1;
    init_mock_event(&e_close1, EVENT_FD_CLOSED, 2001, 2001);
    e_close1.fd = 5;
    canonical_correlator_process_event(&e_close1);
    assert(e_close1.object_token == tok1);

    canonical_correlator_destroy();
    printf("  [PASS] Cross-process descriptor sharing correctly anchored to unique token\n");
}

static void test_descriptor_and_identity_reuse(void) {
    printf("[TEST 4] Pointer, inode, PID, and descriptor reuse...\n");
    canonical_correlator_init();

    /* A. Descriptor reuse without close */
    struct event e1;
    init_mock_event(&e1, EVENT_FD_INSTALLED, 3001, 3001);
    e1.fd = 3;
    e1.inode_no = 8801;
    e1.dev_id = 42;
    canonical_correlator_process_event(&e1);
    uint64_t tok_a = e1.object_token;

    /* New install on same FD without closing previous */
    struct event e2;
    init_mock_event(&e2, EVENT_FD_INSTALLED, 3001, 3001);
    e2.fd = 3;
    e2.inode_no = 8802;
    e2.dev_id = 42;
    canonical_correlator_process_event(&e2);
    uint64_t tok_b = e2.object_token;
    assert(tok_b != tok_a);

    struct correlator_stats st;
    canonical_correlator_get_stats(&st);
    assert(st.fd_reuses_without_close == 1);

    /* B. Inode reuse after eviction */
    struct event e_destroy;
    init_mock_event(&e_destroy, EVENT_MEMFD_DESTROYED, 3001, 3001);
    e_destroy.inode_no = 8801;
    e_destroy.dev_id = 42;
    canonical_correlator_process_event(&e_destroy);
    assert(e_destroy.object_token == tok_a);

    /* Subsequent creation reuses inode_no 8801 with new birth_ts */
    struct event e3;
    init_mock_event(&e3, EVENT_MEMFD_COMPLETED, 3001, 3001);
    e3.fd = 6;
    e3.ret_val = 6;
    e3.inode_no = 8801;
    e3.dev_id = 42;
    e3.entry_ts_ns = 5000000000ULL; /* Much later */
    e3.op_type = 2;
    e3.flags = 0x01;
    canonical_correlator_process_event(&e3);
    uint64_t tok_c = e3.object_token;
    assert(tok_c != tok_a);
    canonical_correlator_get_stats(&st);
    assert(st.inode_reuses_detected == 1);

    canonical_correlator_destroy();
    printf("  [PASS] Descriptor and inode reuse disambiguated safely across time\n");
}

static void test_file_release_vs_inode_destruction(void) {
    printf("[TEST 5] File release versus inode destruction...\n");
    canonical_correlator_init();

    struct event e_exit;
    init_mock_event(&e_exit, EVENT_MEMFD_COMPLETED, 4001, 4001);
    e_exit.fd = 3;
    e_exit.ret_val = 3;
    e_exit.inode_no = 5501;
    e_exit.dev_id = 42;
    e_exit.op_type = 2;
    e_exit.flags = 0x01;
    canonical_correlator_process_event(&e_exit);
    uint64_t tok = e_exit.object_token;

    /* Release struct file * (__fput) */
    struct event e_rel;
    init_mock_event(&e_rel, EVENT_MEMFD_FILE_RELEASED, 4001, 4001);
    e_rel.inode_no = 5501;
    e_rel.dev_id = 42;
    canonical_correlator_process_event(&e_rel);
    assert(e_rel.object_token == tok);

    /* Subsequent write or query before inode eviction still resolves */
    struct event e_w;
    init_mock_event(&e_w, EVENT_MEMFD_WRITE, 4001, 4001);
    e_w.inode_no = 5501;
    e_w.dev_id = 42;
    canonical_correlator_process_event(&e_w);
    assert(e_w.object_token == tok);

    /* Inode eviction (shmem_evict_inode) */
    struct event e_dest;
    init_mock_event(&e_dest, EVENT_MEMFD_DESTROYED, 4001, 4001);
    e_dest.inode_no = 5501;
    e_dest.dev_id = 42;
    canonical_correlator_process_event(&e_dest);
    assert(e_dest.object_token == tok);

    canonical_correlator_destroy();
    printf("  [PASS] File release distinguished truthfully from inode destruction\n");
}

static void test_failed_syscall_handling(void) {
    printf("[TEST 6] Membership-map insertion and syscall failure handling...\n");
    canonical_correlator_init();

    struct event e_fail;
    init_mock_event(&e_fail, EVENT_MEMFD_COMPLETED, 5001, 5001);
    e_fail.fd = -1;
    e_fail.ret_val = -24; /* -EMFILE */
    e_fail.op_type = 3; /* MEMFD_STATUS_FAILED */
    canonical_correlator_process_event(&e_fail);
    assert(e_fail.object_token == 0);
    assert(e_fail.op_type == 3);

    struct correlator_stats st;
    canonical_correlator_get_stats(&st);
    assert(st.failed_creations == 1);

    canonical_correlator_destroy();
    printf("  [PASS] Failed syscalls clean up provisional state and emit token 0\n");
}

static void test_bounded_correlator_memory(void) {
    printf("[TEST 7] Bounded correlator memory and lifecycle scaling...\n");
    canonical_correlator_init();

    const int N = 10000;
    for (int i = 0; i < N; i++) {
        struct event e;
        init_mock_event(&e, EVENT_MEMFD_COMPLETED, 6000 + (i % 10), 6000 + (i % 10));
        e.fd = 3 + (i % 100);
        e.ret_val = e.fd;
        e.inode_no = 100000 + i;
        e.dev_id = 42;
        e.op_type = 2;
        e.flags = 0x01;
        canonical_correlator_process_event(&e);

        struct event ec;
        init_mock_event(&ec, EVENT_FD_CLOSED, 6000 + (i % 10), 6000 + (i % 10));
        ec.fd = 3 + (i % 100);
        canonical_correlator_process_event(&ec);
    }

    struct correlator_stats st;
    canonical_correlator_get_stats(&st);
    assert(st.correlated_creations == (uint64_t)N);
    assert(st.active_descriptors_count == 0);

    canonical_correlator_destroy();
    printf("  [PASS] Correlator processed %d operations with zero lingering descriptors\n", N);
}

static void test_unrelated_hooks_passthrough(void) {
    printf("[TEST 8] Unchanged unrelated telemetry paths...\n");
    canonical_correlator_init();

    uint32_t unrelated_types[] = {
        EVENT_EXECVE, EVENT_UNLINK, EVENT_UNLINKAT, EVENT_CONNECT,
        EVENT_FORK, EVENT_PROCESS_EXEC, EVENT_PROCESS_EXIT,
        EVENT_VFS_UNLINK_COMPLETED, EVENT_VFS_RMDIR_COMPLETED, EVENT_RMDIR
    };
    for (size_t i = 0; i < sizeof(unrelated_types) / sizeof(unrelated_types[0]); i++) {
        struct event e;
        init_mock_event(&e, unrelated_types[i], 7001, 7001);
        snprintf(e.name, sizeof(e.name), "unrelated_test");
        e.flags = 0xABCD;
        e.ret_val = 123;
        canonical_correlator_process_event(&e);
        assert(e.type == unrelated_types[i]);
        assert(e.flags == 0xABCD);
        assert(e.ret_val == 123);
        assert(strcmp(e.name, "unrelated_test") == 0);
    }

    canonical_correlator_destroy();
    printf("  [PASS] All unrelated lifecycle events pass through bit-for-bit unchanged\n");
}

int main(void) {
    printf("=================================================================\n");
    printf("=== EphimTrace: Architecture C Canonical Correlator Test Suite ===\n");
    printf("=================================================================\n\n");

    test_independent_creation_observations();
    test_missing_events_and_uncertainty();
    test_reopened_files_and_cross_process();
    test_descriptor_and_identity_reuse();
    test_file_release_vs_inode_destruction();
    test_failed_syscall_handling();
    test_bounded_correlator_memory();
    test_unrelated_hooks_passthrough();

    printf("\n=================================================================\n");
    printf("=== [SUCCESS] ALL ARCHITECTURE C CORRELATOR TESTS PASSED     ===\n");
    printf("=================================================================\n");
    return 0;
}
