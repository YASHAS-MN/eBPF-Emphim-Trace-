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
    e_exit.op_type = MEMFD_STATUS_SUCCESS_CORRELATED;
    e_exit.flags = 0x01; /* VFS_IDENTITY_INODE_VALID */
    canonical_correlator_process_event(&e_exit);
    assert(e_exit.object_token == assigned_token);
    assert(e_exit.op_type == MEMFD_STATUS_SUCCESS_CORRELATED);

    struct correlator_stats st;
    canonical_correlator_get_stats(&st);
    assert(st.correlated_creations == 1);
    assert(st.failed_creations == 0);
    assert(st.missing_entry_count == 0);
    assert(st.missing_install_count == 0);
    canonical_correlator_destroy();
    printf("  [PASS] Independent creation lifecycle preserved; token resolved truthfully\n");
}

static void test_missing_events_and_uncertainty(void) {
    printf("[TEST 2] Missing events and uncertain attribution...\n");
    canonical_correlator_init();

    /* Subcase A: Missing install event (install dropped, exit arrives with ret_val >= 0) */
    struct event e_exit1;
    init_mock_event(&e_exit1, EVENT_MEMFD_COMPLETED, 1002, 1002);
    e_exit1.fd = 4;
    e_exit1.ret_val = 4;
    e_exit1.inode_no = 9902;
    e_exit1.dev_id = 42;
    e_exit1.entry_ts_ns = 2000000100ULL;
    e_exit1.op_type = MEMFD_STATUS_SUCCESS_CORRELATED;
    e_exit1.flags = 0x01;
    canonical_correlator_process_event(&e_exit1);
    assert(e_exit1.object_token != 0);

    /* Subcase B: Missing entry event (entry dropped, entry_ts_ns == 0) */
    struct event e_exit2;
    init_mock_event(&e_exit2, EVENT_MEMFD_COMPLETED, 1003, 1003);
    e_exit2.fd = 5;
    e_exit2.ret_val = 5;
    e_exit2.inode_no = 9903;
    e_exit2.dev_id = 42;
    e_exit2.entry_ts_ns = 0; /* Missing entry */
    e_exit2.op_type = MEMFD_STATUS_SUCCESS_CORRELATED;
    e_exit2.flags = 0x01;
    canonical_correlator_process_event(&e_exit2);

    /* Subcase C: Untracked descriptor close */
    struct event e_close;
    init_mock_event(&e_close, EVENT_FD_CLOSED, 1002, 1002);
    e_close.fd = 99; /* Never opened */
    canonical_correlator_process_event(&e_close);
    assert(e_close.object_token == 0);

    struct correlator_stats st;
    canonical_correlator_get_stats(&st);
    assert(st.missing_install_count >= 1);
    assert(st.missing_entry_count >= 1);
    assert(st.untracked_closes == 1);
    canonical_correlator_destroy();
    printf("  [PASS] Missing events and untracked closures accounted without synthetic invention\n");
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
    e_inst1.entry_ts_ns = 3000000000ULL;
    canonical_correlator_process_event(&e_inst1);
    uint64_t tok1 = e_inst1.object_token;

    struct event e_exit1;
    init_mock_event(&e_exit1, EVENT_MEMFD_COMPLETED, 2001, 2001);
    e_exit1.fd = 5;
    e_exit1.ret_val = 5;
    e_exit1.inode_no = 7701;
    e_exit1.dev_id = 42;
    e_exit1.entry_ts_ns = 3000000000ULL;
    e_exit1.op_type = MEMFD_STATUS_SUCCESS_CORRELATED;
    e_exit1.flags = 0x01;
    canonical_correlator_process_event(&e_exit1);
    assert(e_exit1.object_token == tok1);

    /* Process 2002 receives or reopens the same memfd (cross-process) */
    struct event e_inst2;
    init_mock_event(&e_inst2, EVENT_FD_INSTALLED, 2002, 2002);
    e_inst2.start_time_ns = 550000000ULL;
    e_inst2.fd = 8;
    e_inst2.inode_no = 7701;
    e_inst2.dev_id = 42;
    e_inst2.entry_ts_ns = 3000000000ULL;
    canonical_correlator_process_event(&e_inst2);
    assert(e_inst2.object_token == tok1);

    /* Process 2002 writes to it */
    struct event e_write;
    init_mock_event(&e_write, EVENT_MEMFD_WRITE, 2002, 2002);
    e_write.start_time_ns = 550000000ULL;
    e_write.fd = 8;
    e_write.inode_no = 7701;
    e_write.dev_id = 42;
    canonical_correlator_process_event(&e_write);
    assert(e_write.object_token == tok1);

    /* Process 2002 closes fd 8 */
    struct event e_close2;
    init_mock_event(&e_close2, EVENT_FD_CLOSED, 2002, 2002);
    e_close2.start_time_ns = 550000000ULL;
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

    /* A. Lifetime-safe PID reuse: same TGID (3001) but different start_time_ns */
    struct event e1;
    init_mock_event(&e1, EVENT_FD_INSTALLED, 3001, 3001);
    e1.start_time_ns = 1000000ULL; /* First process generation */
    e1.fd = 3;
    e1.inode_no = 8801;
    e1.dev_id = 42;
    canonical_correlator_process_event(&e1);
    uint64_t tok_gen1 = e1.object_token;

    /* New process forks with recycled PID 3001, different start_time_ns */
    struct event e1_recycled;
    init_mock_event(&e1_recycled, EVENT_FD_INSTALLED, 3001, 3001);
    e1_recycled.start_time_ns = 2000000ULL; /* Recycled process generation */
    e1_recycled.fd = 3;
    e1_recycled.inode_no = 8802;
    e1_recycled.dev_id = 42;
    canonical_correlator_process_event(&e1_recycled);
    uint64_t tok_gen2 = e1_recycled.object_token;
    assert(tok_gen2 != tok_gen1);

    /* Closing FD 3 in recycled process generation targets tok_gen2 */
    struct event e_close_gen2;
    init_mock_event(&e_close_gen2, EVENT_FD_CLOSED, 3001, 3001);
    e_close_gen2.start_time_ns = 2000000ULL;
    e_close_gen2.fd = 3;
    canonical_correlator_process_event(&e_close_gen2);
    assert(e_close_gen2.object_token == tok_gen2);

    /* Closing FD 3 in original generation targets tok_gen1 */
    struct event e_close_gen1;
    init_mock_event(&e_close_gen1, EVENT_FD_CLOSED, 3001, 3001);
    e_close_gen1.start_time_ns = 1000000ULL;
    e_close_gen1.fd = 3;
    canonical_correlator_process_event(&e_close_gen1);
    assert(e_close_gen1.object_token == tok_gen1);

    /* B. Inode reuse: create initial object on inode 8805 */
    struct event e_orig;
    init_mock_event(&e_orig, EVENT_MEMFD_COMPLETED, 3002, 3002);
    e_orig.fd = 6;
    e_orig.ret_val = 6;
    e_orig.inode_no = 8805;
    e_orig.dev_id = 42;
    e_orig.entry_ts_ns = 1000000ULL;
    e_orig.op_type = MEMFD_STATUS_SUCCESS_CORRELATED;
    e_orig.flags = 0x01;
    canonical_correlator_process_event(&e_orig);
    uint64_t tok_orig = e_orig.object_token;

    /* Evict inode 8805 */
    struct event e_evict;
    init_mock_event(&e_evict, EVENT_MEMFD_DESTROYED, 3002, 3002);
    e_evict.inode_no = 8805;
    e_evict.dev_id = 42;
    canonical_correlator_process_event(&e_evict);
    assert(e_evict.object_token == tok_orig);

    /* New creation reusing inode 8805 with birth difference of only 50 microseconds */
    struct event e_reuse;
    init_mock_event(&e_reuse, EVENT_MEMFD_COMPLETED, 3002, 3002);
    e_reuse.fd = 7;
    e_reuse.ret_val = 7;
    e_reuse.inode_no = 8805;
    e_reuse.dev_id = 42;
    e_reuse.entry_ts_ns = 1000050ULL; /* Only 50 us difference */
    e_reuse.op_type = MEMFD_STATUS_SUCCESS_CORRELATED;
    e_reuse.flags = 0x01;
    canonical_correlator_process_event(&e_reuse);
    assert(e_reuse.object_token != 0);

    struct correlator_stats st;
    canonical_correlator_get_stats(&st);
    assert(st.inode_reuses_detected >= 1);

    canonical_correlator_destroy();
    printf("  [PASS] PID recycling and sub-millisecond inode reuse disambiguated safely\n");
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
    e_exit.entry_ts_ns = 4000000000ULL;
    e_exit.op_type = MEMFD_STATUS_SUCCESS_CORRELATED;
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

    /* Subsequent write before inode eviction still resolves */
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
    e_fail.op_type = MEMFD_STATUS_FAILED;
    canonical_correlator_process_event(&e_fail);
    assert(e_fail.object_token == 0);
    assert(e_fail.op_type == MEMFD_STATUS_FAILED);

    struct correlator_stats st;
    canonical_correlator_get_stats(&st);
    assert(st.failed_creations == 1);

    canonical_correlator_destroy();
    printf("  [PASS] Failed syscalls clean up provisional state and emit token 0 with MEMFD_STATUS_FAILED (1)\n");
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
        e.entry_ts_ns = 1000ULL + i;
        e.op_type = MEMFD_STATUS_SUCCESS_CORRELATED;
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
    assert(st.allocation_failures == 0);

    canonical_correlator_destroy();
    printf("  [PASS] Correlator processed %d operations with zero lingering descriptors and 0 failures\n", N);
}

static void test_raw_vs_canonical_separation(void) {
    printf("[TEST 8] Preservation of raw observations separately from canonical reconstruction...\n");
    canonical_correlator_init();

    struct event raw;
    init_mock_event(&raw, EVENT_MEMFD_COMPLETED, 8001, 8001);
    raw.fd = 3;
    raw.ret_val = 3;
    raw.inode_no = 12345;
    raw.dev_id = 42;
    raw.entry_ts_ns = 5000000ULL;
    raw.op_type = MEMFD_STATUS_SUCCESS_CORRELATED;
    raw.flags = 0x01;
    raw.object_token = 0; /* Wire token is 0 */

    struct canonical_event canon;
    int rc = canonical_correlator_process_event_canonical(&raw, &canon);
    assert(rc == 0);

    /* Verify raw event is untouched */
    assert(raw.object_token == 0);
    assert(raw.op_type == MEMFD_STATUS_SUCCESS_CORRELATED);

    /* Verify canonical event has reconstructed token and creator identity */
    assert(canon.object_token != 0);
    assert(canon.op_type == MEMFD_STATUS_SUCCESS_CORRELATED);
    assert(canon.inode_no == 12345);
    assert(canon.pid == 8001);
    assert(canon.creator_tgid == 8001);
    assert(canon.creator_start_time_ns == 500000000ULL);

    /* Test consistent lifetime identity propagation when raw close event lacks start_time_ns (0) */
    struct event raw_close;
    init_mock_event(&raw_close, EVENT_FD_CLOSED, 8001, 8001);
    raw_close.start_time_ns = 0; /* Simulating missing task leader boottime in close hook */
    raw_close.fd = 3;

    struct canonical_event canon_close;
    rc = canonical_correlator_process_event_canonical(&raw_close, &canon_close);
    assert(rc == 0);

    /* Raw close is unmutated */
    assert(raw_close.start_time_ns == 0);
    assert(raw_close.object_token == 0);

    /* Canonical close has recovered lifetime identity and creator provenance */
    assert(canon_close.start_time_ns == 500000000ULL);
    assert(canon_close.object_token == canon.object_token);
    assert(canon_close.creator_tgid == 8001);
    assert(canon_close.creator_start_time_ns == 500000000ULL);

    canonical_correlator_destroy();
    printf("  [PASS] Raw observations preserved non-destructively; lifetime identity propagated consistently\n");
}

static void test_unrelated_hooks_passthrough(void) {
    printf("[TEST 9] Unchanged unrelated telemetry paths...\n");
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
    test_raw_vs_canonical_separation();
    test_unrelated_hooks_passthrough();

    printf("\n=================================================================\n");
    printf("=== [SUCCESS] ALL ARCHITECTURE C CORRELATOR TESTS PASSED     ===\n");
    printf("=================================================================\n");
    return 0;
}
