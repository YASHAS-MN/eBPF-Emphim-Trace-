#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <sys/stat.h>
#include <unistd.h>

#include "provenance.h"

static struct event make_memfd_completed(uint32_t pid, uint64_t start_time,
                                         uint64_t token, const char *name,
                                         uint64_t ino, uint64_t dev,
                                         int32_t fd, uint64_t ts) {
    struct event e;
    memset(&e, 0, sizeof(e));
    e.type = EVENT_MEMFD_COMPLETED;
    e.op_type = 2; /* MEMFD_STATUS_SUCCESS_CORRELATED */
    e.pid = pid;
    e.ppid = 1;
    e.start_time_ns = start_time;
    e.object_token = token;
    e.inode_no = ino;
    e.dev_id = dev;
    e.fd = fd;
    e.timestamp_ns = ts;
    if (name) {
        strncpy(e.name, name, sizeof(e.name) - 1);
    }
    return e;
}

static void test_complexity_scaling(void) {
    printf("=== Test 1: Adjacency Comparison Complexity Scaling ===\n");
    int test_sizes[] = {100, 500, 1000};
    int num_tests = sizeof(test_sizes) / sizeof(test_sizes[0]);

    for (int t = 0; t < num_tests; t++) {
        int N = test_sizes[t];

        /* Run 1: Outgoing adjacency search (Reference) */
        prov_engine_init();
        prov_engine_set_search_mode(1); /* Outgoing */
        prov_engine_reset_edge_comparisons();

        uint32_t pid = 5000;
        uint64_t p_start = 1000000;
        for (int i = 0; i < N; i++) {
            char name[64];
            snprintf(name, sizeof(name), "shm_out_%d", i);
            struct event e = make_memfd_completed(pid, p_start, 10000 + i, name,
                                                  20000 + i, 1, 3, 2000000 + i * 1000);
            prov_engine_process_event(&e);
        }
        size_t out_nodes = 0, out_edges = 0;
        prov_engine_get_counts(&out_nodes, &out_edges);
        uint64_t out_comps = prov_engine_get_edge_comparisons();
        prov_engine_destroy();

        /* Run 2: Incoming adjacency search (Modified) */
        prov_engine_init();
        prov_engine_set_search_mode(0); /* Incoming */
        prov_engine_reset_edge_comparisons();

        for (int i = 0; i < N; i++) {
            char name[64];
            snprintf(name, sizeof(name), "shm_out_%d", i);
            struct event e = make_memfd_completed(pid, p_start, 10000 + i, name,
                                                  20000 + i, 1, 3, 2000000 + i * 1000);
            prov_engine_process_event(&e);
        }
        size_t in_nodes = 0, in_edges = 0;
        prov_engine_get_counts(&in_nodes, &in_edges);
        uint64_t in_comps = prov_engine_get_edge_comparisons();
        prov_engine_destroy();

        printf("  N = %4d | Outgoing comps: %8llu (O(N^2)) | Incoming comps: %8llu (O(1)) | Reduction: %6.1fx\n",
               N, (unsigned long long)out_comps, (unsigned long long)in_comps,
               (in_comps > 0) ? ((double)out_comps / in_comps) : (double)out_comps);

        assert(out_nodes == in_nodes);
        assert(out_edges == in_edges);
        assert(out_edges == (size_t)N);
        /* In outgoing mode, N creations accumulate 0 + 1 + ... + (N-1) = N*(N-1)/2 comparisons */
        uint64_t expected_out = (uint64_t)N * (N - 1) / 2;
        assert(out_comps == expected_out);
        /* In incoming mode, before the edge is added, memfd->in_edges is empty, so 0 comparisons */
        assert(in_comps == 0);
    }
    printf("  [PASS] Complexity scaling verified: Outgoing is quadratic O(N^2), Incoming is O(1) per event.\n\n");
}

static void test_duplicate_suppression(void) {
    printf("=== Test 2: Duplicate Event Suppression & Comparison Count ===\n");
    int N = 200;

    /* Outgoing */
    prov_engine_init();
    prov_engine_set_search_mode(1);
    prov_engine_reset_edge_comparisons();

    uint32_t pid = 6000;
    uint64_t p_start = 1500000;
    for (int i = 0; i < N; i++) {
        char name[64];
        snprintf(name, sizeof(name), "dup_%d", i);
        struct event e = make_memfd_completed(pid, p_start, 20000 + i, name,
                                              30000 + i, 1, 3, 3000000 + i * 1000);
        prov_engine_process_event(&e);
    }
    /* Send duplicate completions */
    for (int i = 0; i < N; i++) {
        char name[64];
        snprintf(name, sizeof(name), "dup_%d", i);
        struct event e = make_memfd_completed(pid, p_start, 20000 + i, name,
                                              30000 + i, 1, 3, 3000000 + i * 1000);
        prov_engine_process_event(&e);
    }
    size_t out_nodes = 0, out_edges = 0;
    prov_engine_get_counts(&out_nodes, &out_edges);
    uint64_t out_comps = prov_engine_get_edge_comparisons();
    prov_engine_export_dot("/tmp/test_dup_outgoing.dot");
    prov_engine_destroy();

    /* Incoming */
    prov_engine_init();
    prov_engine_set_search_mode(0);
    prov_engine_reset_edge_comparisons();

    for (int i = 0; i < N; i++) {
        char name[64];
        snprintf(name, sizeof(name), "dup_%d", i);
        struct event e = make_memfd_completed(pid, p_start, 20000 + i, name,
                                              30000 + i, 1, 3, 3000000 + i * 1000);
        prov_engine_process_event(&e);
    }
    /* Send duplicate completions */
    for (int i = 0; i < N; i++) {
        char name[64];
        snprintf(name, sizeof(name), "dup_%d", i);
        struct event e = make_memfd_completed(pid, p_start, 20000 + i, name,
                                              30000 + i, 1, 3, 3000000 + i * 1000);
        prov_engine_process_event(&e);
    }
    size_t in_nodes = 0, in_edges = 0;
    prov_engine_get_counts(&in_nodes, &in_edges);
    uint64_t in_comps = prov_engine_get_edge_comparisons();
    prov_engine_export_dot("/tmp/test_dup_incoming.dot");
    prov_engine_destroy();

    printf("  Duplicate tests: Outgoing edges=%zu, comps=%llu | Incoming edges=%zu, comps=%llu\n",
           out_edges, (unsigned long long)out_comps,
           in_edges, (unsigned long long)in_comps);

    assert(out_nodes == in_nodes);
    assert(out_edges == in_edges);
    assert(out_edges == (size_t)N); /* Duplicate edges suppressed in both */

    /* In incoming mode: 0 comparisons on first pass, exactly 1 comparison per memfd on duplicate pass = N */
    assert(in_comps == (uint64_t)N);

    /* Verify DOT graph identical */
    FILE *f1 = fopen("/tmp/test_dup_outgoing.dot", "r");
    FILE *f2 = fopen("/tmp/test_dup_incoming.dot", "r");
    assert(f1 && f2);
    int c1, c2;
    do {
        c1 = fgetc(f1);
        c2 = fgetc(f2);
        assert(c1 == c2);
    } while (c1 != EOF);
    fclose(f1);
    fclose(f2);
    unlink("/tmp/test_dup_outgoing.dot");
    unlink("/tmp/test_dup_incoming.dot");

    printf("  [PASS] Duplicate suppression verified: Identical edges, identical suppression, bit-for-bit DOT match.\n\n");
}

static void test_multi_process_identity(void) {
    printf("=== Test 3: Multiple Process Identities & Graph Equivalence ===\n");
    int P = 4;   /* 4 distinct processes */
    int M = 50;  /* 50 memfds each */

    /* Outgoing */
    prov_engine_init();
    prov_engine_set_search_mode(1);
    prov_engine_reset_edge_comparisons();

    for (int p = 0; p < P; p++) {
        uint32_t pid = 1001 + p;
        uint64_t p_start = 5000000 + p * 100000;
        for (int m = 0; m < M; m++) {
            char name[64];
            snprintf(name, sizeof(name), "multi_p%d_m%d", p, m);
            uint64_t token = (uint64_t)(p + 1) * 100000 + m;
            struct event e = make_memfd_completed(pid, p_start, token, name,
                                                  token + 500, 1, 3, 6000000 + m * 100);
            prov_engine_process_event(&e);
        }
    }
    size_t out_nodes = 0, out_edges = 0;
    prov_engine_get_counts(&out_nodes, &out_edges);
    prov_engine_export_dot("/tmp/test_multi_outgoing.dot");
    prov_engine_destroy();

    /* Incoming */
    prov_engine_init();
    prov_engine_set_search_mode(0);
    prov_engine_reset_edge_comparisons();

    for (int p = 0; p < P; p++) {
        uint32_t pid = 1001 + p;
        uint64_t p_start = 5000000 + p * 100000;
        for (int m = 0; m < M; m++) {
            char name[64];
            snprintf(name, sizeof(name), "multi_p%d_m%d", p, m);
            uint64_t token = (uint64_t)(p + 1) * 100000 + m;
            struct event e = make_memfd_completed(pid, p_start, token, name,
                                                  token + 500, 1, 3, 6000000 + m * 100);
            prov_engine_process_event(&e);
        }
    }
    size_t in_nodes = 0, in_edges = 0;
    prov_engine_get_counts(&in_nodes, &in_edges);
    prov_engine_export_dot("/tmp/test_multi_incoming.dot");
    prov_engine_destroy();

    printf("  Multi-process counts: Outgoing nodes=%zu, edges=%zu | Incoming nodes=%zu, edges=%zu\n",
           out_nodes, out_edges, in_nodes, in_edges);

    assert(out_nodes == in_nodes);
    assert(out_edges == in_edges);
    assert(out_edges == (size_t)(P * M));
    assert(out_nodes == (size_t)(P + P * M));

    /* Verify DOT graph identical */
    FILE *f1 = fopen("/tmp/test_multi_outgoing.dot", "r");
    FILE *f2 = fopen("/tmp/test_multi_incoming.dot", "r");
    assert(f1 && f2);
    int c1, c2;
    do {
        c1 = fgetc(f1);
        c2 = fgetc(f2);
        assert(c1 == c2);
    } while (c1 != EOF);
    fclose(f1);
    fclose(f2);
    unlink("/tmp/test_multi_outgoing.dot");
    unlink("/tmp/test_multi_incoming.dot");

    printf("  [PASS] Multi-process identity verified: Correct process attribution, bit-for-bit DOT equivalence.\n\n");
}

int main(void) {
    printf("=================================================================\n");
    printf("  Issue #7: Adjacency Lookup Experiment Unit & Equivalence Tests  \n");
    printf("=================================================================\n\n");

    test_complexity_scaling();
    test_duplicate_suppression();
    test_multi_process_identity();

    printf("=================================================================\n");
    printf("  ALL UNIT & EQUIVALENCE TESTS PASSED SUCCESSFULLY!             \n");
    printf("=================================================================\n");
    return 0;
}
