#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#include "provenance.h"
#include "evidence_io.h"

int main(void) {
    printf("[TEST] Running Model M replay provenance equivalence test...\n");

    const char *evid_path = "/tmp/test_model_m_replay.evid";
    const char *dot_online = "/tmp/test_model_m_online.dot";
    const char *dot_replayed = "/tmp/test_model_m_replayed.dot";
    unlink(evid_path);
    unlink(dot_online);
    unlink(dot_replayed);

    /* --- Step 1: Model M (Online) Execution --- */
    assert(prov_engine_init() == 0);

    struct evidence_writer writer;
    assert(evidence_writer_init(&writer, evid_path, EVIDENCE_MODE_ONLINE, 1234, 4096, 0) == 0);

    const int OPS = 50;
    for (int i = 0; i < OPS; i++) {
        uint64_t t_entry = 1000000000ULL + i * 20000;
        uint64_t t_comp = t_entry + 5000;
        uint64_t token = 90000 + i;

        /* Event 1: Creation Intent (type 2) */
        struct event e_create;
        memset(&e_create, 0, sizeof(e_create));
        e_create.type = 2; /* EVENT_MEMFD_CREATE */
        e_create.pid = 1234;
        e_create.tid = 1234;
        e_create.start_time_ns = 55555;
        e_create.timestamp_ns = t_entry;
        e_create.entry_ts_ns = t_entry;
        e_create.fd = -1;
        e_create.object_token = 0;
        snprintf(e_create.name, sizeof(e_create.name), "memfd_obj_%d", i);

        /* Model M: preserve original evidence */
        assert(evidence_writer_write(&writer, &e_create, t_entry) == 0);
        /* Model M: process online */
        prov_engine_process_event(&e_create);

        /* Event 2: Completion (type 12) */
        struct event e_comp;
        memset(&e_comp, 0, sizeof(e_comp));
        e_comp.type = 12; /* EVENT_MEMFD_COMPLETED */
        e_comp.pid = 1234;
        e_comp.tid = 1234;
        e_comp.start_time_ns = 55555;
        e_comp.timestamp_ns = t_comp;
        e_comp.entry_ts_ns = t_entry;
        e_comp.fd = 3 + (i % 10);
        e_comp.ret_val = e_comp.fd;
        e_comp.op_type = 2; /* MEMFD_STATUS_SUCCESS_CORRELATED */
        e_comp.object_token = token;
        e_comp.inode_no = 200000 + i;
        e_comp.dev_id = 1;
        snprintf(e_comp.name, sizeof(e_comp.name), "memfd_obj_%d", i);

        /* Model M: preserve original evidence */
        assert(evidence_writer_write(&writer, &e_comp, t_comp) == 0);
        /* Model M: process online */
        prov_engine_process_event(&e_comp);
    }

    assert(evidence_writer_close(&writer) == 0);

    size_t online_nodes = 0, online_edges = 0;
    prov_engine_get_counts(&online_nodes, &online_edges);
    assert(prov_engine_export_dot(dot_online) == 0);
    prov_engine_destroy();

    printf("  Model M Online constructed: %zu nodes, %zu edges\n", online_nodes, online_edges);
    assert(online_nodes > 0);
    assert(online_edges > 0);

    /* --- Step 2: Replay of M's Saved Evidence in Fresh Engine --- */
    assert(prov_engine_init() == 0);

    struct evidence_reader reader;
    assert(evidence_reader_open(&reader, evid_path) == 0);

    struct event ev;
    int replayed_count = 0;
    while (evidence_reader_read_next(&reader, &ev, NULL) == 1) {
        prov_engine_process_event(&ev);
        replayed_count++;
    }
    evidence_reader_close(&reader);

    assert(replayed_count == OPS * 2);

    size_t replay_nodes = 0, replay_edges = 0;
    prov_engine_get_counts(&replay_nodes, &replay_edges);
    assert(prov_engine_export_dot(dot_replayed) == 0);
    prov_engine_destroy();

    printf("  Replay constructed:        %zu nodes, %zu edges\n", replay_nodes, replay_edges);

    /* Validate equivalence */
    assert(online_nodes == replay_nodes);
    assert(online_edges == replay_edges);

    /* Compare exported graphs */
    FILE *f1 = fopen(dot_online, "r");
    FILE *f2 = fopen(dot_replayed, "r");
    assert(f1 && f2);

    char line1[512], line2[512];
    while (fgets(line1, sizeof(line1), f1)) {
        assert(fgets(line2, sizeof(line2), f2) != NULL);
        assert(strcmp(line1, line2) == 0);
    }
    assert(fgets(line2, sizeof(line2), f2) == NULL); /* Both EOF at same line */
    fclose(f1);
    fclose(f2);

    unlink(evid_path);
    unlink(dot_online);
    unlink(dot_replayed);

    printf("[PASS] Replay of Model M evidence bit-for-bit reproduces online provenance graph!\n");
    return 0;
}
