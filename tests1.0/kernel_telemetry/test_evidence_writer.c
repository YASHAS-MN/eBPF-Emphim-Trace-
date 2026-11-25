#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#include "evidence_io.h"

static void test_normal_write_and_replay(void) {
    const char *test_path = "/tmp/test_evidence_normal.evid";
    unlink(test_path);

    struct evidence_writer w;
    int rc = evidence_writer_init(&w, test_path, EVIDENCE_MODE_ONLINE, 12345, 4096, 0);
    assert(rc == 0);

    const int N = 100;
    for (int i = 0; i < N; i++) {
        struct event ev;
        memset(&ev, 0, sizeof(ev));
        ev.type = (i % 2 == 0) ? 2 : 12;
        ev.pid = 12345;
        ev.tid = 12345 + i;
        ev.object_token = 1000 + i;
        ev.ret_val = (i % 5 == 0) ? -1 : 3;
        ev.entry_ts_ns = 5000000000ULL + i * 1000;
        ev.timestamp_ns = 5000000000ULL + i * 1000 + 500;
        snprintf(ev.name, sizeof(ev.name), "test_memfd_%d", i);

        rc = evidence_writer_write(&w, &ev, ev.entry_ts_ns);
        assert(rc == 0);
    }

    assert(w.stats.records_received == (uint64_t)N);
    assert(w.stats.records_written == (uint64_t)N);

    rc = evidence_writer_close(&w);
    assert(rc == 0);
    assert(w.stats.records_synced == (uint64_t)N);
    assert(w.stats.storage_bytes > 0);

    /* Read back with evidence_reader */
    struct evidence_reader r;
    rc = evidence_reader_open(&r, test_path);
    assert(rc == 0);
    assert(r.header.magic == EPHIM_EVIDENCE_FILE_MAGIC);
    assert(r.header.version == EPHIM_EVIDENCE_VERSION);
    assert(r.header.mode == EVIDENCE_MODE_ONLINE);
    assert(r.header.target_pid == 12345);

    int count = 0;
    struct event ev_read;
    struct evidence_record_frame frame;
    while ((rc = evidence_reader_read_next(&r, &ev_read, &frame)) == 1) {
        assert(frame.seq_num == (uint64_t)count);
        assert(ev_read.type == (count % 2 == 0 ? 2U : 12U));
        assert(ev_read.pid == 12345);
        assert(ev_read.object_token == (uint64_t)(1000 + count));
        char expected_name[64];
        snprintf(expected_name, sizeof(expected_name), "test_memfd_%d", count);
        assert(strcmp(ev_read.name, expected_name) == 0);
        count++;
    }
    assert(rc == 0); /* clean EOF */
    assert(count == N);
    assert(r.stats.records_replayed == (uint64_t)N);
    assert(r.stats.corrupt_records == 0);
    assert(r.stats.seq_gaps == 0);
    assert(r.stats.incomplete_records == 0);

    evidence_reader_close(&r);
    unlink(test_path);
    printf("  [PASS] test_normal_write_and_replay (100 records)\n");
}

static void test_capacity_bound(void) {
    const char *test_path = "/tmp/test_evidence_bounded.evid";
    unlink(test_path);

    /* Limit max storage to header + 5 records */
    size_t record_sz = sizeof(struct evidence_record_frame) + sizeof(struct event);
    uint64_t max_bytes = sizeof(struct evidence_file_header) + 5 * record_sz;

    struct evidence_writer w;
    int rc = evidence_writer_init(&w, test_path, EVIDENCE_MODE_DEFERRED, 999, 1024, max_bytes);
    assert(rc == 0);

    for (int i = 0; i < 10; i++) {
        struct event ev;
        memset(&ev, 0, sizeof(ev));
        ev.pid = 999;
        ev.object_token = i + 1;
        rc = evidence_writer_write(&w, &ev, 1000 * (i + 1));
        if (i < 5) {
            assert(rc == 0);
        } else {
            /* Should reject cleanly due to bound */
            assert(rc == -1);
        }
    }

    assert(w.stats.records_received == 10);
    assert(w.stats.records_written == 5);
    assert(w.stats.write_errors == 5);

    evidence_writer_close(&w);

    /* Read back only the 5 written records */
    struct evidence_reader r;
    rc = evidence_reader_open(&r, test_path);
    assert(rc == 0);
    int read_count = 0;
    struct event ev;
    while ((rc = evidence_reader_read_next(&r, &ev, NULL)) == 1) {
        read_count++;
    }
    assert(rc == 0);
    assert(read_count == 5);
    evidence_reader_close(&r);

    unlink(test_path);
    printf("  [PASS] test_capacity_bound (clean rejection past bound)\n");
}

static void test_crc_and_corruption_detection(void) {
    const char *test_path = "/tmp/test_evidence_corrupt.evid";
    unlink(test_path);

    struct evidence_writer w;
    evidence_writer_init(&w, test_path, EVIDENCE_MODE_ONLINE, 555, 4096, 0);

    for (int i = 0; i < 5; i++) {
        struct event ev;
        memset(&ev, 0, sizeof(ev));
        ev.pid = 555;
        ev.object_token = 5000 + i;
        evidence_writer_write(&w, &ev, 1000);
    }
    evidence_writer_close(&w);

    /* Intentionally corrupt a byte inside record 2 payload */
    FILE *f = fopen(test_path, "r+b");
    assert(f != NULL);
    /* Seek into 2nd record payload */
    long offset = sizeof(struct evidence_file_header) +
                  sizeof(struct evidence_record_frame) + sizeof(struct event) +
                  sizeof(struct evidence_record_frame) + 50;
    fseek(f, offset, SEEK_SET);
    int b = fgetc(f);
    fseek(f, offset, SEEK_SET);
    fputc(b ^ 0xFF, f); /* Flip bits */
    fclose(f);

    struct evidence_reader r;
    int rc = evidence_reader_open(&r, test_path);
    assert(rc == 0);

    struct event ev;
    /* Record 0: valid */
    assert(evidence_reader_read_next(&r, &ev, NULL) == 1);
    /* Record 1 (corrupted): should return -1 and increment corrupt_records */
    assert(evidence_reader_read_next(&r, &ev, NULL) == -1);
    assert(r.stats.corrupt_records == 1);

    evidence_reader_close(&r);
    unlink(test_path);
    printf("  [PASS] test_crc_and_corruption_detection (detected flipped bit)\n");
}

static void test_incomplete_record_truncation(void) {
    const char *test_path = "/tmp/test_evidence_trunc.evid";
    unlink(test_path);

    struct evidence_writer w;
    evidence_writer_init(&w, test_path, EVIDENCE_MODE_ONLINE, 777, 4096, 0);
    for (int i = 0; i < 3; i++) {
        struct event ev;
        memset(&ev, 0, sizeof(ev));
        ev.pid = 777;
        evidence_writer_write(&w, &ev, 1000);
    }
    evidence_writer_close(&w);

    /* Truncate file mid-record (truncate 20 bytes off the end) */
    struct stat st;
    stat(test_path, &st);
    (void)!truncate(test_path, st.st_size - 20);

    struct evidence_reader r;
    assert(evidence_reader_open(&r, test_path) == 0);

    struct event ev;
    assert(evidence_reader_read_next(&r, &ev, NULL) == 1); /* rec 0 */
    assert(evidence_reader_read_next(&r, &ev, NULL) == 1); /* rec 1 */
    assert(evidence_reader_read_next(&r, &ev, NULL) == -2); /* rec 2 truncated */
    assert(r.stats.incomplete_records == 1);

    evidence_reader_close(&r);
    unlink(test_path);
    printf("  [PASS] test_incomplete_record_truncation (detected EOF truncation)\n");
}

int main(void) {
    printf("[TEST] Running evidence_io deterministic tests...\n");
    test_normal_write_and_replay();
    test_capacity_bound();
    test_crc_and_corruption_detection();
    test_incomplete_record_truncation();
    printf("[ALL PASS] evidence_io tests passed successfully.\n");
    return 0;
}
