#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "provenance.h"
#include "evidence_io.h"
#include "provenance.c"

#define TEST_EVID_FILE "/tmp/test_integration.evid"
#define TEST_CORRUPT_EVID "/tmp/test_corrupt.evid"
#define TEST_TRUNC_EVID "/tmp/test_trunc.evid"
#define TEST_DOT_FILE "/tmp/test_dag.dot"
#define TEST_JSON_FILE "/tmp/test_dag.json"
#define TEST_TIMELINE_FILE "/tmp/test_timeline.md"

static void cleanup_files(void) {
    unlink(TEST_EVID_FILE);
    unlink(TEST_CORRUPT_EVID);
    unlink(TEST_TRUNC_EVID);
    unlink(TEST_DOT_FILE);
    unlink(TEST_JSON_FILE);
    unlink(TEST_TIMELINE_FILE);
}

/* 1. Test Capture / Writer */
static void test_writer_and_records(void) {
    printf("[1/4] Testing persistent evidence writer...\n");
    unlink(TEST_EVID_FILE);

    struct evidence_writer writer;
    int rc = evidence_writer_init(&writer, TEST_EVID_FILE, EVIDENCE_MODE_DEFERRED,
                                  1234, 65536, 10 * 1024 * 1024);
    assert(rc == 0);
    assert(writer.fd >= 0);

    // Write a sequence of 6 distinct events
    struct event e;

    // Event 1: Fork
    memset(&e, 0, sizeof(e));
    e.type = EVENT_FORK;
    e.pid = 1234;
    e.child_pid = 5678;
    e.timestamp_ns = 1000000;
    e.start_time_ns = 900000;
    e.child_start_time_ns = 1000000;
    strncpy(e.name, "parent_proc", sizeof(e.name) - 1);
    rc = evidence_writer_write(&writer, &e, e.timestamp_ns);
    assert(rc == 0);

    // Event 2: Execve
    memset(&e, 0, sizeof(e));
    e.type = EVENT_EXECVE;
    e.pid = 5678;
    e.timestamp_ns = 1100000;
    e.start_time_ns = 1000000;
    strncpy(e.name, "child_worker", sizeof(e.name) - 1);
    strncpy(e.path, "/usr/bin/child_worker", sizeof(e.path) - 1);
    rc = evidence_writer_write(&writer, &e, e.timestamp_ns);
    assert(rc == 0);

    // Event 3: Memfd created
    memset(&e, 0, sizeof(e));
    e.type = EVENT_MEMFD_CREATE;
    e.pid = 5678;
    e.timestamp_ns = 1200000;
    e.start_time_ns = 1000000;
    e.object_token = 0xAABBCCDDEEFF0011ULL;
    strncpy(e.name, "child_worker", sizeof(e.name) - 1);
    strncpy(e.path, "memfd:shm_payload", sizeof(e.path) - 1);
    rc = evidence_writer_write(&writer, &e, e.timestamp_ns);
    assert(rc == 0);

    // Event 4: Memfd completed
    memset(&e, 0, sizeof(e));
    e.type = EVENT_MEMFD_COMPLETED;
    e.pid = 5678;
    e.timestamp_ns = 1300000;
    e.start_time_ns = 1000000;
    e.object_token = 0xAABBCCDDEEFF0011ULL;
    e.fd = 3;
    e.ret_val = 3;
    strncpy(e.name, "child_worker", sizeof(e.name) - 1);
    strncpy(e.path, "memfd:shm_payload", sizeof(e.path) - 1);
    rc = evidence_writer_write(&writer, &e, e.timestamp_ns);
    assert(rc == 0);

    // Event 5: Memfd execution success
    memset(&e, 0, sizeof(e));
    e.type = EVENT_MEMFD_EXEC_SUCCESS;
    e.pid = 5678;
    e.timestamp_ns = 1400000;
    e.start_time_ns = 1000000;
    e.object_token = 0xAABBCCDDEEFF0011ULL;
    e.fd = 3;
    strncpy(e.name, "child_worker", sizeof(e.name) - 1);
    strncpy(e.path, "memfd:shm_payload", sizeof(e.path) - 1);
    rc = evidence_writer_write(&writer, &e, e.timestamp_ns);
    assert(rc == 0);

    // Event 6: File unlink
    memset(&e, 0, sizeof(e));
    e.type = EVENT_VFS_UNLINK_COMPLETED;
    e.pid = 5678;
    e.timestamp_ns = 1500000;
    e.start_time_ns = 1000000;
    e.ret_val = 0;
    strncpy(e.name, "child_worker", sizeof(e.name) - 1);
    strncpy(e.path, "/tmp/drop.tmp", sizeof(e.path) - 1);
    rc = evidence_writer_write(&writer, &e, e.timestamp_ns);
    assert(rc == 0);

    // Flush, sync, close
    rc = evidence_writer_sync(&writer);
    assert(rc == 0);
    assert(writer.stats.records_received == 6);
    assert(writer.stats.records_written == 6);
    assert(writer.stats.records_synced == 6);
    assert(writer.stats.storage_bytes > sizeof(struct evidence_file_header));

    evidence_writer_close(&writer);
    assert(writer.fd < 0);
    printf("  Writer test passed (6 records persisted, bytes=%llu)\n",
           (unsigned long long)writer.stats.storage_bytes);
}

/* 2. Test Offline Replay & Provenance Reconstruction */
static void test_reader_and_reconstruction(void) {
    printf("[2/4] Testing offline evidence reader and graph reconstruction...\n");
    struct evidence_reader reader;
    int rc = evidence_reader_open(&reader, TEST_EVID_FILE);
    assert(rc == 0);
    assert(reader.header.target_pid == 1234);
    assert(reader.header.mode == (uint32_t)EVIDENCE_MODE_DEFERRED);

    // Initialize provenance engine
    rc = prov_engine_init();
    assert(rc == 0);

    struct event ev;
    struct evidence_record_frame frame;
    uint64_t count = 0;

    while (1) {
        rc = evidence_reader_read_next(&reader, &ev, &frame);
        if (rc == 0) {
            break; // EOF
        }
        assert(rc == 1);
        assert(frame.seq_num == count);
        prov_engine_process_event(&ev);
        count++;
    }

    assert(count == 6);
    assert(reader.stats.records_verified == 6);
    assert(reader.stats.corrupt_records == 0);
    assert(reader.stats.seq_gaps == 0);
    evidence_reader_close(&reader);

    size_t node_count = 0, edge_count = 0;
    prov_engine_get_counts(&node_count, &edge_count);
    printf("  Reconstruction produced %zu nodes, %zu edges\n", node_count, edge_count);
    assert(node_count > 0);
    assert(edge_count > 0);

    // Export formats
    rc = prov_engine_export_dot(TEST_DOT_FILE);
    assert(rc == 0);
    rc = prov_engine_export_json(TEST_JSON_FILE);
    assert(rc == 0);
    rc = prov_engine_export_timeline(TEST_TIMELINE_FILE, 5678, 0);
    assert(rc == 0);

    // Check files exist and are non-empty
    struct stat st;
    assert(stat(TEST_DOT_FILE, &st) == 0 && st.st_size > 0);
    assert(stat(TEST_JSON_FILE, &st) == 0 && st.st_size > 0);
    assert(stat(TEST_TIMELINE_FILE, &st) == 0 && st.st_size > 0);

    prov_engine_destroy();
    printf("  Reconstruction and export test passed!\n");
}

/* 3. Test Failure Injection: Bit-flip CRC corruption */
static void test_corruption_handling(void) {
    printf("[3/4] Testing corruption detection (bit-flip)...\n");
    unlink(TEST_CORRUPT_EVID);

    // Copy valid file to corrupt file
    int in = open(TEST_EVID_FILE, O_RDONLY);
    assert(in >= 0);
    int out = open(TEST_CORRUPT_EVID, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    assert(out >= 0);

    char buf[4096];
    ssize_t n;
    while ((n = read(in, buf, sizeof(buf))) > 0) {
        assert(write(out, buf, n) == n);
    }
    close(in);

    // Corrupt one byte inside the first record payload (after header + frame header)
    off_t target_offset = sizeof(struct evidence_file_header) + sizeof(struct evidence_record_frame) + 10;
    lseek(out, target_offset, SEEK_SET);
    uint8_t bad_byte = 0xFF;
    assert(write(out, &bad_byte, 1) == 1);
    close(out);

    // Now attempt reading corrupt file
    struct evidence_reader reader;
    int rc = evidence_reader_open(&reader, TEST_CORRUPT_EVID);
    assert(rc == 0);

    struct event ev;
    struct evidence_record_frame frame;
    rc = evidence_reader_read_next(&reader, &ev, &frame);
    // Should detect CRC error: rc == -1
    assert(rc == -1);
    assert(reader.stats.corrupt_records == 1);
    evidence_reader_close(&reader);
    printf("  Bit-flip corruption was detected correctly (CRC error rc=-1, corrupt_records=1)\n");
}

/* 4. Test Truncated Record at EOF */
static void test_truncated_eof(void) {
    printf("[4/4] Testing incomplete / truncated session detection...\n");
    unlink(TEST_TRUNC_EVID);

    int in = open(TEST_EVID_FILE, O_RDONLY);
    assert(in >= 0);
    int out = open(TEST_TRUNC_EVID, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    assert(out >= 0);

    // Truncate inside record frame header of record 2
    size_t trunc_size = sizeof(struct evidence_file_header) +
                        sizeof(struct evidence_record_frame) + sizeof(struct event) + 8;
    char buf[4096];
    assert(read(in, buf, trunc_size) == (ssize_t)trunc_size);
    assert(write(out, buf, trunc_size) == (ssize_t)trunc_size);
    close(in);
    close(out);

    struct evidence_reader reader;
    int rc = evidence_reader_open(&reader, TEST_TRUNC_EVID);
    assert(rc == 0);

    struct event ev;
    struct evidence_record_frame frame;

    // Record 1 succeeds
    rc = evidence_reader_read_next(&reader, &ev, &frame);
    assert(rc == 1);
    assert(frame.seq_num == 0);

    // Record 2 is truncated -> should return error rc == -2 (incomplete record at EOF)
    rc = evidence_reader_read_next(&reader, &ev, &frame);
    assert(rc == -2);
    assert(reader.stats.incomplete_records == 1);
    evidence_reader_close(&reader);
    printf("  Truncated record detected correctly (rc=-2, incomplete_records=1)\n");
}

int main(void) {
    printf("=== Starting EphimTrace Collection-First Integration Tests ===\n");
    cleanup_files();

    test_writer_and_records();
    test_reader_and_reconstruction();
    test_corruption_handling();
    test_truncated_eof();

    cleanup_files();
    printf("=== All Integration Pipeline Tests Passed Successfully! ===\n");
    return 0;
}
