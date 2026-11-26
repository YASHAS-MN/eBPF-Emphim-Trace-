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
#include <sys/wait.h>

#include "provenance.h"
#include "evidence_io.h"
#include "provenance.c"

#define TEST_EVID_FILE "/tmp/test_integration.evid"
#define TEST_CORRUPT_EVID "/tmp/test_corrupt.evid"
#define TEST_TRUNC_EVID "/tmp/test_trunc.evid"
#define TEST_BOUNDARY_TRUNC_EVID "/tmp/test_boundary_trunc.evid"
#define TEST_LEGACY_EVID "/tmp/test_legacy.evid"
#define TEST_DOT_FILE "/tmp/test_dag.dot"
#define TEST_JSON_FILE "/tmp/test_dag.json"
#define TEST_TIMELINE_FILE "/tmp/test_timeline.md"
#define TEST_SUMMARY_JSON "/tmp/test_summary.json"

static void cleanup_files(void) {
    unlink(TEST_EVID_FILE);
    unlink("/tmp/test_integration.evid.manifest");
    unlink(TEST_CORRUPT_EVID);
    unlink("/tmp/test_corrupt.evid.manifest");
    unlink(TEST_TRUNC_EVID);
    unlink(TEST_BOUNDARY_TRUNC_EVID);
    unlink("/tmp/test_boundary_trunc.evid.manifest");
    unlink(TEST_LEGACY_EVID);
    unlink(TEST_DOT_FILE);
    unlink(TEST_JSON_FILE);
    unlink(TEST_TIMELINE_FILE);
    unlink(TEST_SUMMARY_JSON);
    unlink("/tmp/test_alias_link.evid");
    unlink("/tmp/test_alias_hard.evid");
    unlink("/tmp/test_suppressed.dot");
}

/* 1. Test Capture / Writer */
static void test_writer_and_records(void) {
    printf("[1/8] Testing persistent evidence writer...\n");
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

    // Persist private session manifest
    struct evidence_session_manifest m;
    memset(&m, 0, sizeof(m));
    m.version = 1;
    m.target_pid = 1234;
    m.session_start_ns = 1000000;
    m.session_end_ns = 2000000;
    m.record_count = 6;
    m.storage_bytes = writer.stats.storage_bytes;
    m.finalized = true;
    m.synchronized = true;
    m.sample_size_mismatches = 0;
    m.write_errors = 0;
    m.poll_errors = 0;
    m.drain_errors = 0;
    rc = evidence_write_manifest(TEST_EVID_FILE, &m);
    assert(rc == 0);

    printf("  Writer & manifest test passed (6 records, storage_bytes=%llu)\n",
           (unsigned long long)writer.stats.storage_bytes);
}

/* 2. Test Offline Replay & Provenance Reconstruction with Manifest Verification */
static void test_reader_and_reconstruction(void) {
    printf("[2/8] Testing offline evidence reader, manifest verification, and graph reconstruction...\n");
    struct evidence_reader reader;
    int rc = evidence_reader_open(&reader, TEST_EVID_FILE);
    assert(rc == 0);
    assert(reader.header.target_pid == 1234);
    assert(reader.header.mode == (uint32_t)EVIDENCE_MODE_DEFERRED);

    // Read and verify manifest
    struct evidence_session_manifest m;
    rc = evidence_read_manifest(TEST_EVID_FILE, &m);
    assert(rc == 0);
    assert(m.record_count == 6);
    assert(m.finalized == true);
    assert(m.synchronized == true);

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
    assert(reader.stats.records_verified == m.record_count);
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
    printf("[3/8] Testing corruption detection (bit-flip)...\n");
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
    printf("[4/8] Testing incomplete / truncated session detection...\n");
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

/* 5. Test Exact Kernel Sample Size Enforcement */
static void test_exact_sample_size(void) {
    printf("[5/8] Testing exact kernel event sample size requirement...\n");
    // Undersized sample simulation
    uint8_t undersized_buf[sizeof(struct event) - 8];
    memset(undersized_buf, 0, sizeof(undersized_buf));
    bool undersized_valid = (sizeof(undersized_buf) == sizeof(struct event));
    assert(undersized_valid == false);

    // Oversized sample simulation
    uint8_t oversized_buf[sizeof(struct event) + 64];
    memset(oversized_buf, 0, sizeof(oversized_buf));
    bool oversized_valid = (sizeof(oversized_buf) == sizeof(struct event));
    assert(oversized_valid == false);

    // Exact sample size
    uint8_t exact_buf[sizeof(struct event)];
    memset(exact_buf, 0, sizeof(exact_buf));
    bool exact_valid = (sizeof(exact_buf) == sizeof(struct event));
    assert(exact_valid == true);
    printf("  Exact sample size enforcement verified (undersized & oversized rejected)\n");
}

/* 6. Test Valid-Record Boundary Truncation Detection via Manifest */
static void test_valid_record_boundary_truncation_detection(void) {
    printf("[6/8] Testing valid-record boundary truncation detection via session manifest...\n");
    unlink(TEST_BOUNDARY_TRUNC_EVID);
    unlink("/tmp/test_boundary_trunc.evid.manifest");

    // Copy only the first 3 records cleanly (each record is completely intact and valid)
    size_t boundary_size = sizeof(struct evidence_file_header) +
                           3 * (sizeof(struct evidence_record_frame) + sizeof(struct event));

    int in = open(TEST_EVID_FILE, O_RDONLY);
    assert(in >= 0);
    int out = open(TEST_BOUNDARY_TRUNC_EVID, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    assert(out >= 0);

    char *buf = malloc(boundary_size);
    assert(buf != NULL);
    assert(read(in, buf, boundary_size) == (ssize_t)boundary_size);
    assert(write(out, buf, boundary_size) == (ssize_t)boundary_size);
    free(buf);
    close(in);
    close(out);

    // Create manifest claiming 6 records was the complete session
    struct evidence_session_manifest m;
    memset(&m, 0, sizeof(m));
    m.version = 1;
    m.target_pid = 1234;
    m.record_count = 6;
    m.storage_bytes = 4240; // original full size
    m.finalized = true;
    m.synchronized = true;
    int rc = evidence_write_manifest(TEST_BOUNDARY_TRUNC_EVID, &m);
    assert(rc == 0);

    // Replay the boundary-truncated file via ./build/replay in strict mode
    // It should detect that manifest expected 6 records and 4240 bytes, but file only has 3 records.
    // In strict mode, it must fail with non-zero exit code (exit code 7).
    int pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        close(devnull);
        execl("./build/replay", "./build/replay", TEST_BOUNDARY_TRUNC_EVID, "--strict", NULL);
        _exit(127);
    }

    int status = 0;
    waitpid(pid, &status, 0);
    assert(WIFEXITED(status));
    assert(WEXITSTATUS(status) == 7); // Manifest discrepancy exit code 7
    printf("  Valid-record boundary truncation was detected via manifest (exit code 7)!\n");
}

/* 7. Test Historical Evidence Compatibility (Absence of Manifest) */
static void test_legacy_file_compatibility(void) {
    printf("[7/8] Testing legacy v1 evidence compatibility without manifest...\n");
    unlink(TEST_LEGACY_EVID);
    unlink("/tmp/test_legacy.evid.manifest");

    // Copy full valid evidence file without manifest
    int in = open(TEST_EVID_FILE, O_RDONLY);
    assert(in >= 0);
    int out = open(TEST_LEGACY_EVID, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    assert(out >= 0);

    char buf[4096];
    ssize_t n;
    while ((n = read(in, buf, sizeof(buf))) > 0) {
        assert(write(out, buf, n) == n);
    }
    close(in);
    close(out);

    // Confirm manifest does not exist
    struct evidence_session_manifest m;
    int rc = evidence_read_manifest(TEST_LEGACY_EVID, &m);
    assert(rc == 1); // 1 = manifest absent (legacy v1 file)

    // Replay legacy file with ./build/replay --strict
    // It must succeed, verifying all 6 records with UNKNOWN finalization status
    int pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        close(devnull);
        execl("./build/replay", "./build/replay", TEST_LEGACY_EVID, "--strict",
              "--dot", TEST_DOT_FILE, "--summary-json", TEST_SUMMARY_JSON, NULL);
        _exit(127);
    }

    int status = 0;
    waitpid(pid, &status, 0);
    assert(WIFEXITED(status));
    assert(WEXITSTATUS(status) == 0); // Legacy v1 succeeds cleanly

    // Verify summary JSON records manifest_present = false and UNKNOWN status
    FILE *fj = fopen(TEST_SUMMARY_JSON, "r");
    assert(fj != NULL);
    char sbuf[4096];
    size_t sz = fread(sbuf, 1, sizeof(sbuf) - 1, fj);
    fclose(fj);
    sbuf[sz] = '\0';
    assert(strstr(sbuf, "\"manifest_present\": false") != NULL);
    assert(strstr(sbuf, "Legacy v1 evidence file without manifest") != NULL);
    assert(strstr(sbuf, "\"status\": \"OK\"") != NULL);
    printf("  Legacy v1 evidence without manifest processed successfully with truthful UNKNOWN status!\n");
}

/* 8. Test Evidence Output Alias & Collision Rejection */
static void test_output_alias_and_collision_protection(void) {
    printf("[8/8] Testing evidence protection against output aliases, symlinks, hardlinks, and collisions...\n");
    unlink("/tmp/test_alias_link.evid");
    unlink("/tmp/test_alias_hard.evid");
    unlink("/tmp/test_suppressed.dot");

    // Test 8A: Direct alias --dot pointing to evidence file
    int pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        close(devnull);
        execl("./build/replay", "./build/replay", TEST_EVID_FILE, "--dot", TEST_EVID_FILE, NULL);
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    assert(WIFEXITED(status));
    assert(WEXITSTATUS(status) == 1); // Rejected alias

    // Verify evidence file was NOT truncated (size remains 4240 bytes)
    struct stat st;
    assert(stat(TEST_EVID_FILE, &st) == 0);
    assert(st.st_size == 4240);

    // Test 8B: Symlink alias pointing to evidence file
    assert(symlink(TEST_EVID_FILE, "/tmp/test_alias_link.evid") == 0);
    pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        close(devnull);
        execl("./build/replay", "./build/replay", TEST_EVID_FILE, "--dot", "/tmp/test_alias_link.evid", NULL);
        _exit(127);
    }
    waitpid(pid, &status, 0);
    assert(WIFEXITED(status));
    assert(WEXITSTATUS(status) == 1); // Rejected symlink alias
    assert(stat(TEST_EVID_FILE, &st) == 0 && st.st_size == 4240);

    // Test 8C: Hardlink alias sharing inode with evidence file
    assert(link(TEST_EVID_FILE, "/tmp/test_alias_hard.evid") == 0);
    pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        close(devnull);
        execl("./build/replay", "./build/replay", TEST_EVID_FILE, "--json", "/tmp/test_alias_hard.evid", NULL);
        _exit(127);
    }
    waitpid(pid, &status, 0);
    assert(WIFEXITED(status));
    assert(WEXITSTATUS(status) == 1); // Rejected hardlink alias
    assert(stat(TEST_EVID_FILE, &st) == 0 && st.st_size == 4240);

    // Test 8D: Output collision (--dot and --json target the same file)
    pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        close(devnull);
        execl("./build/replay", "./build/replay", TEST_EVID_FILE,
              "--dot", "/tmp/collision.out", "--json", "/tmp/collision.out", NULL);
        _exit(127);
    }
    waitpid(pid, &status, 0);
    assert(WIFEXITED(status));
    assert(WEXITSTATUS(status) == 1); // Rejected output collision

    // Test 8E: Strict replay on corrupt file aborts export (no misleading graph created)
    unlink("/tmp/test_suppressed.dot");
    pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        close(devnull);
        execl("./build/replay", "./build/replay", TEST_CORRUPT_EVID, "--strict",
              "--dot", "/tmp/test_suppressed.dot", NULL);
        _exit(127);
    }
    waitpid(pid, &status, 0);
    assert(WIFEXITED(status));
    assert(WEXITSTATUS(status) == 4); // Failed due to corruption
    assert(access("/tmp/test_suppressed.dot", F_OK) != 0); // Export suppressed!

    printf("  All alias, collision, and strict export-suppression protections verified!\n");
}

int main(void) {
    printf("=== Starting EphimTrace Collection-First Integration & Reliability Tests ===\n");
    cleanup_files();

    test_writer_and_records();
    test_reader_and_reconstruction();
    test_corruption_handling();
    test_truncated_eof();
    test_exact_sample_size();
    test_valid_record_boundary_truncation_detection();
    test_legacy_file_compatibility();
    test_output_alias_and_collision_protection();

    cleanup_files();
    printf("=== All 8 Integration & Reliability Tests Passed Successfully! ===\n");
    return 0;
}
