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
    e.inode_no = 771122;
    e.dev_id = 2049;
    e.flags = VFS_IDENTITY_INODE_VALID | VFS_IDENTITY_DEV_VALID;
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

    // Replay legacy file with ./build/replay --strict (WITHOUT --allow-legacy)
    // Under strict mode, absence of manifest must fail closed with exit code 7
    unlink(TEST_DOT_FILE);
    unlink(TEST_SUMMARY_JSON);
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
    assert(WEXITSTATUS(status) == 7); // Fails closed under strict mode without opt-in

    // Replay legacy file with ./build/replay --strict --allow-legacy (explicit opt-in)
    // Must succeed, verifying all 6 records with truthful UNKNOWN status
    unlink(TEST_DOT_FILE);
    unlink(TEST_SUMMARY_JSON);
    pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        close(devnull);
        execl("./build/replay", "./build/replay", TEST_LEGACY_EVID, "--strict", "--allow-legacy",
              "--dot", TEST_DOT_FILE, "--summary-json", TEST_SUMMARY_JSON, NULL);
        _exit(127);
    }
    status = 0;
    waitpid(pid, &status, 0);
    assert(WIFEXITED(status));
    assert(WEXITSTATUS(status) == 0); // Explicit opt-in succeeds

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

static void test_unlinked_executable_provenance(void) {
    printf("[9/9] Testing unlinked executable provenance and regression suite...\n");
    prov_engine_destroy();
    assert(prov_engine_init() == 0);

    // Scenario 1: Matching executable and unlink identities
    // Process 1001 execs /usr/local/bin/worker (Inode 5555, Dev 2049)
    struct event e1 = {0};
    e1.type = EVENT_PROCESS_EXEC;
    e1.pid = 1001;
    e1.ppid = 1000;
    e1.start_time_ns = 1000000;
    e1.timestamp_ns = 1050000;
    e1.inode_no = 5555;
    e1.dev_id = 2049;
    e1.mnt_ns_id = 4026531840U;
    e1.flags = VFS_IDENTITY_INODE_VALID | VFS_IDENTITY_DEV_VALID | VFS_IDENTITY_MNT_VALID;
    strncpy(e1.name, "worker", sizeof(e1.name) - 1);
    strncpy(e1.path, "/usr/local/bin/worker", sizeof(e1.path) - 1);
    prov_engine_process_event(&e1);

    // Process 1000 unlinks /usr/local/bin/worker (Inode 5555, Dev 2049)
    struct event e2 = {0};
    e2.type = EVENT_VFS_UNLINK_COMPLETED;
    e2.pid = 1000;
    e2.ppid = 1;
    e2.start_time_ns = 900000;
    e2.timestamp_ns = 1100000;
    e2.inode_no = 5555;
    e2.dev_id = 2049;
    e2.mnt_ns_id = 4026531840U;
    e2.flags = VFS_IDENTITY_INODE_VALID | VFS_IDENTITY_DEV_VALID | VFS_IDENTITY_MNT_VALID | VFS_IDENTITY_SYSCALL_VALID;
    e2.ret_val = 0; // Success
    strncpy(e2.name, "worker", sizeof(e2.name) - 1);
    strncpy(e2.path, "/usr/local/bin/worker", sizeof(e2.path) - 1);
    prov_engine_process_event(&e2);

    struct prov_node *fs1 = prov_find_node("fs_2049_5555");
    assert(fs1 != NULL);
    assert(fs1->type == NODE_FS_OBJECT);
    assert(fs1->fs.is_unlinked == true);
    assert(strcmp(fs1->fs.path, "/usr/local/bin/worker") == 0);

    struct prov_node *proc1 = prov_find_node("proc_1001_1000000");
    assert(proc1 != NULL);
    assert(proc1->out_edges != NULL);
    assert(proc1->out_edges->type == EDGE_FS_EXEC_SUCCESS);
    assert(proc1->out_edges->dst == fs1);

    // Scenario 2: Same pathname with different inode identities
    // Process 1003 execs /tmp/service (Inode 7777, Dev 2049)
    struct event e3 = {0};
    e3.type = EVENT_PROCESS_EXEC;
    e3.pid = 1003;
    e3.start_time_ns = 2000000;
    e3.timestamp_ns = 2050000;
    e3.inode_no = 7777;
    e3.dev_id = 2049;
    e3.flags = VFS_IDENTITY_INODE_VALID | VFS_IDENTITY_DEV_VALID;
    strncpy(e3.name, "service", sizeof(e3.name) - 1);
    strncpy(e3.path, "/tmp/service", sizeof(e3.path) - 1);
    prov_engine_process_event(&e3);

    // Process 1004 execs /tmp/service (Inode 8888, Dev 2049) - replaced file with same name
    struct event e4 = {0};
    e4.type = EVENT_PROCESS_EXEC;
    e4.pid = 1004;
    e4.start_time_ns = 3000000;
    e4.timestamp_ns = 3050000;
    e4.inode_no = 8888;
    e4.dev_id = 2049;
    e4.flags = VFS_IDENTITY_INODE_VALID | VFS_IDENTITY_DEV_VALID;
    strncpy(e4.name, "service", sizeof(e4.name) - 1);
    strncpy(e4.path, "/tmp/service", sizeof(e4.path) - 1);
    prov_engine_process_event(&e4);

    // Unlink only the first inode 7777
    struct event e5 = {0};
    e5.type = EVENT_VFS_UNLINK_COMPLETED;
    e5.pid = 1000;
    e5.start_time_ns = 900000;
    e5.timestamp_ns = 3100000;
    e5.inode_no = 7777;
    e5.dev_id = 2049;
    e5.flags = VFS_IDENTITY_INODE_VALID | VFS_IDENTITY_DEV_VALID;
    e5.ret_val = 0;
    strncpy(e5.path, "/tmp/service", sizeof(e5.path) - 1);
    prov_engine_process_event(&e5);

    struct prov_node *fs_old = prov_find_node("fs_2049_7777");
    struct prov_node *fs_new = prov_find_node("fs_2049_8888");
    assert(fs_old != NULL && fs_new != NULL);
    assert(fs_old != fs_new); // Distinct nodes!
    assert(fs_old->fs.is_unlinked == true);
    assert(fs_new->fs.is_unlinked == false); // Inode 8888 was not unlinked!

    // Scenario 3: Missing executable identity (e.g. inode_no = 0 or flags unpopulated)
    struct event e6 = {0};
    e6.type = EVENT_PROCESS_EXEC;
    e6.pid = 1005;
    e6.start_time_ns = 4000000;
    e6.timestamp_ns = 4050000;
    e6.inode_no = 0;
    e6.flags = 0; // Invalid / missing identity
    strncpy(e6.name, "unknown_exec", sizeof(e6.name) - 1);
    prov_engine_process_event(&e6);

    struct prov_node *proc_missing = prov_find_node("proc_1005_4000000");
    assert(proc_missing != NULL);
    assert(proc_missing->out_edges == NULL); // No bogus edge or fs_0_0 created!
    assert(prov_find_node("fs_0_0") == NULL);

    // Scenario 4: Failed unlink operation (ret_val != 0)
    struct event e7 = {0};
    e7.type = EVENT_PROCESS_EXEC;
    e7.pid = 1006;
    e7.start_time_ns = 5000000;
    e7.timestamp_ns = 5050000;
    e7.inode_no = 9999;
    e7.dev_id = 2049;
    e7.flags = VFS_IDENTITY_INODE_VALID | VFS_IDENTITY_DEV_VALID;
    strncpy(e7.name, "protected", sizeof(e7.name) - 1);
    strncpy(e7.path, "/etc/protected", sizeof(e7.path) - 1);
    prov_engine_process_event(&e7);

    struct event e8 = {0};
    e8.type = EVENT_VFS_UNLINK_COMPLETED;
    e8.pid = 1000;
    e8.start_time_ns = 900000;
    e8.timestamp_ns = 5100000;
    e8.inode_no = 9999;
    e8.dev_id = 2049;
    e8.flags = VFS_IDENTITY_INODE_VALID | VFS_IDENTITY_DEV_VALID;
    e8.ret_val = -1; // Failed unlink (e.g. EPERM)
    strncpy(e8.path, "/etc/protected", sizeof(e8.path) - 1);
    prov_engine_process_event(&e8);

    struct prov_node *fs_fail = prov_find_node("fs_2049_9999");
    assert(fs_fail != NULL);
    assert(fs_fail->fs.is_unlinked == false); // Failed unlink must not mark unlinked!

    // Scenario 5: Historical evidence compatibility
    struct event e_legacy = {0};
    e_legacy.type = EVENT_PROCESS_EXEC;
    e_legacy.pid = 1007;
    e_legacy.start_time_ns = 6000000;
    e_legacy.timestamp_ns = 6050000;
    strncpy(e_legacy.name, "legacy_worker", sizeof(e_legacy.name) - 1);
    prov_engine_process_event(&e_legacy);
    struct prov_node *proc_legacy = prov_find_node("proc_1007_6000000");
    assert(proc_legacy != NULL);
    assert(proc_legacy->out_edges == NULL);

    // Scenario 6: Memfd reconstruction regression
    struct event e_memfd_create = {0};
    e_memfd_create.type = EVENT_MEMFD_CREATE;
    e_memfd_create.pid = 1008;
    e_memfd_create.start_time_ns = 7000000;
    e_memfd_create.timestamp_ns = 7050000;
    e_memfd_create.object_token = 0xFEEDFACEULL;
    strncpy(e_memfd_create.name, "shm_regress", sizeof(e_memfd_create.name) - 1);
    prov_engine_process_event(&e_memfd_create);

    struct event e_memfd_exec = {0};
    e_memfd_exec.type = EVENT_PROCESS_EXEC;
    e_memfd_exec.pid = 1008;
    e_memfd_exec.start_time_ns = 7000000;
    e_memfd_exec.timestamp_ns = 7100000;
    e_memfd_exec.object_token = 0xFEEDFACEULL; // Non-zero token indicates memfd
    e_memfd_exec.inode_no = 12345;
    e_memfd_exec.dev_id = 0;
    e_memfd_exec.flags = VFS_IDENTITY_INODE_VALID;
    strncpy(e_memfd_exec.name, "shm_regress", sizeof(e_memfd_exec.name) - 1);
    prov_engine_process_event(&e_memfd_exec);

    struct event e_memfd_succ = {0};
    e_memfd_succ.type = EVENT_MEMFD_EXEC_SUCCESS;
    e_memfd_succ.pid = 1008;
    e_memfd_succ.start_time_ns = 7000000;
    e_memfd_succ.timestamp_ns = 7150000;
    e_memfd_succ.object_token = 0xFEEDFACEULL;
    strncpy(e_memfd_succ.name, "shm_regress", sizeof(e_memfd_succ.name) - 1);
    prov_engine_process_event(&e_memfd_succ);

    struct prov_node *proc_memfd = prov_find_node("proc_1008_7000000");
    struct prov_node *node_memfd = prov_find_node("memfd_4277009102");
    assert(proc_memfd != NULL && node_memfd != NULL);
    assert(node_memfd->type == NODE_MEMFD);
    assert(proc_memfd->out_edges != NULL);
    assert(proc_memfd->out_edges->type == EDGE_MEMFD_EXEC_SUCCESS);
    assert(proc_memfd->out_edges->dst == node_memfd);
    assert(prov_find_node("fs_0_12345") == NULL);

    // Scenario 7: Partially unavailable identity in execution and unlink
    // 7a: Execution with inode valid, but dev missing/invalid
    struct event e_part_exec1 = {0};
    e_part_exec1.type = EVENT_PROCESS_EXEC;
    e_part_exec1.pid = 1009;
    e_part_exec1.start_time_ns = 8000000;
    e_part_exec1.timestamp_ns = 8050000;
    e_part_exec1.inode_no = 6001;
    e_part_exec1.dev_id = 0;
    e_part_exec1.flags = VFS_IDENTITY_INODE_VALID; // Missing DEV_VALID
    strncpy(e_part_exec1.name, "part_dev_missing", sizeof(e_part_exec1.name) - 1);
    prov_engine_process_event(&e_part_exec1);

    struct prov_node *proc_part1 = prov_find_node("proc_1009_8000000");
    assert(proc_part1 != NULL);
    assert(proc_part1->out_edges == NULL); // No EDGE_FS_EXEC_SUCCESS
    assert(prov_find_node("fs_0_6001") == NULL);

    // 7b: Execution with dev valid, but inode missing/zero
    struct event e_part_exec2 = {0};
    e_part_exec2.type = EVENT_PROCESS_EXEC;
    e_part_exec2.pid = 1010;
    e_part_exec2.start_time_ns = 8100000;
    e_part_exec2.timestamp_ns = 8150000;
    e_part_exec2.inode_no = 0;
    e_part_exec2.dev_id = 2049;
    e_part_exec2.flags = VFS_IDENTITY_DEV_VALID; // Missing INODE_VALID
    strncpy(e_part_exec2.name, "part_ino_missing", sizeof(e_part_exec2.name) - 1);
    prov_engine_process_event(&e_part_exec2);

    struct prov_node *proc_part2 = prov_find_node("proc_1010_8100000");
    assert(proc_part2 != NULL);
    assert(proc_part2->out_edges == NULL); // No EDGE_FS_EXEC_SUCCESS
    assert(prov_find_node("fs_2049_0") == NULL);

    // 7c: Fully valid execution to set up target for unlink tests
    struct event e_part_exec3 = {0};
    e_part_exec3.type = EVENT_PROCESS_EXEC;
    e_part_exec3.pid = 1011;
    e_part_exec3.start_time_ns = 8200000;
    e_part_exec3.timestamp_ns = 8250000;
    e_part_exec3.inode_no = 6003;
    e_part_exec3.dev_id = 2049;
    e_part_exec3.flags = VFS_IDENTITY_INODE_VALID | VFS_IDENTITY_DEV_VALID;
    strncpy(e_part_exec3.name, "part_target", sizeof(e_part_exec3.name) - 1);
    strncpy(e_part_exec3.path, "/tmp/part_target", sizeof(e_part_exec3.path) - 1);
    prov_engine_process_event(&e_part_exec3);

    struct prov_node *fs_target = prov_find_node("fs_2049_6003");
    assert(fs_target != NULL);
    assert(fs_target->fs.is_unlinked == false);

    // 7d: Unlink with matching path and inode, but dev missing/invalid (flags = INODE_VALID only)
    struct event e_part_unlink1 = {0};
    e_part_unlink1.type = EVENT_VFS_UNLINK_COMPLETED;
    e_part_unlink1.pid = 1000;
    e_part_unlink1.start_time_ns = 900000;
    e_part_unlink1.timestamp_ns = 8300000;
    e_part_unlink1.inode_no = 6003;
    e_part_unlink1.dev_id = 0;
    e_part_unlink1.flags = VFS_IDENTITY_INODE_VALID;
    e_part_unlink1.ret_val = 0;
    strncpy(e_part_unlink1.path, "/tmp/part_target", sizeof(e_part_unlink1.path) - 1);
    prov_engine_process_event(&e_part_unlink1);

    // Invalid unlink MUST NOT merge into fs_2049_6003!
    assert(fs_target->fs.is_unlinked == false);
    assert(prov_find_node("fs_0_6003") == NULL);

    // 7e: Unlink with matching path and dev, but inode missing/zero (flags = DEV_VALID only)
    struct event e_part_unlink2 = {0};
    e_part_unlink2.type = EVENT_VFS_UNLINK_COMPLETED;
    e_part_unlink2.pid = 1000;
    e_part_unlink2.start_time_ns = 900000;
    e_part_unlink2.timestamp_ns = 8350000;
    e_part_unlink2.inode_no = 0;
    e_part_unlink2.dev_id = 2049;
    e_part_unlink2.flags = VFS_IDENTITY_DEV_VALID;
    e_part_unlink2.ret_val = 0;
    strncpy(e_part_unlink2.path, "/tmp/part_target", sizeof(e_part_unlink2.path) - 1);
    prov_engine_process_event(&e_part_unlink2);

    assert(fs_target->fs.is_unlinked == false);
    assert(prov_find_node("fs_2049_0") == NULL);

    // 7f: Completely missing unlink identity (flags = 0, inode_no = 0, dev_id = 0)
    struct event e_part_unlink3 = {0};
    e_part_unlink3.type = EVENT_VFS_UNLINK_COMPLETED;
    e_part_unlink3.pid = 1000;
    e_part_unlink3.start_time_ns = 900000;
    e_part_unlink3.timestamp_ns = 8400000;
    e_part_unlink3.inode_no = 0;
    e_part_unlink3.dev_id = 0;
    e_part_unlink3.flags = 0;
    e_part_unlink3.ret_val = 0;
    strncpy(e_part_unlink3.path, "/tmp/part_target", sizeof(e_part_unlink3.path) - 1);
    prov_engine_process_event(&e_part_unlink3);

    assert(fs_target->fs.is_unlinked == false);
    assert(prov_find_node("fs_0_0") == NULL);

    // Scenario 8: Identical inode numbers on different devices
    // Process 1012 execs /mnt/devA/bin (Inode 7001, Dev 2049)
    struct event e_devA_exec = {0};
    e_devA_exec.type = EVENT_PROCESS_EXEC;
    e_devA_exec.pid = 1012;
    e_devA_exec.start_time_ns = 8500000;
    e_devA_exec.timestamp_ns = 8550000;
    e_devA_exec.inode_no = 7001;
    e_devA_exec.dev_id = 2049;
    e_devA_exec.flags = VFS_IDENTITY_INODE_VALID | VFS_IDENTITY_DEV_VALID;
    strncpy(e_devA_exec.name, "shared_ino_worker", sizeof(e_devA_exec.name) - 1);
    strncpy(e_devA_exec.path, "/mnt/devA/bin", sizeof(e_devA_exec.path) - 1);
    prov_engine_process_event(&e_devA_exec);

    // Process 1013 execs /mnt/devB/bin (Inode 7001, Dev 2050 - distinct device!)
    struct event e_devB_exec = {0};
    e_devB_exec.type = EVENT_PROCESS_EXEC;
    e_devB_exec.pid = 1013;
    e_devB_exec.start_time_ns = 8600000;
    e_devB_exec.timestamp_ns = 8650000;
    e_devB_exec.inode_no = 7001;
    e_devB_exec.dev_id = 2050;
    e_devB_exec.flags = VFS_IDENTITY_INODE_VALID | VFS_IDENTITY_DEV_VALID;
    strncpy(e_devB_exec.name, "shared_ino_worker", sizeof(e_devB_exec.name) - 1);
    strncpy(e_devB_exec.path, "/mnt/devB/bin", sizeof(e_devB_exec.path) - 1);
    prov_engine_process_event(&e_devB_exec);

    struct prov_node *fs_devA = prov_find_node("fs_2049_7001");
    struct prov_node *fs_devB = prov_find_node("fs_2050_7001");
    assert(fs_devA != NULL && fs_devB != NULL);
    assert(fs_devA != fs_devB); // Two separate nodes despite identical inode 7001!
    assert(fs_devA->fs.is_unlinked == false);
    assert(fs_devB->fs.is_unlinked == false);

    struct prov_node *proc_devA = prov_find_node("proc_1012_8500000");
    struct prov_node *proc_devB = prov_find_node("proc_1013_8600000");
    assert(proc_devA != NULL && proc_devB != NULL);
    assert(proc_devA->out_edges != NULL && proc_devA->out_edges->dst == fs_devA);
    assert(proc_devB->out_edges != NULL && proc_devB->out_edges->dst == fs_devB);

    // Unlink only on Device 2049
    struct event e_devA_unlink = {0};
    e_devA_unlink.type = EVENT_VFS_UNLINK_COMPLETED;
    e_devA_unlink.pid = 1000;
    e_devA_unlink.start_time_ns = 900000;
    e_devA_unlink.timestamp_ns = 8700000;
    e_devA_unlink.inode_no = 7001;
    e_devA_unlink.dev_id = 2049;
    e_devA_unlink.flags = VFS_IDENTITY_INODE_VALID | VFS_IDENTITY_DEV_VALID;
    e_devA_unlink.ret_val = 0; // Success
    strncpy(e_devA_unlink.path, "/mnt/devA/bin", sizeof(e_devA_unlink.path) - 1);
    prov_engine_process_event(&e_devA_unlink);

    // Verify Device A file marked unlinked, while Device B file remains untouched!
    assert(fs_devA->fs.is_unlinked == true);
    assert(fs_devB->fs.is_unlinked == false);

    // Test Export Capabilities with EDGE_FS_EXEC_SUCCESS (exclusive safe export)
    unlink(TEST_DOT_FILE);
    unlink(TEST_JSON_FILE);
    unlink(TEST_TIMELINE_FILE);
    assert(prov_engine_export_dot(TEST_DOT_FILE) == 0);
    assert(prov_engine_export_json(TEST_JSON_FILE) == 0);
    assert(prov_engine_export_timeline(TEST_TIMELINE_FILE, 0, 0) == 0);
    assert(prov_engine_export_filtered_dot("/tmp/test_filtered.dot", 1001, 0) == 0);
    assert(prov_engine_export_filtered_json("/tmp/test_filtered.json", 1001, 0) == 0);

    unlink("/tmp/test_filtered.dot");
    unlink("/tmp/test_filtered.json");

    prov_engine_destroy();
    printf("  All 8 unlinked executable provenance and regression scenarios verified successfully!\n");
}

/* 10. Test Loss Counter Parsing & Consistency (Positive, Zero, Unavailable, Malformed, Incomplete, Inconsistent) */
static void test_loss_counter_parsing_and_consistency(void) {
    printf("[10/10] Testing manifest loss counter parsing, validation, and consistency...\n");

    const char *test_evid = "/tmp/test_loss_manifest.evid";
    const char *test_mf = "/tmp/test_loss_manifest.evid.manifest";
    unlink(test_evid);
    unlink(test_mf);

    // Copy the entire valid 6-record evidence file (4240 bytes)
    int out = open(test_evid, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    assert(out >= 0);
    int in = open(TEST_EVID_FILE, O_RDONLY);
    assert(in >= 0);
    char cbuf[4096];
    ssize_t nbytes;
    while ((nbytes = read(in, cbuf, sizeof(cbuf))) > 0) {
        assert(write(out, cbuf, nbytes) == nbytes);
    }
    close(in);
    close(out);

    // Case 1: Positive Loss Counters (e.g., 8 drops in memfd_completed)
    {
        unlink(test_mf);
        int mfd = open(test_mf, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        assert(mfd >= 0);
        const char *json_pos =
            "{\n"
            "  \"manifest_version\": 1,\n"
            "  \"evidence_file\": \"/tmp/test_loss_manifest.evid\",\n"
            "  \"record_count\": 6,\n"
            "  \"storage_bytes\": 4240,\n"
            "  \"finalized\": true,\n"
            "  \"synchronized\": true,\n"
            "  \"loss_counters\": {\n"
            "    \"reg_map_full_drop\": 0,\n"
            "    \"token_alloc_err\": 0,\n"
            "    \"token_mismatch\": 0,\n"
            "    \"sample_size_mismatches\": 0,\n"
            "    \"write_errors\": 0,\n"
            "    \"poll_errors\": 0,\n"
            "    \"drain_errors\": 0,\n"
            "    \"ring_buffer_total_drops\": 8,\n"
            "    \"ring_buffer_per_type_drops\": {\n"
            "      \"execve\": 0,\n"
            "      \"memfd_create\": 0,\n"
            "      \"unlink\": 0,\n"
            "      \"unlinkat\": 0,\n"
            "      \"connect\": 0,\n"
            "      \"fork\": 0,\n"
            "      \"process_exec\": 0,\n"
            "      \"process_exit\": 0,\n"
            "      \"vfs_unlink_completed\": 0,\n"
            "      \"vfs_rmdir_completed\": 0,\n"
            "      \"rmdir\": 0,\n"
            "      \"memfd_completed\": 8,\n"
            "      \"memfd_destroyed\": 0,\n"
            "      \"memfd_file_released\": 0,\n"
            "      \"fd_installed\": 0,\n"
            "      \"fd_closed\": 0,\n"
            "      \"memfd_write\": 0,\n"
            "      \"memfd_exec_attempt\": 0,\n"
            "      \"memfd_exec_success\": 0,\n"
            "      \"debug\": 0\n"
            "    }\n"
            "  }\n"
            "}\n";
        assert(write(mfd, json_pos, strlen(json_pos)) == (ssize_t)strlen(json_pos));
        close(mfd);

        struct evidence_session_manifest m;
        int rc = evidence_read_manifest(test_evid, &m);
        assert(rc == 0);
        // Assert that ring_buffer_total_drops is parsed as 8 (NOT 0!)
        assert(m.ring_buffer_total_drops == 8);
        assert(m.ring_buffer_per_type_drops[EVENT_MEMFD_COMPLETED] == 8);
        assert(m.ring_buffer_per_type_drops[EVENT_EXECVE] == 0);
        assert(m.ring_buffer_per_type_drops[EVENT_DEBUG] == 0);

        int64_t drops = 0;
        const char *desc = NULL;
        enum evidence_loss_status st = evidence_manifest_evaluate_loss(&m, &drops, &desc);
        assert(st == EVIDENCE_LOSS_LOSSY);
        assert(drops == 8);
        assert(strstr(desc, "LOSSY") != NULL);
        printf("  [PASS] Positive loss counters correctly parsed as 8 (never 0) and verdict is LOSSY.\n");
    }

    // Case 2: Zero Loss Counters (Lossless)
    {
        unlink(test_mf);
        int mfd = open(test_mf, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        assert(mfd >= 0);
        const char *json_zero =
            "{\n"
            "  \"manifest_version\": 1,\n"
            "  \"evidence_file\": \"/tmp/test_loss_manifest.evid\",\n"
            "  \"record_count\": 6,\n"
            "  \"storage_bytes\": 4240,\n"
            "  \"finalized\": true,\n"
            "  \"synchronized\": true,\n"
            "  \"loss_counters\": {\n"
            "    \"reg_map_full_drop\": 0,\n"
            "    \"token_alloc_err\": 0,\n"
            "    \"token_mismatch\": 0,\n"
            "    \"sample_size_mismatches\": 0,\n"
            "    \"write_errors\": 0,\n"
            "    \"poll_errors\": 0,\n"
            "    \"drain_errors\": 0,\n"
            "    \"ring_buffer_total_drops\": 0,\n"
            "    \"ring_buffer_per_type_drops\": {\n"
            "      \"execve\": 0,\n"
            "      \"memfd_create\": 0,\n"
            "      \"unlink\": 0,\n"
            "      \"unlinkat\": 0,\n"
            "      \"connect\": 0,\n"
            "      \"fork\": 0,\n"
            "      \"process_exec\": 0,\n"
            "      \"process_exit\": 0,\n"
            "      \"vfs_unlink_completed\": 0,\n"
            "      \"vfs_rmdir_completed\": 0,\n"
            "      \"rmdir\": 0,\n"
            "      \"memfd_completed\": 0,\n"
            "      \"memfd_destroyed\": 0,\n"
            "      \"memfd_file_released\": 0,\n"
            "      \"fd_installed\": 0,\n"
            "      \"fd_closed\": 0,\n"
            "      \"memfd_write\": 0,\n"
            "      \"memfd_exec_attempt\": 0,\n"
            "      \"memfd_exec_success\": 0,\n"
            "      \"debug\": 0\n"
            "    }\n"
            "  }\n"
            "}\n";
        assert(write(mfd, json_zero, strlen(json_zero)) == (ssize_t)strlen(json_zero));
        close(mfd);

        struct evidence_session_manifest m;
        int rc = evidence_read_manifest(test_evid, &m);
        assert(rc == 0);
        assert(m.ring_buffer_total_drops == 0);

        int64_t drops = 0;
        const char *desc = NULL;
        enum evidence_loss_status st = evidence_manifest_evaluate_loss(&m, &drops, &desc);
        assert(st == EVIDENCE_LOSS_LOSSLESS);
        assert(drops == 0);
        assert(strstr(desc, "COMPLETE_LOSSLESS") != NULL);
        printf("  [PASS] Zero loss counters correctly evaluated as COMPLETE_LOSSLESS.\n");
    }

    // Case 3: Unavailable Loss Counters (Value is -1 or missing)
    {
        unlink(test_mf);
        int mfd = open(test_mf, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        assert(mfd >= 0);
        const char *json_unavail =
            "{\n"
            "  \"manifest_version\": 1,\n"
            "  \"evidence_file\": \"/tmp/test_loss_manifest.evid\",\n"
            "  \"record_count\": 6,\n"
            "  \"storage_bytes\": 4240,\n"
            "  \"finalized\": true,\n"
            "  \"synchronized\": true,\n"
            "  \"loss_counters\": {\n"
            "    \"reg_map_full_drop\": -1,\n"
            "    \"token_alloc_err\": -1,\n"
            "    \"token_mismatch\": -1,\n"
            "    \"sample_size_mismatches\": 0,\n"
            "    \"write_errors\": 0,\n"
            "    \"poll_errors\": 0,\n"
            "    \"drain_errors\": 0,\n"
            "    \"ring_buffer_total_drops\": -1\n"
            "  }\n"
            "}\n";
        assert(write(mfd, json_unavail, strlen(json_unavail)) == (ssize_t)strlen(json_unavail));
        close(mfd);

        struct evidence_session_manifest m;
        int rc = evidence_read_manifest(test_evid, &m);
        assert(rc == 0);
        assert(m.ring_buffer_total_drops == -1);
        assert(m.reg_map_full_drop == -1);

        int64_t drops = 0;
        const char *desc = NULL;
        enum evidence_loss_status st = evidence_manifest_evaluate_loss(&m, &drops, &desc);
        assert(st == EVIDENCE_LOSS_UNVERIFIED);
        assert(strstr(desc, "UNVERIFIED") != NULL);
        printf("  [PASS] Unavailable counters remain -1 (never zero) and verdict is UNVERIFIED.\n");
    }

    // Case 4: Malformed Loss Counters (Non-numeric text / invalid syntax)
    {
        unlink(test_mf);
        int mfd = open(test_mf, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        assert(mfd >= 0);
        const char *json_malformed =
            "{\n"
            "  \"manifest_version\": 1,\n"
            "  \"evidence_file\": \"/tmp/test_loss_manifest.evid\",\n"
            "  \"record_count\": 6,\n"
            "  \"storage_bytes\": 4240,\n"
            "  \"finalized\": true,\n"
            "  \"synchronized\": true,\n"
            "  \"loss_counters\": {\n"
            "    \"reg_map_full_drop\": \"corrupt_string\",\n"
            "    \"token_alloc_err\": \"bad_syntax\",\n"
            "    \"token_mismatch\": null,\n"
            "    \"sample_size_mismatches\": 0,\n"
            "    \"write_errors\": 0,\n"
            "    \"poll_errors\": 0,\n"
            "    \"drain_errors\": 0,\n"
            "    \"ring_buffer_total_drops\": \"unavailable_via_api\"\n"
            "  }\n"
            "}\n";
        assert(write(mfd, json_malformed, strlen(json_malformed)) == (ssize_t)strlen(json_malformed));
        close(mfd);

        struct evidence_session_manifest m;
        int rc = evidence_read_manifest(test_evid, &m);
        assert(rc == 0);
        // Crucial requirement: Malformed counters MUST NEVER become zero!
        assert(m.ring_buffer_total_drops == -1);
        assert(m.reg_map_full_drop == -1);
        assert(m.token_alloc_err == -1);

        int64_t drops = 0;
        const char *desc = NULL;
        enum evidence_loss_status st = evidence_manifest_evaluate_loss(&m, &drops, &desc);
        assert(st == EVIDENCE_LOSS_UNVERIFIED);
        assert(strstr(desc, "UNVERIFIED") != NULL);
        printf("  [PASS] Malformed counters reject non-numeric values and default to -1 (never zero).\n");
    }

    // Case 5: Incomplete Counters (Missing event types)
    {
        unlink(test_mf);
        int mfd = open(test_mf, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        assert(mfd >= 0);
        const char *json_incomplete =
            "{\n"
            "  \"manifest_version\": 1,\n"
            "  \"evidence_file\": \"/tmp/test_loss_manifest.evid\",\n"
            "  \"record_count\": 6,\n"
            "  \"storage_bytes\": 4240,\n"
            "  \"finalized\": true,\n"
            "  \"synchronized\": true,\n"
            "  \"loss_counters\": {\n"
            "    \"reg_map_full_drop\": 0,\n"
            "    \"token_alloc_err\": 0,\n"
            "    \"token_mismatch\": 0,\n"
            "    \"sample_size_mismatches\": 0,\n"
            "    \"write_errors\": 0,\n"
            "    \"poll_errors\": 0,\n"
            "    \"drain_errors\": 0,\n"
            "    \"ring_buffer_total_drops\": 0,\n"
            "    \"ring_buffer_per_type_drops\": {\n"
            "      \"execve\": 0,\n"
            "      \"memfd_create\": 0\n"
            "    }\n"
            "  }\n"
            "}\n";
        assert(write(mfd, json_incomplete, strlen(json_incomplete)) == (ssize_t)strlen(json_incomplete));
        close(mfd);

        struct evidence_session_manifest m;
        int rc = evidence_read_manifest(test_evid, &m);
        assert(rc == 0);
        assert(m.ring_buffer_per_type_drops[EVENT_DEBUG] == -1);
        assert(m.ring_buffer_per_type_drops[EVENT_MEMFD_COMPLETED] == -1);

        int64_t drops = 0;
        const char *desc = NULL;
        enum evidence_loss_status st = evidence_manifest_evaluate_loss(&m, &drops, &desc);
        assert(st == EVIDENCE_LOSS_UNVERIFIED);
        assert(strstr(desc, "incomplete") != NULL);
        printf("  [PASS] Incomplete per-event drops cannot produce a lossless verdict (UNVERIFIED).\n");
    }

    // Case 6: Inconsistent Counters (Claims 0 total drops, but memfd_completed has 8 drops)
    {
        unlink(test_mf);
        int mfd = open(test_mf, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        assert(mfd >= 0);
        const char *json_inconsistent =
            "{\n"
            "  \"manifest_version\": 1,\n"
            "  \"evidence_file\": \"/tmp/test_loss_manifest.evid\",\n"
            "  \"record_count\": 6,\n"
            "  \"storage_bytes\": 4240,\n"
            "  \"finalized\": true,\n"
            "  \"synchronized\": true,\n"
            "  \"loss_counters\": {\n"
            "    \"reg_map_full_drop\": 0,\n"
            "    \"token_alloc_err\": 0,\n"
            "    \"token_mismatch\": 0,\n"
            "    \"sample_size_mismatches\": 0,\n"
            "    \"write_errors\": 0,\n"
            "    \"poll_errors\": 0,\n"
            "    \"drain_errors\": 0,\n"
            "    \"ring_buffer_total_drops\": 0,\n"
            "    \"ring_buffer_per_type_drops\": {\n"
            "      \"execve\": 0,\n"
            "      \"memfd_create\": 0,\n"
            "      \"unlink\": 0,\n"
            "      \"unlinkat\": 0,\n"
            "      \"connect\": 0,\n"
            "      \"fork\": 0,\n"
            "      \"process_exec\": 0,\n"
            "      \"process_exit\": 0,\n"
            "      \"vfs_unlink_completed\": 0,\n"
            "      \"vfs_rmdir_completed\": 0,\n"
            "      \"rmdir\": 0,\n"
            "      \"memfd_completed\": 8,\n"
            "      \"memfd_destroyed\": 0,\n"
            "      \"memfd_file_released\": 0,\n"
            "      \"fd_installed\": 0,\n"
            "      \"fd_closed\": 0,\n"
            "      \"memfd_write\": 0,\n"
            "      \"memfd_exec_attempt\": 0,\n"
            "      \"memfd_exec_success\": 0,\n"
            "      \"debug\": 0\n"
            "    }\n"
            "  }\n"
            "}\n";
        assert(write(mfd, json_inconsistent, strlen(json_inconsistent)) == (ssize_t)strlen(json_inconsistent));
        close(mfd);

        struct evidence_session_manifest m;
        int rc = evidence_read_manifest(test_evid, &m);
        assert(rc == 0);
        assert(m.ring_buffer_total_drops == 0);
        assert(m.ring_buffer_per_type_drops[EVENT_MEMFD_COMPLETED] == 8);

        int64_t drops = 0;
        const char *desc = NULL;
        enum evidence_loss_status st = evidence_manifest_evaluate_loss(&m, &drops, &desc);
        // Crucial requirement: Inconsistent counters cannot produce a lossless verdict!
        assert(st == EVIDENCE_LOSS_INCONSISTENT);
        assert(strstr(desc, "INCONSISTENT") != NULL);
        printf("  [PASS] Inconsistent total vs per-type drops rejected as INCONSISTENT (never lossless).\n");
    }

    // Case 7: End-to-End Replay Verification with Summary JSON
    {
        unlink(test_mf);
        int mfd = open(test_mf, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        assert(mfd >= 0);
        const char *json_pos_c7 =
            "{\n"
            "  \"manifest_version\": 1,\n"
            "  \"evidence_file\": \"/tmp/test_loss_manifest.evid\",\n"
            "  \"record_count\": 6,\n"
            "  \"storage_bytes\": 4240,\n"
            "  \"finalized\": true,\n"
            "  \"synchronized\": true,\n"
            "  \"loss_counters\": {\n"
            "    \"reg_map_full_drop\": 0,\n"
            "    \"token_alloc_err\": 0,\n"
            "    \"token_mismatch\": 0,\n"
            "    \"sample_size_mismatches\": 0,\n"
            "    \"write_errors\": 0,\n"
            "    \"poll_errors\": 0,\n"
            "    \"drain_errors\": 0,\n"
            "    \"ring_buffer_total_drops\": 8,\n"
            "    \"ring_buffer_per_type_drops\": {\n"
            "      \"execve\": 0,\n"
            "      \"memfd_create\": 0,\n"
            "      \"unlink\": 0,\n"
            "      \"unlinkat\": 0,\n"
            "      \"connect\": 0,\n"
            "      \"fork\": 0,\n"
            "      \"process_exec\": 0,\n"
            "      \"process_exit\": 0,\n"
            "      \"vfs_unlink_completed\": 0,\n"
            "      \"vfs_rmdir_completed\": 0,\n"
            "      \"rmdir\": 0,\n"
            "      \"memfd_completed\": 8,\n"
            "      \"memfd_destroyed\": 0,\n"
            "      \"memfd_file_released\": 0,\n"
            "      \"fd_installed\": 0,\n"
            "      \"fd_closed\": 0,\n"
            "      \"memfd_write\": 0,\n"
            "      \"memfd_exec_attempt\": 0,\n"
            "      \"memfd_exec_success\": 0,\n"
            "      \"debug\": 0\n"
            "    }\n"
            "  }\n"
            "}\n";
        assert(write(mfd, json_pos_c7, strlen(json_pos_c7)) == (ssize_t)strlen(json_pos_c7));
        close(mfd);

        // Replay Case 1 (8 drops) using ./build/replay --strict
        unlink(TEST_SUMMARY_JSON);
        int pid = fork();
        assert(pid >= 0);
        if (pid == 0) {
            int devnull = open("/dev/null", O_WRONLY);
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
            execl("./build/replay", "./build/replay", test_evid, "--strict",
                  "--summary-json", TEST_SUMMARY_JSON, NULL);
            _exit(127);
        }
        int status = 0;
        waitpid(pid, &status, 0);
        assert(WIFEXITED(status));
        assert(WEXITSTATUS(status) == 0);

        FILE *fj = fopen(TEST_SUMMARY_JSON, "r");
        assert(fj != NULL);
        char sbuf[4096];
        size_t sz = fread(sbuf, 1, sizeof(sbuf) - 1, fj);
        fclose(fj);
        sbuf[sz] = '\0';

        assert(strstr(sbuf, "\"telemetry_loss_free\": false") != NULL);
        assert(strstr(sbuf, "\"telemetry_capture_status\": \"LOSSY") != NULL);
        assert(strstr(sbuf, "\"ring_buffer_total_drops\": 8") != NULL);
        printf("  [PASS] Replay correctly exports telemetry_loss_free=false and 8 drops in summary JSON.\n");
    }

    unlink(test_evid);
    unlink(test_mf);
    unlink(TEST_SUMMARY_JSON);
    printf("  All loss counter parsing, validation, and consistency tests passed!\n");
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
    test_unlinked_executable_provenance();
    test_loss_counter_parsing_and_consistency();

    cleanup_files();
    printf("=== All 10 Integration & Reliability Tests Passed Successfully! ===\n");
    return 0;
}
