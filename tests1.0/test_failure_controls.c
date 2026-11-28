/*
 * EphimTrace — End-to-End Benchmark 01
 * Bounded Failure Controls & Resilience Verification
 *
 * Evaluates:
 * 1. Orderly Finalization (SIGTERM / normal exit -> valid manifest, clean persistence)
 * 2. Abruptly Stopped Collector (SIGKILL -> unfinalized session, missing manifest, prefix recovery)
 * 3. Truncated Evidence (Partial record at EOF -> standard prefix recovery, strict abort code 4)
 * 4. Bit-Flipped Evidence (CRC32 corruption -> corrupt frame detection, strict abort code 4)
 * 5. Storage-Bound Exhaustion (max_bytes reached -> append refusal, file intact, manifest recorded)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>
#include "evidence_io.h"
#include "provenance.h"

#define TEST_DIR "/tmp/ephim_failure_controls"

static void setup_test_dir(void)
{
    mkdir(TEST_DIR, 0755);
}

static void cleanup_file(const char *path)
{
    unlink(path);
    char manifest[512];
    snprintf(manifest, sizeof(manifest), "%s.manifest", path);
    unlink(manifest);
}

/* Helper to execute ./build/replay in a subprocess and return exit code */
static int run_replay(const char *evid_path, bool strict, const char *dot_out, const char *json_out)
{
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        if (strict) {
            execl("./build/replay", "./build/replay", evid_path, "--strict",
                  "--dot", dot_out, "--json", json_out, NULL);
        } else {
            execl("./build/replay", "./build/replay", evid_path,
                  "--dot", dot_out, "--json", json_out, NULL);
        }
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    return -1;
}

/* Generate a valid base evidence file with N events */
static int generate_base_evidence(const char *path, uint64_t max_bytes, size_t num_events)
{
    cleanup_file(path);
    struct evidence_writer w;
    if (evidence_writer_init(&w, path, EVIDENCE_MODE_DEFERRED, 1000, 0, max_bytes) != 0)
        return -1;

    for (size_t i = 0; i < num_events; i++) {
        struct event e;
        memset(&e, 0, sizeof(e));
        e.type = EVENT_MEMFD_CREATE;
        e.pid = 1000 + i;
        e.start_time_ns = 50000 + i * 100;
        e.object_token = 200 + i;
        e.fd = 3;
        e.timestamp_ns = 60000 + i * 100;
        snprintf(e.name, sizeof(e.name), "test_mfd_%zu", i);
        if (evidence_writer_write(&w, &e, e.timestamp_ns) != 0)
            break;
    }

    evidence_writer_sync(&w);
    uint64_t storage = w.stats.storage_bytes;
    uint64_t rec_count = w.stats.records_written;
    evidence_writer_close(&w);

    struct evidence_session_manifest m;
    memset(&m, 0, sizeof(m));
    m.version = 1;
    m.target_pid = 1000;
    m.session_start_ns = 50000;
    m.session_end_ns = 60000 + num_events * 100;
    m.record_count = rec_count;
    m.storage_bytes = storage;
    m.finalized = true;
    m.synchronized = true;
    m.ring_buffer_total_drops = 0;
    for (int t = 0; t < EPHIM_MAX_EVENT_TYPE; t++) m.ring_buffer_per_type_drops[t] = 0;

    return evidence_write_manifest(path, &m);
}

/* -------------------------------------------------------------------------
 * Control 1: Orderly Finalization (Clean persistence, manifest verified)
 * ------------------------------------------------------------------------- */
static bool test_control_1_orderly_finalization(void)
{
    printf("  [CONTROL 1: Orderly Finalization]\n");
    const char *evid_path = TEST_DIR "/orderly.evid";
    const char *dot_path = TEST_DIR "/orderly.dot";
    const char *json_path = TEST_DIR "/orderly.json";

    cleanup_file(evid_path);
    unlink(dot_path);
    unlink(json_path);

    if (generate_base_evidence(evid_path, EVIDENCE_DEFAULT_MAX_BYTES, 20) != 0) {
        printf("    [FAIL] Failed to generate base evidence\n");
        return false;
    }

    /* Verify manifest exists and is non-empty */
    char mf_path[512];
    snprintf(mf_path, sizeof(mf_path), "%s.manifest", evid_path);
    struct stat st_mf;
    if (stat(mf_path, &st_mf) != 0 || st_mf.st_size == 0) {
        printf("    [FAIL] Manifest missing or zero-sized\n");
        return false;
    }

    /* Replay in standard mode */
    int rc_std = run_replay(evid_path, false, dot_path, json_path);
    if (rc_std != 0) {
        printf("    [FAIL] Standard replay failed with rc=%d\n", rc_std);
        return false;
    }

    /* Replay in strict mode (re-create fresh outputs exclusively) */
    unlink(dot_path);
    unlink(json_path);
    int rc_strict = run_replay(evid_path, true, dot_path, json_path);
    if (rc_strict != 0) {
        printf("    [FAIL] Strict replay failed with rc=%d\n", rc_strict);
        return false;
    }

    printf("    [PASS] Orderly session verified: manifest present, standard & strict replay succeeded (rc=0)\n");
    return true;
}

/* -------------------------------------------------------------------------
 * Control 2: Abruptly Stopped Collector (SIGKILL -> unfinalized session)
 * ------------------------------------------------------------------------- */
static bool test_control_2_abrupt_termination(void)
{
    printf("  [CONTROL 2: Abrupt Collector Termination]\n");
    const char *evid_path = TEST_DIR "/abrupt.evid";
    const char *dot_path = TEST_DIR "/abrupt.dot";
    const char *json_path = TEST_DIR "/abrupt.json";

    cleanup_file(evid_path);
    unlink(dot_path);
    unlink(json_path);

    /* Write events directly without calling evidence_write_manifest (simulates kill -9 before exit) */
    struct evidence_writer w;
    if (evidence_writer_init(&w, evid_path, EVIDENCE_MODE_DEFERRED, 1000, 0, EVIDENCE_DEFAULT_MAX_BYTES) != 0) {
        printf("    [FAIL] Init failed\n");
        return false;
    }

    for (size_t i = 0; i < 15; i++) {
        struct event e;
        memset(&e, 0, sizeof(e));
        e.type = EVENT_MEMFD_CREATE;
        e.pid = 2000 + i;
        e.start_time_ns = 100000 + i * 100;
        e.object_token = 500 + i;
        e.fd = 3;
        e.timestamp_ns = 110000 + i * 100;
        snprintf(e.name, sizeof(e.name), "abrupt_mfd_%zu", i);
        evidence_writer_write(&w, &e, e.timestamp_ns);
    }
    /* Flush buffer to disk without writing manifest */
    evidence_writer_flush(&w);
    uint64_t storage = w.stats.storage_bytes;
    close(w.fd);
    free(w.buffer);

    /* 2a. Abrupt kill with missing manifest:
     * Standard replay recovers flushed records; manifests are marked UNKNOWN */
    int rc_std = run_replay(evid_path, false, dot_path, json_path);
    if (rc_std != 0) {
        printf("    [FAIL] Standard replay failed on unfinalized evidence (rc=%d)\n", rc_std);
        return false;
    }

    struct stat st_dot;
    if (stat(dot_path, &st_dot) != 0 || st_dot.st_size == 0) {
        printf("    [FAIL] Standard replay failed to export recovered graph prefix\n");
        return false;
    }

    /* 2b. Abrupt kill with unfinalized manifest (finalized=false or size mismatch):
     * Strict replay must reject unfinalized session with exit code 7 */
    struct evidence_session_manifest m;
    memset(&m, 0, sizeof(m));
    m.version = 1;
    m.target_pid = 2000;
    m.session_start_ns = 100000;
    m.session_end_ns = 111500;
    m.record_count = 15;
    m.storage_bytes = storage;
    m.finalized = false; /* Unfinalized session */
    m.synchronized = false;
    if (evidence_write_manifest(evid_path, &m) != 0) {
        printf("    [FAIL] Failed to write unfinalized manifest\n");
        return false;
    }

    unlink(dot_path);
    int rc_strict = run_replay(evid_path, true, dot_path, json_path);
    if (rc_strict != 7) {
        printf("    [FAIL] Strict replay did not reject unfinalized session with code 7 (got rc=%d)\n", rc_strict);
        return false;
    }
    if (access(dot_path, F_OK) == 0) {
        printf("    [FAIL] Strict replay did not suppress exports on unfinalized session\n");
        return false;
    }

    printf("    [PASS] Abrupt termination verified: standard replay recovered intact prefix; strict replay rejected unfinalized session (rc=7)\n");
    return true;
}

/* -------------------------------------------------------------------------
 * Control 3: Truncated Evidence (Partial record boundary)
 * ------------------------------------------------------------------------- */
static bool test_control_3_truncated_evidence(void)
{
    printf("  [CONTROL 3: Truncated Evidence Record Boundary]\n");
    const char *evid_path = TEST_DIR "/truncated.evid";
    const char *dot_path = TEST_DIR "/truncated.dot";
    const char *json_path = TEST_DIR "/truncated.json";

    cleanup_file(evid_path);
    unlink(dot_path);
    unlink(json_path);

    if (generate_base_evidence(evid_path, EVIDENCE_DEFAULT_MAX_BYTES, 20) != 0) {
        printf("    [FAIL] Failed to generate base evidence\n");
        return false;
    }

    /* Truncate file by 200 bytes (splits the last 664-byte record frame) */
    struct stat st;
    stat(evid_path, &st);
    off_t trunc_size = st.st_size - 200;
    if (truncate(evid_path, trunc_size) != 0) {
        perror("truncate failed");
        return false;
    }

    /* Standard replay recovers all complete prior records, generates exports, but exits with code 4 */
    int rc_std = run_replay(evid_path, false, dot_path, json_path);
    if (rc_std != 4) {
        printf("    [FAIL] Standard replay did not signal truncated EOF with code 4 (got rc=%d)\n", rc_std);
        return false;
    }

    struct stat st_dot, st_json;
    if (stat(dot_path, &st_dot) != 0 || st_dot.st_size == 0 ||
        stat(json_path, &st_json) != 0 || st_json.st_size == 0) {
        printf("    [FAIL] Standard replay failed to export recovered prefix on truncated evidence\n");
        return false;
    }

    /* Strict replay must abort with code 4 (corruption/truncation) and suppress output */
    unlink(dot_path);
    unlink(json_path);
    int rc_strict = run_replay(evid_path, true, dot_path, json_path);
    if (rc_strict != 4) {
        printf("    [FAIL] Strict replay did not return exit code 4 on truncated evidence (rc=%d)\n", rc_strict);
        return false;
    }
    if (access(dot_path, F_OK) == 0 || access(json_path, F_OK) == 0) {
        printf("    [FAIL] Strict replay failed to suppress export output on corruption\n");
        return false;
    }

    printf("    [PASS] Truncated evidence verified: prefix recovered in standard mode (exports intact, rc=4); strict mode aborted (rc=4) and suppressed exports\n");
    return true;
}

/* -------------------------------------------------------------------------
 * Control 4: Bit-Flipped Evidence (CRC32 mismatch)
 * ------------------------------------------------------------------------- */
static bool test_control_4_bit_flipped_evidence(void)
{
    printf("  [CONTROL 4: Bit-Flipped Evidence Payload]\n");
    const char *evid_path = TEST_DIR "/bitflip.evid";
    const char *dot_path = TEST_DIR "/bitflip.dot";
    const char *json_path = TEST_DIR "/bitflip.json";

    cleanup_file(evid_path);
    unlink(dot_path);
    unlink(json_path);

    if (generate_base_evidence(evid_path, EVIDENCE_DEFAULT_MAX_BYTES, 20) != 0) {
        printf("    [FAIL] Failed to generate base evidence\n");
        return false;
    }

    /* Open file and flip a bit in the middle of event record 5 (offset ~ 64 + 5*664 + 50) */
    int fd = open(evid_path, O_RDWR);
    if (fd < 0) return false;
    off_t flip_offset = 64 + 5 * 664 + 50;
    uint8_t byte = 0;
    if (pread(fd, &byte, 1, flip_offset) != 1) {
        close(fd);
        return false;
    }
    byte ^= 0x01; /* Flip lowest bit */
    if (pwrite(fd, &byte, 1, flip_offset) != 1) {
        close(fd);
        return false;
    }
    close(fd);

    /* Strict replay must abort with code 4 and suppress export output */
    int rc_strict = run_replay(evid_path, true, dot_path, json_path);
    if (rc_strict != 4) {
        printf("    [FAIL] Strict replay did not detect bit-flip CRC32 corruption (rc=%d)\n", rc_strict);
        return false;
    }
    if (access(dot_path, F_OK) == 0) {
        printf("    [FAIL] Strict replay failed to suppress export output on CRC32 corruption\n");
        return false;
    }

    printf("    [PASS] Bit-flip verified: CRC32 mismatch detected; strict mode aborted (rc=4) and suppressed corrupt exports\n");
    return true;
}

/* -------------------------------------------------------------------------
 * Control 5: Storage-Bound Exhaustion (max_bytes ceiling)
 * ------------------------------------------------------------------------- */
static bool test_control_5_storage_bound_exhaustion(void)
{
    printf("  [CONTROL 5: Configured Storage-Bound Exhaustion]\n");
    const char *evid_path = TEST_DIR "/storage_bound.evid";
    const char *dot_path = TEST_DIR "/storage_bound.dot";
    const char *json_path = TEST_DIR "/storage_bound.json";

    cleanup_file(evid_path);
    unlink(dot_path);
    unlink(json_path);

    /* Set tight storage bound of 3000 bytes (header ~64 bytes, each frame ~664 bytes => fits ~4 events) */
    uint64_t tight_bound = 3000;
    struct evidence_writer w;
    if (evidence_writer_init(&w, evid_path, EVIDENCE_MODE_DEFERRED, 1000, 0, tight_bound) != 0) {
        printf("    [FAIL] Init failed\n");
        return false;
    }

    size_t attempted = 20;
    size_t accepted = 0;
    size_t rejected = 0;

    for (size_t i = 0; i < attempted; i++) {
        struct event e;
        memset(&e, 0, sizeof(e));
        e.type = EVENT_MEMFD_CREATE;
        e.pid = 3000 + i;
        e.start_time_ns = 200000 + i * 100;
        e.object_token = 800 + i;
        e.fd = 3;
        e.timestamp_ns = 210000 + i * 100;
        snprintf(e.name, sizeof(e.name), "bound_mfd_%zu", i);
        if (evidence_writer_write(&w, &e, e.timestamp_ns) == 0) {
            accepted++;
        } else {
            rejected++;
        }
    }

    evidence_writer_sync(&w);
    uint64_t actual_storage = w.stats.storage_bytes;
    uint64_t records_written = w.stats.records_written;
    evidence_writer_close(&w);

    if (actual_storage > tight_bound) {
        printf("    [FAIL] Storage exceeded configured limit (%llu > %llu)\n",
               (unsigned long long)actual_storage, (unsigned long long)tight_bound);
        return false;
    }
    if (rejected == 0) {
        printf("    [FAIL] Writer accepted all events without respecting storage bound\n");
        return false;
    }

    /* Write final manifest for the capped session */
    struct evidence_session_manifest m;
    memset(&m, 0, sizeof(m));
    m.version = 1;
    m.target_pid = 3000;
    m.session_start_ns = 200000;
    m.session_end_ns = 210000 + accepted * 100;
    m.record_count = records_written;
    m.storage_bytes = actual_storage;
    m.finalized = true;
    m.synchronized = true;
    m.ring_buffer_total_drops = 0;
    for (int t = 0; t < EPHIM_MAX_EVENT_TYPE; t++) m.ring_buffer_per_type_drops[t] = 0;

    if (evidence_write_manifest(evid_path, &m) != 0) {
        printf("    [FAIL] Failed to write manifest for capped session\n");
        return false;
    }

    /* Verify capped session replays cleanly */
    int rc_std = run_replay(evid_path, false, dot_path, json_path);
    if (rc_std != 0) {
        printf("    [FAIL] Replay of capped evidence failed with rc=%d\n", rc_std);
        return false;
    }

    printf("    [PASS] Storage bound verified: capped at %llu B (actual: %llu B, accepted: %zu, rejected: %zu); valid prefix replayable\n",
           (unsigned long long)tight_bound, (unsigned long long)actual_storage, accepted, rejected);
    return true;
}

int main(void)
{
    printf("=================================================================\n");
    printf("   EphimTrace Benchmark 01 — Bounded Failure Controls & Resilience\n");
    printf("=================================================================\n");
    setup_test_dir();

    bool all_passed = true;
    if (!test_control_1_orderly_finalization()) all_passed = false;
    if (!test_control_2_abrupt_termination()) all_passed = false;
    if (!test_control_3_truncated_evidence()) all_passed = false;
    if (!test_control_4_bit_flipped_evidence()) all_passed = false;
    if (!test_control_5_storage_bound_exhaustion()) all_passed = false;

    printf("=================================================================\n");
    if (all_passed) {
        printf("  [SUCCESS] All 5 bounded failure controls PASSED.\n");
        printf("=================================================================\n");
        return 0;
    } else {
        printf("  [FAILURE] One or more failure controls failed!\n");
        printf("=================================================================\n");
        return 1;
    }
}
