#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <assert.h>

#include "provenance.h"
#include "evidence_io.h"

#define TEST_DIR "/tmp/ephimtrace_qual02_tests"

static void compute_sha256(const char *path, char *out_hex)
{
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "sha256sum \"%s\" 2>/dev/null | awk '{print $1}'", path);
    FILE *p = popen(cmd, "r");
    if (!p || !fgets(out_hex, 65, p)) {
        snprintf(out_hex, 65, "ERROR");
    }
    if (p) pclose(p);
    out_hex[64] = '\0';
}

static void setup_dir(void)
{
    int rc = system("rm -rf " TEST_DIR " && mkdir -p " TEST_DIR);
    (void)rc;
}

static int run_replay_cmd(const char *evid_path, const char *extra_args, char *out_buf, size_t out_len)
{
    char cmd[2048];
    if (extra_args && extra_args[0]) {
        snprintf(cmd, sizeof(cmd), "./build/replay \"%s\" %s 2>&1", evid_path, extra_args);
    } else {
        snprintf(cmd, sizeof(cmd), "./build/replay \"%s\" 2>&1", evid_path);
    }

    FILE *p = popen(cmd, "r");
    if (!p) return -1;

    size_t total = 0;
    if (out_buf && out_len > 0) {
        size_t n;
        while ((n = fread(out_buf + total, 1, out_len - 1 - total, p)) > 0) {
            total += n;
        }
        out_buf[total] = '\0';
    } else {
        char dump[512];
        while (fread(dump, 1, sizeof(dump), p) > 0);
    }

    int st = pclose(p);
    if (WIFEXITED(st))
        return WEXITSTATUS(st);
    return -1;
}

static int generate_clean_evidence(const char *evid_path, size_t num_events, struct evidence_session_manifest *out_m)
{
    unlink(evid_path);
    char m_path[512];
    snprintf(m_path, sizeof(m_path), "%s.manifest", evid_path);
    unlink(m_path);

    struct evidence_writer w;
    if (evidence_writer_init(&w, evid_path, EVIDENCE_MODE_DEFERRED, 1234, 0, EVIDENCE_DEFAULT_MAX_BYTES) != 0)
        return -1;

    for (size_t i = 0; i < num_events; i++) {
        struct event e;
        memset(&e, 0, sizeof(e));
        e.type = EVENT_MEMFD_CREATE;
        e.pid = 1234;
        e.start_time_ns = 1000000 + i * 1000;
        e.object_token = 100 + i;
        e.fd = 3 + (int)i;
        e.timestamp_ns = 1001000 + i * 1000;
        snprintf(e.name, sizeof(e.name), "qual02_mfd_%zu", i);
        evidence_writer_write(&w, &e, e.timestamp_ns);
    }

    evidence_writer_close(&w);

    if (out_m) {
        memset(out_m, 0, sizeof(*out_m));
        out_m->version = 1;
        out_m->target_pid = 1234;
        out_m->session_start_ns = 1000000;
        out_m->session_end_ns = 1001000 + num_events * 1000;
        out_m->record_count = num_events;
        out_m->storage_bytes = w.stats.storage_bytes;
        out_m->finalized = true;
        out_m->synchronized = true;
        out_m->reg_map_full_drop = 0;
        out_m->token_alloc_err = 0;
        out_m->token_mismatch = 0;
        out_m->ring_buffer_total_drops = 0;
        for (int i = 0; i < EPHIM_MAX_EVENT_TYPE; i++) {
            out_m->ring_buffer_per_type_drops[i] = 0;
        }
        evidence_write_manifest(evid_path, out_m);
    }

    return 0;
}

int main(void)
{
    printf("=================================================================\n");
    printf("=== Release Qualification Task 02: Evidence & Manifest Tests  ===\n");
    printf("=================================================================\n\n");
    setup_dir();

    bool all_passed = true;
    char out[4096];
    char args[1024];

    /* --- SUITE 1: Evidence & Session Manifest Overwrite Protection --- */
    printf("[SUITE 1: Evidence and Session Manifest Overwrite Protection]\n");
    const char *evid1 = TEST_DIR "/case1_overwrite.evid";
    char evid1_m[512];
    snprintf(evid1_m, sizeof(evid1_m), "%s.manifest", evid1);

    struct evidence_session_manifest m1;
    generate_clean_evidence(evid1, 10, &m1);

    char hash_evid_orig[65], hash_m_orig[65];
    compute_sha256(evid1, hash_evid_orig);
    compute_sha256(evid1_m, hash_m_orig);

    /* 1.1 --dot targeting manifest directly */
    snprintf(args, sizeof(args), "--dot \"%s\"", evid1_m);
    int rc1_dot = run_replay_cmd(evid1, args, out, sizeof(out));
    char cur_m_hash[65];
    compute_sha256(evid1_m, cur_m_hash);
    if (rc1_dot == 1 && strcmp(hash_m_orig, cur_m_hash) == 0) {
        printf("  [PASS] 1.1: Direct --dot manifest overwrite rejected (rc=1), hash unchanged.\n");
    } else {
        printf("  [FAIL] 1.1: rc=%d, hash match=%d\n", rc1_dot, strcmp(hash_m_orig, cur_m_hash) == 0);
        all_passed = false;
    }

    /* 1.2 --json targeting manifest directly */
    snprintf(args, sizeof(args), "--json \"%s\"", evid1_m);
    int rc1_json = run_replay_cmd(evid1, args, out, sizeof(out));
    compute_sha256(evid1_m, cur_m_hash);
    if (rc1_json == 1 && strcmp(hash_m_orig, cur_m_hash) == 0) {
        printf("  [PASS] 1.2: Direct --json manifest overwrite rejected (rc=1), hash unchanged.\n");
    } else {
        printf("  [FAIL] 1.2: rc=%d\n", rc1_json);
        all_passed = false;
    }

    /* 1.3 --summary-json targeting manifest directly */
    snprintf(args, sizeof(args), "--summary-json \"%s\"", evid1_m);
    int rc1_sum = run_replay_cmd(evid1, args, out, sizeof(out));
    compute_sha256(evid1_m, cur_m_hash);
    if (rc1_sum == 1 && strcmp(hash_m_orig, cur_m_hash) == 0) {
        printf("  [PASS] 1.3: Direct --summary-json manifest overwrite rejected (rc=1), hash unchanged.\n");
    } else {
        printf("  [FAIL] 1.3: rc=%d\n", rc1_sum);
        all_passed = false;
    }

    /* 1.4 Symlink targeting manifest */
    const char *symlink_m = TEST_DIR "/symlink_manifest.dot";
    unlink(symlink_m);
    assert(symlink(evid1_m, symlink_m) == 0);
    snprintf(args, sizeof(args), "--dot \"%s\"", symlink_m);
    int rc1_sym = run_replay_cmd(evid1, args, out, sizeof(out));
    compute_sha256(evid1_m, cur_m_hash);
    unlink(symlink_m);
    if (rc1_sym == 1 && strcmp(hash_m_orig, cur_m_hash) == 0) {
        printf("  [PASS] 1.4: Symlinked manifest overwrite rejected (rc=1), hash unchanged.\n");
    } else {
        printf("  [FAIL] 1.4: rc=%d\n", rc1_sym);
        all_passed = false;
    }

    /* 1.5 Hardlink targeting manifest */
    const char *hardlink_m = TEST_DIR "/hardlink_manifest.dot";
    unlink(hardlink_m);
    assert(link(evid1_m, hardlink_m) == 0);
    snprintf(args, sizeof(args), "--dot \"%s\"", hardlink_m);
    int rc1_hl = run_replay_cmd(evid1, args, out, sizeof(out));
    compute_sha256(evid1_m, cur_m_hash);
    unlink(hardlink_m);
    if (rc1_hl == 1 && strcmp(hash_m_orig, cur_m_hash) == 0) {
        printf("  [PASS] 1.5: Hardlinked manifest overwrite rejected (rc=1), hash unchanged.\n");
    } else {
        printf("  [FAIL] 1.5: rc=%d\n", rc1_hl);
        all_passed = false;
    }

    /* 1.6 Output path aliasing evidence file itself */
    snprintf(args, sizeof(args), "--dot \"%s\"", evid1);
    int rc1_evid = run_replay_cmd(evid1, args, out, sizeof(out));
    char cur_evid_hash[65];
    compute_sha256(evid1, cur_evid_hash);
    if (rc1_evid == 1 && strcmp(hash_evid_orig, cur_evid_hash) == 0) {
        printf("  [PASS] 1.6: Evidence file overwrite rejected (rc=1), evidence hash unchanged.\n");
    } else {
        printf("  [FAIL] 1.6: rc=%d\n", rc1_evid);
        all_passed = false;
    }

    /* 1.7 File-open time rejection of existing target without truncation */
    const char *exist_dot = TEST_DIR "/pre_existing.dot";
    unlink(exist_dot);
    FILE *fe = fopen(exist_dot, "w");
    fprintf(fe, "PRE_EXISTING_DO_NOT_TRUNCATE_CONTENT_12345");
    fclose(fe);
    char exist_hash_before[65], exist_hash_after[65];
    compute_sha256(exist_dot, exist_hash_before);

    snprintf(args, sizeof(args), "--dot \"%s\"", exist_dot);
    int rc1_exist = run_replay_cmd(evid1, args, out, sizeof(out));
    compute_sha256(exist_dot, exist_hash_after);
    bool exist_hash_intact = (strcmp(exist_hash_before, exist_hash_after) == 0);

    if (rc1_exist == 6 && exist_hash_intact) {
        printf("  [PASS] 1.7: Existing export rejected at file-open time without truncation (rc=6), hash unchanged.\n");
    } else {
        printf("  [FAIL] 1.7: rc=%d, hash_intact=%d\n", rc1_exist, exist_hash_intact);
        all_passed = false;
    }

    /* 1.8 Safe overwrite when --overwrite is explicitly requested */
    snprintf(args, sizeof(args), "--overwrite --dot \"%s\"", exist_dot);
    int rc1_ovw = run_replay_cmd(evid1, args, out, sizeof(out));
    bool dot_valid = false;
    FILE *fr = fopen(exist_dot, "r");
    if (fr) {
        char rbuf[128];
        if (fgets(rbuf, sizeof(rbuf), fr) && strstr(rbuf, "digraph")) {
            dot_valid = true;
        }
        fclose(fr);
    }
    if (rc1_ovw == 0 && dot_valid) {
        printf("  [PASS] 1.8: Safe export overwrite allowed when --overwrite requested (rc=0), valid DOT generated.\n");
    } else {
        printf("  [FAIL] 1.8: rc=%d, dot_valid=%d\n", rc1_ovw, dot_valid);
        all_passed = false;
    }

    /* 1.9 Rejection of symlinked target even with --overwrite */
    const char *sym_ovw = TEST_DIR "/symlink_overwrite.dot";
    unlink(sym_ovw);
    assert(symlink(evid1_m, sym_ovw) == 0);
    snprintf(args, sizeof(args), "--overwrite --dot \"%s\"", sym_ovw);
    int rc1_sym_ovw = run_replay_cmd(evid1, args, out, sizeof(out));
    compute_sha256(evid1_m, cur_m_hash);
    unlink(sym_ovw);
    if ((rc1_sym_ovw == 1 || rc1_sym_ovw == 6) && strcmp(hash_m_orig, cur_m_hash) == 0) {
        printf("  [PASS] 1.9: Symlinked target rejected at open-time even with --overwrite, manifest hash unchanged.\n");
    } else {
        printf("  [FAIL] 1.9: rc=%d\n", rc1_sym_ovw);
        all_passed = false;
    }

    /* --- SUITE 2: Inconsistent Manifest Handling --- */
    printf("\n[SUITE 2: Inconsistent Manifest Handling]\n");
    const char *evid2 = TEST_DIR "/case2_inconsistent.evid";
    struct evidence_session_manifest m2;
    generate_clean_evidence(evid2, 10, &m2);

    /* 2.1 Total drops > sum of per-type drops (total=10, sum=0) */
    unlink(TEST_DIR "/case2_inconsistent.evid.manifest");
    m2.ring_buffer_total_drops = 10;
    for (int i = 0; i < EPHIM_MAX_EVENT_TYPE; i++) {
        m2.ring_buffer_per_type_drops[i] = 0;
    }
    evidence_write_manifest(evid2, &m2);

    const char *dot2 = TEST_DIR "/case2.dot";
    unlink(dot2);
    snprintf(args, sizeof(args), "--strict --dot \"%s\"", dot2);
    int rc2_strict = run_replay_cmd(evid2, args, out, sizeof(out));
    bool dot2_exists = (access(dot2, F_OK) == 0);
    if (rc2_strict == 7 && !dot2_exists) {
        printf("  [PASS] 2.1: Strict replay rejected inconsistent manifest (total > sum) with rc=7, exports suppressed.\n");
    } else {
        printf("  [FAIL] 2.1: rc=%d, dot_exists=%d\n", rc2_strict, dot2_exists);
        all_passed = false;
    }

    /* 2.2 Standard mode preserves recoverable evidence but reports inconsistent manifest */
    unlink(dot2);
    snprintf(args, sizeof(args), "--dot \"%s\"", dot2);
    int rc2_std = run_replay_cmd(evid2, args, out, sizeof(out));
    dot2_exists = (access(dot2, F_OK) == 0);
    bool status_inconsistent = (strstr(out, "Inconsistent Loss Manifest") != NULL);
    if (rc2_std == 0 && dot2_exists && status_inconsistent) {
        printf("  [PASS] 2.2: Standard replay recovered prefix, exported graph, truthfully reported 'SUCCESS (Inconsistent Loss Manifest)'.\n");
    } else {
        printf("  [FAIL] 2.2: rc=%d, dot_exists=%d, status_inconsistent=%d\n", rc2_std, dot2_exists, status_inconsistent);
        all_passed = false;
    }

    /* --- SUITE 3: Missing Manifest & Truthful Telemetry Classification --- */
    printf("\n[SUITE 3: Missing Manifest & Truthful Classification]\n");
    const char *evid3 = TEST_DIR "/case3_legacy.evid";
    generate_clean_evidence(evid3, 10, NULL); /* No manifest */

    char hash3_before[65], hash3_after[65];
    compute_sha256(evid3, hash3_before);

    const char *sum3 = TEST_DIR "/case3_summary.json";
    unlink(sum3);
    snprintf(args, sizeof(args), "--summary-json \"%s\"", sum3);
    int rc3 = run_replay_cmd(evid3, args, out, sizeof(out));
    compute_sha256(evid3, hash3_after);

    bool reported_lossy = (strstr(out, "Lossy Telemetry Captured") != NULL);
    bool reported_unverified = (strstr(out, "Unverified Telemetry Completeness") != NULL);
    bool hash3_match = (strcmp(hash3_before, hash3_after) == 0);

    if (rc3 == 0 && !reported_lossy && reported_unverified && hash3_match) {
        printf("  [PASS] 3.1: Clean legacy evidence correctly reported 'SUCCESS (Unverified Telemetry Completeness)', not lossy. Hash preserved.\n");
    } else {
        printf("  [FAIL] 3.1: rc=%d, reported_lossy=%d, reported_unverified=%d\n", rc3, reported_lossy, reported_unverified);
        all_passed = false;
    }

    /* 3.2 Strict replay rejects legacy evidence without manifest when no opt-in is given */
    const char *dot3_strict = TEST_DIR "/case3_strict.dot";
    unlink(dot3_strict);
    snprintf(args, sizeof(args), "--strict --dot \"%s\"", dot3_strict);
    int rc3_strict = run_replay_cmd(evid3, args, out, sizeof(out));
    bool dot3_exists = (access(dot3_strict, F_OK) == 0);

    if (rc3_strict == 7 && !dot3_exists) {
        printf("  [PASS] 3.2: Strict replay rejected legacy evidence without manifest (rc=7), exports suppressed.\n");
    } else {
        printf("  [FAIL] 3.2: rc=%d, dot3_exists=%d\n", rc3_strict, dot3_exists);
        all_passed = false;
    }

    /* 3.3 Strict replay succeeds on legacy evidence with explicit --allow-legacy opt-in */
    unlink(dot3_strict);
    snprintf(args, sizeof(args), "--strict --allow-legacy --dot \"%s\"", dot3_strict);
    int rc3_optin = run_replay_cmd(evid3, args, out, sizeof(out));
    dot3_exists = (access(dot3_strict, F_OK) == 0);
    bool status_unverified = (strstr(out, "Unverified Telemetry Completeness") != NULL);

    if (rc3_optin == 0 && dot3_exists && status_unverified) {
        printf("  [PASS] 3.3: Strict replay with --allow-legacy succeeded (rc=0), exported graph, reported UNVERIFIED.\n");
    } else {
        printf("  [FAIL] 3.3: rc=%d, dot3_exists=%d, status_unverified=%d\n", rc3_optin, dot3_exists, status_unverified);
        all_passed = false;
    }

    /* --- SUITE 4: Malformed Manifest Handling --- */
    printf("\n[SUITE 4: Malformed Manifest Handling]\n");
    const char *evid4 = TEST_DIR "/case4_malformed.evid";
    generate_clean_evidence(evid4, 10, NULL);
    char evid4_m[512];
    snprintf(evid4_m, sizeof(evid4_m), "%s.manifest", evid4);
    FILE *fm = fopen(evid4_m, "w");
    fprintf(fm, "{\"manifest_version\": 99, \"record_count\": 10, \"storage_bytes\": 100}"); /* Incompatible version */
    fclose(fm);

    const char *dot4 = TEST_DIR "/case4.dot";
    unlink(dot4);
    snprintf(args, sizeof(args), "--strict --dot \"%s\"", dot4);
    int rc4_strict = run_replay_cmd(evid4, args, out, sizeof(out));
    bool dot4_exists = (access(dot4, F_OK) == 0);

    if (rc4_strict == 7 && !dot4_exists) {
        printf("  [PASS] 4.1: Strict replay rejected incompatible manifest version with code 7 and suppressed exports.\n");
    } else {
        printf("  [FAIL] 4.1: rc=%d, dot4_exists=%d\n", rc4_strict, dot4_exists);
        all_passed = false;
    }

    /* 4.2 Malformed syntax: unclosed curly brace */
    unlink(evid4_m);
    fm = fopen(evid4_m, "w");
    fprintf(fm, "{\"manifest_version\": 1, \"record_count\": 10"); /* Missing closing brace */
    fclose(fm);
    unlink(dot4);
    int rc4_syn = run_replay_cmd(evid4, "--strict --dot " TEST_DIR "/case4.dot", out, sizeof(out));
    dot4_exists = (access(dot4, F_OK) == 0);
    if (rc4_syn == 7 && !dot4_exists) {
        printf("  [PASS] 4.2: Strict replay rejected unclosed JSON syntax with code 7 and suppressed exports.\n");
    } else {
        printf("  [FAIL] 4.2: rc=%d, dot4_exists=%d\n", rc4_syn, dot4_exists);
        all_passed = false;
    }

    /* 4.3 Trailing non-whitespace garbage after root JSON object */
    unlink(evid4_m);
    fm = fopen(evid4_m, "w");
    fprintf(fm, "{\"manifest_version\": 1, \"record_count\": 10, \"storage_bytes\": 100, \"finalized\": true, \"synchronized\": true, \"loss_counters\": {}} EXTRA_GARBAGE");
    fclose(fm);
    unlink(dot4);
    int rc4_junk = run_replay_cmd(evid4, "--strict --dot " TEST_DIR "/case4.dot", out, sizeof(out));
    dot4_exists = (access(dot4, F_OK) == 0);
    if (rc4_junk == 7 && !dot4_exists) {
        printf("  [PASS] 4.3: Strict replay rejected trailing garbage after root JSON with code 7.\n");
    } else {
        printf("  [FAIL] 4.3: rc=%d, dot4_exists=%d\n", rc4_junk, dot4_exists);
        all_passed = false;
    }

    /* 4.4 Missing required field (missing finalized & synchronized) */
    unlink(evid4_m);
    fm = fopen(evid4_m, "w");
    fprintf(fm, "{\"manifest_version\": 1, \"record_count\": 10, \"storage_bytes\": 100, \"loss_counters\": {}}");
    fclose(fm);
    unlink(dot4);
    int rc4_req = run_replay_cmd(evid4, "--strict --dot " TEST_DIR "/case4.dot", out, sizeof(out));
    dot4_exists = (access(dot4, F_OK) == 0);
    if (rc4_req == 7 && !dot4_exists) {
        printf("  [PASS] 4.4: Strict replay rejected missing required fields (finalized/synchronized) with code 7.\n");
    } else {
        printf("  [FAIL] 4.4: rc=%d, dot4_exists=%d\n", rc4_req, dot4_exists);
        all_passed = false;
    }

    /* 4.5 Checked numeric conversion failure: negative unsigned record_count */
    unlink(evid4_m);
    fm = fopen(evid4_m, "w");
    fprintf(fm, "{\"manifest_version\": 1, \"record_count\": -10, \"storage_bytes\": 100, \"finalized\": true, \"synchronized\": true, \"loss_counters\": {}}");
    fclose(fm);
    unlink(dot4);
    int rc4_num = run_replay_cmd(evid4, "--strict --dot " TEST_DIR "/case4.dot", out, sizeof(out));
    dot4_exists = (access(dot4, F_OK) == 0);
    if (rc4_num == 7 && !dot4_exists) {
        printf("  [PASS] 4.5: Strict replay rejected negative value for unsigned record_count with code 7.\n");
    } else {
        printf("  [FAIL] 4.5: rc=%d, dot4_exists=%d\n", rc4_num, dot4_exists);
        all_passed = false;
    }

    /* --- SUITE 5: Truncated Evidence Handling & Hash Preservation --- */
    printf("\n[SUITE 5: Truncated Evidence Handling & Input Hash Preservation]\n");
    const char *evid5 = TEST_DIR "/case5_trunc.evid";
    generate_clean_evidence(evid5, 10, NULL);
    struct stat st5;
    stat(evid5, &st5);
    int trunc_rc = truncate(evid5, st5.st_size - 100);
    (void)trunc_rc;

    char hash5_before[65], hash5_after[65];
    compute_sha256(evid5, hash5_before);

    const char *dot5_std = TEST_DIR "/case5_std.dot";
    const char *dot5_strict = TEST_DIR "/case5_strict.dot";
    unlink(dot5_std);
    unlink(dot5_strict);

    int rc5_std = run_replay_cmd(evid5, "--dot " TEST_DIR "/case5_std.dot", out, sizeof(out));
    int rc5_strict = run_replay_cmd(evid5, "--strict --dot " TEST_DIR "/case5_strict.dot", out, sizeof(out));
    compute_sha256(evid5, hash5_after);

    bool std_exported = (access(dot5_std, F_OK) == 0);
    bool strict_suppressed = (access(dot5_strict, F_OK) != 0);
    bool hash5_match = (strcmp(hash5_before, hash5_after) == 0);

    if (rc5_std == 4 && std_exported && rc5_strict == 4 && strict_suppressed && hash5_match) {
        printf("  [PASS] 5.1: Truncation: Standard recovered prefix (rc=4, export=YES); Strict aborted (rc=4, export=NO); Input hash preserved.\n");
    } else {
        printf("  [FAIL] 5.1: std_rc=%d, strict_rc=%d, std_exp=%d, strict_supp=%d, hash_match=%d\n",
               rc5_std, rc5_strict, std_exported, strict_suppressed, hash5_match);
        all_passed = false;
    }

    /* --- SUITE 6: Known Positive Loss Preservation with Unavailable Counters --- */
    printf("\n[SUITE 6: Known Positive Loss Preservation with Unavailable Counters]\n");
    const char *evid6 = TEST_DIR "/case6_loss_preservation.evid";
    struct evidence_session_manifest m6;
    generate_clean_evidence(evid6, 10, &m6);
    char evid6_m[512];
    snprintf(evid6_m, sizeof(evid6_m), "%s.manifest", evid6);

    /* 6.1 Total ring buffer drops > 0, but other kernel counters unavailable (-1) */
    unlink(evid6_m);
    FILE *f6 = fopen(evid6_m, "w");
    fprintf(f6,
        "{\n"
        "  \"manifest_version\": 1,\n"
        "  \"evidence_file\": \"%s\",\n"
        "  \"record_count\": 10,\n"
        "  \"storage_bytes\": %llu,\n"
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
        "    \"ring_buffer_total_drops\": 12,\n"
        "    \"ring_buffer_per_type_drops\": {}\n"
        "  }\n"
        "}\n", evid6, (unsigned long long)m6.storage_bytes);
    fclose(f6);

    const char *sum6_1 = TEST_DIR "/case6_1_sum.json";
    unlink(sum6_1);
    snprintf(args, sizeof(args), "--summary-json \"%s\"", sum6_1);
    int rc6_1 = run_replay_cmd(evid6, args, out, sizeof(out));
    bool reported_lossy_6_1 = (strstr(out, "Lossy Telemetry Captured") != NULL);

    if (rc6_1 == 0 && reported_lossy_6_1) {
        printf("  [PASS] 6.1: Positive total drops (12) preserved as LOSSY even when registry counters are unavailable (-1).\n");
    } else {
        printf("  [FAIL] 6.1: rc=%d, reported_lossy=%d\n", rc6_1, reported_lossy_6_1);
        all_passed = false;
    }

    /* 6.2 Total drops unavailable (-1), but per-type drop > 0 (execve=5) */
    unlink(evid6_m);
    f6 = fopen(evid6_m, "w");
    fprintf(f6,
        "{\n"
        "  \"manifest_version\": 1,\n"
        "  \"evidence_file\": \"%s\",\n"
        "  \"record_count\": 10,\n"
        "  \"storage_bytes\": %llu,\n"
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
        "    \"ring_buffer_total_drops\": -1,\n"
        "    \"ring_buffer_per_type_drops\": {\n"
        "      \"execve\": 5\n"
        "    }\n"
        "  }\n"
        "}\n", evid6, (unsigned long long)m6.storage_bytes);
    fclose(f6);

    const char *sum6_2 = TEST_DIR "/case6_2_sum.json";
    unlink(sum6_2);
    snprintf(args, sizeof(args), "--summary-json \"%s\"", sum6_2);
    int rc6_2 = run_replay_cmd(evid6, args, out, sizeof(out));
    bool reported_lossy_6_2 = (strstr(out, "Lossy Telemetry Captured") != NULL);

    if (rc6_2 == 0 && reported_lossy_6_2) {
        printf("  [PASS] 6.2: Per-type positive drop (execve=5) preserved as LOSSY when total counter is unavailable (-1).\n");
    } else {
        printf("  [FAIL] 6.2: rc=%d, reported_lossy=%d\n", rc6_2, reported_lossy_6_2);
        all_passed = false;
    }

    printf("\n=================================================================\n");
    if (all_passed) {
        printf("=== ALL QUALIFICATION TASK 02 TESTS PASSED WITH 100%% FIDELITY ===\n");
        printf("=================================================================\n");
        return 0;
    } else {
        printf("=== QUALIFICATION TASK 02 HAD FAILURES ===\n");
        printf("=================================================================\n");
        return 1;
    }
}
