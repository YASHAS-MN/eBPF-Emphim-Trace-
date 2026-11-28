#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "provenance.h"
#include "evidence_io.h"

static void read_file(const char *path, unsigned char *buf, size_t cap, size_t *n)
{
    FILE *f = fopen(path, "rb");
    assert(f);
    *n = fread(buf, 1, cap, f);
    assert(*n < cap && feof(f) && !ferror(f));
    assert(fclose(f) == 0);
}

static int run_case(const char *evid, const char *dot, const char *summary,
                    unsigned fail_at, bool strict, bool filtered)
{
    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        char number[32];
        snprintf(number, sizeof(number), "%u", fail_at);
        if (setenv("EPHIM_TEST_FAIL_CALLOC", number, 1) != 0)
            _exit(126);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        char *args[12];
        size_t i = 0;
        args[i++] = "./build/replay_graph_fault";
        args[i++] = (char *)evid;
        if (strict) args[i++] = "--strict";
        if (filtered) {
            args[i++] = "--filter-pid";
            args[i++] = "1234";
        }
        args[i++] = filtered ? "--filtered-dot" : "--dot";
        args[i++] = (char *)dot;
        args[i++] = "--summary-json";
        args[i++] = (char *)summary;
        args[i] = NULL;
        execv(args[0], args);
        _exit(127);
    }
    int st;
    assert(waitpid(pid, &st, 0) == pid);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

int main(void)
{
    char dir[] = "/tmp/ephim_graph_alloc_XXXXXX";
    assert(mkdtemp(dir));
    char evid[512], manifest[512], dot[512], summary[512];
    snprintf(evid, sizeof(evid), "%s/session.evid", dir);
    snprintf(manifest, sizeof(manifest), "%s/session.evid.manifest", dir);
    snprintf(dot, sizeof(dot), "%s/graph.dot", dir);
    snprintf(summary, sizeof(summary), "%s/summary.json", dir);

    struct evidence_writer w;
    assert(evidence_writer_init(&w, evid, EVIDENCE_MODE_DEFERRED,
                                1234, 0, EVIDENCE_DEFAULT_MAX_BYTES) == 0);
    struct event e = {0};
    e.type = EVENT_MEMFD_COMPLETED;
    e.op_type = 2;
    e.pid = 1234;
    e.tid = 1234;
    e.start_time_ns = 1000000;
    e.timestamp_ns = 1001000;
    e.object_token = 42;
    e.fd = 3;
    e.ret_val = 3;
    snprintf(e.name, sizeof(e.name), "alloc_test");
    assert(evidence_writer_write(&w, &e, e.timestamp_ns) == 0);
    e.type = EVENT_MEMFD_WRITE;
    e.timestamp_ns++;
    e.ret_val = 4;
    assert(evidence_writer_write(&w, &e, e.timestamp_ns) == 0);
    assert(evidence_writer_close(&w) == 0);

    struct evidence_session_manifest m = {0};
    m.version = 1;
    m.target_pid = 1234;
    m.session_start_ns = 1000000;
    m.session_end_ns = 1002000;
    m.record_count = 2;
    m.storage_bytes = w.stats.storage_bytes;
    m.finalized = true;
    m.synchronized = true;
    assert(evidence_write_manifest(evid, &m) == 0);

    unsigned char original[8192], manifest_original[8192], current[8192];
    size_t orig_n, manifest_n, cur_n;
    read_file(evid, original, sizeof(original), &orig_n);
    read_file(manifest, manifest_original, sizeof(manifest_original), &manifest_n);
    unsigned passes = 0;

    /* calloc order: two engine tables, process, PID index, memfd, creation edge,
     * second-event write edge, then export scratch arrays (or filtered queue). */
    for (unsigned mode = 0; mode < 2; mode++) {
        for (unsigned fail_at = 0; fail_at <= 9; fail_at++) {
            unlink(dot);
            unlink(summary);
            int rc = run_case(evid, dot, summary, fail_at, mode == 1, false);
            int expected = fail_at == 0 ? 0 :
                           fail_at <= 2 ? 3 : fail_at <= 7 ? 8 : 6;
            if (rc != expected) {
                fprintf(stderr, "FAIL: strict=%u calloc=%u expected=%d got=%d\n",
                        mode, fail_at, expected, rc);
                return 1;
            }
            assert((access(dot, F_OK) == 0) == (expected == 0));
            if (fail_at > 2 || fail_at == 0) {
                char buf[8192];
                size_t n;
                read_file(summary, (unsigned char *)buf, sizeof(buf), &n);
                buf[n] = 0;
                assert(strstr(buf, expected ? "\"status\": \"ERROR\"" : "\"status\": \"OK\""));
                assert(strstr(buf, "\"records_verified\": 2"));
                if (expected == 8) {
                    assert(strstr(buf, "\"reconstruction_error\": -12"));
                    assert(strstr(buf, "\"exports_aborted\": true"));
                    assert(strstr(buf, fail_at == 7 ? "\"records_replayed\": 1" : "\"records_replayed\": 0"));
                }
            } else {
                assert(access(summary, F_OK) != 0);
            }
            read_file(evid, current, sizeof(current), &cur_n);
            assert(cur_n == orig_n && memcmp(current, original, orig_n) == 0);
            read_file(manifest, current, sizeof(current), &cur_n);
            assert(cur_n == manifest_n && memcmp(current, manifest_original, manifest_n) == 0);
            printf("[PASS] strict=%u calloc=%u rc=%d evidence and manifest unchanged\n", mode, fail_at, rc);
            passes++;
        }
    }

    /* Filtered exports use a queue plus node/edge arrays. */
    for (unsigned fail_at = 8; fail_at <= 10; fail_at++) {
        unlink(dot);
        unlink(summary);
        int rc = run_case(evid, dot, summary, fail_at, true, true);
        assert(rc == 6 && access(dot, F_OK) != 0);
        char buf[8192];
        size_t n;
        read_file(summary, (unsigned char *)buf, sizeof(buf), &n);
        buf[n] = 0;
        assert(strstr(buf, "\"status\": \"ERROR\""));
        read_file(evid, current, sizeof(current), &cur_n);
        assert(cur_n == orig_n && memcmp(current, original, orig_n) == 0);
        read_file(manifest, current, sizeof(current), &cur_n);
        assert(cur_n == manifest_n && memcmp(current, manifest_original, manifest_n) == 0);
        printf("[PASS] filtered export calloc=%u rc=%d input unchanged\n", fail_at, rc);
        passes++;
    }
    unlink(dot);
    unlink(summary);
    unlink(manifest);
    unlink(evid);
    assert(rmdir(dir) == 0);
    printf("All %u graph allocation qualification cases passed.\n", passes);
    return 0;
}
