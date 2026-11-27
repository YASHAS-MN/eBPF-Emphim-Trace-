#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "provenance.h"
#include "provenance.c"
#include "evidence_io.h"

#define NUM_REPS 5
static const size_t SCALES[] = { 1000, 10000, 100000, 1000000 };
#define NUM_SCALES (sizeof(SCALES) / sizeof(SCALES[0]))

struct trial_result {
    size_t scale;
    int rep;
    double duration_s;
    double throughput_eps;
    double user_cpu_ms;
    double sys_cpu_ms;
    long peak_rss_kb;
    double filter_pid_us;
    double filter_token_us;
    double export_dot_ms;
    double export_json_ms;
    double export_timeline_ms;
    size_t dot_bytes;
    size_t json_bytes;
    size_t timeline_bytes;
    size_t node_count;
    size_t edge_count;
};

struct stat_summary {
    double mean;
    double stddev;
    double min;
    double max;
};

static double simple_sqrt(double x)
{
    if (x <= 0.0) return 0.0;
    double r = x;
    for (int i = 0; i < 20; i++) {
        r = 0.5 * (r + x / r);
    }
    return r;
}

static struct stat_summary calc_stats(const double *vals, size_t n)
{
    struct stat_summary s = { 0 };
    if (n == 0) return s;
    double sum = 0;
    s.min = vals[0];
    s.max = vals[0];
    for (size_t i = 0; i < n; i++) {
        sum += vals[i];
        if (vals[i] < s.min) s.min = vals[i];
        if (vals[i] > s.max) s.max = vals[i];
    }
    s.mean = sum / n;
    double var = 0;
    for (size_t i = 0; i < n; i++) {
        var += (vals[i] - s.mean) * (vals[i] - s.mean);
    }
    s.stddev = simple_sqrt(var / n);
    return s;
}

static inline uint64_t get_time_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* Generate synthetic .evid file with realistic event distribution */
static int generate_synthetic_evidence(const char *filepath, size_t num_events, uint32_t *out_target_pid, uint64_t *out_target_token)
{
    unlink(filepath);
    struct evidence_writer w;
    int rc = evidence_writer_init(&w, filepath, EVIDENCE_MODE_DEFERRED, 1000, 256 * 1024, 2ULL * 1024 * 1024 * 1024);
    if (rc != 0) {
        fprintf(stderr, "Failed to init evidence writer for '%s': %d\n", filepath, rc);
        return -1;
    }

    uint32_t current_pid = 1000;
    uint32_t target_pid = 1000; /* Coordinator process: has outbound edges to all forks and memfds */
    uint64_t target_token = 1;  /* Target memfd: receives create, write, fd install, and exec */
    uint64_t base_ts = 1000000000ULL;

    for (size_t i = 0; i < num_events; i++) {
        struct event ev = { 0 };
        ev.timestamp_ns = base_ts + (i * 100);
        ev.pid = current_pid;
        ev.tid = current_pid;
        ev.start_time_ns = 1000000000ULL;

        /* Prime cycle 23 decouples token assignment from the mod 100 selector,
         * ensuring token 1 receives CREATE, WRITE, DUP, and EXEC events across all scales. */
        uint64_t token = 1 + (i % 23);

        size_t mod = i % 100;
        if (mod < 10) {
            /* FORK: 10% */
            ev.type = EVENT_FORK;
            ev.child_pid = current_pid + 1 + (uint32_t)(i % 500);
            ev.child_tgid = ev.child_pid;
            ev.child_start_time_ns = ev.timestamp_ns;
            snprintf(ev.name, sizeof(ev.name), "proc_%u", ev.child_pid);
        } else if (mod < 30) {
            /* MEMFD_CREATE: 20% */
            ev.type = EVENT_MEMFD_CREATE;
            ev.object_token = token;
            ev.fd = 3 + (int32_t)(i % 10);
            snprintf(ev.name, sizeof(ev.name), "memfd_%llu", (unsigned long long)ev.object_token);
        } else if (mod < 65) {
            /* MEMFD_WRITE: 35% */
            ev.type = EVENT_MEMFD_WRITE;
            ev.object_token = token;
            ev.entry_ts_ns = (i % 10) * 4096; /* offset */
            ev.ret_val = 4096; /* bytes */
        } else if (mod < 80) {
            /* FD_INSTALLED / FD_CLOSED: 15% */
            if (mod < 73) {
                ev.type = EVENT_FD_INSTALLED;
                ev.object_token = token;
                ev.fd = 4 + (int32_t)(i % 10);
                ev.op_type = 3; /* DUP */
            } else {
                ev.type = EVENT_FD_CLOSED;
                ev.object_token = token;
                ev.fd = 3 + (int32_t)(i % 10);
                ev.entry_ts_ns = 50000; /* duration */
            }
        } else if (mod < 90) {
            /* EXEC: 10% */
            if (mod < 85) {
                ev.type = EVENT_MEMFD_EXEC_ATTEMPT;
                ev.object_token = token;
                snprintf(ev.name, sizeof(ev.name), "/dev/fd/%d", 3 + (int)(i % 5));
            } else {
                ev.type = EVENT_MEMFD_EXEC_SUCCESS;
                ev.object_token = token;
                snprintf(ev.name, sizeof(ev.name), "app_exec_%zu", i % 20);
            }
        } else {
            /* EXIT / UNLINK: 10% */
            if (mod < 95) {
                ev.type = EVENT_VFS_UNLINK_COMPLETED;
                ev.inode_no = 10000 + (i % 1000);
                ev.dev_id = 66309;
                ev.ret_val = 0;
                snprintf(ev.path, sizeof(ev.path), "/tmp/bench_file_%zu.dat", i % 1000);
            } else {
                ev.type = EVENT_PROCESS_EXIT;
                ev.reserved = 1;
                ev.ret_val = 0;
            }
        }

        if (evidence_writer_write(&w, &ev, ev.timestamp_ns + 10) != 0) {
            fprintf(stderr, "Failed writing record %zu to '%s'\n", i, filepath);
            evidence_writer_close(&w);
            return -1;
        }
    }

    evidence_writer_close(&w);

    /* Write minimal valid session manifest */
    char manifest_path[512];
    snprintf(manifest_path, sizeof(manifest_path), "%s.manifest", filepath);
    FILE *mf = fopen(manifest_path, "w");
    if (mf) {
        fprintf(mf, "{\n");
        fprintf(mf, "  \"version\": 1,\n");
        fprintf(mf, "  \"target_pid\": 1000,\n");
        fprintf(mf, "  \"record_count\": %zu,\n", num_events);
        fprintf(mf, "  \"finalized\": true,\n");
        fprintf(mf, "  \"synchronized\": true,\n");
        fprintf(mf, "  \"ring_buffer_total_drops\": 0,\n");
        fprintf(mf, "  \"ring_buffer_drops\": \"lossless\"\n");
        fprintf(mf, "}\n");
        fclose(mf);
    }

    if (out_target_pid) *out_target_pid = target_pid;
    if (out_target_token) *out_target_token = target_token;
    return 0;
}

static void run_single_trial_in_process(const char *evid_path, size_t scale, int rep,
                                       uint32_t target_pid, uint64_t target_token, int write_fd)
{
    struct trial_result r = { 0 };
    r.scale = scale;
    r.rep = rep;

    struct evidence_reader reader;
    int rc = evidence_reader_open(&reader, evid_path);
    if (rc != 0) {
        fprintf(stderr, "[ERROR] evidence_reader_open failed: %d\n", rc);
        write(write_fd, &r, sizeof(r));
        exit(1);
    }

    prov_engine_init();
    prov_engine_set_search_mode(0); /* incoming O(1) */

    struct rusage ru_start, ru_end;
    getrusage(RUSAGE_SELF, &ru_start);
    uint64_t t0 = get_time_ns();

    struct event ev;
    struct evidence_record_frame frame;
    while (evidence_reader_read_next(&reader, &ev, &frame) == 1) {
        prov_engine_process_event(&ev);
    }

    uint64_t t1 = get_time_ns();
    getrusage(RUSAGE_SELF, &ru_end);

    r.duration_s = (double)(t1 - t0) / 1e9;
    r.throughput_eps = (r.duration_s > 0) ? ((double)reader.stats.records_replayed / r.duration_s) : 0;
    r.user_cpu_ms = ((ru_end.ru_utime.tv_sec - ru_start.ru_utime.tv_sec) * 1000.0) +
                    ((ru_end.ru_utime.tv_usec - ru_start.ru_utime.tv_usec) / 1000.0);
    r.sys_cpu_ms = ((ru_end.ru_stime.tv_sec - ru_start.ru_stime.tv_sec) * 1000.0) +
                   ((ru_end.ru_stime.tv_usec - ru_start.ru_stime.tv_usec) / 1000.0);

    prov_engine_get_counts(&r.node_count, &r.edge_count);

    /* Benchmark Subgraph Extraction Latency */
    struct prov_graph sub = { 0 };
    uint64_t tf0 = get_time_ns();
    int rc_fpid = prov_engine_filter_subgraph(target_pid, 0, &sub);
    uint64_t tf1 = get_time_ns();
    r.filter_pid_us = (double)(tf1 - tf0) / 1000.0;
    if (rc_fpid != 0 || sub.node_count == 0 || sub.edge_count == 0) {
        fprintf(stderr, "[ERROR] filter_subgraph(pid=%u) failed: rc=%d, nodes=%zu, edges=%zu\n",
                target_pid, rc_fpid, sub.node_count, sub.edge_count);
        prov_graph_free(&sub);
        exit(1);
    }
    prov_graph_free(&sub);

    uint64_t tk0 = get_time_ns();
    int rc_ftok = prov_engine_filter_subgraph(0, target_token, &sub);
    uint64_t tk1 = get_time_ns();
    r.filter_token_us = (double)(tk1 - tk0) / 1000.0;
    if (rc_ftok != 0 || sub.node_count == 0 || sub.edge_count == 0) {
        fprintf(stderr, "[ERROR] filter_subgraph(token=%llu) failed: rc=%d, nodes=%zu, edges=%zu\n",
                (unsigned long long)target_token, rc_ftok, sub.node_count, sub.edge_count);
        prov_graph_free(&sub);
        exit(1);
    }
    prov_graph_free(&sub);

    /* Benchmark Exports (Only measure export cost; keep files in /tmp) */
    char dot_tmp[512], json_tmp[512], tl_tmp[512];
    snprintf(dot_tmp, sizeof(dot_tmp), "/tmp/bench_%zu_r%d.dot", scale, rep);
    snprintf(json_tmp, sizeof(json_tmp), "/tmp/bench_%zu_r%d.json", scale, rep);
    snprintf(tl_tmp, sizeof(tl_tmp), "/tmp/bench_%zu_r%d.md", scale, rep);

    uint64_t ed0 = get_time_ns();
    int rc_dot = prov_engine_export_dot(dot_tmp);
    uint64_t ed1 = get_time_ns();
    r.export_dot_ms = (double)(ed1 - ed0) / 1e6;
    if (rc_dot != 0) {
        fprintf(stderr, "[ERROR] export_dot failed: %d\n", rc_dot);
        exit(1);
    }

    uint64_t ej0 = get_time_ns();
    int rc_json = prov_engine_export_json(json_tmp);
    uint64_t ej1 = get_time_ns();
    r.export_json_ms = (double)(ej1 - ej0) / 1e6;
    if (rc_json != 0) {
        fprintf(stderr, "[ERROR] export_json failed: %d\n", rc_json);
        exit(1);
    }

    uint64_t et0 = get_time_ns();
    int rc_tl = prov_engine_export_timeline(tl_tmp, target_pid, 0);
    uint64_t et1 = get_time_ns();
    r.export_timeline_ms = (double)(et1 - et0) / 1e6;
    if (rc_tl != 0) {
        fprintf(stderr, "[ERROR] export_timeline failed: %d\n", rc_tl);
        exit(1);
    }

    struct stat st;
    if (stat(dot_tmp, &st) == 0 && st.st_size > 0) {
        r.dot_bytes = st.st_size;
    } else {
        fprintf(stderr, "[ERROR] dot export missing or empty: %s\n", dot_tmp);
        exit(1);
    }
    if (stat(json_tmp, &st) == 0 && st.st_size > 0) {
        r.json_bytes = st.st_size;
    } else {
        fprintf(stderr, "[ERROR] json export missing or empty: %s\n", json_tmp);
        exit(1);
    }
    if (stat(tl_tmp, &st) == 0 && st.st_size > 0) {
        r.timeline_bytes = st.st_size;
    } else {
        fprintf(stderr, "[ERROR] timeline export missing or empty: %s\n", tl_tmp);
        exit(1);
    }

    /* Content verification: verify headers and basic structure */
    FILE *f_dot = fopen(dot_tmp, "r");
    char hbuf[256];
    if (f_dot && fgets(hbuf, sizeof(hbuf), f_dot)) {
        if (strncmp(hbuf, "digraph", 7) != 0) {
            fprintf(stderr, "[ERROR] dot export missing valid header: %s\n", hbuf);
            exit(1);
        }
    }
    if (f_dot) fclose(f_dot);

    FILE *f_json = fopen(json_tmp, "r");
    if (f_json && fgets(hbuf, sizeof(hbuf), f_json)) {
        if (strchr(hbuf, '{') == NULL) {
            fprintf(stderr, "[ERROR] json export missing valid header: %s\n", hbuf);
            exit(1);
        }
    }
    if (f_json) fclose(f_json);

    FILE *f_tl = fopen(tl_tmp, "r");
    if (f_tl && fgets(hbuf, sizeof(hbuf), f_tl)) {
        if (strstr(hbuf, "# EphimTrace") == NULL) {
            fprintf(stderr, "[ERROR] timeline export missing valid header: %s\n", hbuf);
            exit(1);
        }
    }
    if (f_tl) fclose(f_tl);

    unlink(dot_tmp);
    unlink(json_tmp);
    unlink(tl_tmp);

    prov_engine_destroy();
    evidence_reader_close(&reader);

    /* Send result structure to parent */
    write(write_fd, &r, sizeof(r));
    exit(0);
}

static struct trial_result run_single_trial(const char *evid_path, size_t scale, int rep, uint32_t target_pid, uint64_t target_token)
{
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        perror("pipe failed");
        struct trial_result r = { 0 };
        return r;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork failed");
        struct trial_result r = { 0 };
        return r;
    }

    if (pid == 0) {
        /* Child */
        close(pipefd[0]);
        run_single_trial_in_process(evid_path, scale, rep, target_pid, target_token, pipefd[1]);
        close(pipefd[1]);
        _exit(0);
    }

    /* Parent */
    close(pipefd[1]);
    struct trial_result r = { 0 };
    ssize_t n = read(pipefd[0], &r, sizeof(r));
    close(pipefd[0]);

    struct rusage ru_child;
    int status = 0;
    wait4(pid, &status, 0, &ru_child);

    if (n == sizeof(r)) {
        r.peak_rss_kb = ru_child.ru_maxrss;
    }
    return r;
}

int main(void)
{
    printf("=================================================================\n");
    printf("  EphimTrace Provenance Benchmark 01 — Computational Performance \n");
    printf("=================================================================\n");
    printf("Protocol: 4 Scales [1K, 10K, 100K, 1M], 5 Repetitions per Scale\n");
    printf("Execution: Isolated child process per trial (Accurate Peak RSS)\n");
    printf("Metrics: Throughput, CPU, RSS, Subgraph Extraction, Export Costs\n");
    printf("Verification: Nonempty subgraphs, return codes == 0, valid contents\n");
    printf("=================================================================\n\n");

    struct trial_result all_trials[NUM_SCALES][NUM_REPS];

    for (size_t s = 0; s < NUM_SCALES; s++) {
        size_t scale = SCALES[s];
        printf("[SCALE %zu/%zu: %zu Events]\n", s + 1, NUM_SCALES, scale);

        char evid_path[512];
        snprintf(evid_path, sizeof(evid_path), "/tmp/perf_bench_%zu.evid", scale);

        uint32_t target_pid = 0;
        uint64_t target_token = 0;
        printf("  -> Generating synthetic binary evidence (%zu events)...\n", scale);
        if (generate_synthetic_evidence(evid_path, scale, &target_pid, &target_token) != 0) {
            fprintf(stderr, "Failed generating evidence for scale %zu\n", scale);
            continue;
        }

        struct stat st_evid;
        stat(evid_path, &st_evid);
        printf("  -> File created: %s (%.2f MiB, %lld bytes, Target PID: %u, Target Token: %llu)\n",
               evid_path, (double)st_evid.st_size / (1024.0 * 1024.0), (long long)st_evid.st_size,
               target_pid, (unsigned long long)target_token);

        for (int r = 0; r < NUM_REPS; r++) {
            printf("  [Rep %d/%d] Executing replay & export benchmarking...", r + 1, NUM_REPS);
            fflush(stdout);
            all_trials[s][r] = run_single_trial(evid_path, scale, r + 1, target_pid, target_token);
            printf(" Done. (%.3fs, %.0f events/s, Isolated RSS: %.2f MiB, Subgraph PID: %.1fus, Token: %.1fus)\n",
                   all_trials[s][r].duration_s, all_trials[s][r].throughput_eps,
                   (double)all_trials[s][r].peak_rss_kb / 1024.0,
                   all_trials[s][r].filter_pid_us, all_trials[s][r].filter_token_us);
        }

        /* Compute stats across 5 reps */
        double tputs[NUM_REPS], durs[NUM_REPS], rsses[NUM_REPS], user_cpus[NUM_REPS], sys_cpus[NUM_REPS];
        double f_pids[NUM_REPS], f_toks[NUM_REPS], exp_dots[NUM_REPS], exp_jsons[NUM_REPS], exp_tls[NUM_REPS];
        for (int r = 0; r < NUM_REPS; r++) {
            tputs[r] = all_trials[s][r].throughput_eps;
            durs[r] = all_trials[s][r].duration_s;
            rsses[r] = (double)all_trials[s][r].peak_rss_kb / 1024.0;
            user_cpus[r] = all_trials[s][r].user_cpu_ms;
            sys_cpus[r] = all_trials[s][r].sys_cpu_ms;
            f_pids[r] = all_trials[s][r].filter_pid_us;
            f_toks[r] = all_trials[s][r].filter_token_us;
            exp_dots[r] = all_trials[s][r].export_dot_ms;
            exp_jsons[r] = all_trials[s][r].export_json_ms;
            exp_tls[r] = all_trials[s][r].export_timeline_ms;
        }

        struct stat_summary st_tp = calc_stats(tputs, NUM_REPS);
        struct stat_summary st_dur = calc_stats(durs, NUM_REPS);
        struct stat_summary st_rss = calc_stats(rsses, NUM_REPS);
        struct stat_summary st_ucpu = calc_stats(user_cpus, NUM_REPS);
        struct stat_summary st_scpu = calc_stats(sys_cpus, NUM_REPS);
        struct stat_summary st_fpid = calc_stats(f_pids, NUM_REPS);
        struct stat_summary st_ftok = calc_stats(f_toks, NUM_REPS);
        struct stat_summary st_edot = calc_stats(exp_dots, NUM_REPS);
        struct stat_summary st_ejson = calc_stats(exp_jsons, NUM_REPS);
        struct stat_summary st_etl = calc_stats(exp_tls, NUM_REPS);

        printf("\n  >>> Aggregated Results for Scale: %zu Events (N=%d Repetitions) <<<\n", scale, NUM_REPS);
        printf("    Nodes / Edges:           %zu nodes, %zu edges\n", all_trials[s][0].node_count, all_trials[s][0].edge_count);
        printf("    Replay Throughput:       %.1f ± %.1f events/s [min: %.1f, max: %.1f]\n",
               st_tp.mean, st_tp.stddev, st_tp.min, st_tp.max);
        printf("    Replay Ingestion Time:   %.4f ± %.4f s [min: %.4f, max: %.4f]\n",
               st_dur.mean, st_dur.stddev, st_dur.min, st_dur.max);
        printf("    CPU Time (User / Sys):   user: %.1f ± %.1f ms | sys: %.1f ± %.1f ms\n",
               st_ucpu.mean, st_ucpu.stddev, st_scpu.mean, st_scpu.stddev);
        printf("    Isolated Peak RSS:       %.2f ± %.2f MiB [min: %.2f, max: %.2f]\n",
               st_rss.mean, st_rss.stddev, st_rss.min, st_rss.max);
        printf("    Subgraph Extraction:     PID filter: %.2f ± %.2f us | Token filter: %.2f ± %.2f us\n",
               st_fpid.mean, st_fpid.stddev, st_ftok.mean, st_ftok.stddev);
        printf("    Export Overhead (DOT):   %.2f ± %.2f ms (output: %zu bytes)\n",
               st_edot.mean, st_edot.stddev, all_trials[s][0].dot_bytes);
        printf("    Export Overhead (JSON):  %.2f ± %.2f ms (output: %zu bytes)\n",
               st_ejson.mean, st_ejson.stddev, all_trials[s][0].json_bytes);
        printf("    Export Overhead (TL):    %.2f ± %.2f ms (output: %zu bytes)\n",
               st_etl.mean, st_etl.stddev, all_trials[s][0].timeline_bytes);
        printf("\n");

        unlink(evid_path);
        char mf_path[512];
        snprintf(mf_path, sizeof(mf_path), "%s.manifest", evid_path);
        unlink(mf_path);
    }

    /* Output complete structured JSON report */
    FILE *fj = fopen("tests1.0/kernel_telemetry/benchmark_provenance_perf_results.json", "w");
    if (fj) {
        fprintf(fj, "{\n");
        fprintf(fj, "  \"benchmark\": \"Provenance Benchmark 01 — Computational Performance\",\n");
        fprintf(fj, "  \"timestamp\": %llu,\n", (unsigned long long)get_time_ns());
        fprintf(fj, "  \"repetitions\": %d,\n", NUM_REPS);
        fprintf(fj, "  \"scales\": [\n");
        for (size_t s = 0; s < NUM_SCALES; s++) {
            fprintf(fj, "    {\n");
            fprintf(fj, "      \"scale\": %zu,\n", SCALES[s]);
            fprintf(fj, "      \"node_count\": %zu,\n", all_trials[s][0].node_count);
            fprintf(fj, "      \"edge_count\": %zu,\n", all_trials[s][0].edge_count);
            fprintf(fj, "      \"trials\": [\n");
            for (int r = 0; r < NUM_REPS; r++) {
                struct trial_result *t = &all_trials[s][r];
                fprintf(fj, "        {\n");
                fprintf(fj, "          \"rep\": %d,\n", t->rep);
                fprintf(fj, "          \"duration_s\": %.6f,\n", t->duration_s);
                fprintf(fj, "          \"throughput_eps\": %.1f,\n", t->throughput_eps);
                fprintf(fj, "          \"user_cpu_ms\": %.2f,\n", t->user_cpu_ms);
                fprintf(fj, "          \"sys_cpu_ms\": %.2f,\n", t->sys_cpu_ms);
                fprintf(fj, "          \"peak_rss_kb\": %ld,\n", t->peak_rss_kb);
                fprintf(fj, "          \"peak_rss_mib\": %.2f,\n", (double)t->peak_rss_kb / 1024.0);
                fprintf(fj, "          \"filter_pid_us\": %.2f,\n", t->filter_pid_us);
                fprintf(fj, "          \"filter_token_us\": %.2f,\n", t->filter_token_us);
                fprintf(fj, "          \"export_dot_ms\": %.2f,\n", t->export_dot_ms);
                fprintf(fj, "          \"export_json_ms\": %.2f,\n", t->export_json_ms);
                fprintf(fj, "          \"export_timeline_ms\": %.2f,\n", t->export_timeline_ms);
                fprintf(fj, "          \"dot_bytes\": %zu,\n", t->dot_bytes);
                fprintf(fj, "          \"json_bytes\": %zu,\n", t->json_bytes);
                fprintf(fj, "          \"timeline_bytes\": %zu\n", t->timeline_bytes);
                fprintf(fj, "        }%s\n", (r == NUM_REPS - 1) ? "" : ",");
            }
            fprintf(fj, "      ]\n");
            fprintf(fj, "    }%s\n", (s == NUM_SCALES - 1) ? "" : ",");
        }
        fprintf(fj, "  ]\n");
        fprintf(fj, "}\n");
        fclose(fj);
        printf("[INFO] Full performance report written to tests1.0/kernel_telemetry/benchmark_provenance_perf_results.json\n");
    }

    return 0;
}
