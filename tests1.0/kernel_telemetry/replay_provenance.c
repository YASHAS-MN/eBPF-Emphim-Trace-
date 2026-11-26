#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/resource.h>

#include "provenance.h"
#include "evidence_io.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <evid_path> [dot_out_path] [--incoming|--outgoing]\n", argv[0]);
        return 1;
    }
    const char *evid_path = NULL;
    const char *dot_out = NULL;
    int search_mode = 0;

    const char *env_mode = getenv("PROV_SEARCH_MODE");
    if (env_mode && atoi(env_mode) == 1) {
        search_mode = 1;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--outgoing") == 0) {
            search_mode = 1;
        } else if (strcmp(argv[i], "--incoming") == 0) {
            search_mode = 0;
        } else if (!evid_path) {
            evid_path = argv[i];
        } else if (!dot_out) {
            dot_out = argv[i];
        }
    }

    if (!evid_path) {
        fprintf(stderr, "Usage: %s <evid_path> [dot_out_path] [--incoming|--outgoing]\n", argv[0]);
        return 1;
    }

    struct evidence_reader reader;
    if (evidence_reader_open(&reader, evid_path) != 0) {
        fprintf(stderr, "Failed to open evidence file %s: corrupt or missing\n", evid_path);
        printf("{\"status\":\"ERROR\",\"error\":\"reader_open_failed\",\"records_verified\":0,\"records_replayed\":0}\n");
        return 2;
    }

    if (prov_engine_init() != 0) {
        evidence_reader_close(&reader);
        fprintf(stderr, "Failed to init provenance engine\n");
        printf("{\"status\":\"ERROR\",\"error\":\"prov_init_failed\",\"records_verified\":0,\"records_replayed\":0}\n");
        return 3;
    }

    prov_engine_set_search_mode(search_mode);

    struct rusage ru_start, ru_end;
    getrusage(RUSAGE_SELF, &ru_start);

    struct event ev;
    struct evidence_record_frame frame;
    uint64_t t0 = evidence_time_now_ns();
    int read_rc = 0;

    while ((read_rc = evidence_reader_read_next(&reader, &ev, &frame)) == 1) {
        prov_engine_process_event(&ev);
        if (reader.stats.records_replayed > 0 && reader.stats.records_replayed % 50000 == 0) {
            uint64_t cur_ts = evidence_time_now_ns();
            double elapsed_s = (double)(cur_ts - t0) / 1e9;
            double rate = (elapsed_s > 0) ? ((double)reader.stats.records_replayed / elapsed_s) : 0;
            size_t cur_nodes = 0, cur_edges = 0;
            prov_engine_get_counts(&cur_nodes, &cur_edges);
            fprintf(stderr, "[replay] Progress: %llu records replayed (%zu nodes, %zu edges, %.2fs, %.1f rec/s)\n",
                    (unsigned long long)reader.stats.records_replayed,
                    cur_nodes, cur_edges, elapsed_s, rate);
        }
    }
    uint64_t t1 = evidence_time_now_ns();

    if (read_rc < 0) {
        fprintf(stderr, "[replay] Reader halted on error: code=%d (corrupt=%llu, seq_gaps=%llu, incomplete=%llu)\n",
                read_rc,
                (unsigned long long)reader.stats.corrupt_records,
                (unsigned long long)reader.stats.seq_gaps,
                (unsigned long long)reader.stats.incomplete_records);
    }

    size_t nodes = 0, edges = 0;
    prov_engine_get_counts(&nodes, &edges);
    uint64_t edge_comps = prov_engine_get_edge_comparisons();

    int dot_rc = 0;
    if (dot_out && dot_out[0]) {
        dot_rc = prov_engine_export_dot(dot_out);
        if (dot_rc != 0) {
            fprintf(stderr, "[replay] Failed to export DOT graph to %s: rc=%d\n", dot_out, dot_rc);
        }
    }

    getrusage(RUSAGE_SELF, &ru_end);
    prov_engine_destroy();
    evidence_reader_close(&reader);

    uint64_t replay_duration_ns = (t1 > t0) ? (t1 - t0) : 0;
    long user_cpu_us = (ru_end.ru_utime.tv_sec - ru_start.ru_utime.tv_sec) * 1000000L +
                       (ru_end.ru_utime.tv_usec - ru_start.ru_utime.tv_usec);
    long sys_cpu_us = (ru_end.ru_stime.tv_sec - ru_start.ru_stime.tv_sec) * 1000000L +
                      (ru_end.ru_stime.tv_usec - ru_start.ru_stime.tv_usec);
    long replay_cpu_us = user_cpu_us + sys_cpu_us;
    long peak_rss_kb = ru_end.ru_maxrss;

    bool success = (read_rc == 0 && dot_rc == 0 &&
                    reader.stats.corrupt_records == 0 &&
                    reader.stats.incomplete_records == 0);

    printf("{\"status\":\"%s\",\"records_verified\":%llu,\"records_replayed\":%llu,\"corrupt_records\":%llu,\"seq_gaps\":%llu,\"incomplete_records\":%llu,\"nodes\":%zu,\"edges\":%zu,\"edge_comparisons\":%llu,\"replay_duration_ns\":%llu,\"replay_cpu_us\":%ld,\"peak_rss_kb\":%ld}\n",
           success ? "OK" : "ERROR",
           (unsigned long long)reader.stats.records_verified,
           (unsigned long long)reader.stats.records_replayed,
           (unsigned long long)reader.stats.corrupt_records,
           (unsigned long long)reader.stats.seq_gaps,
           (unsigned long long)reader.stats.incomplete_records,
           nodes, edges,
           (unsigned long long)edge_comps,
           (unsigned long long)replay_duration_ns,
           replay_cpu_us,
           peak_rss_kb);

    return success ? 0 : 4;
}
