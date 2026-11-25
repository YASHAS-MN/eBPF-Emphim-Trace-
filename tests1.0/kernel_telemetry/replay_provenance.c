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
        fprintf(stderr, "Usage: %s <evid_path> [dot_out_path]\n", argv[0]);
        return 1;
    }
    const char *evid_path = argv[1];
    const char *dot_out = (argc >= 3) ? argv[2] : NULL;

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

    struct rusage ru_start, ru_end;
    getrusage(RUSAGE_SELF, &ru_start);

    struct event ev;
    struct evidence_record_frame frame;
    uint64_t t0 = evidence_time_now_ns();
    while (evidence_reader_read_next(&reader, &ev, &frame) == 1) {
        prov_engine_process_event(&ev);
    }
    uint64_t t1 = evidence_time_now_ns();

    size_t nodes = 0, edges = 0;
    prov_engine_get_counts(&nodes, &edges);

    if (dot_out && dot_out[0]) {
        prov_engine_export_dot(dot_out);
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

    printf("{\"status\":\"OK\",\"records_verified\":%llu,\"records_replayed\":%llu,\"corrupt_records\":%llu,\"seq_gaps\":%llu,\"incomplete_records\":%llu,\"nodes\":%zu,\"edges\":%zu,\"replay_duration_ns\":%llu,\"replay_cpu_us\":%ld}\n",
           (unsigned long long)reader.stats.records_verified,
           (unsigned long long)reader.stats.records_replayed,
           (unsigned long long)reader.stats.corrupt_records,
           (unsigned long long)reader.stats.seq_gaps,
           (unsigned long long)reader.stats.incomplete_records,
           nodes, edges,
           (unsigned long long)replay_duration_ns,
           replay_cpu_us);

    return (reader.stats.corrupt_records == 0 && reader.stats.incomplete_records == 0) ? 0 : 4;
}
