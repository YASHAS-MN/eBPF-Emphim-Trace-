/* Diagnostic Checkpoint P instrumentation for provenance engine */
#ifndef DIAG_PROV_PROBE_H
#define DIAG_PROV_PROBE_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum diag_p_status {
    P_STATUS_UNAVAILABLE = 0,
    P_STATUS_SUCCESS = 1,
    P_STATUS_FILTERED = 2,
    P_STATUS_CORRELATION_DEFICIENCY = 3,
    P_STATUS_EDGE_SUPPRESSED = 4,
    P_STATUS_FAILED = 5
};

struct diag_p_stats {
    uint64_t success;
    uint64_t filtered;
    uint64_t correlation_deficiency;
    uint64_t edge_suppressed;
    uint64_t failed;
};

#ifndef DIAG_TIMING_STAT_DEF
#define DIAG_TIMING_STAT_DEF
struct diag_timing_stat {
    uint64_t count;
    uint64_t total_ns;
    uint64_t min_ns;
    uint64_t max_ns;
};
#endif

static struct diag_p_stats g_diag_p_stats;
static uint32_t g_diag_last_p_status = P_STATUS_UNAVAILABLE;
static int g_diag_inject_p_fail = 0;
static struct diag_timing_stat g_diag_p_timing;

static inline void diag_record_p_outcome(uint32_t status) {
    g_diag_last_p_status = status;
    switch (status) {
        case P_STATUS_SUCCESS: g_diag_p_stats.success++; break;
        case P_STATUS_FILTERED: g_diag_p_stats.filtered++; break;
        case P_STATUS_CORRELATION_DEFICIENCY: g_diag_p_stats.correlation_deficiency++; break;
        case P_STATUS_EDGE_SUPPRESSED: g_diag_p_stats.edge_suppressed++; break;
        case P_STATUS_FAILED: g_diag_p_stats.failed++; break;
        default: break;
    }
}

void diag_p_set_inject_fail(int fail) {
    g_diag_inject_p_fail = fail;
}

int diag_p_should_inject_fail(void) {
    return g_diag_inject_p_fail || (getenv("EPHIM_DIAG_INJECT_P_FAIL") && !strcmp(getenv("EPHIM_DIAG_INJECT_P_FAIL"), "1"));
}

#define diag_should_inject_p_fail() diag_p_should_inject_fail()

uint32_t diag_p_get_last_status(void) {
    return g_diag_last_p_status;
}

void diag_p_get_stats(struct diag_p_stats *out) {
    if (out) *out = g_diag_p_stats;
}

static inline uint64_t diag_p_time_now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static inline void diag_p_record_timing(uint64_t delta_ns) {
    g_diag_p_timing.count++;
    g_diag_p_timing.total_ns += delta_ns;
    if (g_diag_p_timing.count == 1 || delta_ns < g_diag_p_timing.min_ns) g_diag_p_timing.min_ns = delta_ns;
    if (delta_ns > g_diag_p_timing.max_ns) g_diag_p_timing.max_ns = delta_ns;
}

void diag_p_get_timing(uint64_t *count, uint64_t *total_ns, uint64_t *min_ns, uint64_t *max_ns) {
    if (count) *count = g_diag_p_timing.count;
    if (total_ns) *total_ns = g_diag_p_timing.total_ns;
    if (min_ns) *min_ns = g_diag_p_timing.min_ns;
    if (max_ns) *max_ns = g_diag_p_timing.max_ns;
}

void diag_p_reset(void) {
    memset(&g_diag_p_stats, 0, sizeof(g_diag_p_stats));
    memset(&g_diag_p_timing, 0, sizeof(g_diag_p_timing));
    g_diag_last_p_status = P_STATUS_UNAVAILABLE;
    g_diag_inject_p_fail = 0;
}

#endif
