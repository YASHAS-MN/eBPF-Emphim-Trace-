/* Diagnostic userspace probe instrumentation */
#include <time.h>
#include <sys/resource.h>

#ifndef DIAG_QUEUE_STATS_DEF
#define DIAG_QUEUE_STATS_DEF
struct diag_queue_stats {
    uint32_t capacity;
    uint64_t admission_attempts;
    uint64_t enqueued;
    uint64_t dequeued;
    uint64_t drops;
    uint32_t high_water_mark;
};
#endif

#ifndef DIAG_HAS_QUEUE_STATS
__attribute__((weak)) int diag_get_queue_stats(struct diag_queue_stats *qs) {
    (void)qs;
    return -1;
}
#endif

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

struct diag_profile_data {
    uint64_t timer_overhead_ns;
    struct diag_timing_stat total_callback;
    struct diag_timing_stat reception;
    struct diag_timing_stat process_state;
    struct diag_timing_stat provenance;
    struct diag_timing_stat logging;

    /* Latency scaling across graph expansion */
    uint64_t early_count;
    uint64_t early_total_ns;
    uint64_t late_count;
    uint64_t late_total_ns;
    uint64_t total_events_seen;
};

static struct diag_profile_data g_diag_profile;

extern uint32_t diag_p_get_last_status(void);
extern void diag_p_get_stats(struct diag_p_stats *out);
extern void diag_p_reset(void);
extern void diag_p_get_timing(uint64_t *count, uint64_t *total_ns, uint64_t *min_ns, uint64_t *max_ns);

static inline uint64_t diag_time_now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static uint64_t diag_target_first_event_ts_ns = 0;
static uint64_t diag_target_last_event_ts_ns = 0;
static uint64_t diag_global_first_event_ts_ns = 0;
static uint64_t diag_global_last_event_ts_ns = 0;
static struct rusage diag_baseline_ru;
static int diag_baseline_ru_valid = 0;

static inline void diag_record_target_event_ts(void) {
    uint64_t now = diag_time_now_ns();
    if (!diag_target_first_event_ts_ns) {
        diag_target_first_event_ts_ns = now;
    }
    diag_target_last_event_ts_ns = now;
}

static inline void diag_record_global_event_ts(void) {
    uint64_t now = diag_time_now_ns();
    if (!diag_global_first_event_ts_ns) {
        diag_global_first_event_ts_ns = now;
    }
    diag_global_last_event_ts_ns = now;
}

static inline void diag_record_event_proc_timestamp(void) {
    diag_record_target_event_ts();
}

static inline void diag_record_baseline_rusage(void) {
    if (getrusage(RUSAGE_SELF, &diag_baseline_ru) == 0) {
        diag_baseline_ru_valid = 1;
    }
}

static inline void diag_timing_record(struct diag_timing_stat *st, uint64_t delta_ns) {
    st->count++;
    st->total_ns += delta_ns;
    if (st->count == 1 || delta_ns < st->min_ns) st->min_ns = delta_ns;
    if (delta_ns > st->max_ns) st->max_ns = delta_ns;
}

static inline void diag_profile_init(void) {
    memset(&g_diag_profile, 0, sizeof(g_diag_profile));
    uint64_t t0 = diag_time_now_ns();
    const int N = 1000;
    for (int i = 0; i < N; i++) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
    }
    uint64_t t1 = diag_time_now_ns();
    g_diag_profile.timer_overhead_ns = (t1 > t0) ? ((t1 - t0) / N) : 0;
}

static inline void diag_profile_record_latency_growth(uint64_t total_ns) {
    g_diag_profile.total_events_seen++;
    if (g_diag_profile.total_events_seen <= 100) {
        g_diag_profile.early_count++;
        g_diag_profile.early_total_ns += total_ns;
    } else {
        g_diag_profile.late_count++;
        g_diag_profile.late_total_ns += total_ns;
    }
}

struct diag_captured_event {
    uint32_t type;
    uint32_t pid;
    uint32_t tid;
    int32_t  ret_val;
    int32_t  fd;
    uint32_t op_type;
    uint32_t flags;
    uint64_t token;
    uint64_t inode_no;
    uint64_t dev_id;
    uint64_t entry_ts;
    uint64_t ts;
    uint32_t p_status;
    char     name[64];
};

#define DIAG_MAX_CAPTURED 131072
static struct diag_captured_event diag_captured_events[DIAG_MAX_CAPTURED];
static uint32_t diag_captured_count = 0;
static uint32_t diag_captured_overflow = 0;

static uint64_t diag_received[2][100];
static uint64_t diag_invalid, diag_other;
static uint32_t diag_pid;
static int diag_full;
static unsigned diag_delay;
static int diag_receive(void *ctx, void *data, size_t size);

static void json_print_escaped_str(FILE *f, const char *s) {
    if (!s) return;
    for (const char *p = s; *p; p++) {
        if (*p == '"') fputs("\\\"", f);
        else if (*p == '\\') fputs("\\\\", f);
        else if (*p >= 32 && *p <= 126) fputc(*p, f);
    }
}

static int diag_report(struct bpf_object *obj) {
    struct bpf_map *m=bpf_object__find_map_by_name(obj,"diag_stats");
    struct bpf_map *orig=bpf_object__find_map_by_name(obj,"prog_counters");
    int n=libbpf_num_possible_cpus();
    if (!m || !orig || n<=0) return -1;
    uint64_t *v=calloc((size_t)n,sizeof(*v));
    if (!v) return -1;
    uint64_t s[824]={0}, c[128]={0};
    for (uint32_t k=0;k<824;k++) {
        if (bpf_map_lookup_elem(bpf_map__fd(m),&k,v)) { free(v); return -1; }
        for (int j=0;j<n;j++) s[k]+=v[j];
    }
    free(v);
    for (uint32_t k=0;k<128;k++) if (bpf_map_lookup_elem(bpf_map__fd(orig),&k,&c[k])) return -1;

    /* Export individual captured events to dedicated file if requested */
    const char *cap_file = getenv("EPHIM_CAPTURED_EVENTS_FILE");
    if (cap_file && cap_file[0]) {
        FILE *cf = fopen(cap_file, "w");
        if (!cf) {
            fprintf(stderr, "FATAL: Failed to open %s for writing: %s\n", cap_file, strerror(errno));
            return -1;
        }
        if (fputs("[\n", cf) == EOF) { fclose(cf); return -1; }
        for (uint32_t i = 0; i < diag_captured_count; i++) {
            struct diag_captured_event *ce = &diag_captured_events[i];
            if (fprintf(cf, "%s{\"type\":%u,\"pid\":%u,\"tid\":%u,\"ret\":%d,\"fd\":%d,\"op\":%u,\"token\":%llu,\"inode\":%llu,\"dev\":%llu,\"entry_ts\":%llu,\"ts\":%llu,\"p\":%u,\"name\":\"",
                    i ? ",\n" : "", ce->type, ce->pid, ce->tid, ce->ret_val, ce->fd, ce->op_type,
                    (unsigned long long)ce->token, (unsigned long long)ce->inode_no, (unsigned long long)ce->dev_id,
                    (unsigned long long)ce->entry_ts, (unsigned long long)ce->ts, ce->p_status) < 0) {
                fclose(cf); return -1;
            }
            json_print_escaped_str(cf, ce->name);
            if (fputs("\"}", cf) == EOF) { fclose(cf); return -1; }
        }
        if (fputs("\n]\n", cf) == EOF || fflush(cf) != 0 || fclose(cf) != 0) {
            return -1;
        }
    }

    printf("DIAG_JSON {\"pid\":%u,\"event_size\":%zu,\"invalid\":%llu,\"unknown_type\":%llu,\"captured_count\":%u,\"captured_overflow\":%u,\"captured_file\":\"%s\",\"events\":[",
           diag_pid,sizeof(struct event),(unsigned long long)diag_invalid,(unsigned long long)diag_other,
           diag_captured_count, diag_captured_overflow, cap_file ? cap_file : "");
    int comma=0;
    for (unsigned scope=0;scope<2;scope++) for (unsigned t=0;t<100;t++) {
        unsigned k=scope*300+t*3;
        if (!(s[k]||s[k+1]||s[k+2]||diag_received[scope][t])) continue;
        printf("%s{\"scope\":%u,\"type\":%u,\"attempted\":%llu,\"reserve_failed\":%llu,\"submitted\":%llu,\"received\":%llu}",
               comma?",":"",scope,t,(unsigned long long)s[k],(unsigned long long)s[k+1],(unsigned long long)s[k+2],(unsigned long long)diag_received[scope][t]);
        comma=1;
    }
    printf("],\"original_counters\":[");
    for (unsigned k=0;k<128;k++) printf("%s%llu",k?",":"", (unsigned long long)c[k]);
    printf("],\"target_counters\":[");
    for (unsigned k=0;k<128;k++) printf("%s%llu",k?",":"", (unsigned long long)s[600+k]);
    printf("],\"map_mutations\":[");
    const char *maps[]={"pending_memfd_map","pending_syscall_map","unlink_identity_map","rmdir_identity_map","pending_memfd_exec","memfd_file_registry","memfd_desc_registry","memfd_inode_registry"};
    comma=0;
    for (unsigned scope=0;scope<2;scope++) for (unsigned m=0;m<8;m++) for (unsigned op=0;op<2;op++) {
        unsigned k=728+scope*48+m*6+op*3;
        if (!s[k]) continue;
        printf("%s{\"scope\":%u,\"map\":\"%s\",\"op\":\"%s\",\"attempted\":%llu,\"other_error\":%llu,\"enoent\":%llu}",
               comma?",":"",scope,maps[m],op?"delete":"update",(unsigned long long)s[k],(unsigned long long)s[k+1],(unsigned long long)s[k+2]);
        comma=1;
    }
    printf("],\"captured_events\":[");
    if (!cap_file || !cap_file[0] || diag_captured_count <= 2000) {
        for (uint32_t i=0; i < diag_captured_count; i++) {
            struct diag_captured_event *ce = &diag_captured_events[i];
            printf("%s{\"type\":%u,\"pid\":%u,\"tid\":%u,\"ret\":%d,\"fd\":%d,\"op\":%u,\"token\":%llu,\"inode\":%llu,\"dev\":%llu,\"entry_ts\":%llu,\"ts\":%llu,\"p\":%u,\"name\":\"",
                   i?",":"", ce->type, ce->pid, ce->tid, ce->ret_val, ce->fd, ce->op_type,
                   (unsigned long long)ce->token, (unsigned long long)ce->inode_no, (unsigned long long)ce->dev_id,
                   (unsigned long long)ce->entry_ts, (unsigned long long)ce->ts, ce->p_status);
            json_print_escaped_str(stdout, ce->name);
            fputs("\"}", stdout);
        }
    }
    if (diag_full) {
        struct diag_p_stats pst;
        diag_p_get_stats(&pst);
        printf("],\"p_checkpoint\":{\"available\":true,\"success\":%llu,\"filtered\":%llu,\"correlation_deficiency\":%llu,\"edge_suppressed\":%llu,\"failed\":%llu}",
               (unsigned long long)pst.success, (unsigned long long)pst.filtered,
               (unsigned long long)pst.correlation_deficiency, (unsigned long long)pst.edge_suppressed,
               (unsigned long long)pst.failed);
    } else {
        printf("],\"p_checkpoint\":{\"available\":false}");
    }

    uint64_t p_cnt = 0, p_tot = 0, p_min = 0, p_max = 0;
    diag_p_get_timing(&p_cnt, &p_tot, &p_min, &p_max);

    uint64_t prov_cnt = g_diag_profile.provenance.count;
    uint64_t prov_tot = g_diag_profile.provenance.total_ns;
    uint64_t prov_min = g_diag_profile.provenance.min_ns;
    uint64_t prov_max = g_diag_profile.provenance.max_ns;
    uint64_t prov_avg = prov_cnt ? (prov_tot / prov_cnt) : 0ULL;
    uint64_t prov_excl_tot = (prov_tot >= p_tot) ? (prov_tot - p_tot) : 0ULL;
    uint64_t prov_excl_avg = prov_cnt ? (prov_excl_tot / prov_cnt) : 0ULL;

    printf(",\"profiling\":{\"timer_overhead_ns\":%llu,\"quiet_mode\":%d,"
           "\"total_callback\":{\"count\":%llu,\"total_ns\":%llu,\"min_ns\":%llu,\"max_ns\":%llu,\"avg_ns\":%llu},"
           "\"reception\":{\"count\":%llu,\"total_ns\":%llu,\"min_ns\":%llu,\"max_ns\":%llu,\"avg_ns\":%llu},"
           "\"process_state\":{\"count\":%llu,\"total_ns\":%llu,\"min_ns\":%llu,\"max_ns\":%llu,\"avg_ns\":%llu},"
           "\"provenance\":{\"count\":%llu,\"total_ns\":%llu,\"min_ns\":%llu,\"max_ns\":%llu,\"avg_ns\":%llu},"
           "\"provenance_inclusive\":{\"count\":%llu,\"total_ns\":%llu,\"min_ns\":%llu,\"max_ns\":%llu,\"avg_ns\":%llu},"
           "\"provenance_exclusive\":{\"count\":%llu,\"total_ns\":%llu,\"avg_ns\":%llu},"
           "\"logging\":{\"count\":%llu,\"total_ns\":%llu,\"min_ns\":%llu,\"max_ns\":%llu,\"avg_ns\":%llu},"
           "\"p_diag_overhead\":{\"count\":%llu,\"total_ns\":%llu,\"min_ns\":%llu,\"max_ns\":%llu,\"avg_ns\":%llu},"
           "\"latency_growth\":{\"early_count\":%llu,\"early_avg_ns\":%llu,\"late_count\":%llu,\"late_avg_ns\":%llu}"
           "}",
           (unsigned long long)g_diag_profile.timer_overhead_ns,
           quiet_mode,
           (unsigned long long)g_diag_profile.total_callback.count,
           (unsigned long long)g_diag_profile.total_callback.total_ns,
           (unsigned long long)g_diag_profile.total_callback.min_ns,
           (unsigned long long)g_diag_profile.total_callback.max_ns,
           g_diag_profile.total_callback.count ? (unsigned long long)(g_diag_profile.total_callback.total_ns / g_diag_profile.total_callback.count) : 0ULL,
           (unsigned long long)g_diag_profile.reception.count,
           (unsigned long long)g_diag_profile.reception.total_ns,
           (unsigned long long)g_diag_profile.reception.min_ns,
           (unsigned long long)g_diag_profile.reception.max_ns,
           g_diag_profile.reception.count ? (unsigned long long)(g_diag_profile.reception.total_ns / g_diag_profile.reception.count) : 0ULL,
           (unsigned long long)g_diag_profile.process_state.count,
           (unsigned long long)g_diag_profile.process_state.total_ns,
           (unsigned long long)g_diag_profile.process_state.min_ns,
           (unsigned long long)g_diag_profile.process_state.max_ns,
           g_diag_profile.process_state.count ? (unsigned long long)(g_diag_profile.process_state.total_ns / g_diag_profile.process_state.count) : 0ULL,
           (unsigned long long)prov_cnt,
           (unsigned long long)prov_tot,
           (unsigned long long)prov_min,
           (unsigned long long)prov_max,
           (unsigned long long)prov_avg,
           (unsigned long long)prov_cnt,
           (unsigned long long)prov_tot,
           (unsigned long long)prov_min,
           (unsigned long long)prov_max,
           (unsigned long long)prov_avg,
           (unsigned long long)prov_cnt,
           (unsigned long long)prov_excl_tot,
           (unsigned long long)prov_excl_avg,
           (unsigned long long)g_diag_profile.logging.count,
           (unsigned long long)g_diag_profile.logging.total_ns,
           (unsigned long long)g_diag_profile.logging.min_ns,
           (unsigned long long)g_diag_profile.logging.max_ns,
           g_diag_profile.logging.count ? (unsigned long long)(g_diag_profile.logging.total_ns / g_diag_profile.logging.count) : 0ULL,
           (unsigned long long)p_cnt,
           (unsigned long long)p_tot,
           (unsigned long long)p_min,
           (unsigned long long)p_max,
           p_cnt ? (unsigned long long)(p_tot / p_cnt) : 0ULL,
           (unsigned long long)g_diag_profile.early_count,
           g_diag_profile.early_count ? (unsigned long long)(g_diag_profile.early_total_ns / g_diag_profile.early_count) : 0ULL,
           (unsigned long long)g_diag_profile.late_count,
           g_diag_profile.late_count ? (unsigned long long)(g_diag_profile.late_total_ns / g_diag_profile.late_count) : 0ULL
    );

    struct rusage ru;
    uint64_t tot_u_cpu = 0, tot_s_cpu = 0, max_rss = 0;
    uint64_t act_u_cpu = 0, act_s_cpu = 0;
    if (getrusage(RUSAGE_SELF, &ru) == 0) {
        tot_u_cpu = (uint64_t)ru.ru_utime.tv_sec * 1000000ULL + (uint64_t)ru.ru_utime.tv_usec;
        tot_s_cpu = (uint64_t)ru.ru_stime.tv_sec * 1000000ULL + (uint64_t)ru.ru_stime.tv_usec;
        max_rss = (uint64_t)ru.ru_maxrss;
        if (diag_baseline_ru_valid) {
            uint64_t base_u = (uint64_t)diag_baseline_ru.ru_utime.tv_sec * 1000000ULL + (uint64_t)diag_baseline_ru.ru_utime.tv_usec;
            uint64_t base_s = (uint64_t)diag_baseline_ru.ru_stime.tv_sec * 1000000ULL + (uint64_t)diag_baseline_ru.ru_stime.tv_usec;
            act_u_cpu = (tot_u_cpu >= base_u) ? (tot_u_cpu - base_u) : 0;
            act_s_cpu = (tot_s_cpu >= base_s) ? (tot_s_cpu - base_s) : 0;
        } else {
            act_u_cpu = tot_u_cpu;
            act_s_cpu = tot_s_cpu;
        }
    }
    printf(",\"rusage\":{\"user_cpu_us\":%llu,\"sys_cpu_us\":%llu,\"active_user_cpu_us\":%llu,\"active_sys_cpu_us\":%llu,\"total_user_cpu_us\":%llu,\"total_sys_cpu_us\":%llu,\"max_rss_kb\":%llu}",
           (unsigned long long)act_u_cpu, (unsigned long long)act_s_cpu,
           (unsigned long long)act_u_cpu, (unsigned long long)act_s_cpu,
           (unsigned long long)tot_u_cpu, (unsigned long long)tot_s_cpu,
           (unsigned long long)max_rss);

    struct diag_queue_stats qs;
    if (diag_get_queue_stats(&qs) == 0) {
        printf(",\"queue\":{\"capacity\":%u,\"admission_attempts\":%llu,\"enqueued\":%llu,\"dequeued\":%llu,\"drops\":%llu,\"high_water_mark\":%u}",
               qs.capacity, (unsigned long long)qs.admission_attempts,
               (unsigned long long)qs.enqueued, (unsigned long long)qs.dequeued,
               (unsigned long long)qs.drops, qs.high_water_mark);
    }

    printf(",\"timing\":{\"first_event_proc_ts_ns\":%llu,\"last_event_proc_ts_ns\":%llu,\"target_first_event_proc_ts_ns\":%llu,\"target_last_event_proc_ts_ns\":%llu,\"global_first_event_ts_ns\":%llu,\"global_last_event_ts_ns\":%llu}",
           (unsigned long long)diag_target_first_event_ts_ns,
           (unsigned long long)diag_target_last_event_ts_ns,
           (unsigned long long)diag_target_first_event_ts_ns,
           (unsigned long long)diag_target_last_event_ts_ns,
           (unsigned long long)diag_global_first_event_ts_ns,
           (unsigned long long)diag_global_last_event_ts_ns);

    puts("}");
    return fflush(stdout)==0?0:-1;
}
