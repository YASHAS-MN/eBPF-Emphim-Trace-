/* Diagnostic counters only; original ring capacity and hook logic unchanged. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u32);
} diag_cfg SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 824);
    __type(key, __u32);
    __type(value, __u64);
} diag_stats SEC(".maps");
static __always_inline int diag_target(void) {
    __u32 zero=0;
    __u32 *p=bpf_map_lookup_elem(&diag_cfg,&zero);
    return p && *p && *p == (__u32)(bpf_get_current_pid_tgid() >> 32);
}
static __always_inline int diag_inject_map_fail(__u32 base) {
    if (!diag_target()) return 0;
    __u32 one = 1;
    __u32 *flags = bpf_map_lookup_elem(&diag_cfg, &one);
    if (!flags || !*flags) return 0;

    /* Base 758: memfd_file_registry update (MAPS index 5) */
    if (base == 758 && (*flags & 0x1))
        return 1;
    /* Base 764: memfd_desc_registry update (MAPS index 6) */
    if (base == 764 && (*flags & 0x2))
        return 1;
    /* Base 770: memfd_inode_registry update (MAPS index 7) */
    if (base == 770 && (*flags & 0x4))
        return 1;

    return 0;
}
static __always_inline void diag_inc(__u32 k) {
    __u64 *v=bpf_map_lookup_elem(&diag_stats,&k);
    if (v) __sync_fetch_and_add(v,1);
}
static __always_inline void diag_event(__u32 type, __u32 stage) {
    if (type>=100 || stage>=3) return;
    __u32 k=type*3+stage;
    diag_inc(k);
    if (diag_target()) diag_inc(k+300);
}
static __always_inline void diag_submit(struct event *e) {
    diag_event(e->type,2);
    bpf_ringbuf_submit(e,0);
}

static __always_inline void diag_map_count(__u32 k) {
    diag_inc(k);
    if (diag_target()) diag_inc(k+48);
}
#define DIAG_MAP_CALL(base, call) ({ \
    diag_map_count(base); \
    long diag_rc; \
    if (diag_inject_map_fail(base)) { \
        diag_rc = -7; /* Injected -E2BIG on target registry insertion */ \
    } else { \
        diag_rc = (call); \
    } \
    if (diag_rc == -2) diag_map_count((base)+2); \
    else if (diag_rc < 0) diag_map_count((base)+1); \
    diag_rc; \
})
