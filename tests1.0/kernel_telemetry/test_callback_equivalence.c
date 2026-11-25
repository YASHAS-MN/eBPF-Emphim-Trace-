#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/types.h>

/* Rename main in loader.c so we can include it directly */
#define main loader_main
#include "src/user/loader.c"
#undef main

/* Checkpoint P probe prototypes from prov_probe.inc (compiled in provenance.diag.c) */
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

extern uint32_t diag_p_get_last_status(void);
extern void diag_p_get_stats(struct diag_p_stats *out);
extern void diag_p_reset(void);

#define NUM_TEST_EVENTS 26

static void build_deterministic_event_sequence(struct event *ev, size_t max_count) {
    assert(max_count >= NUM_TEST_EVENTS);
    memset(ev, 0, sizeof(*ev) * max_count);

    uint64_t t = 1000000000ULL;

    /* 0: EVENT_FORK - parent 1000 forks child process 2000 (child_tgid 2000, start_time 1000000) */
    ev[0].type = EVENT_FORK;
    ev[0].pid = 1000;
    ev[0].tid = 1000;
    ev[0].ppid = 999;
    ev[0].child_tgid = 2000;
    ev[0].child_pid = 2000;
    ev[0].start_time_ns = 500000;
    ev[0].child_start_time_ns = 1000000;
    ev[0].timestamp_ns = t++;
    snprintf(ev[0].name, sizeof(ev[0].name), "parent_proc");

    /* 1: EVENT_FORK - child process 2000 clones thread 2001 (shares child_start_time 1000000) */
    ev[1].type = EVENT_FORK;
    ev[1].pid = 2000;
    ev[1].tid = 2000;
    ev[1].ppid = 1000;
    ev[1].child_tgid = 2000;
    ev[1].child_pid = 2001;
    ev[1].start_time_ns = 1000000;
    ev[1].child_start_time_ns = 1000000;
    ev[1].timestamp_ns = t++;
    snprintf(ev[1].name, sizeof(ev[1].name), "worker_t1");

    /* 2: EVENT_EXECVE - PID 2000 invokes execve */
    ev[2].type = EVENT_EXECVE;
    ev[2].pid = 2000;
    ev[2].tid = 2000;
    ev[2].ppid = 1000;
    ev[2].start_time_ns = 1000000;
    ev[2].timestamp_ns = t++;
    snprintf(ev[2].name, sizeof(ev[2].name), "/usr/bin/ephim_app");

    /* 3: EVENT_PROCESS_EXEC - commit exec */
    ev[3].type = EVENT_PROCESS_EXEC;
    ev[3].pid = 2000;
    ev[3].tid = 2000;
    ev[3].ppid = 1000;
    ev[3].start_time_ns = 1000000;
    ev[3].timestamp_ns = t++;
    snprintf(ev[3].name, sizeof(ev[3].name), "ephim_app");

    /* 4: EVENT_MEMFD_CREATE - entry of memfd syscall (token 0) */
    ev[4].type = EVENT_MEMFD_CREATE;
    ev[4].pid = 2000;
    ev[4].tid = 2000;
    ev[4].ppid = 1000;
    ev[4].start_time_ns = 1000000;
    ev[4].timestamp_ns = t++;
    ev[4].object_token = 0;
    snprintf(ev[4].name, sizeof(ev[4].name), "shm_payload");

    /* 5: EVENT_MEMFD_COMPLETED - correlated success (token 88801, fd 5) */
    ev[5].type = EVENT_MEMFD_COMPLETED;
    ev[5].pid = 2000;
    ev[5].tid = 2000;
    ev[5].ppid = 1000;
    ev[5].start_time_ns = 1000000;
    ev[5].timestamp_ns = t++;
    ev[5].op_type = 2; /* MEMFD_STATUS_SUCCESS_CORRELATED */
    ev[5].object_token = 88801;
    ev[5].ret_val = 5;
    ev[5].fd = 5;
    ev[5].inode_no = 7001;
    ev[5].dev_id = 15;
    ev[5].flags = VFS_IDENTITY_INODE_VALID | VFS_IDENTITY_DEV_VALID | VFS_IDENTITY_NAME_VALID;
    snprintf(ev[5].name, sizeof(ev[5].name), "shm_payload");
    snprintf(ev[5].path, sizeof(ev[5].path), "/memfd:shm_payload");

    /* 6: EVENT_FD_INSTALLED - creation install */
    ev[6].type = EVENT_FD_INSTALLED;
    ev[6].pid = 2000;
    ev[6].tid = 2000;
    ev[6].start_time_ns = 1000000;
    ev[6].timestamp_ns = t++;
    ev[6].fd = 5;
    ev[6].object_token = 88801;
    ev[6].op_type = 1; /* CREATION */

    /* 7: EVENT_FD_INSTALLED - dup install */
    ev[7].type = EVENT_FD_INSTALLED;
    ev[7].pid = 2000;
    ev[7].tid = 2000;
    ev[7].start_time_ns = 1000000;
    ev[7].timestamp_ns = t++;
    ev[7].fd = 6;
    ev[7].object_token = 88801;
    ev[7].op_type = 3; /* DUP */

    /* 8: EVENT_MEMFD_WRITE - write 4096 bytes at offset 0 */
    ev[8].type = EVENT_MEMFD_WRITE;
    ev[8].pid = 2000;
    ev[8].tid = 2000;
    ev[8].start_time_ns = 1000000;
    ev[8].timestamp_ns = t++;
    ev[8].object_token = 88801;
    ev[8].entry_ts_ns = 0; /* offset */
    ev[8].ret_val = 4096;  /* bytes */

    /* 9: EVENT_MEMFD_EXEC_ATTEMPT */
    ev[9].type = EVENT_MEMFD_EXEC_ATTEMPT;
    ev[9].pid = 2000;
    ev[9].tid = 2000;
    ev[9].start_time_ns = 1000000;
    ev[9].timestamp_ns = t++;
    ev[9].object_token = 88801;
    snprintf(ev[9].name, sizeof(ev[9].name), "embedded_bin");

    /* 10: EVENT_MEMFD_EXEC_SUCCESS */
    ev[10].type = EVENT_MEMFD_EXEC_SUCCESS;
    ev[10].pid = 2000;
    ev[10].tid = 2000;
    ev[10].start_time_ns = 1000000;
    ev[10].timestamp_ns = t++;
    ev[10].object_token = 88801;
    snprintf(ev[10].name, sizeof(ev[10].name), "embedded_bin");

    /* 11: EVENT_FD_CLOSED - close fd 5 */
    ev[11].type = EVENT_FD_CLOSED;
    ev[11].pid = 2000;
    ev[11].tid = 2000;
    ev[11].start_time_ns = 1000000;
    ev[11].timestamp_ns = t++;
    ev[11].fd = 5;
    ev[11].object_token = 88801;
    ev[11].entry_ts_ns = 12000; /* duration */

    /* 12: EVENT_FD_CLOSED - close fd 6 */
    ev[12].type = EVENT_FD_CLOSED;
    ev[12].pid = 2000;
    ev[12].tid = 2000;
    ev[12].start_time_ns = 1000000;
    ev[12].timestamp_ns = t++;
    ev[12].fd = 6;
    ev[12].object_token = 88801;
    ev[12].entry_ts_ns = 15000;

    /* 13: EVENT_MEMFD_FILE_RELEASED */
    ev[13].type = EVENT_MEMFD_FILE_RELEASED;
    ev[13].pid = 2000;
    ev[13].tid = 2000;
    ev[13].start_time_ns = 1000000;
    ev[13].timestamp_ns = t++;
    ev[13].object_token = 88801;
    ev[13].inode_no = 7001;

    /* 14: EVENT_MEMFD_DESTROYED */
    ev[14].type = EVENT_MEMFD_DESTROYED;
    ev[14].pid = 2000;
    ev[14].tid = 2000;
    ev[14].start_time_ns = 1000000;
    ev[14].timestamp_ns = t++;
    ev[14].object_token = 88801;
    ev[14].inode_no = 7001;
    ev[14].dev_id = 15;
    snprintf(ev[14].name, sizeof(ev[14].name), "shm_payload");

    /* 15: EVENT_MEMFD_CREATE - entry of second memfd */
    ev[15].type = EVENT_MEMFD_CREATE;
    ev[15].pid = 2000;
    ev[15].tid = 2001;
    ev[15].ppid = 1000;
    ev[15].start_time_ns = 1000000;
    ev[15].timestamp_ns = t++;
    ev[15].object_token = 0;
    snprintf(ev[15].name, sizeof(ev[15].name), "uncorrelated_memfd");

    /* 16: EVENT_MEMFD_COMPLETED - uncorrelated success (token 0) */
    ev[16].type = EVENT_MEMFD_COMPLETED;
    ev[16].pid = 2000;
    ev[16].tid = 2001;
    ev[16].ppid = 1000;
    ev[16].start_time_ns = 1000000;
    ev[16].timestamp_ns = t++;
    ev[16].op_type = 3; /* MEMFD_STATUS_SUCCESS_UNCORRELATED */
    ev[16].object_token = 0;
    ev[16].ret_val = 7;
    ev[16].fd = 7;
    snprintf(ev[16].name, sizeof(ev[16].name), "uncorrelated_memfd");

    /* 17: EVENT_MEMFD_COMPLETED - failed syscall */
    ev[17].type = EVENT_MEMFD_COMPLETED;
    ev[17].pid = 2000;
    ev[17].tid = 2001;
    ev[17].ppid = 1000;
    ev[17].start_time_ns = 1000000;
    ev[17].timestamp_ns = t++;
    ev[17].op_type = 1; /* MEMFD_STATUS_FAILED */
    ev[17].object_token = 0;
    ev[17].ret_val = -22;
    ev[17].fd = -1;
    snprintf(ev[17].name, sizeof(ev[17].name), "failed_memfd");

    /* 18: EVENT_MEMFD_COMPLETED - duplicate correlated completion (Checkpoint P edge suppression) */
    ev[18] = ev[5];
    ev[18].timestamp_ns = t++;

    /* 19: EVENT_CONNECT */
    ev[19].type = EVENT_CONNECT;
    ev[19].pid = 2000;
    ev[19].tid = 2000;
    ev[19].ppid = 1000;
    ev[19].start_time_ns = 1000000;
    ev[19].timestamp_ns = t++;
    ev[19].family = AF_INET;
    ev[19].port = htons(8080);
    ev[19].fd = 8;
    inet_pton(AF_INET, "127.0.0.1", ev[19].address);

    /* 20: EVENT_UNLINK (intent) */
    ev[20].type = EVENT_UNLINK;
    ev[20].pid = 2000;
    ev[20].tid = 2000;
    ev[20].ppid = 1000;
    ev[20].start_time_ns = 1000000;
    ev[20].timestamp_ns = t++;
    snprintf(ev[20].name, sizeof(ev[20].name), "/tmp/target_file");

    /* 21: EVENT_VFS_UNLINK_COMPLETED */
    ev[21].type = EVENT_VFS_UNLINK_COMPLETED;
    ev[21].pid = 2000;
    ev[21].tid = 2000;
    ev[21].ppid = 1000;
    ev[21].start_time_ns = 1000000;
    ev[21].timestamp_ns = t++;
    ev[21].inode_no = 8001;
    ev[21].dev_id = 15;
    ev[21].mnt_ns_id = 4026531840U;
    ev[21].ret_val = 0;
    ev[21].flags = VFS_IDENTITY_INODE_VALID | VFS_IDENTITY_DEV_VALID | VFS_IDENTITY_NAME_VALID | VFS_IDENTITY_SYSCALL_VALID;
    ev[21].op_type = EVENT_UNLINK;
    snprintf(ev[21].name, sizeof(ev[21].name), "target_file");
    snprintf(ev[21].path, sizeof(ev[21].path), "/tmp/target_file");

    /* 22: EVENT_RMDIR (intent) */
    ev[22].type = EVENT_RMDIR;
    ev[22].pid = 2000;
    ev[22].tid = 2000;
    ev[22].ppid = 1000;
    ev[22].start_time_ns = 1000000;
    ev[22].timestamp_ns = t++;
    snprintf(ev[22].name, sizeof(ev[22].name), "/tmp/target_dir");

    /* 23: EVENT_VFS_RMDIR_COMPLETED */
    ev[23].type = EVENT_VFS_RMDIR_COMPLETED;
    ev[23].pid = 2000;
    ev[23].tid = 2000;
    ev[23].ppid = 1000;
    ev[23].start_time_ns = 1000000;
    ev[23].timestamp_ns = t++;
    ev[23].inode_no = 8002;
    ev[23].dev_id = 15;
    ev[23].mnt_ns_id = 4026531840U;
    ev[23].ret_val = 0;
    ev[23].flags = VFS_IDENTITY_INODE_VALID | VFS_IDENTITY_DEV_VALID | VFS_IDENTITY_NAME_VALID | VFS_IDENTITY_SYSCALL_VALID;
    ev[23].op_type = EVENT_RMDIR;
    snprintf(ev[23].name, sizeof(ev[23].name), "target_dir");
    snprintf(ev[23].path, sizeof(ev[23].path), "/tmp/target_dir");

    /* 24: EVENT_PROCESS_EXIT - thread 2001 exits */
    ev[24].type = EVENT_PROCESS_EXIT;
    ev[24].pid = 2000;
    ev[24].tid = 2001;
    ev[24].start_time_ns = 1000000;
    ev[24].timestamp_ns = t++;
    ev[24].ret_val = 0;
    ev[24].reserved = 0; /* thread exit */
    snprintf(ev[24].name, sizeof(ev[24].name), "ephim_app");

    /* 25: EVENT_PROCESS_EXIT - group process 2000 exits */
    ev[25].type = EVENT_PROCESS_EXIT;
    ev[25].pid = 2000;
    ev[25].tid = 2000;
    ev[25].start_time_ns = 1000000;
    ev[25].timestamp_ns = t++;
    ev[25].ret_val = 0;
    ev[25].reserved = 1; /* process group exit */
    snprintf(ev[25].name, sizeof(ev[25].name), "ephim_app");
}

/* Snapshots for comparative equivalence */
struct run_snapshot {
    long stdout_bytes;
    int process_count;
    struct process_state processes[MAX_PROCESSES];
    int thread_count;
    struct thread_state threads[MAX_THREADS];
    struct diag_p_stats p_stats;
    uint32_t per_event_p_status[NUM_TEST_EVENTS];
    size_t node_count;
    size_t edge_count;
    char json_export[65536];
};

static void execute_callback_sequence(int test_quiet_mode, const struct event *ev, size_t count, struct run_snapshot *snap) {
    memset(snap, 0, sizeof(*snap));

    /* Initialize subsystems */
    assert(prov_engine_init() == 0);
    diag_p_reset();

    process_count = 0;
    thread_count = 0;
    memset(processes, 0, sizeof(processes));
    memset(threads, 0, sizeof(threads));
    next_memfd_instance_id = 1;
    quiet_mode = test_quiet_mode;

    /* Redirect stdout to temporary file to measure exact presentation output bytes */
    FILE *tmp_out = tmpfile();
    assert(tmp_out != NULL);
    int tmp_fd = fileno(tmp_out);
    int saved_stdout = dup(STDOUT_FILENO);
    assert(saved_stdout >= 0);
    fflush(stdout);
    dup2(tmp_fd, STDOUT_FILENO);

    /* Feed identical event sequence through actual handle_event() callback */
    for (size_t i = 0; i < count; i++) {
        handle_event(NULL, (void *)&ev[i], sizeof(ev[i]));
        snap->per_event_p_status[i] = diag_p_get_last_status();
    }

    /* Restore stdout and record bytes written */
    fflush(stdout);
    dup2(saved_stdout, STDOUT_FILENO);
    close(saved_stdout);
    snap->stdout_bytes = ftell(tmp_out);
    fclose(tmp_out);

    /* Record process state snapshot */
    snap->process_count = process_count;
    memcpy(snap->processes, processes, sizeof(processes));
    snap->thread_count = thread_count;
    memcpy(snap->threads, threads, sizeof(threads));

    /* Record Checkpoint P stats */
    diag_p_get_stats(&snap->p_stats);

    /* Record Provenance graph snapshot */
    prov_engine_get_counts(&snap->node_count, &snap->edge_count);

    /* Export JSON graph to verify serialized topology equivalence */
    char tmp_json_path[] = "/tmp/prov_equiv_XXXXXX.json";
    int fd = mkstemps(tmp_json_path, 5);
    assert(fd >= 0);
    close(fd);
    assert(prov_engine_export_json(tmp_json_path) == 0);
    FILE *jf = fopen(tmp_json_path, "r");
    assert(jf != NULL);
    size_t nread = fread(snap->json_export, 1, sizeof(snap->json_export) - 1, jf);
    snap->json_export[nread] = '\0';
    fclose(jf);
    unlink(tmp_json_path);

    /* Clean up provenance engine */
    prov_engine_destroy();
}

int main(void) {
    printf("=================================================================\n");
    printf("=== EphimTrace: Genuine Callback Path Equivalence Test        ===\n");
    printf("=================================================================\n\n");

    struct event ev[NUM_TEST_EVENTS];
    build_deterministic_event_sequence(ev, NUM_TEST_EVENTS);

    struct run_snapshot normal_snap;
    struct run_snapshot quiet_snap;

    printf("[STAGE 1] Executing callback sequence with quiet_mode = 0 (Normal)...\n");
    execute_callback_sequence(0, ev, NUM_TEST_EVENTS, &normal_snap);
    printf("  -> Normal stdout output: %ld bytes emitted\n", normal_snap.stdout_bytes);
    printf("  -> Process count: %d, Thread count: %d\n", normal_snap.process_count, normal_snap.thread_count);
    printf("  -> Provenance Nodes: %zu, Edges: %zu\n", normal_snap.node_count, normal_snap.edge_count);
    printf("  -> Checkpoint P stats: success=%llu, filtered=%llu, uncorr=%llu, suppr=%llu, failed=%llu\n",
           (unsigned long long)normal_snap.p_stats.success,
           (unsigned long long)normal_snap.p_stats.filtered,
           (unsigned long long)normal_snap.p_stats.correlation_deficiency,
           (unsigned long long)normal_snap.p_stats.edge_suppressed,
           (unsigned long long)normal_snap.p_stats.failed);

    assert(normal_snap.stdout_bytes > 0);
    assert(normal_snap.process_count > 0);
    assert(normal_snap.node_count > 0);

    printf("\n[STAGE 2] Executing callback sequence with quiet_mode = 1 (Quiet)...\n");
    execute_callback_sequence(1, ev, NUM_TEST_EVENTS, &quiet_snap);
    printf("  -> Quiet stdout output: %ld bytes emitted\n", quiet_snap.stdout_bytes);
    printf("  -> Process count: %d, Thread count: %d\n", quiet_snap.process_count, quiet_snap.thread_count);
    printf("  -> Provenance Nodes: %zu, Edges: %zu\n", quiet_snap.node_count, quiet_snap.edge_count);
    printf("  -> Checkpoint P stats: success=%llu, filtered=%llu, uncorr=%llu, suppr=%llu, failed=%llu\n",
           (unsigned long long)quiet_snap.p_stats.success,
           (unsigned long long)quiet_snap.p_stats.filtered,
           (unsigned long long)quiet_snap.p_stats.correlation_deficiency,
           (unsigned long long)quiet_snap.p_stats.edge_suppressed,
           (unsigned long long)quiet_snap.p_stats.failed);

    printf("\n[STAGE 3] Performing Exhaustive Invariant & Equivalence Assertions...\n");

    /* 1. Presentation output isolation */
    assert(quiet_snap.stdout_bytes == 0);
    printf("  [PASS] Presentation output strictly silenced in quiet mode (0 bytes vs %ld bytes)\n",
           normal_snap.stdout_bytes);

    /* 2. Process table equivalence */
    assert(normal_snap.process_count == quiet_snap.process_count);
    for (int i = 0; i < normal_snap.process_count; i++) {
        const struct process_state *p1 = &normal_snap.processes[i];
        const struct process_state *p2 = &quiet_snap.processes[i];
        assert(p1->pid == p2->pid);
        assert(p1->start_time_ns == p2->start_time_ns);
        assert(p1->parent_pid == p2->parent_pid);
        assert(p1->last_tid == p2->last_tid);
        assert(p1->thread_count == p2->thread_count);
        assert(p1->exec_count == p2->exec_count);
        assert(p1->active == p2->active);
        assert(strcmp(p1->executable, p2->executable) == 0);
    }
    printf("  [PASS] Process state table is 100%% identical across all %d processes\n", normal_snap.process_count);

    /* 3. Thread table equivalence */
    assert(normal_snap.thread_count == quiet_snap.thread_count);
    for (int i = 0; i < normal_snap.thread_count; i++) {
        const struct thread_state *t1 = &normal_snap.threads[i];
        const struct thread_state *t2 = &quiet_snap.threads[i];
        assert(t1->tid == t2->tid);
        assert(t1->tgid == t2->tgid);
        assert(t1->start_time_ns == t2->start_time_ns);
    }
    printf("  [PASS] Thread state table is 100%% identical across all %d registered threads\n", normal_snap.thread_count);

    /* 4. Checkpoint P outcomes equivalence */
    assert(normal_snap.p_stats.success == quiet_snap.p_stats.success);
    assert(normal_snap.p_stats.filtered == quiet_snap.p_stats.filtered);
    assert(normal_snap.p_stats.correlation_deficiency == quiet_snap.p_stats.correlation_deficiency);
    assert(normal_snap.p_stats.edge_suppressed == quiet_snap.p_stats.edge_suppressed);
    assert(normal_snap.p_stats.failed == quiet_snap.p_stats.failed);

    for (size_t i = 0; i < NUM_TEST_EVENTS; i++) {
        assert(normal_snap.per_event_p_status[i] == quiet_snap.per_event_p_status[i]);
    }
    printf("  [PASS] Checkpoint P per-event statuses and aggregate stats match 100%% identically\n");

    /* 5. Provenance graph equivalence */
    assert(normal_snap.node_count == quiet_snap.node_count);
    assert(normal_snap.edge_count == quiet_snap.edge_count);
    assert(strcmp(normal_snap.json_export, quiet_snap.json_export) == 0);
    printf("  [PASS] Provenance DAG graph topology & attributes match byte-for-byte (%zu nodes, %zu edges)\n",
           normal_snap.node_count, normal_snap.edge_count);

    printf("\n=================================================================\n");
    printf("=== [SUCCESS] ALL CALLBACK EQUIVALENCE INVARIANTS VERIFIED    ===\n");
    printf("=================================================================\n");

    return 0;
}
