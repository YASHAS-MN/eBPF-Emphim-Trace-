#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <assert.h>

#include "../src/user/provenance.h"
#include "../src/user/provenance.c"

#define NOISE_WORKERS 4

static void *noise_worker_thread(void *arg)
{
    long worker_id = (long)arg;
    char name[64];
    snprintf(name, sizeof(name), "noise_worker_mfd_%ld", worker_id);

    int fd = memfd_create(name, 0);
    if (fd >= 0) {
        char buf[256];
        memset(buf, 0x4e, sizeof(buf)); /* 'N' for noise */
        (void)!write(fd, buf, sizeof(buf));
        int d = dup(fd);
        if (d >= 0) close(d);
        close(fd);
    }
    return NULL;
}

int main(void)
{
    printf("\n=================================================================\n");
    printf("=== EphimTrace Milestone 6 Phase 2: Subgraph Filtering & Timeline ===\n");
    printf("=================================================================\n");

    /* 1. Initialize Provenance Engine */
    int rc = prov_engine_init();
    assert(rc == 0);
    printf("[INIT] Provenance engine initialized cleanly.\n");

    /* 2. Create Background Noise (real threads & simulated events) */
    printf("\n[STEP 1: Generating Background Worker Noise]\n");
    pthread_t threads[NOISE_WORKERS];
    for (long i = 0; i < NOISE_WORKERS; i++) {
        pthread_create(&threads[i], NULL, noise_worker_thread, (void *)i);
    }
    for (int i = 0; i < NOISE_WORKERS; i++) {
        pthread_join(threads[i], NULL);
    }

    /* Feed distinct background worker noise events into the provenance engine */
    for (uint32_t w = 1; w <= 5; w++) {
        uint32_t worker_pid = 3000 + w;
        uint64_t worker_token = 10000 + w;

        /* Worker process exec */
        struct event ew_exec = {
            .type = EVENT_PROCESS_EXEC,
            .pid = worker_pid,
            .start_time_ns = 500000000ULL + w,
            .timestamp_ns = 500000100ULL + w,
        };
        snprintf(ew_exec.name, sizeof(ew_exec.name), "background_noise_worker_%u", w);
        prov_engine_process_event(&ew_exec);

        /* Worker creates memfd */
        struct event ew_mfd = {
            .type = EVENT_MEMFD_COMPLETED,
            .pid = worker_pid,
            .start_time_ns = 500000000ULL + w,
            .op_type = 2,
            .object_token = worker_token,
            .inode_no = 80000 + w,
            .dev_id = 66,
            .fd = 3,
            .timestamp_ns = 500000200ULL + w,
        };
        snprintf(ew_mfd.name, sizeof(ew_mfd.name), "noise_payload_%u", w);
        prov_engine_process_event(&ew_mfd);

        /* Worker writes bytes */
        struct event ew_wr = {
            .type = EVENT_MEMFD_WRITE,
            .pid = worker_pid,
            .start_time_ns = 500000000ULL + w,
            .object_token = worker_token,
            .entry_ts_ns = 0,
            .ret_val = 512,
            .timestamp_ns = 500000300ULL + w,
        };
        prov_engine_process_event(&ew_wr);

        /* Worker closes descriptor */
        struct event ew_cl = {
            .type = EVENT_FD_CLOSED,
            .pid = worker_pid,
            .start_time_ns = 500000000ULL + w,
            .object_token = worker_token,
            .fd = 3,
            .entry_ts_ns = 25000,
            .timestamp_ns = 500000400ULL + w,
        };
        prov_engine_process_event(&ew_cl);
    }

    size_t initial_nodes = 0, initial_edges = 0;
    prov_engine_get_counts(&initial_nodes, &initial_edges);
    printf("  [PASS] Background noise registered: %zu nodes, %zu edges\n", initial_nodes, initial_edges);
    assert(initial_nodes >= 10);
    assert(initial_edges >= 15);

    /* 3. Run Distinct Targeted Child Sequence */
    printf("\n[STEP 2: Executing Targeted Target Child Sequence]\n");
    const char *temp_file = "/tmp/test_m6_suspect_temp.dat";

    pid_t target_child = fork();
    assert(target_child >= 0);

    if (target_child == 0) {
        /* In Target Child */
        int fd = memfd_create("suspect_payload", 0);
        if (fd < 0) _exit(1);

        char payload[1024];
        memset(payload, 0x58, sizeof(payload)); /* 'X' */
        if (write(fd, payload, sizeof(payload)) != (ssize_t)sizeof(payload)) _exit(2);

        int dup_fd = dup(fd);
        if (dup_fd < 0) _exit(3);

        int tfd = open(temp_file, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (tfd >= 0) close(tfd);

        if (unlink(temp_file) != 0) _exit(4);

        close(dup_fd);
        close(fd);
        _exit(0);
    }

    /* Master waits for child */
    int status = 0;
    waitpid(target_child, &status, 0);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    printf("  [PASS] Target child %d completed operations cleanly (code 0)\n", target_child);

    /* Feed target sequence telemetry into the engine with strictly increasing timestamps */
    uint64_t target_token = 99001;
    uint64_t t_base = 600000000ULL;

    /* 1. Target child process identity */
    struct event e_target_proc = {
        .type = EVENT_PROCESS_EXEC,
        .pid = (uint32_t)target_child,
        .start_time_ns = t_base,
        .timestamp_ns = t_base + 10,
    };
    snprintf(e_target_proc.name, sizeof(e_target_proc.name), "target_suspect_child");
    prov_engine_process_event(&e_target_proc);

    /* 2. Target child creates memfd "suspect_payload" */
    struct event e_mfd_create = {
        .type = EVENT_MEMFD_COMPLETED,
        .pid = (uint32_t)target_child,
        .start_time_ns = t_base,
        .op_type = 2, /* SUCCESS_CORRELATED */
        .object_token = target_token,
        .inode_no = 771122,
        .dev_id = 66,
        .fd = 3,
        .timestamp_ns = t_base + 100,
    };
    snprintf(e_mfd_create.name, sizeof(e_mfd_create.name), "suspect_payload");
    prov_engine_process_event(&e_mfd_create);

    /* 3. Target child writes 1024 bytes */
    struct event e_mfd_write = {
        .type = EVENT_MEMFD_WRITE,
        .pid = (uint32_t)target_child,
        .start_time_ns = t_base,
        .object_token = target_token,
        .entry_ts_ns = 0,    /* offset */
        .ret_val = 1024,     /* bytes */
        .timestamp_ns = t_base + 200,
    };
    prov_engine_process_event(&e_mfd_write);

    /* 4. Target child duplicates FD */
    struct event e_mfd_dup = {
        .type = EVENT_FD_INSTALLED,
        .pid = (uint32_t)target_child,
        .start_time_ns = t_base,
        .object_token = target_token,
        .fd = 4,
        .op_type = 3, /* DUP */
        .timestamp_ns = t_base + 300,
    };
    prov_engine_process_event(&e_mfd_dup);

    /* 5. Target child unlinks temporary file */
    struct event e_unlink = {
        .type = EVENT_VFS_UNLINK_COMPLETED,
        .pid = (uint32_t)target_child,
        .start_time_ns = t_base,
        .inode_no = 883344,
        .dev_id = 2049,
        .mnt_ns_id = 4026531840U,
        .ret_val = 0,
        .dirfd = -100,
        .timestamp_ns = t_base + 400,
    };
    snprintf(e_unlink.path, sizeof(e_unlink.path), "%s", temp_file);
    prov_engine_process_event(&e_unlink);

    size_t total_nodes = 0, total_edges = 0;
    prov_engine_get_counts(&total_nodes, &total_edges);
    printf("  [INFO] Total unfiltered graph state: %zu nodes, %zu edges\n", total_nodes, total_edges);

    /* 4. Subgraph Filtering Assertion */
    printf("\n[STEP 3: Invoking Subgraph Filtering for Target Child PID %d]\n", target_child);
    struct prov_graph filtered = {0};
    rc = prov_engine_filter_subgraph((uint32_t)target_child, 0, &filtered);
    assert(rc == 0);

    printf("  [VERIFY] Filtered subgraph contains %zu nodes, %zu edges\n",
           filtered.node_count, filtered.edge_count);

    /* Assert that the filtered subgraph contains EXACTLY:
     * 1. Target Child Process
     * 2. Suspect Payload Memfd
     * 3. Temporary Unlinked File
     * And completely omits all 5 background noise workers and their resources.
     */
    assert(filtered.node_count == 3);
    assert(filtered.edge_count == 4);

    bool found_target_child = false;
    bool found_suspect_memfd = false;
    bool found_unlinked_file = false;

    for (size_t i = 0; i < filtered.node_count; i++) {
        struct prov_node *n = filtered.nodes[i];
        if (n->type == NODE_PROCESS) {
            assert(n->proc.pid == (uint32_t)target_child);
            found_target_child = true;
        } else if (n->type == NODE_MEMFD) {
            assert(n->memfd.object_token == target_token);
            assert(strcmp(n->memfd.name, "suspect_payload") == 0);
            found_suspect_memfd = true;
        } else if (n->type == NODE_FS_OBJECT) {
            assert(n->fs.inode_no == 883344);
            assert(strcmp(n->fs.path, temp_file) == 0);
            found_unlinked_file = true;
        } else {
            assert(false && "Unexpected node type in filtered subgraph");
        }
    }

    assert(found_target_child);
    assert(found_suspect_memfd);
    assert(found_unlinked_file);
    printf("  [PASS] Verified: Filtered subgraph strictly isolates target child, suspect memfd, and unlinked file!\n");
    printf("  [PASS] Background worker noise completely omitted (0 noise nodes in subgraph).\n");

    /* 5. Forensic Timeline Verification */
    printf("\n[STEP 4: Generating & Verifying Forensic Timeline]\n");
    const char *timeline_path = "/tmp/test_m6_timeline.md";
    rc = prov_engine_export_timeline(timeline_path, (uint32_t)target_child, 0);
    assert(rc == 0);

    FILE *tf = fopen(timeline_path, "r");
    assert(tf != NULL);

    char line[1024];
    int event_seq = 0;
    bool saw_create = false;
    bool saw_write = false;
    bool saw_dup = false;
    bool saw_unlink = false;

    while (fgets(line, sizeof(line), tf)) {
        if (strstr(line, "[MEMFD_CREATE]")) {
            assert(!saw_create && !saw_write && !saw_dup && !saw_unlink);
            assert(strstr(line, "suspect_payload") != NULL);
            saw_create = true;
            event_seq++;
        } else if (strstr(line, "[MEMFD_WRITE]")) {
            assert(saw_create && !saw_write && !saw_dup && !saw_unlink);
            assert(strstr(line, "Bytes: 1024") != NULL);
            saw_write = true;
            event_seq++;
        } else if (strstr(line, "[FD_INSTALLED]")) {
            assert(saw_create && saw_write && !saw_dup && !saw_unlink);
            assert(strstr(line, "fd_install(DUP)") != NULL);
            saw_dup = true;
            event_seq++;
        } else if (strstr(line, "[UNLINK]")) {
            assert(saw_create && saw_write && saw_dup && !saw_unlink);
            assert(strstr(line, temp_file) != NULL);
            saw_unlink = true;
            event_seq++;
        }

        /* Verify no background worker leaks into timeline */
        assert(strstr(line, "background_noise_worker") == NULL);
        assert(strstr(line, "noise_payload") == NULL);
    }
    fclose(tf);

    assert(saw_create && saw_write && saw_dup && saw_unlink);
    assert(event_seq == 4);
    printf("  [PASS] Timeline sequentially ordered:\n");
    printf("         1. [MEMFD_CREATE] suspect_payload\n");
    printf("         2. [MEMFD_WRITE] 1024 bytes\n");
    printf("         3. [FD_INSTALLED] DUP\n");
    printf("         4. [UNLINK] %s\n", temp_file);
    unlink(timeline_path);

    /* 6. Filtered DOT & JSON Export Verification */
    printf("\n[STEP 5: Testing Filtered DOT and JSON Exports]\n");
    const char *fdot_path = "/tmp/test_m6_filtered.dot";
    const char *fjson_path = "/tmp/test_m6_filtered.json";

    assert(prov_engine_export_filtered_dot(fdot_path, (uint32_t)target_child, 0) == 0);
    assert(prov_engine_export_filtered_json(fjson_path, (uint32_t)target_child, 0) == 0);

    FILE *fdot = fopen(fdot_path, "r");
    assert(fdot != NULL);
    fseek(fdot, 0, SEEK_END);
    long fdot_sz = ftell(fdot);
    fclose(fdot);
    assert(fdot_sz > 200);
    unlink(fdot_path);

    FILE *fjson = fopen(fjson_path, "r");
    assert(fjson != NULL);
    fseek(fjson, 0, SEEK_END);
    long fjson_sz = ftell(fjson);
    fclose(fjson);
    assert(fjson_sz > 200);
    unlink(fjson_path);

    printf("  [PASS] Filtered DOT (%ld bytes) and JSON (%ld bytes) exports verified.\n", fdot_sz, fjson_sz);

    /* Teardown */
    prov_graph_free(&filtered);
    prov_engine_destroy();
    printf("\n=== EphimTrace Milestone 6 Phase 2: All Filtering & Timeline Tests Passed! ===\n\n");
    return 0;
}
