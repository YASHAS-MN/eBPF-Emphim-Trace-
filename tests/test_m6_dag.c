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
#include <assert.h>

#include "../src/user/provenance.h"
#include "../src/user/provenance.c"

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

static char elf_payload[65536];
static size_t elf_payload_len = 0;

static int load_elf_payload(void)
{
    int fd = open("/bin/true", O_RDONLY);
    if (fd < 0) {
        fd = open("/usr/bin/true", O_RDONLY);
    }
    if (fd < 0) {
        perror("Failed to open /bin/true or /usr/bin/true");
        return -1;
    }
    ssize_t n = read(fd, elf_payload, sizeof(elf_payload));
    if (n <= 0) {
        perror("Failed reading ELF binary payload");
        close(fd);
        return -1;
    }
    elf_payload_len = (size_t)n;
    close(fd);
    return 0;
}

static void test_engine_synthetic_dag(void)
{
    printf("\n[TEST] Step 4: Testing in-memory provenance engine DAG construction & export...\n");

    int rc = prov_engine_init();
    assert(rc == 0);

    /* 1. Fork event: parent (1001) -> child (2002) */
    struct event e1 = {
        .type = EVENT_FORK,
        .pid = 1001,
        .tid = 1001,
        .ppid = 1,
        .start_time_ns = 100000000,
        .child_tgid = 2002,
        .child_pid = 2002,
        .child_start_time_ns = 200000000,
        .timestamp_ns = 200000100,
    };
    snprintf(e1.name, sizeof(e1.name), "m6_child_proc");
    prov_engine_process_event(&e1);

    /* 2. Memfd created & completed by child (2002) */
    struct event e2 = {
        .type = EVENT_MEMFD_COMPLETED,
        .pid = 2002,
        .tid = 2002,
        .start_time_ns = 200000000,
        .op_type = 2, /* MEMFD_STATUS_SUCCESS_CORRELATED */
        .object_token = 88888,
        .inode_no = 54321,
        .dev_id = 66,
        .fd = 3,
        .timestamp_ns = 200000200,
    };
    snprintf(e2.name, sizeof(e2.name), "m6_test_memfd");
    prov_engine_process_event(&e2);

    /* 3. Write event by child */
    struct event e3 = {
        .type = EVENT_MEMFD_WRITE,
        .pid = 2002,
        .tid = 2002,
        .start_time_ns = 200000000,
        .object_token = 88888,
        .entry_ts_ns = 0, /* offset */
        .ret_val = 26936, /* bytes */
        .timestamp_ns = 200000300,
    };
    prov_engine_process_event(&e3);

    /* 4. FD installed (DUP) */
    struct event e4 = {
        .type = EVENT_FD_INSTALLED,
        .pid = 2002,
        .tid = 2002,
        .start_time_ns = 200000000,
        .object_token = 88888,
        .fd = 4,
        .op_type = 3, /* DUP */
        .timestamp_ns = 200000400,
    };
    prov_engine_process_event(&e4);

    /* 5. FD closed */
    struct event e5 = {
        .type = EVENT_FD_CLOSED,
        .pid = 2002,
        .tid = 2002,
        .start_time_ns = 200000000,
        .object_token = 88888,
        .fd = 3,
        .entry_ts_ns = 50000, /* duration */
        .timestamp_ns = 200000500,
    };
    prov_engine_process_event(&e5);

    /* 6. Exec attempt */
    struct event e6 = {
        .type = EVENT_MEMFD_EXEC_ATTEMPT,
        .pid = 2002,
        .tid = 2002,
        .start_time_ns = 200000000,
        .object_token = 88888,
        .timestamp_ns = 200000600,
    };
    snprintf(e6.name, sizeof(e6.name), "memfd:m6_test_memfd");
    prov_engine_process_event(&e6);

    /* 7. Exec success */
    struct event e7 = {
        .type = EVENT_MEMFD_EXEC_SUCCESS,
        .pid = 2002,
        .tid = 2002,
        .start_time_ns = 200000000,
        .object_token = 88888,
        .timestamp_ns = 200000700,
    };
    snprintf(e7.name, sizeof(e7.name), "m6_exec_binary");
    prov_engine_process_event(&e7);

    /* 8. Process exit */
    struct event e8 = {
        .type = EVENT_PROCESS_EXIT,
        .pid = 2002,
        .tid = 2002,
        .start_time_ns = 200000000,
        .reserved = 1, /* group dead */
        .ret_val = 0,  /* exit code */
        .timestamp_ns = 200000800,
    };
    prov_engine_process_event(&e8);

    /* 9. FS unlink completed */
    struct event e9 = {
        .type = EVENT_VFS_UNLINK_COMPLETED,
        .pid = 1001,
        .tid = 1001,
        .start_time_ns = 100000000,
        .inode_no = 99901,
        .dev_id = 2049,
        .mnt_ns_id = 4026531840U,
        .ret_val = 0,
        .dirfd = -100,
        .timestamp_ns = 200000900,
    };
    snprintf(e9.path, sizeof(e9.path), "/tmp/m6_temp_file.dat");
    prov_engine_process_event(&e9);

    /* 10. Network connect */
    struct event e10 = {
        .type = EVENT_CONNECT,
        .pid = 1001,
        .tid = 1001,
        .start_time_ns = 100000000,
        .family = AF_INET,
        .port = htons(8080),
        .fd = 5,
        .ret_val = 0,
        .timestamp_ns = 200001000,
    };
    inet_pton(AF_INET, "127.0.0.1", e10.address);
    prov_engine_process_event(&e10);

    /* Verify counts:
     * Nodes:
     * 1. proc_1001_100000000 (Process)
     * 2. proc_2002_200000000 (Process)
     * 3. memfd_88888 (Memfd)
     * 4. fs_2049_99901 (FS Object)
     * 5. net_2_127.0.0.1_8080 (Net Endpoint)
     * Total nodes = 5
     *
     * Edges:
     * 1. FORK (1001 -> 2002)
     * 2. MEMFD_CREATE (2002 -> 88888)
     * 3. MEMFD_WRITE (2002 -> 88888)
     * 4. FD_INSTALLED (2002 -> 88888)
     * 5. FD_CLOSED (2002 -> 88888)
     * 6. MEMFD_EXEC_ATTEMPT (2002 -> 88888)
     * 7. MEMFD_EXEC_SUCCESS (2002 -> 88888)
     * 8. UNLINK (1001 -> fs_2049_99901)
     * 9. CONNECT (1001 -> net_2_127.0.0.1_8080)
     * Total edges = 9
     */
    size_t nc = 0, ec = 0;
    prov_engine_get_counts(&nc, &ec);
    printf("  [VERIFY] Recorded %zu nodes, %zu edges\n", nc, ec);
    assert(nc == 5);
    assert(ec == 9);

    /* Verify node states */
    struct prov_node *child_proc = prov_find_node("proc_2002_200000000");
    assert(child_proc != NULL);
    assert(child_proc->proc.is_alive == false);
    assert(child_proc->proc.exit_code == 0);
    assert(strcmp(child_proc->proc.comm, "m6_exec_binary") == 0);

    struct prov_node *memfd_node = prov_find_node("memfd_88888");
    assert(memfd_node != NULL);
    assert(memfd_node->memfd.object_token == 88888);
    assert(strcmp(memfd_node->memfd.name, "m6_test_memfd") == 0);
    assert(memfd_node->memfd.inode_no == 54321);

    struct prov_node *fs_node = prov_find_node("fs_2049_99901");
    assert(fs_node != NULL);
    assert(fs_node->fs.is_unlinked == true);
    assert(strcmp(fs_node->fs.path, "/tmp/m6_temp_file.dat") == 0);

    struct prov_node *net_node = prov_find_node("net_2_127.0.0.1_8080");
    assert(net_node != NULL);
    assert(net_node->net.port == 8080);
    assert(strcmp(net_node->net.ip_str, "127.0.0.1") == 0);

    /* Export DOT */
    const char *test_dot_path = "/tmp/test_m6_dag.dot";
    int dot_rc = prov_engine_export_dot(test_dot_path);
    assert(dot_rc == 0);

    FILE *df = fopen(test_dot_path, "r");
    assert(df != NULL);
    fseek(df, 0, SEEK_END);
    long df_sz = ftell(df);
    fclose(df);
    assert(df_sz > 200);
    printf("  [PASS] DOT exported successfully (%ld bytes)\n", df_sz);
    unlink(test_dot_path);

    /* Export JSON */
    const char *test_json_path = "/tmp/test_m6_dag.json";
    int json_rc = prov_engine_export_json(test_json_path);
    assert(json_rc == 0);

    FILE *jf = fopen(test_json_path, "r");
    assert(jf != NULL);
    fseek(jf, 0, SEEK_END);
    long jf_sz = ftell(jf);
    fclose(jf);
    assert(jf_sz > 200);
    printf("  [PASS] JSON exported successfully (%ld bytes)\n", jf_sz);
    unlink(test_json_path);

    prov_engine_destroy();
    prov_engine_get_counts(&nc, &ec);
    assert(nc == 0);
    assert(ec == 0);
    printf("  [PASS] Provenance engine destroyed cleanly (0 nodes, 0 edges)\n");
}

int main(void)
{
    pid_t parent_pid = getpid();

    printf("\n=======================================================\n");
    printf("=== EphimTrace Milestone 6: Provenance DAG Test ===\n");
    printf("=======================================================\n");
    printf("[INIT] Master PID: %d\n\n", parent_pid);

    if (load_elf_payload() != 0) {
        fprintf(stderr, "Failed to load ELF binary payload\n");
        return 1;
    }
    printf("  [INIT] Loaded %zu bytes ELF payload from /bin/true\n", elf_payload_len);

    /* 1. Fork child */
    printf("\n[TEST] Step 1: Fork child\n");
    pid_t child = fork();
    if (child < 0) {
        perror("fork failed");
        return 1;
    }

    if (child == 0) {
        /* In Child: */
        /* 2. Create memfd */
        int fd = memfd_create("m6_dag_payload", 0);
        if (fd < 0) {
            perror("memfd_create failed");
            _exit(1);
        }

        /* Write payload */
        if (write(fd, elf_payload, elf_payload_len) != (ssize_t)elf_payload_len) {
            perror("write failed");
            close(fd);
            _exit(2);
        }

        /* Duplicate descriptor across FDs */
        int dup_fd = dup(fd);
        if (dup_fd < 0) {
            perror("dup failed");
            close(fd);
            _exit(3);
        }

        int dup_fd2 = fcntl(fd, F_DUPFD, 35);
        if (dup_fd2 < 0) {
            perror("fcntl F_DUPFD failed");
            close(fd);
            close(dup_fd);
            _exit(4);
        }

        /* Reopen descriptor via /proc/self/fd/N as O_RDONLY for execution */
        char proc_path[64];
        snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", dup_fd);
        int exec_fd = open(proc_path, O_RDONLY);
        if (exec_fd < 0) {
            perror("open /proc/self/fd/N failed");
            close(fd);
            close(dup_fd);
            close(dup_fd2);
            _exit(5);
        }

        /* Close writable descriptors so execveat won't fail with ETXTBSY */
        close(fd);
        close(dup_fd);
        close(dup_fd2);

        /* Execute the surviving reopened descriptor via execveat */
        char *argv[] = { "m6_dag_exec", NULL };
        char *envp[] = { NULL };
        syscall(SYS_execveat, exec_fd, "", argv, envp, AT_EMPTY_PATH);
        perror("execveat failed");
        _exit(127);
    }

    /* In Parent: Wait for child */
    printf("[TEST] Step 2-3: Parent waiting for child (PID %d) to execute memfd and exit...\n", child);
    int status = 0;
    if (waitpid(child, &status, 0) < 0) {
        perror("waitpid failed");
        return 1;
    }

    if (!WIFEXITED(status)) {
        fprintf(stderr, "  [FAIL] Child terminated abnormally\n");
        return 1;
    }

    if (WEXITSTATUS(status) != 0) {
        fprintf(stderr, "  [FAIL] Child exited with non-zero status: %d\n", WEXITSTATUS(status));
        return 1;
    }

    printf("  [PASS] Child executed memfd and exited cleanly with code 0\n");

    /* Also execute the in-memory engine validation */
    test_engine_synthetic_dag();

    printf("\n=== EphimTrace Milestone 6 DAG Test: All Assertions Passed ===\n\n");
    return 0;
}
