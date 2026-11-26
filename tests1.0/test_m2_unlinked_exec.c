#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <string.h>
#include <errno.h>

static void get_mount_ns_id(unsigned int *ns_id)
{
    char buf[128] = {0};
    ssize_t len = readlink("/proc/self/ns/mnt", buf, sizeof(buf) - 1);
    if (len > 0) {
        buf[len] = '\0';
        /* Format: mnt:[<inum>] */
        char *p = strstr(buf, "[");
        if (p) {
            *ns_id = (unsigned int)strtoul(p + 1, NULL, 10);
            return;
        }
    }
    *ns_id = 0;
}

static uint64_t encode_dev(dev_t dev)
{
    uint32_t maj = major(dev);
    uint32_t min = minor(dev);
    return ((uint64_t)maj << 32) | min;
}

int main(int argc, char *argv[])
{
    /* -------------------------------------------------------------
     * Worker Execution Mode (invoked post-exec by child)
     * ------------------------------------------------------------- */
    if (argc >= 4 && strcmp(argv[1], "--worker") == 0) {
        int ready_fd = atoi(argv[2]);
        int release_fd = atoi(argv[3]);

        pid_t worker_pid = getpid();
        pid_t worker_tid = (pid_t)syscall(SYS_gettid);

        printf("  [WORKER] Running as executed binary (PID: %d, TID: %d)\n", worker_pid, worker_tid);
        fflush(stdout);

        /* 1. Synchronize: notify parent that execve() has succeeded and worker is running */
        char ready_byte = 'R';
        if (write(ready_fd, &ready_byte, 1) != 1) {
            perror("worker: write ready failed");
            _exit(1);
        }
        close(ready_fd);

        /* 2. Block until parent unlinks our binary and sends release signal */
        char release_byte = 0;
        if (read(release_fd, &release_byte, 1) != 1 || release_byte != 'U') {
            perror("worker: read release failed");
            _exit(2);
        }
        close(release_fd);

        printf("  [WORKER] Release received after unlink; terminating cleanly.\n");
        fflush(stdout);
        _exit(0);
    }

    /* -------------------------------------------------------------
     * Parent Orchestrator Mode
     * ------------------------------------------------------------- */
    pid_t parent_pid = getpid();
    pid_t parent_tid = (pid_t)syscall(SYS_gettid);
    unsigned int mnt_ns = 0;
    get_mount_ns_id(&mnt_ns);

    printf("\n=================================================================\n");
    printf("=== EphimTrace Milestone M2.5: Unlinked Regular-ELF Execution ===\n");
    printf("=================================================================\n");
    printf("[INIT] Parent PID: %d, TID: %d, MountNS: %u\n\n", parent_pid, parent_tid, mnt_ns);

    char binary_path[256];
    snprintf(binary_path, sizeof(binary_path), "/tmp/ephim_unlinked_worker_%d", parent_pid);
    unlink(binary_path);

    /* Step 1: Create standalone benign ELF executable from /proc/self/exe */
    int src_fd = open("/proc/self/exe", O_RDONLY);
    if (src_fd < 0) {
        perror("open /proc/self/exe failed");
        return 1;
    }

    int dst_fd = open(binary_path, O_CREAT | O_WRONLY | O_TRUNC, 0755);
    if (dst_fd < 0) {
        perror("open destination binary failed");
        close(src_fd);
        return 1;
    }

    char buf[65536];
    ssize_t bytes_read;
    while ((bytes_read = read(src_fd, buf, sizeof(buf))) > 0) {
        if (write(dst_fd, buf, bytes_read) != bytes_read) {
            perror("write binary failed");
            close(src_fd);
            close(dst_fd);
            unlink(binary_path);
            return 1;
        }
    }
    close(src_fd);
    fchmod(dst_fd, 0755);

    /* Step 2: Record authoritative ground-truth identity via stat */
    struct stat st;
    if (fstat(dst_fd, &st) != 0) {
        perror("fstat failed");
        close(dst_fd);
        unlink(binary_path);
        return 1;
    }
    close(dst_fd);

    uint64_t expected_inode = (uint64_t)st.st_ino;
    uint64_t expected_dev = encode_dev(st.st_dev);

    printf("[GROUND TRUTH IDENTITY]\n");
    printf("  Binary Path:      %s\n", binary_path);
    printf("  Expected Inode:   %llu\n", (unsigned long long)expected_inode);
    printf("  Expected Device:  %u:%u (Encoded: %llu)\n", major(st.st_dev), minor(st.st_dev), (unsigned long long)expected_dev);
    printf("  Expected MountNS: %u\n", mnt_ns);
    printf("  File Size:        %lld bytes\n\n", (long long)st.st_size);

    /* Step 3: Setup pipes for bidirectional handshake (zero timing sleeps) */
    int ready_pipe[2];
    int release_pipe[2];
    if (pipe(ready_pipe) != 0 || pipe(release_pipe) != 0) {
        perror("pipe failed");
        unlink(binary_path);
        return 1;
    }

    /* Step 4: Fork child process */
    pid_t child = fork();
    if (child < 0) {
        perror("fork failed");
        unlink(binary_path);
        return 1;
    }

    if (child == 0) {
        /* Child: close unused read ends and execute target binary */
        close(ready_pipe[0]);
        close(release_pipe[1]);

        char ready_str[16];
        char release_str[16];
        snprintf(ready_str, sizeof(ready_str), "%d", ready_pipe[1]);
        snprintf(release_str, sizeof(release_str), "%d", release_pipe[0]);

        char *argv_exec[] = {
            "benign_unlinked_worker",
            "--worker",
            ready_str,
            release_str,
            NULL
        };
        char *envp_exec[] = { NULL };

        execve(binary_path, argv_exec, envp_exec);
        perror("execve failed");
        _exit(127);
    }

    /* Parent: close child's write/read ends */
    close(ready_pipe[1]);
    close(release_pipe[0]);

    /* Step 5: Wait for explicit handshake that child has executed the binary */
    printf("[SYNCHRONIZATION PHASE 1]\n");
    printf("  Waiting for child %d to complete execve()...\n", child);
    char ready_token = 0;
    if (read(ready_pipe[0], &ready_token, 1) != 1 || ready_token != 'R') {
        fprintf(stderr, "FAIL: child failed to report ready\n");
        unlink(binary_path);
        return 1;
    }
    close(ready_pipe[0]);
    printf("  [CONFIRMED] Child %d successfully executed %s\n\n", child, binary_path);

    /* Step 6: Unlink the binary while child is actively running */
    printf("[SYNCHRONIZATION PHASE 2: Unlink while running]\n");
    if (unlink(binary_path) != 0) {
        perror("FAIL: unlink failed");
        return 1;
    }
    printf("  [PASS] unlink(%s) returned 0 (SUCCESS)\n", binary_path);

    /* Verify file is unlinked from filesystem directory */
    if (access(binary_path, F_OK) == 0) {
        fprintf(stderr, "FAIL: file still accessible after unlink\n");
        return 1;
    }
    printf("  [VERIFIED] Directory entry removed (access returns ENOENT)\n");

    /* Inspect /proc/<child>/exe target */
    char proc_exe[64];
    char exe_target[512] = {0};
    snprintf(proc_exe, sizeof(proc_exe), "/proc/%d/exe", child);
    ssize_t link_len = readlink(proc_exe, exe_target, sizeof(exe_target) - 1);
    if (link_len > 0) {
        exe_target[link_len] = '\0';
        printf("  [VERIFIED] /proc/%d/exe -> %s\n\n", child, exe_target);
    }

    /* Step 7: Release child worker */
    printf("[SYNCHRONIZATION PHASE 3: Releasing child]\n");
    char release_token = 'U';
    if (write(release_pipe[1], &release_token, 1) != 1) {
        perror("write release token failed");
        return 1;
    }
    close(release_pipe[1]);

    /* Step 8: Wait for child exit */
    int status = 0;
    waitpid(child, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        printf("  [PASS] Child %d exited cleanly with code 0\n", child);
    } else {
        printf("  [FAIL] Child %d failed: status 0x%x\n", child, status);
        return 1;
    }

    printf("\n=== M2.5 Unlinked Regular-ELF Execution Test Complete ===\n\n");
    return 0;
}
