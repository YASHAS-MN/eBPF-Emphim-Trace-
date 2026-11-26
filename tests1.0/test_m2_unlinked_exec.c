#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <time.h>
#include <signal.h>
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

static unsigned long long read_proc_starttime(pid_t pid)
{
    char stat_path[64];
    snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);
    FILE *f = fopen(stat_path, "r");
    if (!f)
        return 0;

    char buf[1024];
    if (!fgets(buf, sizeof(buf), f)) {
        fclose(f);
        return 0;
    }
    fclose(f);

    /* The comm field can contain arbitrary characters including spaces and ')'.
     * The last ')' in the line demarcates the end of field 2 (comm). */
    char *p = strrchr(buf, ')');
    if (!p)
        return 0;
    p++;

    /* Starting from field 3 (state), field 22 (starttime) is the 20th field */
    unsigned long long starttime = 0;
    char state;
    int ppid, pgrp, session, tty_nr, tpgid;
    unsigned int flags;
    unsigned long minflt, cminflt, majflt, cmajflt, utime, stime;
    long cutime, cstime, priority, nice, num_threads, itrealvalue;
    if (sscanf(p, " %c %d %d %d %d %d %u %lu %lu %lu %lu %lu %lu %ld %ld %ld %ld %ld %ld %llu",
               &state, &ppid, &pgrp, &session, &tty_nr, &tpgid, &flags,
               &minflt, &cminflt, &majflt, &cmajflt, &utime, &stime,
               &cutime, &cstime, &priority, &nice, &num_threads, &itrealvalue,
               &starttime) >= 20) {
        return starttime;
    }
    return 0;
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

    /* Step 1: Create private temporary directory with restricted permissions */
    char temp_dir[] = "/tmp/ephim_unlinked_XXXXXX";
    if (!mkdtemp(temp_dir)) {
        perror("FAIL: mkdtemp failed");
        return 1;
    }
    chmod(temp_dir, 0700);

    char binary_path[512];
    snprintf(binary_path, sizeof(binary_path), "%s/unlinked_worker", temp_dir);

    /* Step 2: Create standalone benign ELF executable from /proc/self/exe */
    int src_fd = open("/proc/self/exe", O_RDONLY);
    if (src_fd < 0) {
        perror("FAIL: open /proc/self/exe failed");
        rmdir(temp_dir);
        return 1;
    }

    int dst_fd = open(binary_path, O_CREAT | O_WRONLY | O_TRUNC, 0755);
    if (dst_fd < 0) {
        perror("FAIL: open destination binary failed");
        close(src_fd);
        rmdir(temp_dir);
        return 1;
    }

    char copy_buf[65536];
    ssize_t bytes_read;
    while ((bytes_read = read(src_fd, copy_buf, sizeof(copy_buf))) > 0) {
        if (write(dst_fd, copy_buf, bytes_read) != bytes_read) {
            perror("FAIL: write binary failed");
            close(src_fd);
            close(dst_fd);
            unlink(binary_path);
            rmdir(temp_dir);
            return 1;
        }
    }
    close(src_fd);
    fchmod(dst_fd, 0755);

    /* Step 3: Record authoritative ground-truth identity via fstat */
    struct stat st;
    if (fstat(dst_fd, &st) != 0) {
        perror("FAIL: fstat failed");
        close(dst_fd);
        unlink(binary_path);
        rmdir(temp_dir);
        return 1;
    }
    close(dst_fd);

    uint64_t expected_inode = (uint64_t)st.st_ino;
    uint64_t expected_dev = (uint64_t)st.st_dev; /* Actual st_dev representation consistent with encode_user_dev */

    printf("[GROUND TRUTH IDENTITY]\n");
    printf("  Temp Dir:         %s\n", temp_dir);
    printf("  Binary Path:      %s\n", binary_path);
    printf("  Expected Inode:   %llu\n", (unsigned long long)expected_inode);
    printf("  Expected Device:  %u:%u (%llu)\n", major(st.st_dev), minor(st.st_dev), (unsigned long long)expected_dev);
    printf("  Expected MountNS: %u\n", mnt_ns);
    printf("  File Size:        %lld bytes\n\n", (long long)st.st_size);

    /* Step 4: Setup pipes for bidirectional handshake (zero timing sleeps) */
    int ready_pipe[2];
    int release_pipe[2];
    if (pipe(ready_pipe) != 0 || pipe(release_pipe) != 0) {
        perror("FAIL: pipe failed");
        unlink(binary_path);
        rmdir(temp_dir);
        return 1;
    }

    struct timespec ts_boot_ref = {0};
    clock_gettime(CLOCK_BOOTTIME, &ts_boot_ref);
    uint64_t child_start_ref_ns = (uint64_t)ts_boot_ref.tv_sec * 1000000000ULL + ts_boot_ref.tv_nsec;

    /* Step 5: Fork child process */
    pid_t child = fork();
    if (child < 0) {
        perror("FAIL: fork failed");
        unlink(binary_path);
        rmdir(temp_dir);
        return 1;
    }

    if (child == 0) {
        /* Child: close unused ends and execute target binary */
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
        perror("FAIL: execve failed");
        _exit(127);
    }

    /* Parent: close child's ends */
    close(ready_pipe[1]);
    close(release_pipe[0]);

    /* Step 6: Wait for explicit handshake that child has executed the binary */
    printf("[SYNCHRONIZATION PHASE 1: Execution Handshake]\n");
    printf("  Waiting for child %d to complete execve()...\n", child);
    char ready_token = 0;
    if (read(ready_pipe[0], &ready_token, 1) != 1 || ready_token != 'R') {
        fprintf(stderr, "FAIL: child failed to report ready\n");
        unlink(binary_path);
        rmdir(temp_dir);
        return 1;
    }
    close(ready_pipe[0]);
    printf("  [CONFIRMED] Child %d successfully executed %s\n\n", child, binary_path);

    /* Step 7: Record independent process start-time information */
    unsigned long long child_starttime_ticks = read_proc_starttime(child);
    printf("[INDEPENDENT PROCESS GROUND TRUTH]\n");
    printf("  Child PID:               %d\n", child);
    printf("  Child Starttime (ticks): %llu (from /proc/%d/stat)\n", child_starttime_ticks, child);
    printf("  Reference Boottime (ns): %llu\n\n", (unsigned long long)child_start_ref_ns);

    /* Step 8: Verify /proc/child/exe device and inode BEFORE unlink */
    char proc_exe[64];
    snprintf(proc_exe, sizeof(proc_exe), "/proc/%d/exe", child);

    struct stat st_exe_before;
    if (stat(proc_exe, &st_exe_before) != 0) {
        perror("FAIL: stat(/proc/child/exe) before unlink failed");
        unlink(binary_path);
        rmdir(temp_dir);
        return 1;
    }

    char link_before[512] = {0};
    ssize_t len_before = readlink(proc_exe, link_before, sizeof(link_before) - 1);
    if (len_before <= 0) {
        perror("FAIL: readlink(/proc/child/exe) before unlink failed");
        unlink(binary_path);
        rmdir(temp_dir);
        return 1;
    }
    link_before[len_before] = '\0';

    if ((uint64_t)st_exe_before.st_ino != expected_inode ||
        (uint64_t)st_exe_before.st_dev != expected_dev) {
        fprintf(stderr, "FAIL: /proc/child/exe identity mismatch before unlink: ino=%llu dev=%llu (expected ino=%llu dev=%llu)\n",
                (unsigned long long)st_exe_before.st_ino, (unsigned long long)st_exe_before.st_dev,
                (unsigned long long)expected_inode, (unsigned long long)expected_dev);
        unlink(binary_path);
        rmdir(temp_dir);
        return 1;
    }
    printf("[VERIFICATION BEFORE UNLINK]\n");
    printf("  /proc/%d/exe -> %s\n", child, link_before);
    printf("  Verified Inode:  %llu\n", (unsigned long long)st_exe_before.st_ino);
    printf("  Verified Device: %u:%u (%llu)\n\n",
           major(st_exe_before.st_dev), minor(st_exe_before.st_dev),
           (unsigned long long)st_exe_before.st_dev);

    /* Step 9: Unlink the binary while child is actively running */
    printf("[SYNCHRONIZATION PHASE 2: Unlink While Running]\n");
    if (unlink(binary_path) != 0) {
        perror("FAIL: unlink failed");
        rmdir(temp_dir);
        return 1;
    }
    printf("  [PASS] unlink(%s) returned 0 (SUCCESS)\n", binary_path);

    /* Step 10: Verify ENOENT for the removed pathname */
    struct stat st_removed;
    if (stat(binary_path, &st_removed) == 0) {
        fprintf(stderr, "FAIL: stat(%s) succeeded after unlink (expected ENOENT)\n", binary_path);
        rmdir(temp_dir);
        return 1;
    }
    if (errno != ENOENT) {
        fprintf(stderr, "FAIL: stat(%s) returned error %d (%s), expected ENOENT (%d)\n",
                binary_path, errno, strerror(errno), ENOENT);
        rmdir(temp_dir);
        return 1;
    }
    if (access(binary_path, F_OK) == 0 || errno != ENOENT) {
        fprintf(stderr, "FAIL: access(%s) returned unexpected status after unlink (expected ENOENT)\n", binary_path);
        rmdir(temp_dir);
        return 1;
    }
    printf("  [VERIFIED] Directory entry removed: stat and access strictly return ENOENT\n");

    /* Step 11: Verify deleted executable reference while child remains alive */
    if (kill(child, 0) != 0) {
        fprintf(stderr, "FAIL: child process %d died prematurely\n", child);
        rmdir(temp_dir);
        return 1;
    }

    char link_after[512] = {0};
    ssize_t len_after = readlink(proc_exe, link_after, sizeof(link_after) - 1);
    if (len_after <= 0) {
        perror("FAIL: readlink(/proc/child/exe) after unlink failed");
        rmdir(temp_dir);
        return 1;
    }
    link_after[len_after] = '\0';

    if (!strstr(link_after, "(deleted)")) {
        fprintf(stderr, "FAIL: /proc/%d/exe does not indicate deleted reference: '%s'\n", child, link_after);
        rmdir(temp_dir);
        return 1;
    }
    printf("  [VERIFIED] Active child holds deleted executable reference: /proc/%d/exe -> %s\n", child, link_after);

    /* Step 12: Verify /proc/child/exe device and inode AFTER unlink */
    struct stat st_exe_after;
    if (stat(proc_exe, &st_exe_after) != 0) {
        perror("FAIL: stat(/proc/child/exe) after unlink failed");
        rmdir(temp_dir);
        return 1;
    }
    if ((uint64_t)st_exe_after.st_ino != expected_inode ||
        (uint64_t)st_exe_after.st_dev != expected_dev) {
        fprintf(stderr, "FAIL: /proc/child/exe identity mismatch after unlink: ino=%llu dev=%llu (expected ino=%llu dev=%llu)\n",
                (unsigned long long)st_exe_after.st_ino, (unsigned long long)st_exe_after.st_dev,
                (unsigned long long)expected_inode, (unsigned long long)expected_dev);
        rmdir(temp_dir);
        return 1;
    }
    printf("  [VERIFIED AFTER UNLINK] Inode: %llu, Device: %u:%u (%llu)\n\n",
           (unsigned long long)st_exe_after.st_ino,
           major(st_exe_after.st_dev), minor(st_exe_after.st_dev),
           (unsigned long long)st_exe_after.st_dev);

    /* Step 13: Release child worker */
    printf("[SYNCHRONIZATION PHASE 3: Releasing Child]\n");
    char release_token = 'U';
    if (write(release_pipe[1], &release_token, 1) != 1) {
        perror("FAIL: write release token failed");
        rmdir(temp_dir);
        return 1;
    }
    close(release_pipe[1]);

    /* Step 14: Wait for child exit */
    int status = 0;
    waitpid(child, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        printf("  [PASS] Child %d exited cleanly with code 0\n", child);
    } else {
        printf("  [FAIL] Child %d failed: status 0x%x\n", child, status);
        rmdir(temp_dir);
        return 1;
    }

    /* Step 15: Clean up private temporary directory */
    if (rmdir(temp_dir) != 0) {
        perror("FAIL: rmdir temp_dir failed");
        return 1;
    }
    printf("  [VERIFIED] Private temporary directory cleaned up: %s\n", temp_dir);

    printf("\n=== M2.5 Unlinked Regular-ELF Execution Test Complete ===\n\n");
    return 0;
}
