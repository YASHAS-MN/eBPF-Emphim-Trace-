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
#include <dirent.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

#define STRESS_THREADS 8
#define STRESS_ITERATIONS 100

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
        perror("Failed reading true binary payload");
        close(fd);
        return -1;
    }
    elf_payload_len = (size_t)n;
    close(fd);
    return 0;
}

static int count_open_fds(void)
{
    DIR *d = opendir("/proc/self/fd");
    if (!d) return -1;
    int dfd = dirfd(d);
    int count = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;
        int fd_num = atoi(de->d_name);
        if (fd_num == dfd) continue;
        count++;
    }
    closedir(d);
    return count;
}

struct thread_ctx {
    int thread_id;
    int success_count;
    int failure_count;
};

static void *stress_worker(void *arg)
{
    struct thread_ctx *ctx = (struct thread_ctx *)arg;
    int is_valid_group = (ctx->thread_id < 4);

    for (int iter = 0; iter < STRESS_ITERATIONS; iter++) {
        char name[64];
        snprintf(name, sizeof(name), "stress_mfd_%d_%d", ctx->thread_id, iter);

        int fd = memfd_create(name, 0);
        if (fd < 0) {
            ctx->failure_count++;
            continue;
        }

        /* Duplicate descriptors */
        int d1 = dup(fd);
        int d2 = fcntl(fd, F_DUPFD_CLOEXEC, 50 + ctx->thread_id * 4);

        if (is_valid_group) {
            /* Valid execution path: write ELF payload */
            if (write(fd, elf_payload, elf_payload_len) != (ssize_t)elf_payload_len) {
                ctx->failure_count++;
            }

            pid_t cp = fork();
            if (cp == 0) {
                char *argv[] = { "stress_valid", NULL };
                char *envp[] = { NULL };
                syscall(SYS_execveat, fd, "", argv, envp, AT_EMPTY_PATH);
                _exit(127);
            } else if (cp > 0) {
                int st = 0;
                waitpid(cp, &st, 0);
                if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
                    ctx->failure_count++;
                }
            } else {
                ctx->failure_count++;
            }
        } else {
            /* Corrupted execution path */
            const char corrupt_bytes[] = "\xff\xff" "CORRUPT_PAYLOAD";
            if (write(fd, corrupt_bytes, sizeof(corrupt_bytes) - 1) < 0) {
                ctx->failure_count++;
            }

            pid_t cp = fork();
            if (cp == 0) {
                char *argv[] = { "stress_corrupt", NULL };
                char *envp[] = { NULL };
                int ret = syscall(SYS_execveat, fd, "", argv, envp, AT_EMPTY_PATH);
                if (ret < 0 && errno == ENOEXEC) {
                    _exit(42);
                }
                _exit(127);
            } else if (cp > 0) {
                int st = 0;
                waitpid(cp, &st, 0);
                if (!WIFEXITED(st) || WEXITSTATUS(st) != 42) {
                    ctx->failure_count++;
                }
            } else {
                ctx->failure_count++;
            }
        }

        /* Close descriptors in randomized / non-linear order */
        if (iter % 2 == 0) {
            if (d2 >= 0) close(d2);
            close(fd);
            if (d1 >= 0) close(d1);
        } else {
            if (d1 >= 0) close(d1);
            if (d2 >= 0) close(d2);
            close(fd);
        }

        ctx->success_count++;
    }

    return NULL;
}

int main(void)
{
    pid_t pid = getpid();
    pid_t tid = (pid_t)syscall(SYS_gettid);

    printf("\n=================================================================\n");
    printf("=== EphimTrace Milestone M2.5: Integration & Stress Validation ===\n");
    printf("=================================================================\n");
    printf("[INIT] Master PID: %d, TID: %d\n\n", pid, tid);

    if (load_elf_payload() != 0) {
        fprintf(stderr, "Failed loading ELF payload from /bin/true\n");
        return 1;
    }
    printf("  [INIT] Loaded %zu bytes ELF payload from /bin/true\n", elf_payload_len);

    /* -------------------------------------------------------------
     * Scenario 1: Complete Single-Process Forensic Flow
     * ------------------------------------------------------------- */
    printf("\n[SCENARIO 1: Complete Single-Process Forensic Flow]\n");
    pid_t s1_proc = fork();
    if (s1_proc < 0) {
        perror("fork failed for Scenario 1");
        return 1;
    }

    if (s1_proc == 0) {
        /* Child runs the complete forensic flow */
        int mfd = memfd_create("m2_integ_flow", 0);
        if (mfd < 0) _exit(1);

        /* Write payload via write() and pwrite() */
        if (write(mfd, elf_payload, elf_payload_len) != (ssize_t)elf_payload_len) _exit(2);
        const char pwrite_data[] = "PWRITE_TRACKING_PAYLOAD_BYTES";
        if (pwrite(mfd, pwrite_data, sizeof(pwrite_data), elf_payload_len) < 0) _exit(3);

        /* Duplication across 3 descriptors (dup, dup2, fcntl) */
        int d1 = dup(mfd);
        if (d1 < 0) _exit(4);
        int d2 = dup2(mfd, 30);
        if (d2 < 0) _exit(5);
        int d3 = fcntl(mfd, F_DUPFD, 31);
        if (d3 < 0) _exit(6);

        /* Reopen via /proc/self/fd/N as O_RDONLY for execution */
        char proc_path[64];
        snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", mfd);
        int rfd = open(proc_path, O_RDONLY);
        if (rfd < 0) _exit(7);

        /* Close original and intermediate duplicate descriptors */
        close(mfd);
        close(d1);
        close(d2);
        close(d3);

        /* Execute surviving reopened descriptor */
        char *argv[] = { "m2_integ_s1_exec", NULL };
        char *envp[] = { NULL };
        syscall(SYS_execveat, rfd, "", argv, envp, AT_EMPTY_PATH);
        _exit(127);
    }

    int s1_status = 0;
    waitpid(s1_proc, &s1_status, 0);
    if (WIFEXITED(s1_status) && WEXITSTATUS(s1_status) == 0) {
        printf("  [PASS] Single-process forensic flow completed: creation -> write+pwrite -> dup3 -> reopen -> close originals -> execveat (exit 0)\n");
    } else {
        printf("  [FAIL] Scenario 1 failed: status 0x%x\n", s1_status);
        return 1;
    }

    /* -------------------------------------------------------------
     * Scenario 2: Cross-Process & Fork Inheritance Flow
     * ------------------------------------------------------------- */
    printf("\n[SCENARIO 2: Cross-Process & Fork Inheritance Flow]\n");
    int s2_mfd = memfd_create("m2_cross_proc", 0);
    if (s2_mfd < 0) {
        perror("memfd_create failed");
        return 1;
    }
    if (write(s2_mfd, elf_payload, elf_payload_len) != (ssize_t)elf_payload_len) {
        perror("write failed");
        close(s2_mfd);
        return 1;
    }

    pid_t s2_child = fork();
    if (s2_child < 0) {
        perror("fork failed");
        close(s2_mfd);
        return 1;
    }

    if (s2_child == 0) {
        /* Child inherits s2_mfd, appends tracking bytes, and executes it */
        lseek(s2_mfd, 0, SEEK_END);
        const char child_payload[] = "CHILD_CROSS_PROC_TRACKING_BYTES";
        if (write(s2_mfd, child_payload, sizeof(child_payload)) < 0) {
            _exit(1);
        }

        char *argv[] = { "child_inherited_exec", NULL };
        char *envp[] = { NULL };
        syscall(SYS_execveat, s2_mfd, "", argv, envp, AT_EMPTY_PATH);
        _exit(127);
    }

    /* Parent immediately closes its copy of the descriptor */
    close(s2_mfd);

    int s2_status = 0;
    waitpid(s2_child, &s2_status, 0);
    if (WIFEXITED(s2_status) && WEXITSTATUS(s2_status) == 0) {
        printf("  [PASS] Child inherited descriptor, wrote tracking bytes, executed, and exited cleanly (code 0) while parent copy was closed\n");
    } else {
        printf("  [FAIL] Scenario 2 failed: status 0x%x\n", s2_status);
        return 1;
    }

    /* -------------------------------------------------------------
     * Scenario 3: Concurrent Stress / Churn Test
     * ------------------------------------------------------------- */
    printf("\n[SCENARIO 3: Concurrent Stress / Churn Test (8 threads x 100 iterations)]\n");
    int initial_fds = count_open_fds();
    printf("  Initial open FD count: %d\n", initial_fds);

    pthread_t threads[STRESS_THREADS];
    struct thread_ctx ctxs[STRESS_THREADS];

    for (int i = 0; i < STRESS_THREADS; i++) {
        ctxs[i].thread_id = i;
        ctxs[i].success_count = 0;
        ctxs[i].failure_count = 0;
        if (pthread_create(&threads[i], NULL, stress_worker, &ctxs[i]) != 0) {
            perror("pthread_create failed");
            return 1;
        }
    }

    int total_success = 0;
    int total_failures = 0;
    for (int i = 0; i < STRESS_THREADS; i++) {
        pthread_join(threads[i], NULL);
        total_success += ctxs[i].success_count;
        total_failures += ctxs[i].failure_count;
    }

    int final_fds = count_open_fds();
    printf("  Final open FD count: %d\n", final_fds);
    printf("  Stress Results: %d iterations succeeded, %d failed\n", total_success, total_failures);

    if (total_failures != 0) {
        printf("  [FAIL] Concurrent stress test encountered %d failures\n", total_failures);
        return 1;
    }

    if (final_fds != initial_fds) {
        printf("  [FAIL] Descriptor leak detected: initial FDs %d != final FDs %d\n", initial_fds, final_fds);
        return 1;
    }

    printf("  [PASS] Zero descriptor leaks, zero hanging threads/processes, 100%% successful executions\n");

    printf("\n=== M2.5 Integration & Stress Validation Suite Complete ===\n\n");
    return 0;
}
