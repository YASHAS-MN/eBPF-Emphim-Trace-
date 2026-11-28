#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

/*
 * EphimTrace — Release Qualification Task 01: Descriptor Lifecycle Suite
 * Covers GitHub Issue #5:
 * 1. Descriptor duplication & replacement (dup, dup2, dup3, fcntl)
 * 2. Replacement of tracked descriptors with ordinary files
 * 3. Descriptor reuse and failed operations
 * 4. Concurrent operations involving shared descriptor tables (threads & CLONE_FILES)
 */

struct suite_result {
    int total_assertions;
    int passed_assertions;
    int failed_assertions;
};

static struct suite_result g_res = {0, 0, 0};

#define ASSERT_TRUE(cond, msg, ...) do { \
    g_res.total_assertions++; \
    if (cond) { \
        g_res.passed_assertions++; \
        printf("    [PASS] " msg "\n", ##__VA_ARGS__); \
    } else { \
        g_res.failed_assertions++; \
        printf("    [FAIL] " msg "\n", ##__VA_ARGS__); \
    } \
} while(0)

/* --------------------------------------------------------------------------
 * Suite 1: Descriptor Duplication and Replacement (dup, dup2, dup3, fcntl)
 * -------------------------------------------------------------------------- */
static void run_suite_1_duplication(void)
{
    printf("\n=== SUITE 1: Descriptor Duplication and Replacement ===\n");

    int orig_fd = memfd_create("qual_mfd_dup", MFD_CLOEXEC);
    ASSERT_TRUE(orig_fd >= 0, "Created memfd 'qual_mfd_dup' (FD %d)", orig_fd);
    if (orig_fd < 0) return;

    struct stat st_orig;
    fstat(orig_fd, &st_orig);
    printf("    [INFO] Backing Inode: %llu, Device: %llu\n",
           (unsigned long long)st_orig.st_ino, (unsigned long long)st_orig.st_dev);

    /* 1.1 dup() */
    int fd_dup = dup(orig_fd);
    ASSERT_TRUE(fd_dup >= 0, "dup(orig_fd) succeeded -> FD %d", fd_dup);

    /* 1.2 fcntl(F_DUPFD) */
    int fd_fcntl = fcntl(orig_fd, F_DUPFD, 30);
    ASSERT_TRUE(fd_fcntl >= 30, "fcntl(orig_fd, F_DUPFD, 30) succeeded -> FD %d", fd_fcntl);

    /* 1.3 dup2() to unused slot */
    int fd_dup2 = dup2(orig_fd, 35);
    ASSERT_TRUE(fd_dup2 == 35, "dup2(orig_fd, 35) to unused descriptor succeeded -> FD %d", fd_dup2);

    /* 1.4 dup3() to unused slot with O_CLOEXEC */
    int fd_dup3 = dup3(orig_fd, 36, O_CLOEXEC);
    ASSERT_TRUE(fd_dup3 == 36, "dup3(orig_fd, 36, O_CLOEXEC) to unused descriptor succeeded -> FD %d", fd_dup3);

    /* Verify all duplicated descriptors share backing inode */
    int fds[] = { orig_fd, fd_dup, fd_fcntl, fd_dup2, fd_dup3 };
    bool all_match = true;
    for (int i = 0; i < 5; i++) {
        struct stat st;
        if (fstat(fds[i], &st) != 0 || st.st_ino != st_orig.st_ino) {
            all_match = false;
            break;
        }
    }
    ASSERT_TRUE(all_match, "All 5 descriptors share identical backing inode %llu", (unsigned long long)st_orig.st_ino);

    /* Close descriptors */
    for (int i = 0; i < 5; i++) {
        close(fds[i]);
    }
    printf("    [INFO] Cleaned up all Suite 1 descriptors.\n");
}

/* --------------------------------------------------------------------------
 * Suite 2: Replacement of Tracked Descriptors with Ordinary Files
 * -------------------------------------------------------------------------- */
static void run_suite_2_replacement_with_ordinary(void)
{
    printf("\n=== SUITE 2: Replacement of Tracked Descriptors with Ordinary Files ===\n");

    /* 2.1 Create tracked memfd */
    int mfd = memfd_create("qual_mfd_replace", MFD_CLOEXEC);
    ASSERT_TRUE(mfd >= 0, "Created memfd 'qual_mfd_replace' at FD %d", mfd);
    if (mfd < 0) return;

    struct stat st_mfd;
    fstat(mfd, &st_mfd);

    /* 2.2 Open ordinary regular file */
    char tmp_path[] = "/tmp/ephim_qual_ordinary_XXXXXX";
    int ord_fd = mkstemp(tmp_path);
    ASSERT_TRUE(ord_fd >= 0, "Created temporary ordinary file at FD %d (%s)", ord_fd, tmp_path);
    if (ord_fd < 0) { close(mfd); return; }

    struct stat st_ord;
    fstat(ord_fd, &st_ord);
    ASSERT_TRUE(st_ord.st_ino != st_mfd.st_ino, "Ordinary file inode (%llu) differs from memfd inode (%llu)",
                (unsigned long long)st_ord.st_ino, (unsigned long long)st_mfd.st_ino);

    /* 2.3 Use dup2 to atomically REPLACE the tracked memfd with the ordinary file */
    printf("    [ACTION] Executing dup2(ord_fd=%d, mfd=%d) to replace memfd with ordinary file...\n", ord_fd, mfd);
    int rep_res = dup2(ord_fd, mfd);
    ASSERT_TRUE(rep_res == mfd, "dup2(ord_fd, mfd) succeeded, returning %d", rep_res);

    /* Verify FD mfd now references ordinary file */
    struct stat st_after;
    fstat(mfd, &st_after);
    ASSERT_TRUE(st_after.st_ino == st_ord.st_ino,
                "FD %d now points to ordinary file inode %llu (was memfd inode %llu)",
                mfd, (unsigned long long)st_after.st_ino, (unsigned long long)st_mfd.st_ino);

    /* 2.4 Write to the replaced descriptor */
    const char msg[] = "payload_written_to_ordinary_file\n";
    ssize_t w = write(mfd, msg, strlen(msg));
    ASSERT_TRUE(w == (ssize_t)strlen(msg), "Wrote %zd bytes to replaced FD %d", w, mfd);

    /* 2.5 Close replaced descriptor */
    printf("    [ACTION] Closing replaced FD %d (now an ordinary file)...\n", mfd);
    int c_res = close(mfd);
    ASSERT_TRUE(c_res == 0, "close(mfd=%d) succeeded", mfd);

    close(ord_fd);
    unlink(tmp_path);
    printf("    [INFO] Cleaned up Suite 2 files.\n");
}

/* --------------------------------------------------------------------------
 * Suite 3: Descriptor Reuse and Failed Operations
 * -------------------------------------------------------------------------- */
static void run_suite_3_reuse_and_failed_ops(void)
{
    printf("\n=== SUITE 3: Descriptor Reuse and Failed Operations ===\n");

    /* 3.1 Failed operations on invalid file descriptors */
    printf("    [SUBTEST 3.1: Negative Syscall Error Handling]\n");
    int bad_dup = dup(-1);
    ASSERT_TRUE(bad_dup == -1 && errno == EBADF, "dup(-1) rejected with -EBADF (%s)", strerror(errno));

    int bad_dup2 = dup2(-1, 50);
    ASSERT_TRUE(bad_dup2 == -1 && errno == EBADF, "dup2(-1, 50) rejected with -EBADF (%s)", strerror(errno));

    int bad_dup3 = dup3(50, 50, O_CLOEXEC);
    ASSERT_TRUE(bad_dup3 == -1 && errno == EINVAL, "dup3(50, 50) rejected with -EINVAL (%s)", strerror(errno));

    int bad_close = close(-1);
    ASSERT_TRUE(bad_close == -1 && errno == EBADF, "close(-1) rejected with -EBADF (%s)", strerror(errno));

    int bad_mfd = memfd_create("", 0xFFFFFFFFU);
    ASSERT_TRUE(bad_mfd == -1 && errno == EINVAL, "memfd_create with invalid flags rejected with -EINVAL (%s)", strerror(errno));

    /* 3.2 Descriptor Reuse after closure */
    printf("    [SUBTEST 3.2: Descriptor Slot Reuse Sequence]\n");
    int mfd = memfd_create("qual_mfd_reuse", MFD_CLOEXEC);
    ASSERT_TRUE(mfd >= 0, "Allocated memfd 'qual_mfd_reuse' at slot FD %d", mfd);

    int saved_slot = mfd;
    int cr = close(mfd);
    ASSERT_TRUE(cr == 0, "Closed memfd at slot FD %d", saved_slot);

    /* Open regular file, which should get the lowest available descriptor (saved_slot) */
    char tmp_path[] = "/tmp/ephim_qual_reuse_XXXXXX";
    int reused_fd = mkstemp(tmp_path);
    ASSERT_TRUE(reused_fd == saved_slot, "Reused descriptor slot FD %d for regular file (%s)", reused_fd, tmp_path);

    /* Close reused descriptor */
    close(reused_fd);
    unlink(tmp_path);
    printf("    [INFO] Descriptor slot %d successfully recycled.\n", saved_slot);
}

/* --------------------------------------------------------------------------
 * Suite 4: Concurrent Operations Involving Shared Descriptor Tables
 * -------------------------------------------------------------------------- */
#define NUM_THREADS 4
struct thr_ctx {
    int thread_id;
    int base_fd;
    int success;
};

static void *thread_worker(void *arg)
{
    struct thr_ctx *ctx = (struct thr_ctx *)arg;
    ctx->success = 1;

    for (int iter = 0; iter < 50; iter++) {
        int d = dup(ctx->base_fd);
        if (d < 0) { ctx->success = 0; break; }

        const char wbuf[] = "X";
        if (write(d, wbuf, 1) != 1) {
            close(d);
            ctx->success = 0;
            break;
        }

        if (close(d) != 0) {
            ctx->success = 0;
            break;
        }
    }
    return NULL;
}

static int clone_child_fn(void *arg)
{
    int shared_fd = *(int *)arg;
    /* Child shares file descriptor table (CLONE_FILES) but has distinct PID/TGID */
    pid_t c_pid = getpid();
    pid_t c_tid = (pid_t)syscall(SYS_gettid);
    printf("    [CLONE_CHILD] Running in child (PID %d, TID %d), testing shared FD %d...\n",
           c_pid, c_tid, shared_fd);

    const char msg[] = "clone_child_shared_write\n";
    if (write(shared_fd, msg, strlen(msg)) != (ssize_t)strlen(msg)) {
        return 1;
    }

    /* Child closes shared descriptor */
    printf("    [CLONE_CHILD] Child closing shared FD %d...\n", shared_fd);
    if (close(shared_fd) != 0) {
        return 2;
    }

    return 0;
}

static void run_suite_4_concurrency(void)
{
    printf("\n=== SUITE 4: Concurrent Operations and Shared Descriptor Tables ===\n");

    /* 4.1 Multithreaded concurrent descriptor operations */
    printf("    [SUBTEST 4.1: Multithreaded Shared Files Table]\n");
    int mfd = memfd_create("qual_mfd_threads", MFD_CLOEXEC);
    ASSERT_TRUE(mfd >= 0, "Created memfd 'qual_mfd_threads' at FD %d", mfd);

    pthread_t thrs[NUM_THREADS];
    struct thr_ctx ctxs[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; i++) {
        ctxs[i].thread_id = i;
        ctxs[i].base_fd = mfd;
        ctxs[i].success = 0;
        pthread_create(&thrs[i], NULL, thread_worker, &ctxs[i]);
    }

    bool all_thrs_ok = true;
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(thrs[i], NULL);
        if (!ctxs[i].success) all_thrs_ok = false;
    }
    ASSERT_TRUE(all_thrs_ok, "All %d concurrent threads executed 50 dup/write/close iterations cleanly", NUM_THREADS);
    close(mfd);

    /* 4.2 Shared descriptor table across distinct processes via clone(CLONE_FILES) */
    printf("    [SUBTEST 4.2: Shared Files Table Across Processes via clone(CLONE_FILES)]\n");
    int shared_mfd = memfd_create("qual_mfd_clone", MFD_CLOEXEC);
    ASSERT_TRUE(shared_mfd >= 0, "Created memfd 'qual_mfd_clone' at FD %d", shared_mfd);

    /* Allocate stack for clone child */
    const size_t STACK_SIZE = 1024 * 1024;
    char *stack = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    ASSERT_TRUE(stack != MAP_FAILED, "Allocated 1 MiB child stack for clone()");

    pid_t parent_pid = getpid();
    printf("    [PARENT] Parent PID: %d, spawning CLONE_FILES child with distinct TGID...\n", parent_pid);

    /* clone with CLONE_FILES | SIGCHLD (new thread group / distinct TGID, shared files) */
    pid_t child_pid = clone(clone_child_fn, stack + STACK_SIZE,
                            CLONE_FILES | SIGCHLD, &shared_mfd);
    ASSERT_TRUE(child_pid > 0, "clone(CLONE_FILES) spawned child PID %d", child_pid);

    int status = 0;
    waitpid(child_pid, &status, 0);
    ASSERT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0,
                "Child PID %d exited cleanly (exit status %d)", child_pid, WEXITSTATUS(status));

    /* In parent, check if shared_fd is already closed */
    struct stat st;
    int fstat_res = fstat(shared_mfd, &st);
    ASSERT_TRUE(fstat_res == -1 && errno == EBADF,
                "Parent observes FD %d was closed by child (-EBADF: %s)", shared_mfd, strerror(errno));

    munmap(stack, STACK_SIZE);
}

int main(void)
{
    printf("=================================================================\n");
    printf("=== EphimTrace Release Qualification 01: Descriptor Lifecycle ===\n");
    printf("=================================================================\n");
    printf("[INIT] Workload Process PID: %d, TID: %d\n", getpid(), (pid_t)syscall(SYS_gettid));

    run_suite_1_duplication();
    run_suite_2_replacement_with_ordinary();
    run_suite_3_reuse_and_failed_ops();
    run_suite_4_concurrency();

    printf("\n=================================================================\n");
    printf("=== Qualification Suite Summary: %d/%d Assertions Passed (%d Failed) ===\n",
           g_res.passed_assertions, g_res.total_assertions, g_res.failed_assertions);
    printf("=================================================================\n");

    return (g_res.failed_assertions == 0) ? 0 : 1;
}
