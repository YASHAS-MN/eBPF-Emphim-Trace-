#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <sched.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING 0x0002U
#endif

#ifndef MFD_NOEXEC_SEAL
#define MFD_NOEXEC_SEAL 0x0008U
#endif

#ifndef F_ADD_SEALS
#define F_ADD_SEALS 1033
#define F_GET_SEALS 1034
#define F_SEAL_SEAL   0x0001
#define F_SEAL_SHRINK 0x0002
#define F_SEAL_GROW   0x0004
#define F_SEAL_WRITE  0x0008
#endif

static void print_fd_info(int fd, const char *label)
{
    struct stat st;
    if (fstat(fd, &st) != 0) {
        printf("  [%s] fstat failed: %s\n", label, strerror(errno));
        return;
    }

    char fd_path[64];
    char link_dest[256] = {0};
    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
    ssize_t len = readlink(fd_path, link_dest, sizeof(link_dest) - 1);
    if (len > 0)
        link_dest[len] = '\0';
    else
        snprintf(link_dest, sizeof(link_dest), "<readlink failed>");

    printf("  [%s] FD: %d | Inode: %llu | Dev: %u:%u (%llu) | /proc/self/fd: %s\n",
           label, fd, (unsigned long long)st.st_ino,
           major(st.st_dev), minor(st.st_dev), (unsigned long long)st.st_dev,
           link_dest);
}

/* Thread worker for Scenario 4 */
struct thread_arg {
    int thread_id;
    int fd;
    uint64_t inode;
    pid_t tid;
};

static void *thread_worker(void *arg)
{
    struct thread_arg *ta = (struct thread_arg *)arg;
    ta->tid = (pid_t)syscall(SYS_gettid);

    char name[64];
    snprintf(name, sizeof(name), "test_mfd_thread_%d", ta->thread_id);

    usleep(10000 * ta->thread_id); /* slight stagger */
    int fd = memfd_create(name, MFD_CLOEXEC);
    ta->fd = fd;
    if (fd >= 0) {
        struct stat st;
        if (fstat(fd, &st) == 0)
            ta->inode = st.st_ino;
    }

    usleep(50000); /* hold FD open for a short time */
    if (fd >= 0)
        close(fd);
    return NULL;
}

int main(void)
{
    pid_t pid = getpid();
    pid_t tid = (pid_t)syscall(SYS_gettid);

    printf("\n=======================================================\n");
    printf("=== EphimTrace Milestone M1: Memfd Identity Tests ===\n");
    printf("=======================================================\n");
    printf("[INIT] Process PID: %d, TID: %d\n\n", pid, tid);
    fflush(stdout);

    /* ------------------------------------------------------------------
     * Scenario 1: Basic Successful Creation
     * ------------------------------------------------------------------ */
    printf("[SCENARIO 1: Basic Successful Creation]\n");
    const char *s1_name = "test_mfd_basic";
    int fd1 = memfd_create(s1_name, MFD_CLOEXEC);
    if (fd1 < 0) {
        printf("  FAILED: memfd_create returned %d (%s)\n", fd1, strerror(errno));
    } else {
        printf("  SUCCESS: memfd_create(\"%s\", MFD_CLOEXEC) returned FD %d\n", s1_name, fd1);
        print_fd_info(fd1, "Scenario 1");
        close(fd1);
    }
    fflush(stdout);
    usleep(50000);

    /* ------------------------------------------------------------------
     * Scenario 2: Invalid Flags and Negative Errno
     * ------------------------------------------------------------------ */
    printf("\n[SCENARIO 2: Invalid Flags and Negative Errno]\n");
    const char *s2_name = "test_mfd_inval";
    unsigned int inval_flags = 0xFFFFFFFF;
    int fd2 = memfd_create(s2_name, inval_flags);
    if (fd2 < 0) {
        printf("  SUCCESS (expected failure): returned %d, errno=%d (%s)\n",
               fd2, errno, strerror(errno));
    } else {
        printf("  UNEXPECTED: memfd_create succeeded with invalid flags! FD: %d\n", fd2);
        close(fd2);
    }
    fflush(stdout);
    usleep(50000);

    /* ------------------------------------------------------------------
     * Scenario 3: Multiple Sequential Creations
     * ------------------------------------------------------------------ */
    printf("\n[SCENARIO 3: Multiple Sequential Creations]\n");
    int fds[5] = {-1};
    for (int i = 0; i < 5; i++) {
        char name[64];
        snprintf(name, sizeof(name), "test_mfd_seq_%d", i);
        fds[i] = memfd_create(name, MFD_CLOEXEC);
        if (fds[i] >= 0) {
            char label[32];
            snprintf(label, sizeof(label), "Seq #%d", i);
            print_fd_info(fds[i], label);
        } else {
            printf("  FAILED: Seq #%d returned %d (%s)\n", i, fds[i], strerror(errno));
        }
        usleep(10000);
    }
    for (int i = 0; i < 5; i++) {
        if (fds[i] >= 0) close(fds[i]);
    }
    fflush(stdout);
    usleep(50000);

    /* ------------------------------------------------------------------
     * Scenario 4: Concurrent Creation from Multiple Threads
     * ------------------------------------------------------------------ */
    printf("\n[SCENARIO 4: Concurrent Creation from Multiple Threads]\n");
    const int NUM_THREADS = 4;
    pthread_t threads[4];
    struct thread_arg args[4];

    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].thread_id = i;
        args[i].fd = -1;
        args[i].inode = 0;
        args[i].tid = 0;
        pthread_create(&threads[i], NULL, thread_worker, &args[i]);
    }
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
        printf("  Thread %d (TID: %d): returned FD %d | Inode: %llu\n",
               i, args[i].tid, args[i].fd, (unsigned long long)args[i].inode);
    }
    fflush(stdout);
    usleep(50000);

    /* ------------------------------------------------------------------
     * Scenario 5: FD-Number Reuse after Close
     * ------------------------------------------------------------------ */
    printf("\n[SCENARIO 5: FD-Number Reuse after Close]\n");
    int fd_orig = memfd_create("test_mfd_reuse_1", MFD_CLOEXEC);
    struct stat st_orig;
    if (fd_orig >= 0 && fstat(fd_orig, &st_orig) == 0) {
        printf("  Created 1st: FD %d | Inode: %llu\n", fd_orig, (unsigned long long)st_orig.st_ino);
        close(fd_orig);
        printf("  Closed FD %d\n", fd_orig);

        /* Immediately create another - kernel should reassign the lowest freed FD */
        int fd_reuse = memfd_create("test_mfd_reuse_2", MFD_CLOEXEC);
        struct stat st_reuse;
        if (fd_reuse >= 0 && fstat(fd_reuse, &st_reuse) == 0) {
            printf("  Created 2nd: FD %d | Inode: %llu\n", fd_reuse, (unsigned long long)st_reuse.st_ino);
            if (fd_reuse == fd_orig) {
                printf("  [CONFIRMED] FD number %d was reused, but inode changed (%llu -> %llu)\n",
                       fd_orig, (unsigned long long)st_orig.st_ino, (unsigned long long)st_reuse.st_ino);
            } else {
                printf("  [NOTE] FD number was not identical (%d vs %d), inodes: %llu vs %llu\n",
                       fd_orig, fd_reuse, (unsigned long long)st_orig.st_ino, (unsigned long long)st_reuse.st_ino);
            }
            close(fd_reuse);
        }
    }
    fflush(stdout);
    usleep(50000);

    /* ------------------------------------------------------------------
     * Scenario 6: Relevant Creation Flags (MFD_ALLOW_SEALING)
     * ------------------------------------------------------------------ */
    printf("\n[SCENARIO 6: Relevant Creation Flags (MFD_ALLOW_SEALING)]\n");
    int fd_seal = memfd_create("test_mfd_seal", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (fd_seal >= 0) {
        print_fd_info(fd_seal, "MFD_ALLOW_SEALING");
        int seal_res = fcntl(fd_seal, F_ADD_SEALS, F_SEAL_WRITE);
        printf("  fcntl(F_ADD_SEALS, F_SEAL_WRITE) returned: %d (%s)\n",
               seal_res, seal_res == 0 ? "SUCCESS" : strerror(errno));
        close(fd_seal);
    } else {
        printf("  FAILED: %s\n", strerror(errno));
    }
    fflush(stdout);
    usleep(50000);

    /* ------------------------------------------------------------------
     * Scenario 7: Execution Pinned to CPU 0 and CPU 1
     * ------------------------------------------------------------------ */
    printf("\n[SCENARIO 7: Execution Pinned to CPU 0 and CPU 1]\n");
    for (int cpu = 0; cpu <= 1; cpu++) {
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(cpu, &set);
        if (sched_setaffinity(0, sizeof(set), &set) != 0) {
            printf("  CPU %d affinity setting failed: %s\n", cpu, strerror(errno));
            continue;
        }

        int cur_cpu = sched_getcpu();
        char name[64];
        snprintf(name, sizeof(name), "test_mfd_pinned_cpu_%d", cur_cpu);
        int fd_cpu = memfd_create(name, MFD_CLOEXEC);
        if (fd_cpu >= 0) {
            char label[32];
            snprintf(label, sizeof(label), "Pinned CPU %d", cur_cpu);
            print_fd_info(fd_cpu, label);
            close(fd_cpu);
        } else {
            printf("  CPU %d memfd_create failed: %s\n", cur_cpu, strerror(errno));
        }
        usleep(20000);
    }
    fflush(stdout);
    usleep(50000);

    /* ------------------------------------------------------------------
     * Scenario 8: Long Name / Truncation Handling
     * ------------------------------------------------------------------ */
    printf("\n[SCENARIO 8: Long Name Truncation Handling]\n");
    char long_name[300];
    memset(long_name, 'A', sizeof(long_name) - 1);
    long_name[sizeof(long_name) - 1] = '\0';
    memcpy(long_name, "test_mfd_trunc_", 15);

    int fd_trunc = memfd_create(long_name, MFD_CLOEXEC);
    if (fd_trunc >= 0) {
        printf("  SUCCESS: memfd_create with %zu-byte name returned FD %d\n",
               strlen(long_name), fd_trunc);
        print_fd_info(fd_trunc, "Long Name");
        close(fd_trunc);
    } else {
        printf("  Returned %d (%s)\n", fd_trunc, strerror(errno));
    }

    printf("\n=== Memfd Tests Complete ===\n\n");
    return 0;
}
