#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

#define NUM_CONCURRENT_THREADS 4

struct thread_arg {
    int id;
    int success;
};

static void *worker_desc_thread(void *arg)
{
    struct thread_arg *ta = (struct thread_arg *)arg;
    char name[64];
    snprintf(name, sizeof(name), "m2_desc_thr_%d", ta->id);

    int fd = memfd_create(name, MFD_CLOEXEC);
    if (fd < 0) {
        ta->success = 0;
        return NULL;
    }

    int d1 = dup(fd);
    int d2 = fcntl(fd, F_DUPFD_CLOEXEC, 40 + ta->id * 2);

    /* Write data via d1 */
    const char msg[] = "thread_dup_data";
    if (write(d1, msg, sizeof(msg)) < 0) {
        ta->success = 0;
        close(fd);
        if (d1 >= 0) close(d1);
        if (d2 >= 0) close(d2);
        return NULL;
    }

    /* Close original and first dup */
    close(fd);
    close(d1);

    /* Verify d2 is still writable */
    if (write(d2, msg, sizeof(msg)) < 0) {
        ta->success = 0;
        close(d2);
        return NULL;
    }

    close(d2);
    ta->success = 1;
    return NULL;
}

int main(void)
{
    pid_t pid = getpid();
    pid_t tid = (pid_t)syscall(SYS_gettid);

    printf("\n=======================================================\n");
    printf("=== EphimTrace Milestone M2.2: Descriptor Lifecycle ===\n");
    printf("=======================================================\n");
    printf("[INIT] Process PID: %d, TID: %d\n\n", pid, tid);

    /* -------------------------------------------------------------
     * Test 1: Memfd Creation & Initial Descriptor Installation
     * ------------------------------------------------------------- */
    printf("[TEST 1: Memfd Creation & Initial Descriptor Installation]\n");
    int orig_fd = memfd_create("m2_desc_test", MFD_CLOEXEC);
    if (orig_fd < 0) {
        perror("memfd_create failed");
        return 1;
    }
    struct stat st_orig;
    if (fstat(orig_fd, &st_orig) != 0) {
        perror("fstat failed");
        return 1;
    }
    printf("  Created memfd 'm2_desc_test': FD %d | Inode %llu | Dev %u:%u (%llu)\n",
           orig_fd, (unsigned long long)st_orig.st_ino,
           major(st_orig.st_dev), minor(st_orig.st_dev), (unsigned long long)st_orig.st_dev);

    const char initial_payload[] = "ephimtrace_m2_initial_data";
    ssize_t wlen = write(orig_fd, initial_payload, sizeof(initial_payload));
    if (wlen != (ssize_t)sizeof(initial_payload)) {
        printf("  [FAIL] Failed writing initial payload: %s\n", strerror(errno));
        return 1;
    }
    printf("  [PASS] Successfully initialized memfd descriptor FD %d with %zd bytes\n", orig_fd, wlen);

    /* -------------------------------------------------------------
     * Test 2: Descriptor Duplication (dup, dup2, dup3, fcntl) & Reopen
     * ------------------------------------------------------------- */
    printf("\n[TEST 2: Descriptor Duplication & /proc Reopening]\n");
    int fd_dup = dup(orig_fd);
    if (fd_dup < 0) { perror("dup failed"); return 1; }
    printf("  dup() returned FD %d\n", fd_dup);

    int fd_dup2 = dup2(orig_fd, 20);
    if (fd_dup2 < 0) { perror("dup2 failed"); return 1; }
    printf("  dup2() returned FD %d\n", fd_dup2);

    int fd_dup3 = dup3(orig_fd, 21, O_CLOEXEC);
    if (fd_dup3 < 0) { perror("dup3 failed"); return 1; }
    printf("  dup3() returned FD %d\n", fd_dup3);

    int fd_fcntl1 = fcntl(orig_fd, F_DUPFD, 22);
    if (fd_fcntl1 < 0) { perror("fcntl(F_DUPFD) failed"); return 1; }
    printf("  fcntl(F_DUPFD) returned FD %d\n", fd_fcntl1);

    int fd_fcntl2 = fcntl(orig_fd, F_DUPFD_CLOEXEC, 23);
    if (fd_fcntl2 < 0) { perror("fcntl(F_DUPFD_CLOEXEC) failed"); return 1; }
    printf("  fcntl(F_DUPFD_CLOEXEC) returned FD %d\n", fd_fcntl2);

    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", orig_fd);
    int fd_reopen = open(proc_path, O_RDWR);
    if (fd_reopen < 0) { perror("open /proc/self/fd/N failed"); return 1; }
    printf("  Reopened via %s returned FD %d\n", proc_path, fd_reopen);

    /* Verify inode equality */
    int all_fds[] = { orig_fd, fd_dup, fd_dup2, fd_dup3, fd_fcntl1, fd_fcntl2, fd_reopen };
    for (int i = 0; i < 7; i++) {
        struct stat st_cur;
        if (fstat(all_fds[i], &st_cur) != 0 || st_cur.st_ino != st_orig.st_ino) {
            printf("  [FAIL] Descriptor FD %d inode mismatch\n", all_fds[i]);
            return 1;
        }
    }
    printf("  [PASS] All 7 descriptors share identical backing inode %llu\n", (unsigned long long)st_orig.st_ino);

    /* Verify file offset sharing for duplicated descriptors vs independent offset for reopened */
    lseek(orig_fd, 50, SEEK_SET);
    off_t pos_dup = lseek(fd_dup, 0, SEEK_CUR);
    off_t pos_d2  = lseek(fd_dup2, 0, SEEK_CUR);
    off_t pos_d3  = lseek(fd_dup3, 0, SEEK_CUR);
    off_t pos_fc1 = lseek(fd_fcntl1, 0, SEEK_CUR);
    off_t pos_fc2 = lseek(fd_fcntl2, 0, SEEK_CUR);
    off_t pos_re  = lseek(fd_reopen, 0, SEEK_CUR);

    if (pos_dup == 50 && pos_d2 == 50 && pos_d3 == 50 && pos_fc1 == 50 && pos_fc2 == 50) {
        printf("  [PASS] Duplicated descriptors strictly share file description state (offset %ld)\n", (long)pos_dup);
    } else {
        printf("  [FAIL] Duplicated descriptors did not share file offset\n");
        return 1;
    }
    if (pos_re == 0) {
        printf("  [PASS] Reopened descriptor maintains independent file description state (offset %ld)\n", (long)pos_re);
    } else {
        printf("  [FAIL] Reopened descriptor unexpectedly shared offset: %ld\n", (long)pos_re);
        return 1;
    }

    /* -------------------------------------------------------------
     * Test 3: Individual Descriptor Closure & Backing Object Continuity
     * ------------------------------------------------------------- */
    printf("\n[TEST 3: Individual Descriptor Closure & Backing Object Continuity]\n");
    /* Close original descriptor FD */
    printf("  Closing original descriptor FD %d...\n", orig_fd);
    close(orig_fd);

    /* Verify surviving duplicated descriptors are fully readable and writable */
    char read_buf[64] = {0};
    lseek(fd_dup, 0, SEEK_SET);
    ssize_t rlen = read(fd_dup, read_buf, sizeof(initial_payload));
    if (rlen == (ssize_t)sizeof(initial_payload) && strcmp(read_buf, initial_payload) == 0) {
        printf("  [PASS] Duplicated FD %d successfully read data written before orig_fd closed\n", fd_dup);
    } else {
        printf("  [FAIL] Read through duplicated FD %d failed\n", fd_dup);
        return 1;
    }

    /* Close duplicate descriptors one by one */
    printf("  Closing duplicate FDs %d, %d, %d, %d...\n", fd_dup, fd_dup2, fd_dup3, fd_fcntl1);
    close(fd_dup);
    close(fd_dup2);
    close(fd_dup3);
    close(fd_fcntl1);

    /* Write through the single surviving duplicate FD (fd_fcntl2) */
    const char survivor_msg[] = "_survivor_write";
    if (write(fd_fcntl2, survivor_msg, sizeof(survivor_msg)) > 0) {
        printf("  [PASS] Last duplicated descriptor FD %d remains functional after closing peers\n", fd_fcntl2);
    } else {
        printf("  [FAIL] Write to surviving FD %d failed: %s\n", fd_fcntl2, strerror(errno));
        return 1;
    }

    /* Close last duplicated descriptor */
    printf("  Closing last duplicated descriptor FD %d...\n", fd_fcntl2);
    close(fd_fcntl2);

    /* Verify backing object still active and writable via reopened descriptor */
    if (write(fd_reopen, survivor_msg, sizeof(survivor_msg)) > 0) {
        printf("  [PASS] Backing object remains active through reopened FD %d after all original duplicates closed\n", fd_reopen);
    } else {
        printf("  [FAIL] Write to reopened FD %d failed: %s\n", fd_reopen, strerror(errno));
        return 1;
    }

    /* Close reopened descriptor */
    printf("  Closing reopened descriptor FD %d...\n", fd_reopen);
    close(fd_reopen);
    printf("  [PASS] All descriptors cleanly closed; backing object evicted.\n");

    /* -------------------------------------------------------------
     * Test 4: Concurrent Descriptor Creation, Duplication & Closure
     * ------------------------------------------------------------- */
    printf("\n[TEST 4: Concurrent Multithreaded Descriptor Lifecycle]\n");
    pthread_t threads[NUM_CONCURRENT_THREADS];
    struct thread_arg args[NUM_CONCURRENT_THREADS];

    for (int i = 0; i < NUM_CONCURRENT_THREADS; i++) {
        args[i].id = i;
        args[i].success = 0;
        if (pthread_create(&threads[i], NULL, worker_desc_thread, &args[i]) != 0) {
            perror("pthread_create failed");
            return 1;
        }
    }

    for (int i = 0; i < NUM_CONCURRENT_THREADS; i++) {
        pthread_join(threads[i], NULL);
        if (!args[i].success) {
            printf("  [FAIL] Worker thread %d reported failure\n", i);
            return 1;
        }
    }
    printf("  [PASS] All %d concurrent threads successfully completed creation, duplication, and closure.\n",
           NUM_CONCURRENT_THREADS);

    printf("\n=== M2.2 Descriptor Lifecycle Tests Complete ===\n\n");
    return 0;
}
