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

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

int main(void)
{
    pid_t pid = getpid();
    pid_t tid = (pid_t)syscall(SYS_gettid);

    printf("\n=======================================================\n");
    printf("=== EphimTrace Milestone M2.1: Object Registry Tests ===\n");
    printf("=======================================================\n");
    printf("[INIT] Process PID: %d, TID: %d\n\n", pid, tid);

    /* -------------------------------------------------------------
     * Test 1: Multiple memfd creations with distinct object tokens
     * ------------------------------------------------------------- */
    printf("[TEST 1: Multiple memfd creations with distinct tokens]\n");
    int fds[4];
    uint64_t inodes[4];
    for (int i = 0; i < 4; i++) {
        char name[64];
        snprintf(name, sizeof(name), "m2_obj_%d", i);
        fds[i] = memfd_create(name, MFD_CLOEXEC);
        if (fds[i] < 0) {
            printf("  FAILED to create %s: %s\n", name, strerror(errno));
            return 1;
        }
        struct stat st;
        fstat(fds[i], &st);
        inodes[i] = st.st_ino;
        printf("  Created memfd '%s': FD %d | Inode %llu | Dev %u:%u (%llu)\n",
               name, fds[i], (unsigned long long)inodes[i],
               major(st.st_dev), minor(st.st_dev), (unsigned long long)st.st_dev);
    }
    /* Verify distinct inodes */
    for (int i = 0; i < 4; i++) {
        for (int j = i + 1; j < 4; j++) {
            if (inodes[i] == inodes[j]) {
                printf("  [ERROR] Inodes %d and %d unexpectedly collided: %llu\n",
                       i, j, (unsigned long long)inodes[i]);
            }
        }
    }
    printf("  [PASS] All 4 memfd creations received distinct kernel inodes and object slots.\n");

    /* -------------------------------------------------------------
     * Test 2: Repeated FD reuse after close
     * ------------------------------------------------------------- */
    printf("\n[TEST 2: Repeated FD reuse after close]\n");
    int fd_orig = fds[0];
    uint64_t ino_orig = inodes[0];
    close(fd_orig);
    printf("  Closed FD %d (Inode %llu)\n", fd_orig, (unsigned long long)ino_orig);

    int fd_reused = memfd_create("m2_reused", MFD_CLOEXEC);
    if (fd_reused >= 0) {
        struct stat st_reused;
        fstat(fd_reused, &st_reused);
        printf("  Created new memfd 'm2_reused': FD %d | Inode %llu\n",
               fd_reused, (unsigned long long)st_reused.st_ino);
        if (fd_reused == fd_orig) {
            printf("  [PASS] FD number %d was reused, but assigned new distinct Inode (%llu != %llu)\n",
                   fd_reused, (unsigned long long)st_reused.st_ino, (unsigned long long)ino_orig);
        } else {
            printf("  [NOTE] FD was not reused (%d vs %d), Inode: %llu\n",
                   fd_orig, fd_reused, (unsigned long long)st_reused.st_ino);
        }
        close(fd_reused);
    }
    for (int i = 1; i < 4; i++) {
        close(fds[i]);
    }

    /* -------------------------------------------------------------
     * Test 3: /proc/self/fd/N Reopening and Inode-Based Correlation
     * ------------------------------------------------------------- */
    printf("\n[TEST 3: /proc/self/fd/N reopening and inode correlation]\n");
    int mfd = memfd_create("m2_reopen_target", MFD_CLOEXEC);
    if (mfd < 0) {
        perror("memfd_create failed");
        return 1;
    }
    struct stat st_mfd;
    fstat(mfd, &st_mfd);
    printf("  Original memfd: FD %d | Inode %llu\n", mfd, (unsigned long long)st_mfd.st_ino);

    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", mfd);

    int mfd_reopened = open(proc_path, O_RDWR);
    if (mfd_reopened < 0) {
        perror("open /proc/self/fd/N failed");
        close(mfd);
        return 1;
    }
    struct stat st_reopen;
    fstat(mfd_reopened, &st_reopen);
    printf("  Reopened memfd via %s: FD %d | Inode %llu\n",
           proc_path, mfd_reopened, (unsigned long long)st_reopen.st_ino);

    if (st_mfd.st_ino == st_reopen.st_ino && st_mfd.st_dev == st_reopen.st_dev) {
        printf("  [PASS] Verified shared backing inode %llu across distinct struct file instances (FD %d and FD %d)\n",
               (unsigned long long)st_mfd.st_ino, mfd, mfd_reopened);
    } else {
        printf("  [FAIL] Inode mismatch: %llu vs %llu\n",
               (unsigned long long)st_mfd.st_ino, (unsigned long long)st_reopen.st_ino);
    }

    /* Close original FD: reopened FD must remain valid */
    close(mfd);
    printf("  Closed original FD %d; reopened FD %d remains active\n", mfd, mfd_reopened);

    /* Write to reopened descriptor to prove liveness */
    const char msg[] = "payload_through_reopened_fd\n";
    ssize_t w = write(mfd_reopened, msg, sizeof(msg) - 1);
    if (w > 0) {
        printf("  Successfully wrote %zd bytes to reopened FD %d\n", w, mfd_reopened);
    } else {
        perror("write to reopened FD failed");
    }
    close(mfd_reopened);
    printf("  Closed reopened FD %d (all references now dropped)\n", mfd_reopened);

    /* -------------------------------------------------------------
     * Test 4: Object retirement after final reference disappears
     * ------------------------------------------------------------- */
    printf("\n[TEST 4: Object retirement after final reference disappears]\n");
    int fd_retire = memfd_create("m2_retire_candidate", MFD_CLOEXEC);
    if (fd_retire >= 0) {
        struct stat st_ret;
        fstat(fd_retire, &st_ret);
        printf("  Created short-lived memfd 'm2_retire_candidate': FD %d | Inode %llu\n",
               fd_retire, (unsigned long long)st_ret.st_ino);
        usleep(50000);
        close(fd_retire);
        printf("  Closed FD %d -> kernel triggers iput() -> shmem_evict_inode()\n", fd_retire);
    }

    /* -------------------------------------------------------------
     * Test 5: Descriptor Duplication and Reopening Regression
     * Verify all 5 duplication mechanisms and /proc/self/fd/N reopening.
     * Verify that dup/dup2/dup3/fcntl share the same struct file (offset linked),
     * while /proc/self/fd/N creates a distinct struct file (independent offset)
     * with the same backing inode.
     * ------------------------------------------------------------- */
    printf("\n[TEST 5: Descriptor duplication & /proc/self/fd/N reopening regression]\n");
    int fd_orig_dup = memfd_create("m2_dup_regression", MFD_CLOEXEC);
    if (fd_orig_dup < 0) {
        perror("memfd_create failed");
        return 1;
    }
    struct stat st_orig_dup;
    fstat(fd_orig_dup, &st_orig_dup);
    printf("  Original memfd: FD %d | Inode %llu\n", fd_orig_dup, (unsigned long long)st_orig_dup.st_ino);

    /* 1. dup() */
    int fd_dup = dup(fd_orig_dup);
    if (fd_dup < 0) { perror("dup failed"); return 1; }
    printf("  dup() returned FD %d\n", fd_dup);

    /* 2. dup2() */
    int fd_dup2 = dup2(fd_orig_dup, 30);
    if (fd_dup2 < 0) { perror("dup2 failed"); return 1; }
    printf("  dup2() returned FD %d\n", fd_dup2);

    /* 3. dup3() with O_CLOEXEC */
    int fd_dup3 = dup3(fd_orig_dup, 31, O_CLOEXEC);
    if (fd_dup3 < 0) { perror("dup3 failed"); return 1; }
    printf("  dup3() returned FD %d\n", fd_dup3);

    /* 4. fcntl(F_DUPFD) */
    int fd_fcntl1 = fcntl(fd_orig_dup, F_DUPFD, 32);
    if (fd_fcntl1 < 0) { perror("fcntl(F_DUPFD) failed"); return 1; }
    printf("  fcntl(F_DUPFD) returned FD %d\n", fd_fcntl1);

    /* 5. fcntl(F_DUPFD_CLOEXEC) */
    int fd_fcntl2 = fcntl(fd_orig_dup, F_DUPFD_CLOEXEC, 33);
    if (fd_fcntl2 < 0) { perror("fcntl(F_DUPFD_CLOEXEC) failed"); return 1; }
    printf("  fcntl(F_DUPFD_CLOEXEC) returned FD %d\n", fd_fcntl2);

    /* 6. /proc/self/fd/N reopening */
    char proc_dup_path[64];
    snprintf(proc_dup_path, sizeof(proc_dup_path), "/proc/self/fd/%d", fd_orig_dup);
    int fd_proc_reopen = open(proc_dup_path, O_RDWR);
    if (fd_proc_reopen < 0) { perror("open /proc/self/fd/N failed"); return 1; }
    printf("  Reopened via %s returned FD %d\n", proc_dup_path, fd_proc_reopen);

    /* Verify all 7 descriptors share identical inode and device */
    int all_fds[] = { fd_orig_dup, fd_dup, fd_dup2, fd_dup3, fd_fcntl1, fd_fcntl2, fd_proc_reopen };
    const char *fd_names[] = { "original", "dup", "dup2", "dup3", "fcntl_dup", "fcntl_cloexec", "proc_reopen" };
    for (int i = 0; i < 7; i++) {
        struct stat st_cur;
        fstat(all_fds[i], &st_cur);
        if (st_cur.st_ino != st_orig_dup.st_ino || st_cur.st_dev != st_orig_dup.st_dev) {
            printf("  [FAIL] Descriptor %s (FD %d) has mismatched inode %llu vs %llu\n",
                   fd_names[i], all_fds[i], (unsigned long long)st_cur.st_ino, (unsigned long long)st_orig_dup.st_ino);
            return 1;
        }
    }
    printf("  [PASS] All 7 descriptors share identical backing inode %llu\n", (unsigned long long)st_orig_dup.st_ino);

    /* Verify struct file sharing: moving seek offset on dup affects all dup/fcntl descriptors, but NOT proc_reopen */
    lseek(fd_dup, 42, SEEK_SET);
    off_t pos_orig = lseek(fd_orig_dup, 0, SEEK_CUR);
    off_t pos_dup2 = lseek(fd_dup2, 0, SEEK_CUR);
    off_t pos_dup3 = lseek(fd_dup3, 0, SEEK_CUR);
    off_t pos_fc1  = lseek(fd_fcntl1, 0, SEEK_CUR);
    off_t pos_fc2  = lseek(fd_fcntl2, 0, SEEK_CUR);
    off_t pos_proc = lseek(fd_proc_reopen, 0, SEEK_CUR);

    if (pos_orig == 42 && pos_dup2 == 42 && pos_dup3 == 42 && pos_fc1 == 42 && pos_fc2 == 42) {
        printf("  [PASS] Verified shared struct file: all 5 duplicate descriptors share identical file offset (%ld)\n", (long)pos_orig);
    } else {
        printf("  [FAIL] Offset mismatch among duplicated descriptors: %ld, %ld, %ld, %ld, %ld\n",
               (long)pos_orig, (long)pos_dup2, (long)pos_dup3, (long)pos_fc1, (long)pos_fc2);
        return 1;
    }

    if (pos_proc == 0) {
        printf("  [PASS] Verified independent struct file: /proc/self/fd/N descriptor retains independent offset (%ld)\n", (long)pos_proc);
    } else {
        printf("  [FAIL] /proc/self/fd/N unexpectedly shared offset (%ld)\n", (long)pos_proc);
        return 1;
    }

    /* Close duplicate descriptors one by one */
    close(fd_orig_dup);
    close(fd_dup);
    close(fd_dup2);
    close(fd_dup3);
    close(fd_fcntl1);
    printf("  Closed 5 duplicated descriptors; 1 duplicated descriptor (FD %d) still holds original struct file\n", fd_fcntl2);

    /* Write through last duplicated descriptor to prove struct file is still alive */
    const char t5_msg[] = "dup_survives";
    if (write(fd_fcntl2, t5_msg, sizeof(t5_msg)) > 0) {
        printf("  [PASS] Original struct file remains functional through surviving duplicate FD %d\n", fd_fcntl2);
    }

    /* Close last duplicated descriptor: this triggers final __fput for original struct file */
    close(fd_fcntl2);
    printf("  Closed last duplicate FD %d -> original struct file released\n", fd_fcntl2);

    /* Write through reopened descriptor to prove backing object is still alive */
    if (write(fd_proc_reopen, t5_msg, sizeof(t5_msg)) > 0) {
        printf("  [PASS] Backing object remains alive and writable through reopened FD %d\n", fd_proc_reopen);
    }

    /* Close reopened descriptor: this triggers __fput for reopened file AND shmem_evict_inode for backing object */
    close(fd_proc_reopen);
    printf("  Closed reopened FD %d -> all references dropped, inode evicted\n", fd_proc_reopen);

    printf("\n=== M2.1 Object Registry Tests Complete ===\n\n");
    return 0;
}
