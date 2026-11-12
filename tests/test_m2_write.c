#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
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
    printf("=== EphimTrace Milestone M2.3: Explicit Write Tracking ===\n");
    printf("=======================================================\n");
    printf("[INIT] Process PID: %d, TID: %d\n\n", pid, tid);

    int fd = memfd_create("m2_write_test", MFD_CLOEXEC);
    if (fd < 0) {
        perror("memfd_create failed");
        return 1;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        perror("fstat failed");
        return 1;
    }
    printf("  Created memfd 'm2_write_test': FD %d | Inode %llu | Dev %u:%u\n",
           fd, (unsigned long long)st.st_ino, major(st.st_dev), minor(st.st_dev));

    /* -------------------------------------------------------------
     * Test 1: Standard write() at offset 0
     * ------------------------------------------------------------- */
    printf("\n[TEST 1: Standard write() at offset 0]\n");
    const char data0[] = "HEADER_START_OFFSET_0_DATA";
    size_t len0 = strlen(data0);
    off_t pos_before = lseek(fd, 0, SEEK_CUR);
    ssize_t w0 = write(fd, data0, len0);
    off_t pos_after = lseek(fd, 0, SEEK_CUR);

    if (w0 == (ssize_t)len0 && pos_before == 0 && pos_after == (off_t)len0) {
        printf("  [PASS] Standard write at pos %ld wrote %zd bytes, new pos %ld\n",
               (long)pos_before, w0, (long)pos_after);
    } else {
        printf("  [FAIL] Standard write mismatch: w0=%zd, pos_before=%ld, pos_after=%ld\n",
               w0, (long)pos_before, (long)pos_after);
        return 1;
    }

    /* -------------------------------------------------------------
     * Test 2: Sequential append writes verifying advancing offsets
     * ------------------------------------------------------------- */
    printf("\n[TEST 2: Sequential append writes with advancing offsets]\n");
    for (int i = 1; i <= 3; i++) {
        char append_buf[64];
        snprintf(append_buf, sizeof(append_buf), "_CHUNK_%d_DATA_", i);
        size_t append_len = strlen(append_buf);

        off_t expected_offset = lseek(fd, 0, SEEK_CUR);
        ssize_t w_chunk = write(fd, append_buf, append_len);
        off_t new_offset = lseek(fd, 0, SEEK_CUR);

        if (w_chunk == (ssize_t)append_len && new_offset == (off_t)(expected_offset + append_len)) {
            printf("  [PASS] Chunk %d: offset %ld -> wrote %zd bytes -> offset %ld\n",
                   i, (long)expected_offset, w_chunk, (long)new_offset);
        } else {
            printf("  [FAIL] Chunk %d write failed: w=%zd, exp_off=%ld, new_off=%ld\n",
                   i, w_chunk, (long)expected_offset, (long)new_offset);
            return 1;
        }
    }

    /* -------------------------------------------------------------
     * Test 3: Positional writes (pwrite()) at arbitrary offsets
     * ------------------------------------------------------------- */
    printf("\n[TEST 3: Positional writes (pwrite()) at arbitrary offsets]\n");
    off_t saved_pos = lseek(fd, 0, SEEK_CUR);

    /* Positional write at offset 1024 */
    const char pwrite_data_1k[] = "PWRITE_DATA_AT_1024";
    size_t pwrite_len_1k = strlen(pwrite_data_1k);
    ssize_t pw1 = pwrite(fd, pwrite_data_1k, pwrite_len_1k, 1024);
    off_t pos_after_pw1 = lseek(fd, 0, SEEK_CUR);

    if (pw1 == (ssize_t)pwrite_len_1k && pos_after_pw1 == saved_pos) {
        printf("  [PASS] pwrite() at offset 1024 wrote %zd bytes, file pos preserved at %ld\n",
               pw1, (long)pos_after_pw1);
    } else {
        printf("  [FAIL] pwrite(1024) failed: ret=%zd, pos_after=%ld\n", pw1, (long)pos_after_pw1);
        return 1;
    }

    /* Positional write at offset 4096 */
    const char pwrite_data_4k[] = "PWRITE_DATA_AT_4096";
    size_t pwrite_len_4k = strlen(pwrite_data_4k);
    ssize_t pw2 = pwrite(fd, pwrite_data_4k, pwrite_len_4k, 4096);
    off_t pos_after_pw2 = lseek(fd, 0, SEEK_CUR);

    if (pw2 == (ssize_t)pwrite_len_4k && pos_after_pw2 == saved_pos) {
        printf("  [PASS] pwrite() at offset 4096 wrote %zd bytes, file pos preserved at %ld\n",
               pw2, (long)pos_after_pw2);
    } else {
        printf("  [FAIL] pwrite(4096) failed: ret=%zd, pos_after=%ld\n", pw2, (long)pos_after_pw2);
        return 1;
    }

    /* -------------------------------------------------------------
     * Test 4: Vectored writes (writev()) verifying iov_iter aggregation
     * ------------------------------------------------------------- */
    printf("\n[TEST 4: Vectored writes (writev()) verifying proper byte count aggregation]\n");
    char vec_part1[] = "VEC_PART_1_";
    char vec_part2[] = "VEC_PART_2_LONGER_";
    char vec_part3[] = "VEC_PART_3_END";

    struct iovec iov[3];
    iov[0].iov_base = vec_part1;
    iov[0].iov_len = strlen(vec_part1);
    iov[1].iov_base = vec_part2;
    iov[1].iov_len = strlen(vec_part2);
    iov[2].iov_base = vec_part3;
    iov[2].iov_len = strlen(vec_part3);

    size_t total_vec_bytes = iov[0].iov_len + iov[1].iov_len + iov[2].iov_len;
    off_t vec_pos_before = lseek(fd, 0, SEEK_CUR);
    ssize_t wv = writev(fd, iov, 3);
    off_t vec_pos_after = lseek(fd, 0, SEEK_CUR);

    if (wv == (ssize_t)total_vec_bytes && vec_pos_after == (off_t)(vec_pos_before + total_vec_bytes)) {
        printf("  [PASS] writev() 3 vectors: aggregated %zu bytes written at offset %ld -> new pos %ld\n",
               total_vec_bytes, (long)vec_pos_before, (long)vec_pos_after);
    } else {
        printf("  [FAIL] writev() failed: wv=%zd vs expected %zu\n", wv, total_vec_bytes);
        return 1;
    }

    /* -------------------------------------------------------------
     * Test 5: Writing to reopened /proc/self/fd/N descriptor
     * ------------------------------------------------------------- */
    printf("\n[TEST 5: Writing to reopened /proc/self/fd/N descriptor]\n");
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
    int reopen_fd = open(proc_path, O_RDWR);
    if (reopen_fd < 0) {
        perror("open /proc/self/fd/N failed");
        return 1;
    }

    struct stat st_reopen;
    fstat(reopen_fd, &st_reopen);
    if (st_reopen.st_ino != st.st_ino) {
        printf("  [FAIL] Reopened FD inode %llu does not match original %llu\n",
               (unsigned long long)st_reopen.st_ino, (unsigned long long)st.st_ino);
        close(reopen_fd);
        close(fd);
        return 1;
    }
    printf("  Reopened via %s returned FD %d (Inode %llu matched)\n",
           proc_path, reopen_fd, (unsigned long long)st_reopen.st_ino);

    /* Write via reopened FD */
    const char reopen_data[] = "WRITTEN_VIA_REOPENED_FD";
    size_t reopen_len = strlen(reopen_data);
    ssize_t rw = write(reopen_fd, reopen_data, reopen_len);

    if (rw == (ssize_t)reopen_len) {
        printf("  [PASS] Successfully wrote %zd bytes via reopened FD %d to identical backing object\n",
               rw, reopen_fd);
    } else {
        printf("  [FAIL] Write via reopened FD failed: rw=%zd\n", rw);
        close(reopen_fd);
        close(fd);
        return 1;
    }

    close(reopen_fd);
    close(fd);

    printf("\n=== M2.3 Explicit Write Tracking Tests Complete ===\n\n");
    return 0;
}
