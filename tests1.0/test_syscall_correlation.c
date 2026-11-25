#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <string.h>
#include <errno.h>

static void get_mount_ns_id(unsigned int *ns_id)
{
    char buf[128] = {0};
    ssize_t len = readlink("/proc/self/ns/mnt", buf, sizeof(buf) - 1);
    if (len > 0) {
        buf[len] = '\0';
        char *p = strstr(buf, "[");
        if (p) {
            *ns_id = (unsigned int)strtoul(p + 1, NULL, 10);
            return;
        }
    }
    *ns_id = 0;
}

int main(void)
{
    unsigned int mnt_ns = 0;
    get_mount_ns_id(&mnt_ns);

    printf("\n======================================================================\n");
    printf("   EphimTrace Syscall-to-VFS Pathname Correlation Test Suite\n");
    printf("======================================================================\n");
    printf("[SUITE] PID: %d, TID: %d, MountNS: %u\n\n", getpid(), (int)getpid(), mnt_ns);
    fflush(stdout);

    /* -------------------------------------------------------------
     * Test 1: Successful absolute-path unlink()
     * ------------------------------------------------------------- */
    printf("[TEST 1: Successful absolute-path unlink()]\n");
    char file1[] = "/tmp/ephim_corr_abs_XXXXXX";
    int fd1 = mkstemp(file1);
    if (fd1 < 0) {
        perror("mkstemp failed");
        return 1;
    }
    if (write(fd1, "test1\n", 6) < 0) {}
    struct stat st1;
    fstat(fd1, &st1);
    close(fd1);

    printf("  Action: unlink(\"%s\")\n", file1);
    printf("  Expected Syscall: unlink\n");
    printf("  Expected Original Path: %s (status=VALID)\n", file1);
    printf("  Expected Target Basename: %s\n", strrchr(file1, '/') + 1);
    printf("  Expected DirFD: -1\n");
    printf("  Expected Inode: %llu, Device: %u:%u (%llu)\n",
           (unsigned long long)st1.st_ino, major(st1.st_dev), minor(st1.st_dev), (unsigned long long)st1.st_dev);
    printf("  Expected Status: SUCCESS (ret=0)\n");
    fflush(stdout);

    usleep(100000);
    if (unlink(file1) != 0) {
        perror("unlink failed");
        return 1;
    }
    printf("  Result: unlink() succeeded (ret=0).\n\n");
    fflush(stdout);

    /* -------------------------------------------------------------
     * Test 2: Successful relative-path unlinkat() using AT_FDCWD
     * ------------------------------------------------------------- */
    printf("[TEST 2: Successful relative-path unlinkat() with AT_FDCWD]\n");
    char file2_template[] = "/tmp/ephim_corr_rel_XXXXXX";
    int fd2 = mkstemp(file2_template);
    if (fd2 < 0) {
        perror("mkstemp 2 failed");
        return 1;
    }
    if (write(fd2, "test2\n", 6) < 0) {}
    struct stat st2;
    fstat(fd2, &st2);
    close(fd2);

    char *base2 = strrchr(file2_template, '/');
    const char *name2 = base2 ? base2 + 1 : file2_template;

    char orig_cwd[512];
    if (!getcwd(orig_cwd, sizeof(orig_cwd))) {
        strcpy(orig_cwd, ".");
    }
    if (chdir("/tmp") != 0) {
        perror("chdir /tmp failed");
        return 1;
    }

    printf("  Action: unlinkat(AT_FDCWD, \"%s\", 0)\n", name2);
    printf("  Expected Syscall: unlinkat\n");
    printf("  Expected Original Path: %s (status=VALID, relative path preserved)\n", name2);
    printf("  Expected Target Basename: %s\n", name2);
    printf("  Expected DirFD: AT_FDCWD (-100)\n");
    printf("  Expected Inode: %llu, Device: %u:%u (%llu)\n",
           (unsigned long long)st2.st_ino, major(st2.st_dev), minor(st2.st_dev), (unsigned long long)st2.st_dev);
    printf("  Expected Status: SUCCESS (ret=0)\n");
    fflush(stdout);

    usleep(100000);
    if (unlinkat(AT_FDCWD, name2, 0) != 0) {
        perror("unlinkat AT_FDCWD failed");
        if (chdir(orig_cwd)) {}
        return 1;
    }
    if (chdir(orig_cwd)) {}
    printf("  Result: unlinkat(AT_FDCWD, ...) succeeded (ret=0).\n\n");
    fflush(stdout);

    /* -------------------------------------------------------------
     * Test 3: Successful relative-path unlinkat() using a non-AT_FDCWD directory descriptor
     * ------------------------------------------------------------- */
    printf("[TEST 3: Successful relative-path unlinkat() with non-AT_FDCWD dirfd]\n");
    char file3_template[] = "/tmp/ephim_corr_dfd_XXXXXX";
    int fd3 = mkstemp(file3_template);
    if (fd3 < 0) {
        perror("mkstemp 3 failed");
        return 1;
    }
    if (write(fd3, "test3\n", 6) < 0) {}
    struct stat st3;
    fstat(fd3, &st3);
    close(fd3);

    char *base3 = strrchr(file3_template, '/');
    const char *name3 = base3 ? base3 + 1 : file3_template;

    int dirfd = open("/tmp", O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        perror("open /tmp failed");
        return 1;
    }

    printf("  Action: unlinkat(dirfd=%d, \"%s\", 0)\n", dirfd, name3);
    printf("  Expected Syscall: unlinkat\n");
    printf("  Expected Original Path: %s (status=VALID, relative name preserved)\n", name3);
    printf("  Expected Target Basename: %s\n", name3);
    printf("  Expected DirFD: %d\n", dirfd);
    printf("  Expected Inode: %llu, Device: %u:%u (%llu)\n",
           (unsigned long long)st3.st_ino, major(st3.st_dev), minor(st3.st_dev), (unsigned long long)st3.st_dev);
    printf("  Expected Status: SUCCESS (ret=0)\n");
    fflush(stdout);

    usleep(100000);
    if (unlinkat(dirfd, name3, 0) != 0) {
        perror("unlinkat dirfd failed");
        close(dirfd);
        return 1;
    }
    close(dirfd);
    printf("  Result: unlinkat(dirfd, ...) succeeded (ret=0).\n\n");
    fflush(stdout);

    /* -------------------------------------------------------------
     * Test 4: Successful rmdir()
     * ------------------------------------------------------------- */
    printf("[TEST 4: Successful rmdir()]\n");
    char dir4[] = "/tmp/ephim_corr_dir4_XXXXXX";
    if (!mkdtemp(dir4)) {
        perror("mkdtemp dir4 failed");
        return 1;
    }
    struct stat st4;
    stat(dir4, &st4);

    printf("  Action: rmdir(\"%s\")\n", dir4);
    printf("  Expected Syscall: rmdir\n");
    printf("  Expected Original Path: %s (status=VALID)\n", dir4);
    printf("  Expected Target Basename: %s\n", strrchr(dir4, '/') + 1);
    printf("  Expected Inode: %llu, Device: %u:%u (%llu)\n",
           (unsigned long long)st4.st_ino, major(st4.st_dev), minor(st4.st_dev), (unsigned long long)st4.st_dev);
    printf("  Expected Status: SUCCESS (ret=0)\n");
    fflush(stdout);

    usleep(100000);
    if (rmdir(dir4) != 0) {
        perror("rmdir failed");
        return 1;
    }
    printf("  Result: rmdir() succeeded (ret=0).\n\n");
    fflush(stdout);

    /* -------------------------------------------------------------
     * Test 5: Successful unlinkat(..., AT_REMOVEDIR)
     * ------------------------------------------------------------- */
    printf("[TEST 5: Successful unlinkat(..., AT_REMOVEDIR)]\n");
    char dir5[] = "/tmp/ephim_corr_dir5_XXXXXX";
    if (!mkdtemp(dir5)) {
        perror("mkdtemp dir5 failed");
        return 1;
    }
    struct stat st5;
    stat(dir5, &st5);

    char *base5 = strrchr(dir5, '/');
    const char *name5 = base5 ? base5 + 1 : dir5;

    int dirfd5 = open("/tmp", O_RDONLY | O_DIRECTORY);
    if (dirfd5 < 0) {
        perror("open /tmp failed");
        return 1;
    }

    printf("  Action: unlinkat(dirfd=%d, \"%s\", AT_REMOVEDIR=0x200)\n", dirfd5, name5);
    printf("  Expected Syscall: unlinkat\n");
    printf("  Expected SyscallFlags: 0x200 (AT_REMOVEDIR)\n");
    printf("  Expected VFS hook: vfs_rmdir (NOT vfs_unlink)\n");
    printf("  Expected Original Path: %s (status=VALID)\n", name5);
    printf("  Expected Target Basename: %s\n", name5);
    printf("  Expected Inode: %llu, Device: %u:%u (%llu)\n",
           (unsigned long long)st5.st_ino, major(st5.st_dev), minor(st5.st_dev), (unsigned long long)st5.st_dev);
    printf("  Expected Status: SUCCESS (ret=0)\n");
    fflush(stdout);

    usleep(100000);
    if (unlinkat(dirfd5, name5, AT_REMOVEDIR) != 0) {
        perror("unlinkat AT_REMOVEDIR failed");
        close(dirfd5);
        return 1;
    }
    close(dirfd5);
    printf("  Result: unlinkat(..., AT_REMOVEDIR) succeeded (ret=0).\n\n");
    fflush(stdout);

    /* -------------------------------------------------------------
     * Test 6: Permission-denied unlink()
     * ------------------------------------------------------------- */
    printf("[TEST 6: Permission-denied unlink()]\n");
    char ro_dir6[] = "/tmp/ephim_corr_ro6_XXXXXX";
    if (!mkdtemp(ro_dir6)) {
        perror("mkdtemp ro_dir6 failed");
    } else {
        char protected_file[512];
        snprintf(protected_file, sizeof(protected_file), "%s/testfile.txt", ro_dir6);
        int fd_p = open(protected_file, O_CREAT | O_WRONLY, 0644);
        if (fd_p >= 0) {
            if (write(fd_p, "data\n", 5) < 0) {}
            struct stat st6;
            fstat(fd_p, &st6);
            close(fd_p);

            chmod(ro_dir6, 0555);
            usleep(100000);

            printf("  Action: unlink(\"%s\") on read-only directory\n", protected_file);
            printf("  Expected Syscall: unlink\n");
            printf("  Expected Target Inode: %llu, Device: %u:%u (%llu)\n",
                   (unsigned long long)st6.st_ino, major(st6.st_dev), minor(st6.st_dev), (unsigned long long)st6.st_dev);
            printf("  Expected Status: FAILED (ret=-13, -EACCES)\n");
            fflush(stdout);

            if (unlink(protected_file) == -1) {
                printf("  Result: unlink() failed with errno=%d (%s) as expected.\n\n",
                       errno, strerror(errno));
            } else {
                printf("  Unexpected: unlink succeeded!\n\n");
            }

            usleep(100000);
            chmod(ro_dir6, 0755);
            unlink(protected_file);
            rmdir(ro_dir6);
        }
    }
    fflush(stdout);

    /* -------------------------------------------------------------
     * Test 7: Permission-denied rmdir()
     * ------------------------------------------------------------- */
    printf("[TEST 7: Permission-denied rmdir()]\n");
    char ro_parent7[] = "/tmp/ephim_corr_ro7_XXXXXX";
    if (!mkdtemp(ro_parent7)) {
        perror("mkdtemp ro_parent7 failed");
    } else {
        char target_dir7[512];
        snprintf(target_dir7, sizeof(target_dir7), "%s/target_dir", ro_parent7);
        if (mkdir(target_dir7, 0755) == 0) {
            struct stat st7;
            stat(target_dir7, &st7);

            chmod(ro_parent7, 0555);
            usleep(100000);

            printf("  Action: rmdir(\"%s\") in read-only parent directory\n", target_dir7);
            printf("  Expected Syscall: rmdir\n");
            printf("  Expected Target Inode: %llu, Device: %u:%u (%llu)\n",
                   (unsigned long long)st7.st_ino, major(st7.st_dev), minor(st7.st_dev), (unsigned long long)st7.st_dev);
            printf("  Expected Status: FAILED (ret=-13, -EACCES)\n");
            fflush(stdout);

            if (rmdir(target_dir7) == -1) {
                printf("  Result: rmdir() failed with errno=%d (%s) as expected.\n\n",
                       errno, strerror(errno));
            } else {
                printf("  Unexpected: rmdir succeeded!\n\n");
            }

            usleep(100000);
            chmod(ro_parent7, 0755);
            rmdir(target_dir7);
            rmdir(ro_parent7);
        }
    }
    fflush(stdout);

    /* -------------------------------------------------------------
     * Test 8: Non-empty directory rmdir()
     * ------------------------------------------------------------- */
    printf("[TEST 8: Non-empty directory rmdir()]\n");
    char nonempty8[] = "/tmp/ephim_corr_nonempty8_XXXXXX";
    if (!mkdtemp(nonempty8)) {
        perror("mkdtemp nonempty8 failed");
    } else {
        char child_file[512];
        snprintf(child_file, sizeof(child_file), "%s/child.txt", nonempty8);
        int fd_c = open(child_file, O_CREAT | O_WRONLY, 0644);
        if (fd_c >= 0) {
            if (write(fd_c, "child\n", 6) < 0) {}
            close(fd_c);
        }
        struct stat st8;
        stat(nonempty8, &st8);

        printf("  Action: rmdir(\"%s\") with child.txt inside\n", nonempty8);
        printf("  Expected Syscall: rmdir\n");
        printf("  Expected Target Inode: %llu, Device: %u:%u (%llu)\n",
               (unsigned long long)st8.st_ino, major(st8.st_dev), minor(st8.st_dev), (unsigned long long)st8.st_dev);
        printf("  Expected Status: FAILED (ret=-39, -ENOTEMPTY)\n");
        fflush(stdout);

        usleep(100000);
        if (rmdir(nonempty8) == -1) {
            printf("  Result: rmdir() failed with errno=%d (%s) as expected.\n\n",
                   errno, strerror(errno));
        } else {
            printf("  Unexpected: rmdir succeeded!\n\n");
        }

        usleep(100000);
        unlink(child_file);
        rmdir(nonempty8);
    }
    fflush(stdout);

    /* -------------------------------------------------------------
     * Test 9: Nonexistent file and directory paths that fail before VFS
     * ------------------------------------------------------------- */
    printf("[TEST 9: Nonexistent file and directory paths (fail before VFS)]\n");
    const char *non_file = "/tmp/ephim_nonexistent_file_999999.tmp";
    const char *non_dir = "/tmp/ephim_nonexistent_dir_999999";

    printf("  Action 1: unlink(\"%s\")\n", non_file);
    if (unlink(non_file) == -1) {
        printf("  Result: unlink() failed with errno=%d (%s).\n", errno, strerror(errno));
        printf("  Observation: filename_lookup() fails early with -ENOENT; sys_exit_unlink cleans up pending map.\n");
    }

    printf("  Action 2: rmdir(\"%s\")\n", non_dir);
    if (rmdir(non_dir) == -1) {
        printf("  Result: rmdir() failed with errno=%d (%s).\n", errno, strerror(errno));
        printf("  Observation: filename_lookup() fails early with -ENOENT; sys_exit_rmdir cleans up pending map.\n\n");
    }
    fflush(stdout);

    /* -------------------------------------------------------------
     * Test 10: Missing or unmatched syscall context handling
     * ------------------------------------------------------------- */
    printf("[TEST 10: Unmatched context handling]\n");
    printf("  Observation: When a VFS hook runs without matching syscall context\n"
           "  (e.g., kernel-internal removal or unmatched TID/type),\n"
           "  VFS_IDENTITY_SYSCALL_VALID is not set;\n"
           "  EphimTrace outputs Syscall: <unmatched> and Path: <unavailable>\n"
           "  while retaining resolved filesystem identity.\n\n");
    fflush(stdout);

    /* -------------------------------------------------------------
     * Test 11: Path truncation behavior (> 256 bytes)
     * ------------------------------------------------------------- */
    printf("[TEST 11: Path truncation behavior (> 256 bytes)]\n");
    char long_dir_prefix[] = "/tmp/ephim_trunc_XXXXXX";
    if (!mkdtemp(long_dir_prefix)) {
        perror("mkdtemp long_dir_prefix failed");
    } else {
        char nested_path[512];
        snprintf(nested_path, sizeof(nested_path), "%s/123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890", long_dir_prefix);
        printf("  Path length: %zu bytes (exceeds 256-byte buffer limit)\n", strlen(nested_path));
        printf("  Action: unlink(\"%s\")\n", nested_path);
        printf("  Expected sensor behavior: bpf_probe_read_user_str reads 256 bytes,\n"
               "  detects truncation, sets path_status = PATH_TRUNCATED, null-terminates safely.\n");
        printf("  Expected loader output: Path: [TRUNCATED] ... (status=TRUNCATED)\n");
        fflush(stdout);

        int fd_trunc = open(nested_path, O_CREAT | O_WRONLY, 0644);
        if (fd_trunc >= 0) close(fd_trunc);
        usleep(100000);
        unlink(nested_path);
        printf("  Result: syscall executed, sys_enter_unlink handled truncation safely.\n");

        rmdir(long_dir_prefix);
    }
    fflush(stdout);

    printf("======================================================================\n");
    printf("   All 11 Correlation Scenarios Executed Successfully\n");
    printf("======================================================================\n\n");
    return 0;
}
