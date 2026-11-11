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
    char dir1[] = "/tmp/ephim_test_rmdir_XXXXXX";
    char dir2[] = "/tmp/ephim_test_unlinkat_dir_XXXXXX";
    char dir_nonempty[] = "/tmp/ephim_test_nonempty_XXXXXX";
    char perm_parent[] = "/tmp/ephim_test_perm_parent_XXXXXX";
    struct stat st1, st2, st_ne, st_perm;
    unsigned int mnt_ns = 0;

    get_mount_ns_id(&mnt_ns);

    printf("\n=== EphimTrace Rmdir File Identity & Completion Test ===\n");
    printf("[TEST] Process PID: %d, TID: %d, MountNS: %u\n", getpid(), (int)getpid(), mnt_ns);
    fflush(stdout);

    /* --- Test 1: Controlled successful rmdir() --- */
    if (!mkdtemp(dir1)) {
        perror("mkdtemp dir1 failed");
        return 1;
    }
    stat(dir1, &st1);

    printf("\n[TEST 1: Successful rmdir()]\n");
    printf("Created directory: %s\n", dir1);
    printf("Expected Inode: %llu\n", (unsigned long long)st1.st_ino);
    printf("Expected Device: %u:%u (%llu)\n", major(st1.st_dev), minor(st1.st_dev), (unsigned long long)st1.st_dev);
    printf("Expected MountNS: %u\n", mnt_ns);
    fflush(stdout);

    usleep(100000);

    if (rmdir(dir1) != 0) {
        perror("rmdir failed");
        return 1;
    }
    printf("[TEST 1] rmdir(%s) returned 0 (SUCCESS).\n", dir1);
    fflush(stdout);

    /* --- Test 2: Controlled successful unlinkat(..., AT_REMOVEDIR) --- */
    if (!mkdtemp(dir2)) {
        perror("mkdtemp dir2 failed");
        return 1;
    }
    stat(dir2, &st2);

    char *base2 = strrchr(dir2, '/');
    const char *name2 = base2 ? base2 + 1 : dir2;
    int dirfd = open("/tmp", O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        perror("open /tmp failed");
        return 1;
    }

    printf("\n[TEST 2: Successful unlinkat(..., AT_REMOVEDIR)]\n");
    printf("Created directory: %s (in dirfd for /tmp, relative name: %s)\n", dir2, name2);
    printf("Expected Inode: %llu\n", (unsigned long long)st2.st_ino);
    printf("Expected Device: %u:%u (%llu)\n", major(st2.st_dev), minor(st2.st_dev), (unsigned long long)st2.st_dev);
    printf("Expected MountNS: %u\n", mnt_ns);
    fflush(stdout);

    usleep(100000);

    if (unlinkat(dirfd, name2, AT_REMOVEDIR) != 0) {
        perror("unlinkat AT_REMOVEDIR failed");
        close(dirfd);
        return 1;
    }
    close(dirfd);
    printf("[TEST 2] unlinkat(dirfd, %s, AT_REMOVEDIR) returned 0 (SUCCESS).\n", name2);
    fflush(stdout);

    /* --- Test 3: Failed removal of nonexistent directory --- */
    printf("\n[TEST 3: Failed rmdir() of nonexistent directory]\n");
    const char *non_existent = "/tmp/ephim_nonexistent_dir_99999";
    if (rmdir(non_existent) == -1) {
        printf("rmdir(%s) failed as expected (errno=%d: %s)\n",
               non_existent, errno, strerror(errno));
        printf("Kernel observation: Path resolution fails early in filename_lookup() with -ENOENT before vfs_rmdir().\n");
    }
    fflush(stdout);

    /* --- Test 4: Failed removal of non-empty directory --- */
    printf("\n[TEST 4: Failed rmdir() of non-empty directory]\n");
    if (!mkdtemp(dir_nonempty)) {
        perror("mkdtemp dir_nonempty failed");
    } else {
        char nested_file[512];
        snprintf(nested_file, sizeof(nested_file), "%s/child.txt", dir_nonempty);
        int fd_n = open(nested_file, O_CREAT | O_WRONLY, 0644);
        if (fd_n >= 0) {
            if (write(fd_n, "content\n", 8) < 0) {}
            close(fd_n);
        }
        stat(dir_nonempty, &st_ne);

        printf("Created directory: %s (populated with child.txt)\n", dir_nonempty);
        printf("Expected Inode: %llu\n", (unsigned long long)st_ne.st_ino);
        printf("Expected Device: %u:%u (%llu)\n", major(st_ne.st_dev), minor(st_ne.st_dev), (unsigned long long)st_ne.st_dev);
        printf("Expected MountNS: %u\n", mnt_ns);

        usleep(100000);

        if (rmdir(dir_nonempty) == -1) {
            printf("rmdir(%s) failed with errno=%d (%s) as expected.\n",
                   dir_nonempty, errno, strerror(errno));
            printf("Kernel observation: Path resolves successfully and invokes vfs_rmdir(). Filesystem rejects deletion because directory is not empty (ret=-%d).\n", errno);
        } else {
            printf("Unexpected: rmdir succeeded on non-empty directory!\n");
        }

        /* Clean up */
        unlink(nested_file);
        rmdir(dir_nonempty);
    }
    fflush(stdout);

    /* --- Test 5: Failed removal due to insufficient permissions in parent directory --- */
    printf("\n[TEST 5: Failed rmdir() due to insufficient permissions]\n");
    if (!mkdtemp(perm_parent)) {
        perror("mkdtemp perm_parent failed");
    } else {
        char target_subdir[512];
        snprintf(target_subdir, sizeof(target_subdir), "%s/target_dir", perm_parent);
        if (mkdir(target_subdir, 0755) == 0) {
            stat(target_subdir, &st_perm);

            printf("Created parent: %s\n", perm_parent);
            printf("Created subdirectory: %s\n", target_subdir);
            printf("Expected Inode: %llu\n", (unsigned long long)st_perm.st_ino);
            printf("Expected Device: %u:%u (%llu)\n", major(st_perm.st_dev), minor(st_perm.st_dev), (unsigned long long)st_perm.st_dev);
            printf("Expected MountNS: %u\n", mnt_ns);

            /* Revoke write permission on parent directory so deletion is disallowed */
            chmod(perm_parent, 0555);

            usleep(100000);

            if (rmdir(target_subdir) == -1) {
                printf("rmdir(%s) failed with errno=%d (%s) as expected.\n",
                       target_subdir, errno, strerror(errno));
                printf("Kernel observation: Path resolves target_subdir (parent retains +r+x). vfs_rmdir() is entered and may_delete() fails with -EACCES (ret=-13).\n");
            } else {
                printf("Unexpected: rmdir succeeded (running as root?)\n");
            }

            /* Restore parent write permission and clean up */
            chmod(perm_parent, 0755);
            rmdir(target_subdir);
            rmdir(perm_parent);
        }
    }
    fflush(stdout);

    printf("\n=== Test Completed Successfully ===\n");
    return 0;
}
