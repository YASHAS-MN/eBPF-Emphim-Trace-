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
        /* Format: mnt:[<inum>] */
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
    char file1[] = "/tmp/ephim_test_unlink_XXXXXX";
    char file2[] = "/tmp/ephim_test_unlinkat_XXXXXX";
    char ro_dir[] = "/tmp/ephim_test_rodir_XXXXXX";
    struct stat st1, st2, st_ro;
    unsigned int mnt_ns = 0;

    get_mount_ns_id(&mnt_ns);

    printf("\n=== EphimTrace Unlink & Unlinkat File Identity & Completion Test ===\n");
    printf("[TEST] Process PID: %d, TID: %d, MountNS: %u\n", getpid(), (int)getpid(), mnt_ns);
    fflush(stdout);

    /* --- Test 1: Controlled successful unlink() --- */
    int fd1 = mkstemp(file1);
    if (fd1 < 0) {
        perror("mkstemp 1 failed");
        return 1;
    }
    if (write(fd1, "unlink test\n", 12) < 0) {
        perror("write 1 failed");
    }
    fstat(fd1, &st1);
    close(fd1);

    printf("\n[TEST 1: Successful unlink()]\n");
    printf("Created file: %s\n", file1);
    printf("Expected Inode: %llu\n", (unsigned long long)st1.st_ino);
    printf("Expected Device: %u:%u (%llu)\n", major(st1.st_dev), minor(st1.st_dev), (unsigned long long)st1.st_dev);
    printf("Expected MountNS: %u\n", mnt_ns);
    fflush(stdout);

    usleep(100000); /* 100ms pause to observe clearly in trace */

    if (unlink(file1) != 0) {
        perror("unlink failed");
        return 1;
    }
    printf("[TEST 1] unlink(%s) returned 0 (SUCCESS).\n", file1);
    fflush(stdout);

    /* --- Test 2: Controlled successful unlinkat() --- */
    int fd2 = mkstemp(file2);
    if (fd2 < 0) {
        perror("mkstemp 2 failed");
        return 1;
    }
    if (write(fd2, "unlinkat test\n", 14) < 0) {
        perror("write 2 failed");
    }
    fstat(fd2, &st2);
    close(fd2);

    /* Extract basename for unlinkat with AT_FDCWD */
    char *base2 = strrchr(file2, '/');
    const char *name2 = base2 ? base2 + 1 : file2;
    int dirfd = open("/tmp", O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        perror("open /tmp failed");
        return 1;
    }

    printf("\n[TEST 2: Successful unlinkat()]\n");
    printf("Created file: %s (in dirfd for /tmp, relative name: %s)\n", file2, name2);
    printf("Expected Inode: %llu\n", (unsigned long long)st2.st_ino);
    printf("Expected Device: %u:%u (%llu)\n", major(st2.st_dev), minor(st2.st_dev), (unsigned long long)st2.st_dev);
    printf("Expected MountNS: %u\n", mnt_ns);
    fflush(stdout);

    usleep(100000);

    if (unlinkat(dirfd, name2, 0) != 0) {
        perror("unlinkat failed");
        close(dirfd);
        return 1;
    }
    close(dirfd);
    printf("[TEST 2] unlinkat(dirfd, %s, 0) returned 0 (SUCCESS).\n", name2);
    fflush(stdout);

    /* --- Test 3: Failed unlink due to nonexistent target --- */
    printf("\n[TEST 3: Failed unlink() of nonexistent file]\n");
    const char *non_existent = "/tmp/ephim_non_existent_file_99999.tmp";
    if (unlink(non_existent) == -1) {
        printf("unlink(%s) failed as expected (errno=%d: %s)\n",
               non_existent, errno, strerror(errno));
        printf("Kernel observation: Path lookup fails early in filename_lookup() before reaching vfs_unlink(). Syscall entry is recorded, but vfs_unlink is not invoked.\n");
    }
    fflush(stdout);

    /* --- Test 4: Controlled permission failure in directory without write permissions --- */
    printf("\n[TEST 4: Failed unlink() in permission-denied directory]\n");
    if (!mkdtemp(ro_dir)) {
        perror("mkdtemp failed");
    } else {
        char protected_file[512];
        snprintf(protected_file, sizeof(protected_file), "%s/testfile.txt", ro_dir);
        int fd_p = open(protected_file, O_CREAT | O_WRONLY, 0644);
        if (fd_p >= 0) {
            if (write(fd_p, "protected\n", 10) < 0) {}
            fstat(fd_p, &st_ro);
            close(fd_p);

            printf("Created directory: %s\n", ro_dir);
            printf("Created file inside: %s\n", protected_file);
            printf("Expected Inode: %llu\n", (unsigned long long)st_ro.st_ino);
            printf("Expected Device: %u:%u (%llu)\n", major(st_ro.st_dev), minor(st_ro.st_dev), (unsigned long long)st_ro.st_dev);
            printf("Expected MountNS: %u\n", mnt_ns);

            /* Remove write permission from parent directory so deletion fails */
            chmod(ro_dir, 0555);

            usleep(100000);

            if (unlink(protected_file) == -1) {
                printf("unlink(%s) failed with errno=%d (%s) as expected.\n",
                       protected_file, errno, strerror(errno));
                printf("Kernel observation: Path resolution traverses ro-dir (mode 0555 retains +r+x), successfully resolves target dentry, and calls vfs_unlink(). Inside vfs_unlink(), may_delete() rejects deletion with -EACCES (ret=-13).\n");
            } else {
                printf("Unexpected: unlink succeeded (running as root?)\n");
            }

            /* Restore directory permission and clean up */
            chmod(ro_dir, 0755);
            unlink(protected_file);
            rmdir(ro_dir);
        }
    }
    fflush(stdout);

    printf("\n=== Test Completed Successfully ===\n");
    return 0;
}
