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
#include <string.h>
#include <errno.h>

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

int main(void)
{
    pid_t pid = getpid();
    pid_t tid = (pid_t)syscall(SYS_gettid);

    printf("\n=======================================================\n");
    printf("=== EphimTrace Milestone M2.4: Execution Provenance ===\n");
    printf("=======================================================\n");
    printf("[INIT] Process PID: %d, TID: %d\n\n", pid, tid);

    /* -------------------------------------------------------------
     * Test 1: Successful execution via execveat(AT_EMPTY_PATH)
     * ------------------------------------------------------------- */
    printf("[TEST 1: Execution via execveat(AT_EMPTY_PATH)]\n");
    int fd1 = memfd_create("m2_exec_script_1", 0);
    if (fd1 < 0) {
        perror("memfd_create failed");
        return 1;
    }
    const char script1[] = "#!/bin/sh\nexit 0\n";
    if (write(fd1, script1, sizeof(script1) - 1) < 0) {
        perror("write failed");
        close(fd1);
        return 1;
    }
    fchmod(fd1, 0755);

    pid_t child1 = fork();
    if (child1 < 0) {
        perror("fork failed");
        close(fd1);
        return 1;
    }
    if (child1 == 0) {
        char *argv[] = { "m2_exec_test_child", NULL };
        char *envp[] = { NULL };
        syscall(SYS_execveat, fd1, "", argv, envp, AT_EMPTY_PATH);
        perror("execveat failed");
        _exit(127);
    }

    int status1 = 0;
    waitpid(child1, &status1, 0);
    if (WIFEXITED(status1) && WEXITSTATUS(status1) == 0) {
        printf("  [PASS] Child %d executed memfd script via execveat and exited cleanly (code 0)\n", child1);
    } else {
        printf("  [FAIL] Child %d failed or exited non-zero: 0x%x\n", child1, status1);
        close(fd1);
        return 1;
    }
    close(fd1);

    /* -------------------------------------------------------------
     * Test 2: Successful execution via fexecve()
     * ------------------------------------------------------------- */
    printf("\n[TEST 2: Execution via fexecve()]\n");
    int fd2 = memfd_create("m2_exec_fexecve", 0);
    if (fd2 < 0) {
        perror("memfd_create failed");
        return 1;
    }
    const char script2[] = "#!/bin/sh\nexit 0\n";
    if (write(fd2, script2, sizeof(script2) - 1) < 0) {
        perror("write failed");
        close(fd2);
        return 1;
    }
    fchmod(fd2, 0755);

    pid_t child2 = fork();
    if (child2 < 0) {
        perror("fork failed");
        close(fd2);
        return 1;
    }
    if (child2 == 0) {
        char *argv[] = { "m2_fexecve_child", NULL };
        char *envp[] = { NULL };
        fexecve(fd2, argv, envp);
        perror("fexecve failed");
        _exit(127);
    }

    int status2 = 0;
    waitpid(child2, &status2, 0);
    if (WIFEXITED(status2) && WEXITSTATUS(status2) == 0) {
        printf("  [PASS] Child %d executed memfd script via fexecve and exited cleanly (code 0)\n", child2);
    } else {
        printf("  [FAIL] Child %d failed: 0x%x\n", child2, status2);
        close(fd2);
        return 1;
    }
    close(fd2);

    /* -------------------------------------------------------------
     * Test 3: Successful execution via /proc/self/fd/N path
     * ------------------------------------------------------------- */
    printf("\n[TEST 3: Execution via /proc/self/fd/N reopening]\n");
    int fd3 = memfd_create("m2_exec_proc_reopen", 0);
    if (fd3 < 0) {
        perror("memfd_create failed");
        return 1;
    }
    const char script3[] = "#!/bin/sh\nexit 0\n";
    if (write(fd3, script3, sizeof(script3) - 1) < 0) {
        perror("write failed");
        close(fd3);
        return 1;
    }
    fchmod(fd3, 0755);

    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd3);

    pid_t child3 = fork();
    if (child3 < 0) {
        perror("fork failed");
        close(fd3);
        return 1;
    }
    if (child3 == 0) {
        char *argv[] = { "m2_proc_reopen_child", NULL };
        char *envp[] = { NULL };
        execve(proc_path, argv, envp);
        perror("execve via /proc/self/fd failed");
        _exit(127);
    }

    int status3 = 0;
    waitpid(child3, &status3, 0);
    if (WIFEXITED(status3) && WEXITSTATUS(status3) == 0) {
        printf("  [PASS] Child %d executed memfd via %s and exited cleanly (code 0)\n", child3, proc_path);
    } else {
        printf("  [FAIL] Child %d failed: 0x%x\n", child3, status3);
        close(fd3);
        return 1;
    }
    close(fd3);

    /* -------------------------------------------------------------
     * Test 4: Execution failure on corrupted/invalid memfd binary
     * ------------------------------------------------------------- */
    printf("\n[TEST 4: Corrupted/invalid memfd binary execution abort]\n");
    int fd_corrupt = memfd_create("m2_corrupt_exec", 0);
    if (fd_corrupt < 0) {
        perror("memfd_create failed");
        return 1;
    }
    const char bad_payload[] = "INVALID_CORRUPTED_BINARY_NOT_ELF_NOT_SCRIPT\n";
    if (write(fd_corrupt, bad_payload, sizeof(bad_payload)) < 0) {
        perror("write failed");
        close(fd_corrupt);
        return 1;
    }
    fchmod(fd_corrupt, 0755);

    /* Attempt execution directly in a child to observe failure and trigger sys_exit_execveat */
    pid_t child_fail = fork();
    if (child_fail < 0) {
        perror("fork failed");
        close(fd_corrupt);
        return 1;
    }
    if (child_fail == 0) {
        char *argv[] = { "corrupt_child", NULL };
        char *envp[] = { NULL };
        int ret = syscall(SYS_execveat, fd_corrupt, "", argv, envp, AT_EMPTY_PATH);
        if (ret < 0) {
            /* Successfully failed with negative ret, expected errno is ENOEXEC (8) */
            _exit(errno == ENOEXEC ? 42 : 43);
        }
        _exit(0);
    }

    int status_fail = 0;
    waitpid(child_fail, &status_fail, 0);
    if (WIFEXITED(status_fail) && WEXITSTATUS(status_fail) == 42) {
        printf("  [PASS] Invalid memfd binary execution rejected with -ENOEXEC as expected\n");
    } else {
        printf("  [FAIL] Unexpected exit status for corrupt execution: 0x%x\n", status_fail);
        close(fd_corrupt);
        return 1;
    }
    close(fd_corrupt);

    printf("\n=== M2.4 Execution Provenance Tests Complete ===\n\n");
    return 0;
}
