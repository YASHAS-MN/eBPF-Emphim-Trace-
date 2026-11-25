#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>

static pid_t gettid_sys(void)
{
    return (pid_t)syscall(SYS_gettid);
}

static void *worker_thread(void *arg)
{
    long id = (long)arg;
    pid_t pid = getpid();
    pid_t tid = gettid_sys();

    printf("[TEST] Worker thread %ld running (PID=%d, TID=%d)\n", id, pid, tid);
    fflush(stdout);

    /* Sleep briefly so EphimTrace registers the thread before it exits */
    usleep(300000); /* 300 ms */

    printf("[TEST] Worker thread %ld exiting (non-final thread exit)\n", id);
    fflush(stdout);

    return NULL;
}

int main(void)
{
    pid_t main_pid = getpid();
    pid_t main_tid = gettid_sys();
    pthread_t t1, t2;

    printf("\n=== EphimTrace Lifecycle Test Harness ===\n");
    printf("[TEST] Stage 1: Main process alive (PID=%d, TID=%d)\n", main_pid, main_tid);
    fflush(stdout);

    /* Allow initial main thread discovery */
    usleep(200000);

    /* Stage 2: Create thread 1 (thread clone) */
    printf("\n[TEST] Stage 2: Creating worker thread 1...\n");
    fflush(stdout);
    if (pthread_create(&t1, NULL, worker_thread, (void *)1) != 0) {
        perror("pthread_create 1 failed");
        return 1;
    }
    usleep(100000);

    /* Stage 3: Create thread 2 (thread clone) */
    printf("\n[TEST] Stage 3: Creating worker thread 2...\n");
    fflush(stdout);
    if (pthread_create(&t2, NULL, worker_thread, (void *)2) != 0) {
        perror("pthread_create 2 failed");
        return 1;
    }

    /* Stage 4: Wait for thread 1 and thread 2 non-final exits */
    printf("\n[TEST] Stage 4: Joining worker threads...\n");
    fflush(stdout);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    printf("[TEST] Both worker threads terminated and joined.\n");
    fflush(stdout);
    usleep(200000);

    /* Stage 5: Fork child process and execute an external binary */
    printf("\n[TEST] Stage 5: Forking child process...\n");
    fflush(stdout);
    pid_t child_pid = fork();

    if (child_pid < 0) {
        perror("fork failed");
        return 1;
    }

    if (child_pid == 0) {
        /* In child process */
        printf("[TEST CHILD] Child process running (PID=%d, TID=%d). Executing /bin/true...\n",
               getpid(), gettid_sys());
        fflush(stdout);

        char *const argv[] = {"true", NULL};
        char *const envp[] = {NULL};
        execve("/bin/true", argv, envp);

        perror("execve failed");
        exit(1);
    }

    /* In parent process: wait for child to complete */
    int status;
    waitpid(child_pid, &status, 0);
    printf("[TEST] Child process (PID=%d) finished with status %d (final process exit).\n",
           child_pid, WEXITSTATUS(status));
    fflush(stdout);

    usleep(200000);

    /* Stage 6: Main process terminates (final process exit of main PID) */
    printf("\n[TEST] Stage 6: Main process exiting.\n");
    fflush(stdout);

    return 0;
}
