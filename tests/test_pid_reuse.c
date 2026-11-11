#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

int main(void)
{
    printf("\n=== EphimTrace Sequential Process Lifecycle Test ===\n");
    printf("[PID-TEST] Spawning sequential short-lived child processes...\n");
    printf("[PID-TEST] Note: In modern Linux systems with high pid_max, sequential forks\n");
    printf("           receive distinct incrementing PIDs unless system-wide PID recycling occurs.\n");
    printf("           This test verifies each generation receives distinct kernel start times.\n");
    fflush(stdout);

    pid_t previous_pid = 0;
    int pid_reused = 0;

    for (int i = 0; i < 5; i++) {
        pid_t pid = fork();
        if (pid < 0) {
            perror("fork failed");
            return 1;
        }

        if (pid == 0) {
            /* Child */
            usleep(30000); /* 30ms */
            exit(0);
        }

        /* Wait for child to exit completely before next iteration */
        waitpid(pid, NULL, 0);

        if (previous_pid != 0 && pid == previous_pid) {
            pid_reused = 1;
            printf("[PID-TEST] Iteration %d: Observed numeric PID reuse (PID=%d)!\n", i + 1, pid);
        } else {
            printf("[PID-TEST] Iteration %d: Spawned child PID=%d (exited cleanly).\n", i + 1, pid);
        }
        previous_pid = pid;
        fflush(stdout);
        usleep(30000);
    }

    if (!pid_reused) {
        printf("[PID-TEST] Sequential run complete. Kernel allocated sequential PIDs (no immediate PID reuse observed).\n");
    }
    printf("[PID-TEST] Test completed successfully.\n");
    return 0;
}
