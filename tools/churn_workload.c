#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <string.h>

#define DEFAULT_ITERATIONS 5000

int main(int argc, char **argv)
{
    int iterations = DEFAULT_ITERATIONS;
    if (argc > 1) {
        iterations = atoi(argv[1]);
        if (iterations <= 0) iterations = DEFAULT_ITERATIONS;
    }

    printf("[CHURN WORKLOAD] Running %d rapid memfd create/write/close iterations...\n", iterations);
    fflush(stdout);

    const char payload[] = "EPHIMTRACE_BENCHMARK_CHURN_PAYLOAD_BYTES_64B_TEST_METRICS_ABCDEF\n";
    size_t payload_len = sizeof(payload) - 1;

    struct timespec ts_start, ts_end;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    int successes = 0;
    int failures = 0;

    for (int i = 0; i < iterations; i++) {
        char name[32];
        snprintf(name, sizeof(name), "bench_%d", i);

        int fd = memfd_create(name, 0);
        if (fd < 0) {
            failures++;
            continue;
        }

        if (write(fd, payload, payload_len) != (ssize_t)payload_len) {
            failures++;
        } else {
            successes++;
        }

        close(fd);
    }

    clock_gettime(CLOCK_MONOTONIC, &ts_end);
    double elapsed_sec = (ts_end.tv_sec - ts_start.tv_sec) + (ts_end.tv_nsec - ts_start.tv_nsec) / 1e9;
    double throughput = (elapsed_sec > 0) ? (iterations / elapsed_sec) : 0;

    printf("[CHURN WORKLOAD] Completed %d iterations in %.4f seconds (%.1f ops/sec, failures: %d)\n",
           iterations, elapsed_sec, throughput, failures);
    return (failures == 0) ? 0 : 1;
}
