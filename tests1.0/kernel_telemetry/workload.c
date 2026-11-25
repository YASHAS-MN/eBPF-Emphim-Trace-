#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <string.h>
#include <stdatomic.h>
#include <sys/resource.h>

struct op_record {
    uint64_t op_id;
    char name[64];
    pid_t pid;
    pid_t tid;
    int ret;
    int err;
    int success;
};

static unsigned iterations, delay_us, hold;
static unsigned memfd_flags = MFD_CLOEXEC;
static const char *ground_truth_path = NULL;

/* Separate aggregate counters for creation */
static atomic_ulong create_attempts;
static atomic_ulong create_successes;
static atomic_ulong create_failures;

/* Separate aggregate counters for write */
static atomic_ulong write_attempts;
static atomic_ulong write_successes;
static atomic_ulong write_failures;

/* Separate aggregate counters for close */
static atomic_ulong close_attempts;
static atomic_ulong close_successes;
static atomic_ulong close_failures;

/* Backward-compatible aggregate counters */
static atomic_ulong calls;
static atomic_ulong creates;
static atomic_ulong writes;
static atomic_ulong closes;
static atomic_ulong failures;

/* Global monotonic operation sequence ID */
static atomic_ulong global_op_seq;

/* Preallocated per-operation records */
static struct op_record *records = NULL;
static size_t total_ops = 0;

/* Robust synchronization gate (replaces pthread_barrier_t to prevent deadlocks on partial launch) */
static pthread_mutex_t start_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t start_cond = PTHREAD_COND_INITIALIZER;
static unsigned ready_count = 0;
static int start_go = 0;
static int abort_launch = 0;

static void *worker(void *arg) {
    unsigned long id = (unsigned long)(uintptr_t)arg;
    pid_t my_pid = getpid();
    pid_t my_tid = (pid_t)syscall(SYS_gettid);
    int *fds = hold ? calloc(iterations, sizeof(int)) : NULL;
    if (hold && !fds) {
        atomic_fetch_add(&failures, 1);
    }
    unsigned n = 0;

    /* Robust launch synchronization */
    pthread_mutex_lock(&start_lock);
    ready_count++;
    pthread_cond_broadcast(&start_cond);
    while (!start_go && !abort_launch) {
        pthread_cond_wait(&start_cond, &start_lock);
    }
    if (abort_launch) {
        pthread_mutex_unlock(&start_lock);
        free(fds);
        return NULL;
    }
    pthread_mutex_unlock(&start_lock);

    if (hold && !fds) return NULL;

    for (unsigned i = 0; i < iterations; i++) {
        size_t idx = (size_t)id * iterations + i;
        struct op_record *rec = &records[idx];
        rec->op_id = (uint64_t)atomic_fetch_add(&global_op_seq, 1) + 1;
        snprintf(rec->name, sizeof(rec->name), "ephim_lab_%lu_%u", id, i);
        rec->pid = my_pid;
        rec->tid = my_tid;

        atomic_fetch_add(&create_attempts, 1);
        atomic_fetch_add(&calls, 1);

        rec->ret = memfd_create(rec->name, memfd_flags);
        if (rec->ret < 0) {
            rec->err = errno;
            rec->success = 0;
            atomic_fetch_add(&create_failures, 1);
            atomic_fetch_add(&failures, 1);
            if (delay_us) usleep(delay_us);
            continue;
        }

        rec->err = 0;
        rec->success = 1;
        atomic_fetch_add(&create_successes, 1);
        atomic_fetch_add(&creates, 1);

        int fd = rec->ret;

        atomic_fetch_add(&write_attempts, 1);
        if (write(fd, "E", 1) == 1) {
            atomic_fetch_add(&write_successes, 1);
            atomic_fetch_add(&writes, 1);
        } else {
            atomic_fetch_add(&write_failures, 1);
            atomic_fetch_add(&failures, 1);
        }

        if (hold) {
            fds[n++] = fd;
        } else {
            atomic_fetch_add(&close_attempts, 1);
            if (close(fd) == 0) {
                atomic_fetch_add(&close_successes, 1);
                atomic_fetch_add(&closes, 1);
            } else {
                atomic_fetch_add(&close_failures, 1);
                atomic_fetch_add(&failures, 1);
            }
        }

        if (delay_us) usleep(delay_us);
    }

    for (unsigned i = 0; i < n; i++) {
        atomic_fetch_add(&close_attempts, 1);
        if (close(fds[i]) == 0) {
            atomic_fetch_add(&close_successes, 1);
            atomic_fetch_add(&closes, 1);
        } else {
            atomic_fetch_add(&close_failures, 1);
            atomic_fetch_add(&failures, 1);
        }
    }
    free(fds);
    return NULL;
}

static int export_records_json(FILE *f, double elapsed_sec, int include_records, const char *records_file_path) {
    if (!f) return -1;
    uint64_t c_att = atomic_load(&create_attempts);
    uint64_t c_succ = atomic_load(&create_successes);
    uint64_t c_fail = atomic_load(&create_failures);
    uint64_t w_att = atomic_load(&write_attempts);
    uint64_t w_succ = atomic_load(&write_successes);
    uint64_t w_fail = atomic_load(&write_failures);
    uint64_t cl_att = atomic_load(&close_attempts);
    uint64_t cl_succ = atomic_load(&close_successes);
    uint64_t cl_fail = atomic_load(&close_failures);
    uint64_t total_fail = atomic_load(&failures);

    fprintf(f, "{\"status\":\"VALID\",\"calls\":%lu,\"creates\":%lu,\"writes\":%lu,\"closes\":%lu,\"failures\":%lu,"
               "\"create_attempts\":%lu,\"create_successes\":%lu,\"create_failures\":%lu,"
               "\"write_attempts\":%lu,\"write_successes\":%lu,\"write_failures\":%lu,"
               "\"close_attempts\":%lu,\"close_successes\":%lu,\"close_failures\":%lu,"
               "\"seconds\":%.9f",
               c_att, c_succ, w_succ, cl_succ, total_fail,
               c_att, c_succ, c_fail,
               w_att, w_succ, w_fail,
               cl_att, cl_succ, cl_fail,
               elapsed_sec);

    if (records_file_path && records_file_path[0]) {
        fprintf(f, ",\"records_file\":\"%s\"", records_file_path);
    }

    if (include_records) {
        fprintf(f, ",\"records\":[");
        for (size_t i = 0; i < total_ops; i++) {
            struct op_record *r = &records[i];
            fprintf(f, "%s{\"op_id\":%lu,\"name\":\"%s\",\"pid\":%d,\"tid\":%d,\"ret\":%d,\"errno\":%d,\"success\":%d}",
                    (i > 0) ? "," : "",
                    (unsigned long)r->op_id, r->name, (int)r->pid, (int)r->tid, r->ret, r->err, r->success);
        }
        fprintf(f, "]");
    }

    fprintf(f, "}\n");
    return (fflush(f) == 0 && !ferror(f)) ? 0 : -1;
}

int main(int argc, char **argv) {
    if (argc < 5 || argc > 7) return 2;
    iterations = strtoul(argv[1], NULL, 10);
    unsigned workers = strtoul(argv[2], NULL, 10);
    delay_us = strtoul(argv[3], NULL, 10);
    hold = strtoul(argv[4], NULL, 10);

    /* Optional flag parameter for controlled failure testing */
    const char *env_flags = getenv("EPHIM_MEMFD_FLAGS");
    if (env_flags) memfd_flags = (unsigned)strtoul(env_flags, NULL, 0);
    if (argc >= 6) memfd_flags = (unsigned)strtoul(argv[5], NULL, 0);

    /* Optional file export path */
    const char *env_file = getenv("EPHIM_GROUND_TRUTH_FILE");
    if (env_file) ground_truth_path = env_file;
    if (argc >= 7) ground_truth_path = argv[6];

    if (!iterations || iterations > 1000000 || !workers || workers > 64 ||
        (hold && (uint64_t)iterations * workers > 100000))
        return 2;

    total_ops = (size_t)iterations * workers;
    records = calloc(total_ops, sizeof(struct op_record));
    if (!records) {
        fprintf(stderr, "FATAL: Preallocation of %zu operation records failed\n", total_ops);
        return 2;
    }

    if (hold) {
        struct rlimit r;
        if (!getrlimit(RLIMIT_NOFILE, &r)) {
            r.rlim_cur = r.rlim_max;
            setrlimit(RLIMIT_NOFILE, &r);
        }
    }

    pthread_t *threads = calloc(workers, sizeof(*threads));
    if (!threads) {
        free(records);
        return 2;
    }

    /* Thread creation loop with robust error cleanup */
    for (unsigned i = 0; i < workers; i++) {
        if (pthread_create(&threads[i], NULL, worker, (void *)(uintptr_t)i)) {
            perror("pthread_create");
            /* Signal abort to any already running workers */
            pthread_mutex_lock(&start_lock);
            abort_launch = 1;
            pthread_cond_broadcast(&start_cond);
            pthread_mutex_unlock(&start_lock);

            /* Join already created workers to prevent orphan threads */
            for (unsigned j = 0; j < i; j++) {
                (void)pthread_join(threads[j], NULL);
            }
            free(threads);
            free(records);
            return 2;
        }
    }

    /* Wait until all workers are waiting at the start gate */
    pthread_mutex_lock(&start_lock);
    while (ready_count < workers) {
        pthread_cond_wait(&start_cond, &start_lock);
    }
    pthread_mutex_unlock(&start_lock);

    /* Ready handshake */
    puts("WORKLOAD_READY");
    if (fflush(stdout) != 0 || ferror(stdout)) {
        pthread_mutex_lock(&start_lock);
        abort_launch = 1;
        pthread_cond_broadcast(&start_cond);
        pthread_mutex_unlock(&start_lock);
        for (unsigned i = 0; i < workers; i++) (void)pthread_join(threads[i], NULL);
        free(threads);
        free(records);
        return 2;
    }

    if (getchar() == EOF) {
        pthread_mutex_lock(&start_lock);
        abort_launch = 1;
        pthread_cond_broadcast(&start_cond);
        pthread_mutex_unlock(&start_lock);
        for (unsigned i = 0; i < workers; i++) (void)pthread_join(threads[i], NULL);
        free(threads);
        free(records);
        return 2;
    }

    struct timespec a, b;
    clock_gettime(CLOCK_MONOTONIC, &a);

    /* Release workers */
    pthread_mutex_lock(&start_lock);
    start_go = 1;
    pthread_cond_broadcast(&start_cond);
    pthread_mutex_unlock(&start_lock);

    /* Join workers and verify each thread join succeeded */
    int join_errors = 0;
    for (unsigned i = 0; i < workers; i++) {
        int jr = pthread_join(threads[i], NULL);
        if (jr != 0) {
            fprintf(stderr, "FATAL: pthread_join failed for worker %u: %d\n", i, jr);
            join_errors++;
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &b);
    double elapsed = (b.tv_sec - a.tv_sec) + (b.tv_nsec - a.tv_nsec) / 1e9;

    if (join_errors > 0) {
        free(threads);
        free(records);
        return 3;
    }

    /* Invariant Validation: attempted = succeeded + failed */
    uint64_t c_att = atomic_load(&create_attempts);
    uint64_t c_succ = atomic_load(&create_successes);
    uint64_t c_fail = atomic_load(&create_failures);

    if (c_att != c_succ + c_fail || c_att != total_ops) {
        fprintf(stderr, "FATAL: Invariant violated: attempted (%lu) != succeeded (%lu) + failed (%lu) or total_ops (%zu)\n",
                (unsigned long)c_att, (unsigned long)c_succ, (unsigned long)c_fail, total_ops);
        free(threads);
        free(records);
        return 3;
    }

    /* Verify each individual record */
    uint64_t verified_succ = 0;
    uint64_t verified_fail = 0;
    for (size_t i = 0; i < total_ops; i++) {
        struct op_record *r = &records[i];
        if (r->op_id == 0) {
            fprintf(stderr, "FATAL: Incomplete record at index %zu (op_id == 0)\n", i);
            free(threads);
            free(records);
            return 3;
        }
        if (r->success == 1) {
            if (r->ret < 0 || r->err != 0) {
                fprintf(stderr, "FATAL: Inconsistent success record at index %zu: ret=%d, err=%d\n", i, r->ret, r->err);
                free(threads);
                free(records);
                return 3;
            }
            verified_succ++;
        } else if (r->success == 0) {
            if (r->ret >= 0 || r->err == 0) {
                fprintf(stderr, "FATAL: Inconsistent failure record at index %zu: ret=%d, err=%d\n", i, r->ret, r->err);
                free(threads);
                free(records);
                return 3;
            }
            verified_fail++;
        } else {
            fprintf(stderr, "FATAL: Corrupted success flag at index %zu: %d\n", i, r->success);
            free(threads);
            free(records);
            return 3;
        }
    }

    if (verified_succ != c_succ || verified_fail != c_fail) {
        fprintf(stderr, "FATAL: Record verification mismatch: verified_succ (%lu) != c_succ (%lu) or verified_fail (%lu) != c_fail (%lu)\n",
                (unsigned long)verified_succ, (unsigned long)c_succ, (unsigned long)verified_fail, (unsigned long)c_fail);
        free(threads);
        free(records);
        return 3;
    }

    /* Optional export to file (written first so path can be verified) */
    if (ground_truth_path && ground_truth_path[0]) {
        FILE *fp = fopen(ground_truth_path, "w");
        if (!fp) {
            fprintf(stderr, "FATAL: Failed to open ground truth file %s for writing: %s\n",
                    ground_truth_path, strerror(errno));
            free(threads);
            free(records);
            return 2;
        }
        /* Full export with complete records array to file */
        if (export_records_json(fp, elapsed, 1, ground_truth_path) != 0) {
            fprintf(stderr, "FATAL: Failed writing records to %s\n", ground_truth_path);
            fclose(fp);
            free(threads);
            free(records);
            return 2;
        }
        if (fclose(fp) != 0) {
            fprintf(stderr, "FATAL: Failed closing ground truth file %s: %s\n",
                    ground_truth_path, strerror(errno));
            free(threads);
            free(records);
            return 2;
        }
    }

    /* Export machine-readable JSON summary to stdout.
     * Include full inline records array if no separate output file was requested,
     * or if total_ops is small (<= 2000) for convenient pipeline consumption.
     */
    int include_stdout_records = (!ground_truth_path || !ground_truth_path[0] || total_ops <= 2000);
    if (export_records_json(stdout, elapsed, include_stdout_records, ground_truth_path) != 0) {
        fprintf(stderr, "FATAL: Failed exporting records to stdout\n");
        free(threads);
        free(records);
        return 2;
    }

    free(threads);

    /* Keep TGID alive until measurement ends */
    (void)getchar();
    free(records);
    return 0;
}
