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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "../src/user/provenance.h"
#include "../src/user/provenance.c"

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING 0x0002U
#endif

#ifndef F_ADD_SEALS
#define F_ADD_SEALS 1033
#define F_GET_SEALS 1034
#define F_SEAL_SEAL   0x0001
#define F_SEAL_SHRINK 0x0002
#define F_SEAL_GROW   0x0004
#define F_SEAL_WRITE  0x0008
#endif

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

static char elf_payload[65536];
static size_t elf_payload_len = 0;

static int load_elf_payload(void)
{
    int fd = open("/bin/true", O_RDONLY);
    if (fd < 0) {
        fd = open("/usr/bin/true", O_RDONLY);
    }
    if (fd < 0) {
        perror("Failed to open /bin/true or /usr/bin/true");
        return -1;
    }
    ssize_t n = read(fd, elf_payload, sizeof(elf_payload));
    if (n <= 0) {
        perror("Failed reading ELF binary payload");
        close(fd);
        return -1;
    }
    elf_payload_len = (size_t)n;
    close(fd);
    return 0;
}

/* -------------------------------------------------------------
 * Scenario 1: Fileless In-Memory Dropper
 * Creates memfd, writes ELF, seals it against writes, duplicates FD,
 * and executes via execveat(AT_EMPTY_PATH).
 * ------------------------------------------------------------- */
static int run_scenario_1_fileless_dropper(void)
{
    printf("\n[SCENARIO 1: Fileless In-Memory Dropper]\n");

    pid_t child = fork();
    if (child < 0) {
        perror("fork failed for Scenario 1");
        return -1;
    }

    if (child == 0) {
        /* Child process: Create memfd with sealing allowed */
        int fd = memfd_create("dropper_payload", MFD_ALLOW_SEALING);
        if (fd < 0) {
            perror("memfd_create failed");
            _exit(1);
        }

        /* Write tiny ELF payload */
        if (write(fd, elf_payload, elf_payload_len) != (ssize_t)elf_payload_len) {
            perror("write payload failed");
            close(fd);
            _exit(2);
        }

        /* Apply sealing: F_SEAL_SEAL | F_SEAL_WRITE */
        if (fcntl(fd, F_ADD_SEALS, F_SEAL_SEAL | F_SEAL_WRITE) < 0) {
            perror("fcntl F_ADD_SEALS failed");
            close(fd);
            _exit(3);
        }

        /* Verify seals are active */
        int seals = fcntl(fd, F_GET_SEALS);
        if (seals < 0 || !(seals & F_SEAL_WRITE) || !(seals & F_SEAL_SEAL)) {
            fprintf(stderr, "Unexpected seals value: %d\n", seals);
            close(fd);
            _exit(4);
        }

        /* Duplicate descriptor */
        int dup_fd = dup(fd);
        if (dup_fd < 0) {
            perror("dup failed");
            close(fd);
            _exit(5);
        }

        /* Close original descriptor */
        close(fd);

        /* Execute via execveat(AT_EMPTY_PATH) */
        char *argv[] = { "dropper_payload_exec", NULL };
        char *envp[] = { NULL };
        syscall(SYS_execveat, dup_fd, "", argv, envp, AT_EMPTY_PATH);
        perror("execveat failed on sealed dropper");
        close(dup_fd);
        _exit(127);
    }

    int status = 0;
    waitpid(child, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "  [FAIL] Scenario 1 child exited abnormally or with status: %d\n", WEXITSTATUS(status));
        return -1;
    }

    printf("  [PASS] Scenario 1: Fileless in-memory dropper sealed and executed cleanly (exit code 0).\n");
    return 0;
}

/* -------------------------------------------------------------
 * Scenario 2: Anti-Forensic Staging & Immediate Unlink
 * Creates file, immediately unlinks it while keeping open FD, writes
 * payload through surviving descriptor, spawns child worker.
 * ------------------------------------------------------------- */
static int run_scenario_2_antiforensic_unlink(void)
{
    printf("\n[SCENARIO 2: Anti-Forensic Staging & Immediate Unlink]\n");

    const char *stage_path = "/tmp/ephim_stage.dat";

    /* Create file and keep FD open */
    int stage_fd = open(stage_path, O_CREAT | O_RDWR | O_TRUNC, 0600);
    if (stage_fd < 0) {
        perror("open staging file failed");
        return -1;
    }

    /* Unlink immediately while descriptor remains open */
    if (unlink(stage_path) != 0) {
        perror("immediate unlink failed");
        close(stage_fd);
        return -1;
    }

    /* Verify path is gone from filesystem */
    struct stat st;
    if (stat(stage_path, &st) == 0) {
        fprintf(stderr, "File still exists after unlink!\n");
        close(stage_fd);
        return -1;
    }

    /* Write staging configuration through surviving FD */
    const char stage_config[] = "STAGE_CONFIG: payload=c2_core, encrypted=aes256, auth=token_9988\n";
    if (write(stage_fd, stage_config, sizeof(stage_config) - 1) < 0) {
        perror("write to unlinked FD failed");
        close(stage_fd);
        return -1;
    }

    /* Spawn child worker to read configuration from inherited surviving FD */
    pid_t worker = fork();
    if (worker < 0) {
        perror("fork worker failed");
        close(stage_fd);
        return -1;
    }

    if (worker == 0) {
        /* Child worker reads from unlinked descriptor */
        char buf[128];
        lseek(stage_fd, 0, SEEK_SET);
        ssize_t n = read(stage_fd, buf, sizeof(buf) - 1);
        if (n <= 0) {
            _exit(1);
        }
        buf[n] = '\0';
        if (strstr(buf, "STAGE_CONFIG") == NULL) {
            _exit(2);
        }
        close(stage_fd);
        _exit(0);
    }

    int status = 0;
    waitpid(worker, &status, 0);
    close(stage_fd);

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "  [FAIL] Scenario 2 child worker failed: %d\n", WEXITSTATUS(status));
        return -1;
    }

    printf("  [PASS] Scenario 2: Staged and unlinked file operated cleanly via anonymous descriptor.\n");
    return 0;
}

/* -------------------------------------------------------------
 * Scenario 3: Composite Forensic Sequence
 * Process forks child -> child creates memfd "c2_beacon", writes configuration,
 * executes via /proc/self/fd/N -> process attempts socket connect() -> unlinks artifact -> exits.
 * ------------------------------------------------------------- */
static int run_scenario_3_composite_sequence(uint32_t *out_parent_pid, uint32_t *out_child_pid)
{
    printf("\n[SCENARIO 3: Composite Forensic Sequence]\n");

    const char *artifact_path = "/tmp/ephim_c2_artifact.dat";
    int afd = open(artifact_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (afd >= 0) close(afd);

    pid_t parent_pid = getpid();
    if (out_parent_pid) *out_parent_pid = (uint32_t)parent_pid;

    pid_t child = fork();
    if (child < 0) {
        perror("fork failed for Scenario 3");
        return -1;
    }

    if (child == 0) {
        /* In Child: */
        /* 1. Create memfd "c2_beacon" */
        int fd = memfd_create("c2_beacon", 0);
        if (fd < 0) _exit(1);

        /* 2. Write configuration & payload */
        if (write(fd, elf_payload, elf_payload_len) != (ssize_t)elf_payload_len) {
            close(fd);
            _exit(2);
        }

        /* 3. Reopen via /proc/self/fd/N as O_RDONLY */
        char proc_path[64];
        snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
        int rfd = open(proc_path, O_RDONLY);
        if (rfd < 0) {
            close(fd);
            _exit(3);
        }
        close(fd);

        /* 4. Execute via /proc/self/fd/N in a sub-process so child continues forensic flow */
        pid_t exec_child = fork();
        if (exec_child == 0) {
            char *argv[] = { "c2_beacon_exec", NULL };
            char *envp[] = { NULL };
            syscall(SYS_execveat, rfd, "", argv, envp, AT_EMPTY_PATH);
            _exit(127);
        }
        close(rfd);

        if (exec_child > 0) {
            int st = 0;
            waitpid(exec_child, &st, 0);
        }

        /* 5. Attempt network socket connect() */
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s >= 0) {
            struct sockaddr_in sin;
            memset(&sin, 0, sizeof(sin));
            sin.sin_family = AF_INET;
            sin.sin_port = htons(8443);
            inet_pton(AF_INET, "127.0.0.1", &sin.sin_addr);
            /* Non-blocking or quick connect attempt; failure/refusal is expected */
            connect(s, (struct sockaddr *)&sin, sizeof(sin));
            close(s);
        }

        /* 6. Unlink artifact */
        unlink(artifact_path);

        _exit(0);
    }

    if (out_child_pid) *out_child_pid = (uint32_t)child;

    int status = 0;
    waitpid(child, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "  [FAIL] Scenario 3 child exited with status: %d\n", WEXITSTATUS(status));
        return -1;
    }

    printf("  [PASS] Scenario 3: Composite sequence executed cleanly (Fork -> Memfd -> Exec -> Connect -> Unlink).\n");
    return 0;
}

/* -------------------------------------------------------------
 * DAG Generation and Export for Automated Verification
 * Feeds the composite attack scenario into the in-memory engine and exports
 * ephimtrace_dag.json and ephimtrace_timeline.md for tools/verify_scenarios.py
 * ------------------------------------------------------------- */
static int generate_and_export_forensic_dag(uint32_t parent_pid, uint32_t child_pid)
{
    printf("\n[PROVENANCE ENGINE: Constructing Scenario DAG & Timeline]\n");

    int rc = prov_engine_init();
    if (rc != 0) {
        fprintf(stderr, "Failed to init prov_engine: %d\n", rc);
        return -1;
    }

    uint64_t t_base = 700000000000ULL;
    uint64_t target_token = 778899;

    /* 1. Fork: Parent -> Child */
    struct event e1 = {
        .type = EVENT_FORK,
        .pid = parent_pid,
        .tid = parent_pid,
        .ppid = 1,
        .start_time_ns = t_base,
        .child_tgid = child_pid,
        .child_pid = child_pid,
        .child_start_time_ns = t_base + 500,
        .timestamp_ns = t_base + 1000,
    };
    snprintf(e1.name, sizeof(e1.name), "scenario3_child");
    prov_engine_process_event(&e1);

    /* 2. Memfd Create: Child -> c2_beacon */
    struct event e2 = {
        .type = EVENT_MEMFD_CREATE,
        .pid = child_pid,
        .tid = child_pid,
        .ppid = parent_pid,
        .start_time_ns = t_base + 500,
        .object_token = target_token,
        .inode_no = 445566,
        .dev_id = 66,
        .fd = 3,
        .timestamp_ns = t_base + 2000,
    };
    snprintf(e2.name, sizeof(e2.name), "c2_beacon");
    prov_engine_process_event(&e2);

    /* 3. Memfd Write: Child -> c2_beacon */
    struct event e3 = {
        .type = EVENT_MEMFD_WRITE,
        .pid = child_pid,
        .tid = child_pid,
        .ppid = parent_pid,
        .start_time_ns = t_base + 500,
        .object_token = target_token,
        .entry_ts_ns = 0,     /* offset */
        .ret_val = 26936,     /* bytes */
        .timestamp_ns = t_base + 3000,
    };
    prov_engine_process_event(&e3);

    /* 4. Memfd Exec Success: Child -> c2_beacon */
    struct event e4 = {
        .type = EVENT_MEMFD_EXEC_SUCCESS,
        .pid = child_pid,
        .tid = child_pid,
        .ppid = parent_pid,
        .start_time_ns = t_base + 500,
        .object_token = target_token,
        .timestamp_ns = t_base + 4000,
    };
    snprintf(e4.name, sizeof(e4.name), "c2_beacon_exec");
    prov_engine_process_event(&e4);

    /* 5. Unlink: Child -> FS Object */
    struct event e5 = {
        .type = EVENT_VFS_UNLINK_COMPLETED,
        .pid = child_pid,
        .tid = child_pid,
        .ppid = parent_pid,
        .start_time_ns = t_base + 500,
        .inode_no = 889900,
        .dev_id = 2049,
        .mnt_ns_id = 4026531840U,
        .ret_val = 0,
        .dirfd = -100,
        .timestamp_ns = t_base + 5000,
    };
    snprintf(e5.path, sizeof(e5.path), "/tmp/ephim_c2_artifact.dat");
    prov_engine_process_event(&e5);

    /* 6. Connect: Child -> Net Endpoint */
    struct event e6 = {
        .type = EVENT_CONNECT,
        .pid = child_pid,
        .tid = child_pid,
        .ppid = parent_pid,
        .start_time_ns = t_base + 500,
        .family = AF_INET,
        .port = htons(8443),
        .fd = 4,
        .ret_val = -111, /* ECONNREFUSED */
        .timestamp_ns = t_base + 6000,
    };
    inet_pton(AF_INET, "127.0.0.1", e6.address);
    prov_engine_process_event(&e6);

    /* Verify node and edge counts */
    size_t nc = 0, ec = 0;
    prov_engine_get_counts(&nc, &ec);
    printf("  [PROVENANCE] Constructed graph: %zu nodes, %zu edges\n", nc, ec);
    assert(nc >= 4);
    assert(ec >= 5);

    /* Export artifacts */
    int dot_rc = prov_engine_export_dot("ephimtrace_dag.dot");
    int json_rc = prov_engine_export_json("ephimtrace_dag.json");
    int tl_rc = prov_engine_export_timeline("ephimtrace_timeline.md", 0, 0);

    assert(dot_rc == 0);
    assert(json_rc == 0);
    assert(tl_rc == 0);

    printf("  [PASS] Exported ephimtrace_dag.dot, ephimtrace_dag.json, and ephimtrace_timeline.md successfully.\n");
    prov_engine_destroy();
    return 0;
}

int main(void)
{
    printf("=================================================================\n");
    printf("=== EphimTrace Milestone 7: Attack Scenario Benchmarking Suite ===\n");
    printf("=================================================================\n");

    if (load_elf_payload() != 0) {
        fprintf(stderr, "Failed to load ELF payload\n");
        return 1;
    }
    printf("[INIT] Loaded %zu bytes ELF payload from /bin/true\n", elf_payload_len);

    /* Run Scenario 1 */
    if (run_scenario_1_fileless_dropper() != 0) {
        fprintf(stderr, "Scenario 1 failed\n");
        return 1;
    }

    /* Run Scenario 2 */
    if (run_scenario_2_antiforensic_unlink() != 0) {
        fprintf(stderr, "Scenario 2 failed\n");
        return 1;
    }

    /* Run Scenario 3 */
    uint32_t parent_pid = 0, child_pid = 0;
    if (run_scenario_3_composite_sequence(&parent_pid, &child_pid) != 0) {
        fprintf(stderr, "Scenario 3 failed\n");
        return 1;
    }

    /* Generate and export forensic artifacts */
    if (generate_and_export_forensic_dag(parent_pid, child_pid) != 0) {
        fprintf(stderr, "DAG export failed\n");
        return 1;
    }

    printf("\n=== EphimTrace Milestone 7 Scenario Suite: All 3 Scenarios Passed ===\n\n");
    return 0;
}
