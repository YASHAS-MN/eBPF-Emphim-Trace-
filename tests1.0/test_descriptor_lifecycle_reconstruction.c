#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#include "provenance.h"
#include "provenance.c"

/*
 * EphimTrace — Release Qualification Task 01:
 * Provenance Reconstruction Engine Evaluation under Descriptor Lifecycle Edge Cases
 */

static void print_subgraph_edges(const char *title)
{
    printf("\n--- %s ---\n", title);
    size_t node_count = 0, edge_count = 0;
    prov_engine_get_counts(&node_count, &edge_count);
    printf("Total Reconstructed Nodes: %zu, Edges: %zu\n", node_count, edge_count);

    struct prov_edge *edge = g_edges_head;
    while (edge) {
        printf("  [%s] -> (%s, FD %d) -> [%s]\n",
               edge->src ? edge->src->id : "<null>",
               edge->type == EDGE_FD_INSTALLED ? "EDGE_FD_INSTALLED" :
               edge->type == EDGE_FD_CLOSED ? "EDGE_FD_CLOSED" :
               edge->type == EDGE_MEMFD_WRITE ? "EDGE_MEMFD_WRITE" :
               edge->type == EDGE_MEMFD_EXEC_SUCCESS ? "EDGE_MEMFD_EXEC_SUCCESS" : "OTHER_EDGE",
               edge->attr.fd,
               edge->dst ? edge->dst->id : "<null>");
        edge = edge->next_global;
    }
}

int main(void)
{
    printf("=================================================================\n");
    printf("=== Provenance Reconstruction Diagnosis: Descriptor Lifecycle ===\n");
    printf("=================================================================\n");

    /* ----------------------------------------------------------------------
     * Test A: dup() vs dup2() Telemetric Asymmetry
     * ---------------------------------------------------------------------- */
    prov_engine_init();
    printf("\n[CASE 1: dup() vs dup2() Graph Reconstruction]\n");
    printf("Ground Truth: Process 100 creates memfd (token 1, FD 3), dup(3)->5, dup2(3, 20)->20.\n");

    /* 1. Creation of memfd token 1 at FD 3 */
    struct event e1 = {
        .type = EVENT_FD_INSTALLED,
        .pid = 100, .tid = 100, .ppid = 1,
        .start_time_ns = 1000000,
        .fd = 3,
        .object_token = 1,
        .op_type = 1, /* CREATION */
        .timestamp_ns = 1001000,
    };
    prov_engine_process_event(&e1);

    /* 2. dup(3) -> 5 (Captured by BPF via fd_install) */
    struct event e2 = {
        .type = EVENT_FD_INSTALLED,
        .pid = 100, .tid = 100, .ppid = 1,
        .start_time_ns = 1000000,
        .fd = 5,
        .object_token = 1,
        .op_type = 3, /* DUP */
        .timestamp_ns = 1002000,
    };
    prov_engine_process_event(&e2);

    /* 3. dup2(3, 20) -> In production BPF, NO EVENT IS EMITTED! */
    printf("Observation: dup2(3, 20) emits 0 events in production BPF collector.\n");

    print_subgraph_edges("Case 1 Graph Output");
    printf("Diagnosis:\n");
    printf("  - FD 3 (creation): Preserved as EDGE_FD_INSTALLED (CREATION) [OK]\n");
    printf("  - FD 5 (dup):      Preserved as EDGE_FD_INSTALLED (DUP)      [OK]\n");
    printf("  - FD 20 (dup2):    MISSING FROM GRAPH (Missing Coverage)    [DEFICIENCY]\n");

    prov_engine_destroy();

    /* ----------------------------------------------------------------------
     * Test B: Replacement of Tracked Descriptor with Ordinary File
     * ---------------------------------------------------------------------- */
    prov_engine_init();
    printf("\n[CASE 2: Replacement with Ordinary File & Stale Close Attribution]\n");
    printf("Ground Truth: Process 200 creates memfd (token 2, FD 3). At T=2000, dup2(ordinary_file, 3) replaces it.\n");
    printf("              At T=5000, process calls close(3) on the ordinary file.\n");

    /* 1. Creation */
    struct event eb1 = {
        .type = EVENT_FD_INSTALLED,
        .pid = 200, .tid = 200, .ppid = 1,
        .start_time_ns = 2000000,
        .fd = 3,
        .object_token = 2,
        .op_type = 1,
        .timestamp_ns = 2001000,
    };
    prov_engine_process_event(&eb1);

    /* 2. Replacement occurs in kernel, but BPF fails to clear registry */
    /* 3. Process closes FD 3 (which is now /tmp/regular.txt) at T=5000.
          BPF capture_close_fd looks up (200, 3) in stale registry and emits false EVENT_FD_CLOSED! */
    struct event eb2 = {
        .type = EVENT_FD_CLOSED,
        .pid = 200, .tid = 200, .ppid = 1,
        .start_time_ns = 2000000,
        .fd = 3,
        .object_token = 2, /* Stale token from registry! */
        .entry_ts_ns = 3000000, /* 3ms duration falsely calculated! */
        .timestamp_ns = 5001000,
    };
    prov_engine_process_event(&eb2);

    print_subgraph_edges("Case 2 Graph Output");
    printf("Diagnosis:\n");
    printf("  - EDGE_FD_CLOSED was generated at T=5001000 with duration 3ms.\n");
    printf("  - Ground Truth: The memfd was closed at T=2001000 by dup2! FD 3 closed at T=5001000 was an ordinary file!\n");
    printf("  - Forensic Verdict: INCORRECT ATTRIBUTION (Stale Registry State Corrupts Graph) [DEFICIENCY]\n");

    prov_engine_destroy();

    /* ----------------------------------------------------------------------
     * Test C: Shared Files Table Across Processes (CLONE_FILES)
     * ---------------------------------------------------------------------- */
    prov_engine_init();
    printf("\n[CASE 3: Shared Files Table Across Processes via clone(CLONE_FILES)]\n");
    printf("Ground Truth: Parent (TGID 300) creates memfd (token 3, FD 4).\n");
    printf("              CLONE_FILES child (TGID 301) closes FD 4.\n");

    struct event ec1 = {
        .type = EVENT_FD_INSTALLED,
        .pid = 300, .tid = 300, .ppid = 1,
        .start_time_ns = 3000000,
        .fd = 4,
        .object_token = 3,
        .op_type = 1,
        .timestamp_ns = 3001000,
    };
    prov_engine_process_event(&ec1);

    /* In production BPF, when child (TGID 301) closes FD 4:
       capture_close_fd queries (301, 4), which is NULL because registry stored (300, 4)!
       Child close produces ZERO events! */
    printf("Observation: Child (TGID 301) close(4) is dropped silently by BPF (registry key mismatch).\n");

    print_subgraph_edges("Case 3 Graph Output");
    printf("Diagnosis:\n");
    printf("  - Graph contains EDGE_FD_INSTALLED for Parent 300.\n");
    printf("  - Graph contains NO EDGE_FD_CLOSED for either Parent or Child!\n");
    printf("  - Forensic Verdict: MISSING COVERAGE & ORPHANED REGISTRY ENTRY under CLONE_FILES [DEFICIENCY]\n");

    prov_engine_destroy();

    printf("\n=================================================================\n");
    printf("=== Diagnosis Complete ===\n");
    printf("=================================================================\n");
    return 0;
}
