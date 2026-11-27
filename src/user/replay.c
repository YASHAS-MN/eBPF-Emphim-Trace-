#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#include "provenance.h"
#include "evidence_io.h"

struct replay_config {
    const char *evid_path;
    const char *dot_path;
    const char *json_path;
    const char *timeline_path;
    const char *filtered_dot_path;
    const char *filtered_json_path;
    const char *summary_json_path;
    uint32_t filter_pid;
    uint64_t filter_token;
    uint64_t progress_interval;
    bool strict;
    bool verbose;
    bool quiet;
    int search_mode;
};

static void print_usage(const char *prog_name) {
    printf("Usage: %s [OPTIONS] <evidence_file.evid>\n\n", prog_name);
    printf("EphimTrace Offline Provenance Reconstruction Utility.\n");
    printf("Reconstructs forensic provenance graphs offline from immutable binary evidence\n");
    printf("without requiring eBPF programs, kernel hooks, or root privileges.\n\n");
    printf("Options:\n");
    printf("  -d, --dot <filepath>         Path to export full DAG in Graphviz DOT format\n");
    printf("                               (default: ephimtrace_dag.dot)\n");
    printf("  -j, --json <filepath>        Path to export full graph in JSON format\n");
    printf("                               (default: ephimtrace_dag.json)\n");
    printf("  -t, --timeline <filepath>    Path to export forensic timeline markdown\n");
    printf("                               (default: ephimtrace_timeline.md)\n");
    printf("  -p, --filter-pid <pid>       Target PID for filtered graph & timeline export\n");
    printf("  -k, --filter-token <token>   Target object token for filtered export\n");
    printf("  --filtered-dot <filepath>    Path to export filtered DOT graph\n");
    printf("                               (default: ephimtrace_filtered.dot)\n");
    printf("  --filtered-json <filepath>   Path to export filtered JSON graph\n");
    printf("                               (default: ephimtrace_filtered.json)\n");
    printf("  --summary-json <filepath>    Path to write machine-readable reconstruction summary\n");
    printf("  --strict                     Fail closed on gaps, corruptions, or unfinalized manifests;\n");
    printf("                               abort graph exports on validation failure\n");
    printf("  --progress <n>               Report progress every N records (default: 50000, 0=disable)\n");
    printf("  --outgoing                   Use reference outgoing search mode (for benchmarking)\n");
    printf("  --incoming                   Use default incoming search mode (O(1) in-degree)\n");
    printf("  -v, --verbose                Enable verbose log output\n");
    printf("  -q, --quiet                  Suppress per-interval progress output\n");
    printf("  -h, --help                   Show this help message\n\n");
}

int main(int argc, char *argv[]) {
    struct replay_config cfg = {
        .evid_path = NULL,
        .dot_path = "ephimtrace_dag.dot",
        .json_path = "ephimtrace_dag.json",
        .timeline_path = "ephimtrace_timeline.md",
        .filtered_dot_path = "ephimtrace_filtered.dot",
        .filtered_json_path = "ephimtrace_filtered.json",
        .summary_json_path = NULL,
        .filter_pid = 0,
        .filter_token = 0,
        .progress_interval = 50000,
        .strict = false,
        .verbose = false,
        .quiet = false,
        .search_mode = 0, /* Incoming adjacency default */
    };

    const char *env_mode = getenv("PROV_SEARCH_MODE");
    if (env_mode && atoi(env_mode) == 1) {
        cfg.search_mode = 1;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--dot") == 0) {
            if (i + 1 < argc) { cfg.dot_path = argv[++i]; }
            else { fprintf(stderr, "Error: %s requires a filepath\n", argv[i]); return 1; }
        } else if (strcmp(argv[i], "-j") == 0 || strcmp(argv[i], "--json") == 0) {
            if (i + 1 < argc) { cfg.json_path = argv[++i]; }
            else { fprintf(stderr, "Error: %s requires a filepath\n", argv[i]); return 1; }
        } else if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--timeline") == 0) {
            if (i + 1 < argc) { cfg.timeline_path = argv[++i]; }
            else { fprintf(stderr, "Error: %s requires a filepath\n", argv[i]); return 1; }
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--filter-pid") == 0) {
            if (i + 1 < argc) { cfg.filter_pid = (uint32_t)strtoul(argv[++i], NULL, 10); }
            else { fprintf(stderr, "Error: %s requires a PID\n", argv[i]); return 1; }
        } else if (strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--filter-token") == 0) {
            if (i + 1 < argc) { cfg.filter_token = (uint64_t)strtoull(argv[++i], NULL, 10); }
            else { fprintf(stderr, "Error: %s requires a token\n", argv[i]); return 1; }
        } else if (strcmp(argv[i], "--filtered-dot") == 0) {
            if (i + 1 < argc) { cfg.filtered_dot_path = argv[++i]; }
            else { fprintf(stderr, "Error: %s requires a filepath\n", argv[i]); return 1; }
        } else if (strcmp(argv[i], "--filtered-json") == 0) {
            if (i + 1 < argc) { cfg.filtered_json_path = argv[++i]; }
            else { fprintf(stderr, "Error: %s requires a filepath\n", argv[i]); return 1; }
        } else if (strcmp(argv[i], "--summary-json") == 0) {
            if (i + 1 < argc) { cfg.summary_json_path = argv[++i]; }
            else { fprintf(stderr, "Error: %s requires a filepath\n", argv[i]); return 1; }
        } else if (strcmp(argv[i], "--strict") == 0) {
            cfg.strict = true;
        } else if (strcmp(argv[i], "--progress") == 0) {
            if (i + 1 < argc) { cfg.progress_interval = (uint64_t)strtoull(argv[++i], NULL, 10); }
            else { fprintf(stderr, "Error: %s requires a number\n", argv[i]); return 1; }
        } else if (strcmp(argv[i], "--incoming") == 0) {
            cfg.search_mode = 0;
        } else if (strcmp(argv[i], "--outgoing") == 0) {
            cfg.search_mode = 1;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            cfg.verbose = true;
        } else if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0) {
            cfg.quiet = true;
            cfg.progress_interval = 0;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (argv[i][0] != '-' && !cfg.evid_path) {
            cfg.evid_path = argv[i];
        } else {
            fprintf(stderr, "Unknown or unexpected argument: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (!cfg.evid_path) {
        fprintf(stderr, "Error: Missing required evidence file path.\n\n");
        print_usage(argv[0]);
        return 1;
    }

    struct stat st_evid;
    if (stat(cfg.evid_path, &st_evid) != 0) {
        fprintf(stderr, "[ERROR] Cannot access evidence file '%s': %s\n", cfg.evid_path, strerror(errno));
        return 1;
    }

    /* Output collision and alias protection against input evidence file */
    const char *out_paths[6] = {
        cfg.dot_path,
        cfg.json_path,
        cfg.timeline_path,
        cfg.filtered_dot_path,
        cfg.filtered_json_path,
        cfg.summary_json_path
    };
    const char *out_names[6] = {
        "--dot",
        "--json",
        "--timeline",
        "--filtered-dot",
        "--filtered-json",
        "--summary-json"
    };

    for (size_t i = 0; i < 6; i++) {
        if (!out_paths[i] || !out_paths[i][0])
            continue;

        /* Check if output path points to evidence file (symlink, hardlink, or path alias) */
        struct stat st_out;
        if (stat(out_paths[i], &st_out) == 0) {
            if (st_out.st_dev == st_evid.st_dev && st_out.st_ino == st_evid.st_ino) {
                fprintf(stderr, "[ERROR] Output path '%s' (%s) aliases input evidence file '%s' (inode %llu)! Aborting to prevent truncation.\n",
                        out_paths[i], out_names[i], cfg.evid_path, (unsigned long long)st_out.st_ino);
                return 1;
            }
        }
        char res_in[4096], res_out[4096];
        if (realpath(cfg.evid_path, res_in) && realpath(out_paths[i], res_out)) {
            if (strcmp(res_in, res_out) == 0) {
                fprintf(stderr, "[ERROR] Output path '%s' (%s) resolves to input evidence file '%s'! Aborting to prevent truncation.\n",
                        out_paths[i], out_names[i], cfg.evid_path);
                return 1;
            }
        }

        /* Check collisions between distinct output paths */
        for (size_t j = i + 1; j < 6; j++) {
            if (!out_paths[j] || !out_paths[j][0])
                continue;
            if (strcmp(out_paths[i], out_paths[j]) == 0) {
                fprintf(stderr, "[ERROR] Output path collision: '%s' and '%s' target the same path '%s'! Aborting.\n",
                        out_names[i], out_names[j], out_paths[i]);
                return 1;
            }
            struct stat st_other;
            if (stat(out_paths[i], &st_out) == 0 && stat(out_paths[j], &st_other) == 0) {
                if (st_out.st_dev == st_other.st_dev && st_out.st_ino == st_other.st_ino) {
                    fprintf(stderr, "[ERROR] Output path collision: '%s' (%s) and '%s' (%s) share the same inode! Aborting.\n",
                            out_paths[i], out_names[i], out_paths[j], out_names[j]);
                    return 1;
                }
            }
        }
    }

    /* Open and validate evidence file header */
    struct evidence_reader reader;
    int open_rc = evidence_reader_open(&reader, cfg.evid_path);
    if (open_rc != 0) {
        fprintf(stderr, "[ERROR] Failed to open evidence file '%s': error %d (%s)\n",
                cfg.evid_path, open_rc,
                (open_rc == -1) ? "file not found or access denied" :
                (open_rc == -2) ? "magic/version mismatch" :
                (open_rc == -3) ? "header CRC32 corruption" : "unknown header error");
        return 2;
    }

    /* Initialize provenance reconstruction engine */
    if (prov_engine_init() != 0) {
        evidence_reader_close(&reader);
        fprintf(stderr, "[ERROR] Failed to initialize provenance engine\n");
        return 3;
    }

    prov_engine_set_search_mode(cfg.search_mode);

    if (cfg.verbose) {
        printf("[INFO] Replaying evidence: %s (Mode: %u, Target PID: %u)\n",
               cfg.evid_path, reader.header.mode, reader.header.target_pid);
        printf("[INFO] Search mode: %s\n", (cfg.search_mode == 0) ? "incoming (O(1))" : "outgoing (reference)");
    }

    struct rusage ru_start, ru_end;
    getrusage(RUSAGE_SELF, &ru_start);
    uint64_t t0 = evidence_time_now_ns();

    struct event ev;
    struct evidence_record_frame frame;
    int read_rc = 0;

    while ((read_rc = evidence_reader_read_next(&reader, &ev, &frame)) == 1) {
        prov_engine_process_event(&ev);

        if (!cfg.quiet && cfg.progress_interval > 0 &&
            reader.stats.records_replayed > 0 &&
            reader.stats.records_replayed % cfg.progress_interval == 0) {
            uint64_t cur_ts = evidence_time_now_ns();
            double elapsed_s = (double)(cur_ts - t0) / 1e9;
            double rate = (elapsed_s > 0) ? ((double)reader.stats.records_replayed / elapsed_s) : 0;
            size_t cur_nodes = 0, cur_edges = 0;
            prov_engine_get_counts(&cur_nodes, &cur_edges);
            fprintf(stderr, "[replay] Progress: %llu records replayed (%zu nodes, %zu edges, %.2fs, %.1f rec/s)\n",
                    (unsigned long long)reader.stats.records_replayed,
                    cur_nodes, cur_edges, elapsed_s, rate);
        }
    }
    uint64_t t1 = evidence_time_now_ns();
    getrusage(RUSAGE_SELF, &ru_end);

    if (read_rc < 0) {
        fprintf(stderr, "[ERROR] Evidence reader stopped with error %d: %s\n",
                read_rc,
                (read_rc == -1) ? "frame magic / CRC32 corruption detected" :
                (read_rc == -2) ? "incomplete/truncated record at EOF" : "read failure");
    }

    /* Read and verify private session manifest if present */
    struct evidence_session_manifest manifest;
    int manifest_rc = evidence_read_manifest(cfg.evid_path, &manifest);
    bool manifest_present = (manifest_rc == 0 || manifest_rc < 0);
    bool manifest_verified = false;
    bool telemetry_lossless = false;
    const char *persist_desc = "UNKNOWN (Legacy v1 evidence file without manifest)";
    const char *capture_desc = "UNKNOWN (Legacy v1 evidence file without manifest)";
    const char *manifest_status = persist_desc;
    int64_t computed_drops = 0;

    if (manifest_rc == 0) {
        bool size_match = (st_evid.st_size == (off_t)manifest.storage_bytes);
        bool count_match = (reader.stats.records_verified == manifest.record_count);
        bool final_clean = manifest.finalized && manifest.synchronized;
        bool loss_clean = (manifest.sample_size_mismatches == 0 &&
                           manifest.write_errors == 0 &&
                           manifest.poll_errors == 0 &&
                           manifest.drain_errors == 0);

        if (size_match && count_match && final_clean && loss_clean) {
            manifest_verified = true;
            persist_desc = "VERIFIED (Storage & CRC clean)";
        } else {
            manifest_verified = false;
            persist_desc = "DISCREPANCY (Storage corruption or size/count mismatch)";
        }

        enum evidence_loss_status loss_st = evidence_manifest_evaluate_loss(&manifest, &computed_drops, &capture_desc);
        telemetry_lossless = (loss_st == EVIDENCE_LOSS_LOSSLESS);
        manifest_status = persist_desc;
    } else if (manifest_rc < 0) {
        manifest_verified = false;
        persist_desc = "FAILED (Corrupt manifest or symlink/alias rejected)";
        capture_desc = "FAILED (Corrupt manifest or symlink/alias rejected)";
        manifest_status = persist_desc;
    } else {
        manifest_present = false;
        manifest_verified = false;
        persist_desc = "UNKNOWN (Legacy v1 evidence file without manifest)";
        capture_desc = "UNKNOWN (Legacy v1 evidence file without manifest)";
        manifest_status = persist_desc;
    }

    /* Success Criteria */
    bool clean_eof = (read_rc == 0);
    bool no_corruption = (reader.stats.corrupt_records == 0);
    bool no_incompleteness = (reader.stats.incomplete_records == 0);
    bool gaps_acceptable = (!cfg.strict || reader.stats.seq_gaps == 0);
    bool manifest_acceptable = (!cfg.strict || !manifest_present || manifest_verified);

    bool replay_valid = clean_eof && no_corruption && no_incompleteness && gaps_acceptable && manifest_acceptable;

    /* Graph Element Counts */
    size_t total_nodes = 0, total_edges = 0;
    prov_engine_get_counts(&total_nodes, &total_edges);
    uint64_t edge_comparisons = prov_engine_get_edge_comparisons();

    /* Perform Exports: Prevent strict replay failures from producing misleading successful graph outputs */
    int dot_rc = 0, json_rc = 0, timeline_rc = 0;
    int filtered_dot_rc = 0, filtered_json_rc = 0;
    bool exports_aborted = false;

    if (!replay_valid && cfg.strict) {
        fprintf(stderr, "[WARNING] Strict replay validation failed: aborting graph exports to prevent misleading outputs.\n");
        exports_aborted = true;
        dot_rc = -1;
        json_rc = -1;
        timeline_rc = -1;
        filtered_dot_rc = -1;
        filtered_json_rc = -1;
    } else {
        if (cfg.dot_path && cfg.dot_path[0]) {
            dot_rc = prov_engine_export_dot(cfg.dot_path);
            if (dot_rc != 0) {
                fprintf(stderr, "[ERROR] Failed to export DOT graph to '%s': %d\n", cfg.dot_path, dot_rc);
            }
        }

        if (cfg.json_path && cfg.json_path[0]) {
            json_rc = prov_engine_export_json(cfg.json_path);
            if (json_rc != 0) {
                fprintf(stderr, "[ERROR] Failed to export JSON graph to '%s': %d\n", cfg.json_path, json_rc);
            }
        }

        if (cfg.timeline_path && cfg.timeline_path[0]) {
            timeline_rc = prov_engine_export_timeline(cfg.timeline_path, cfg.filter_pid, cfg.filter_token);
            if (timeline_rc != 0) {
                fprintf(stderr, "[ERROR] Failed to export timeline to '%s': %d\n", cfg.timeline_path, timeline_rc);
            }
        }

        bool has_filter = (cfg.filter_pid != 0 || cfg.filter_token != 0);
        if (has_filter) {
            if (cfg.filtered_dot_path && cfg.filtered_dot_path[0]) {
                filtered_dot_rc = prov_engine_export_filtered_dot(cfg.filtered_dot_path, cfg.filter_pid, cfg.filter_token);
                if (filtered_dot_rc != 0) {
                    fprintf(stderr, "[ERROR] Failed to export filtered DOT graph to '%s': %d\n", cfg.filtered_dot_path, filtered_dot_rc);
                }
            }
            if (cfg.filtered_json_path && cfg.filtered_json_path[0]) {
                filtered_json_rc = prov_engine_export_filtered_json(cfg.filtered_json_path, cfg.filter_pid, cfg.filter_token);
                if (filtered_json_rc != 0) {
                    fprintf(stderr, "[ERROR] Failed to export filtered JSON graph to '%s': %d\n", cfg.filtered_json_path, filtered_json_rc);
                }
            }
        }
    }

    /* Clean up engine and reader */
    prov_engine_destroy();
    evidence_reader_close(&reader);

    /* Compute Metrics */
    uint64_t replay_duration_ns = (t1 > t0) ? (t1 - t0) : 0;
    double replay_duration_s = (double)replay_duration_ns / 1e9;
    long user_cpu_us = (ru_end.ru_utime.tv_sec - ru_start.ru_utime.tv_sec) * 1000000L +
                       (ru_end.ru_utime.tv_usec - ru_start.ru_utime.tv_usec);
    long sys_cpu_us = (ru_end.ru_stime.tv_sec - ru_start.ru_stime.tv_sec) * 1000000L +
                      (ru_end.ru_stime.tv_usec - ru_start.ru_stime.tv_usec);
    long max_rss_kb = ru_end.ru_maxrss;
    double max_rss_mib = (double)max_rss_kb / 1024.0;
    double events_per_sec = (replay_duration_s > 0) ? ((double)reader.stats.records_replayed / replay_duration_s) : 0;

    /* Get File Sizes for Exports */
    struct stat st_dot = {0}, st_json = {0}, st_tl = {0};
    if (!exports_aborted && cfg.dot_path) stat(cfg.dot_path, &st_dot);
    if (!exports_aborted && cfg.json_path) stat(cfg.json_path, &st_json);
    if (!exports_aborted && cfg.timeline_path) stat(cfg.timeline_path, &st_tl);

    bool exports_ok = !exports_aborted && (dot_rc == 0 && json_rc == 0 && timeline_rc == 0 &&
                                          filtered_dot_rc == 0 && filtered_json_rc == 0);

    bool overall_success = replay_valid && exports_ok;

    /* Print Structured Reconstruction Summary */
    printf("\n=================================================================\n");
    printf("         EphimTrace Provenance Reconstruction Summary            \n");
    printf("=================================================================\n");
    printf("Evidence File:             %s\n", cfg.evid_path);
    printf("Session Target PID:        %u\n", reader.header.target_pid);
    printf("Session Mode:              %u (%s)\n",
           reader.header.mode,
           (reader.header.mode == EVIDENCE_MODE_ONLINE) ? "Online (M)" :
           (reader.header.mode == EVIDENCE_MODE_DEFERRED) ? "Deferred (P)" : "Unknown");
    printf("Records Verified:          %llu\n", (unsigned long long)reader.stats.records_verified);
    printf("Records Replayed:          %llu\n", (unsigned long long)reader.stats.records_replayed);
    printf("Corrupt Records:           %llu\n", (unsigned long long)reader.stats.corrupt_records);
    printf("Sequence Gaps:             %llu\n", (unsigned long long)reader.stats.seq_gaps);
    printf("Incomplete / Short Records:%llu\n", (unsigned long long)reader.stats.incomplete_records);
    printf("Storage Persistence:       %s\n", persist_desc);
    printf("Telemetry Completeness:    %s\n", capture_desc);
    if (manifest_rc == 0 && computed_drops > 0) {
        printf("Ring Buffer Drops:         %lld\n", (long long)computed_drops);
    }
    printf("-----------------------------------------------------------------\n");
    printf("Provenance Nodes:          %zu\n", total_nodes);
    printf("Provenance Edges:          %zu\n", total_edges);
    printf("Adjacency Comparisons:     %llu (%s mode)\n",
           (unsigned long long)edge_comparisons,
           (cfg.search_mode == 0) ? "incoming O(1)" : "outgoing reference");
    printf("-----------------------------------------------------------------\n");
    printf("Reconstruction Duration:   %.3f s (%.1f events/s)\n", replay_duration_s, events_per_sec);
    printf("CPU Time:                  %.3f s (user: %.3fs, sys: %.3fs)\n",
           (double)(user_cpu_us + sys_cpu_us) / 1e6, (double)user_cpu_us / 1e6, (double)sys_cpu_us / 1e6);
    printf("Peak Memory (RSS):         %.2f MiB (%ld KiB)\n", max_rss_mib, max_rss_kb);
    printf("-----------------------------------------------------------------\n");
    if (exports_aborted) {
        printf("Graph Exports:             ABORTED (Suppressed due to validation errors)\n");
    } else {
        printf("DOT Graph Export:          %s (%lld bytes, status: %s)\n",
               cfg.dot_path, (long long)st_dot.st_size, (dot_rc == 0) ? "OK" : "FAILED");
        printf("JSON Graph Export:         %s (%lld bytes, status: %s)\n",
               cfg.json_path, (long long)st_json.st_size, (json_rc == 0) ? "OK" : "FAILED");
        printf("Timeline Export:           %s (%lld bytes, status: %s)\n",
               cfg.timeline_path, (long long)st_tl.st_size, (timeline_rc == 0) ? "OK" : "FAILED");
        if (cfg.filter_pid != 0 || cfg.filter_token != 0) {
            printf("Filtered Exports:          PID=%u, Token=%llu (DOT: %s, JSON: %s)\n",
                   cfg.filter_pid, (unsigned long long)cfg.filter_token,
                   (filtered_dot_rc == 0) ? "OK" : "FAILED",
                   (filtered_json_rc == 0) ? "OK" : "FAILED");
        }
    }
    printf("=================================================================\n");
    printf("Reconstruction Status:     %s\n",
           overall_success ? (telemetry_lossless ? "SUCCESS (Complete & Lossless)" : "SUCCESS (Lossy Telemetry Captured)") :
           (!clean_eof || !no_incompleteness) ? "FAILED (Incomplete evidence / EOF truncation)" :
           (!no_corruption) ? "FAILED (Corrupt records / CRC32 mismatch)" :
           (!gaps_acceptable) ? "FAILED (Sequence gaps under strict mode)" :
           (!manifest_acceptable) ? "FAILED (Session unfinalized or manifest discrepancy)" : "FAILED (Export error)");
    printf("=================================================================\n\n");
    fflush(stdout);

    /* Optional JSON summary file output with checked ferror/fflush/fclose */
    int summary_rc = 0;
    if (cfg.summary_json_path && cfg.summary_json_path[0]) {
        FILE *fj = fopen(cfg.summary_json_path, "w");
        if (fj) {
            fprintf(fj, "{\n");
            fprintf(fj, "  \"status\": \"%s\",\n", overall_success ? "OK" : "ERROR");
            fprintf(fj, "  \"evidence_file\": \"%s\",\n", cfg.evid_path);
            fprintf(fj, "  \"manifest_present\": %s,\n", manifest_present ? "true" : "false");
            fprintf(fj, "  \"manifest_verified\": %s,\n", manifest_verified ? "true" : "false");
            fprintf(fj, "  \"manifest_status\": \"%s\",\n", manifest_status);
            fprintf(fj, "  \"persistence_verified\": %s,\n", manifest_verified ? "true" : "false");
            fprintf(fj, "  \"persistence_status\": \"%s\",\n", persist_desc);
            fprintf(fj, "  \"telemetry_loss_free\": %s,\n", telemetry_lossless ? "true" : "false");
            fprintf(fj, "  \"telemetry_capture_status\": \"%s\",\n", capture_desc);
            fprintf(fj, "  \"ring_buffer_total_drops\": %lld,\n", (manifest_rc == 0) ? (long long)computed_drops : -1LL);
            fprintf(fj, "  \"records_verified\": %llu,\n", (unsigned long long)reader.stats.records_verified);
            fprintf(fj, "  \"records_replayed\": %llu,\n", (unsigned long long)reader.stats.records_replayed);
            fprintf(fj, "  \"corrupt_records\": %llu,\n", (unsigned long long)reader.stats.corrupt_records);
            fprintf(fj, "  \"seq_gaps\": %llu,\n", (unsigned long long)reader.stats.seq_gaps);
            fprintf(fj, "  \"incomplete_records\": %llu,\n", (unsigned long long)reader.stats.incomplete_records);
            fprintf(fj, "  \"nodes\": %zu,\n", total_nodes);
            fprintf(fj, "  \"edges\": %zu,\n", total_edges);
            fprintf(fj, "  \"edge_comparisons\": %llu,\n", (unsigned long long)edge_comparisons);
            fprintf(fj, "  \"duration_s\": %.4f,\n", replay_duration_s);
            fprintf(fj, "  \"events_per_sec\": %.1f,\n", events_per_sec);
            fprintf(fj, "  \"user_cpu_us\": %ld,\n", user_cpu_us);
            fprintf(fj, "  \"sys_cpu_us\": %ld,\n", sys_cpu_us);
            fprintf(fj, "  \"peak_rss_kb\": %ld,\n", max_rss_kb);
            fprintf(fj, "  \"peak_rss_mib\": %.2f,\n", max_rss_mib);
            fprintf(fj, "  \"exports_aborted\": %s,\n", exports_aborted ? "true" : "false");
            fprintf(fj, "  \"dot_bytes\": %lld,\n", (long long)st_dot.st_size);
            fprintf(fj, "  \"json_bytes\": %lld,\n", (long long)st_json.st_size);
            fprintf(fj, "  \"timeline_bytes\": %lld\n", (long long)st_tl.st_size);
            fprintf(fj, "}\n");
            if (fflush(fj) != 0 || ferror(fj) != 0 || fclose(fj) != 0) {
                fprintf(stderr, "[ERROR] Failed to write summary JSON '%s': write/close error\n", cfg.summary_json_path);
                summary_rc = -EIO;
            }
        } else {
            fprintf(stderr, "[ERROR] Failed to open summary JSON '%s': %s\n", cfg.summary_json_path, strerror(errno));
            summary_rc = -errno;
        }
    }

    if (!overall_success || summary_rc != 0) {
        if (!clean_eof || !no_incompleteness) return 4;
        if (!no_corruption) return 4;
        if (!gaps_acceptable) return 5;
        if (!manifest_acceptable) return 7;
        if (!exports_ok || summary_rc != 0) return 6;
        return 1;
    }

    return 0;
}
