#ifndef CANONICAL_CORRELATOR_H
#define CANONICAL_CORRELATOR_H

#include "provenance.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CORRELATOR_MAX_OBJECTS 32768
#define CORRELATOR_MAX_DESCRIPTORS 32768

/* Status/Uncertainty indicators */
struct correlator_stats {
  uint64_t raw_events_in;
  uint64_t canonical_events_out;
  uint64_t correlated_creations;
  uint64_t uncorrelated_creations;
  uint64_t failed_creations;
  uint64_t missing_entry_count;
  uint64_t missing_install_count;
  uint64_t untracked_closes;
  uint64_t fd_reuses_without_close;
  uint64_t pointer_reuses_detected;
  uint64_t inode_reuses_detected;
  uint64_t out_of_order_buffered;
  uint64_t allocation_failures;
  uint64_t active_objects_count;
  uint64_t active_descriptors_count;
};

/* Reconstructed canonical event separating canonical truth from raw
 * wire-observation */
struct canonical_event {
  uint32_t type;
  uint32_t pid;
  uint32_t tid;
  uint64_t start_time_ns;
  int32_t fd;
  uint64_t object_token;
  uint32_t creator_tgid;
  uint64_t creator_start_time_ns;
  uint64_t inode_no;
  uint64_t dev_id;
  uint32_t op_type; /* Canonical status: MEMFD_STATUS_* */
  uint64_t timestamp_ns;
};

/* Global last correlated token for diagnostic instrumentation */
extern uint64_t diag_last_processed_token;

/* Initialize correlator tables and state */
void canonical_correlator_init(void);

/* Tear down and free all correlator heap allocations */
void canonical_correlator_destroy(void);

/* Process an incoming event in-place:
 * - Assigns/resolves canonical object_token for memfd lifecycle events.
 * - Tracks per-process file descriptor state keyed lifetime-safely by (tgid,
 * start_time, fd).
 * - Records uncertainty metrics when observations are missing/reordered.
 * - Populates e->object_token and sets e->op_type using named constants.
 * Returns 0 on success, negative error code on failure.
 */
int canonical_correlator_process_event(struct event *e);

/* Process an incoming raw event non-mutatingly and output the canonical
 * reconstruction separately, leaving the raw input event unmutated. Propagates
 * lifetime identity consistently:
 * - Reconstructs process start_time_ns from descriptor tracking if missing in
 * raw event.
 * - Propagates creator_tgid and creator_start_time_ns across all object
 * operations. Returns 0 on success, negative error code on failure.
 */
int canonical_correlator_process_event_canonical(const struct event *raw,
                                                 struct canonical_event *canon);

/* Retrieve current correlator statistics */
void canonical_correlator_get_stats(struct correlator_stats *out);

/* Reset stats counters */
void canonical_correlator_reset_stats(void);

#endif /* CANONICAL_CORRELATOR_H */
