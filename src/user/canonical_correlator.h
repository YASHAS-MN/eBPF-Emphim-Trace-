#ifndef CANONICAL_CORRELATOR_H
#define CANONICAL_CORRELATOR_H

#include "provenance.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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
  uint64_t active_objects_count;
  uint64_t active_descriptors_count;
};

/* Global last correlated token for diagnostic instrumentation */
extern uint64_t diag_last_processed_token;

/* Initialize correlator tables and state */
void canonical_correlator_init(void);

/* Tear down and free all correlator heap allocations */
void canonical_correlator_destroy(void);

/* Process an incoming event:
 * - Assigns/resolves canonical object_token for memfd lifecycle events.
 * - Tracks per-process file descriptor state.
 * - Records uncertainty metrics when observations are missing/reordered.
 * - Populates e->object_token and sets e->op_type.
 * Returns 0 on success, negative error code on failure.
 */
int canonical_correlator_process_event(struct event *e);

/* Retrieve current correlator statistics */
void canonical_correlator_get_stats(struct correlator_stats *out);

/* Reset stats counters */
void canonical_correlator_reset_stats(void);

#endif /* CANONICAL_CORRELATOR_H */
