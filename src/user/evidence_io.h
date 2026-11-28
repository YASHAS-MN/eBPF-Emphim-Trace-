#ifndef EPHIM_EVIDENCE_IO_H
#define EPHIM_EVIDENCE_IO_H

#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "provenance.h"

#ifdef __cplusplus
extern "C" {
#endif

#define EPHIM_EVIDENCE_FILE_MAGIC 0x45564944U   /* 'E','V','I','D' */
#define EPHIM_EVIDENCE_RECORD_MAGIC 0x52454344U /* 'R','E','C','D' */
#define EPHIM_EVIDENCE_VERSION 1U

enum evidence_mode {
  EVIDENCE_MODE_NONE = 0,
  EVIDENCE_MODE_ONLINE =
      1, /* Model M: Receive -> Preserve -> Process -> Graph */
  EVIDENCE_MODE_DEFERRED =
      2 /* Model P: Receive -> Preserve -> Complete -> Replay -> Graph */
};

#define EVIDENCE_DEFAULT_BUFFER_SIZE                                           \
  (64 * 1024) /* 64 KiB bounded write buffer */
#define EVIDENCE_DEFAULT_MAX_BYTES                                             \
  (1024ULL * 1024 * 1024) /* 1 GiB storage bound */

/* --- CRC32 Implementation (IEEE 802.3) --- */
static inline uint32_t ephim_crc32_update(uint32_t crc, const void *buf,
                                          size_t len) {
  static uint32_t table[256];
  static bool table_init = false;
  if (!table_init) {
    for (uint32_t i = 0; i < 256; i++) {
      uint32_t c = i;
      for (int j = 0; j < 8; j++) {
        if (c & 1)
          c = 0xEDB88320U ^ (c >> 1);
        else
          c = c >> 1;
      }
      table[i] = c;
    }
    table_init = true;
  }

  const uint8_t *p = (const uint8_t *)buf;
  crc ^= 0xFFFFFFFFU;
  for (size_t i = 0; i < len; i++) {
    crc = table[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
  }
  return crc ^ 0xFFFFFFFFU;
}

static inline uint32_t ephim_crc32(const void *buf, size_t len) {
  return ephim_crc32_update(0, buf, len);
}

/* Monotonic time helper */
static inline uint64_t evidence_time_now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* --- Binary Evidence Wire Format --- */

#pragma pack(push, 1)

struct evidence_file_header {
  uint32_t magic;               /* 4 bytes: EPHIM_EVIDENCE_FILE_MAGIC */
  uint32_t version;             /* 4 bytes: EPHIM_EVIDENCE_VERSION */
  uint32_t mode;                /* 4 bytes: enum evidence_mode */
  uint32_t target_pid;          /* 4 bytes: target workload PID */
  uint64_t session_start_ts_ns; /* 8 bytes: monotonic start timestamp */
  uint32_t event_size;          /* 4 bytes: sizeof(struct event) = 664 */
  uint32_t header_size; /* 4 bytes: sizeof(struct evidence_file_header) = 64 */
  uint64_t max_bytes;   /* 8 bytes: configured storage ceiling */
  uint64_t max_records; /* 8 bytes: configured record ceiling (0 = unlimited) */
  uint32_t reserved[3]; /* 12 bytes: reserved extension fields (zeroed) */
  uint32_t header_crc32; /* 4 bytes: CRC32 of preceding 60 bytes in header */
};

struct evidence_record_frame {
  uint32_t magic;   /* 4 bytes: EPHIM_EVIDENCE_RECORD_MAGIC */
  uint32_t flags;   /* 4 bytes: status / framing flags */
  uint64_t seq_num; /* 8 bytes: strict monotonic sequence (0, 1, 2, ...) */
  uint64_t reception_ts_ns; /* 8 bytes: userspace reception monotonic ns */
  uint32_t payload_len;     /* 4 bytes: sizeof(struct event) = 664 */
  uint32_t payload_crc32;   /* 4 bytes: IEEE 802.3 CRC32 of payload */
};

#pragma pack(pop)

#ifndef __cplusplus
_Static_assert(sizeof(struct evidence_file_header) == 64,
               "Evidence file header must be 64 bytes");
_Static_assert(sizeof(struct evidence_record_frame) == 32,
               "Evidence record frame must be 32 bytes");
#endif

/* --- Evidence Statistics --- */

struct evidence_stats {
  uint64_t records_received;   /* Offered to writer from ring buffer */
  uint64_t records_written;    /* Successfully packed & buffered */
  uint64_t records_synced;     /* Confirmed flushed & fdatasync'd */
  uint64_t records_verified;   /* Successfully read & verified from file */
  uint64_t records_replayed;   /* Passed to provenance replay */
  uint64_t write_errors;       /* Buffer/storage/system write failures */
  uint64_t corrupt_records;    /* CRC32 / magic / framing mismatches */
  uint64_t seq_gaps;           /* Sequence number breaks */
  uint64_t incomplete_records; /* Truncated records at EOF / short reads */
  uint64_t storage_bytes;      /* Total bytes written to disk file */
  uint64_t flush_count;        /* Number of flush operations executed */
  uint64_t sync_duration_ns;   /* Total time spent inside fdatasync */
  uint64_t persist_drain_latency_ns; /* Latency from collection done to
                                        persistence sync */
  uint64_t replay_duration_ns;       /* Duration of replay phase in Model P */
  uint64_t total_time_to_graph_ns;   /* Total duration from workload start to
                                        graph complete */
};

/* --- Private Session Manifest --- */
static inline const char *evidence_event_type_name(uint32_t type) {
  switch (type) {
  case EVENT_EXECVE: return "execve";
  case EVENT_MEMFD_CREATE: return "memfd_create";
  case EVENT_UNLINK: return "unlink";
  case EVENT_UNLINKAT: return "unlinkat";
  case EVENT_CONNECT: return "connect";
  case EVENT_FORK: return "fork";
  case EVENT_PROCESS_EXEC: return "process_exec";
  case EVENT_PROCESS_EXIT: return "process_exit";
  case EVENT_VFS_UNLINK_COMPLETED: return "vfs_unlink_completed";
  case EVENT_VFS_RMDIR_COMPLETED: return "vfs_rmdir_completed";
  case EVENT_RMDIR: return "rmdir";
  case EVENT_MEMFD_COMPLETED: return "memfd_completed";
  case EVENT_MEMFD_DESTROYED: return "memfd_destroyed";
  case EVENT_MEMFD_FILE_RELEASED: return "memfd_file_released";
  case EVENT_FD_INSTALLED: return "fd_installed";
  case EVENT_FD_CLOSED: return "fd_closed";
  case EVENT_MEMFD_WRITE: return "memfd_write";
  case EVENT_MEMFD_EXEC_ATTEMPT: return "memfd_exec_attempt";
  case EVENT_MEMFD_EXEC_SUCCESS: return "memfd_exec_success";
  case EVENT_DEBUG: return "debug";
  default: return "unknown";
  }
}

#ifndef EPHIM_MAX_EVENT_TYPE
#define EPHIM_MAX_EVENT_TYPE 128
#endif

/* --- Private Session Manifest --- */

struct evidence_session_manifest {
  uint32_t version;
  uint32_t target_pid;
  uint64_t session_start_ns;
  uint64_t session_end_ns;
  uint64_t record_count;
  uint64_t storage_bytes;
  bool finalized;
  bool synchronized;

  /* Loss accounting */
  int64_t reg_map_full_drop; /* -1 if unavailable */
  int64_t token_alloc_err;   /* -1 if unavailable */
  int64_t token_mismatch;    /* -1 if unavailable */
  uint64_t sample_size_mismatches;
  uint64_t write_errors;
  uint64_t poll_errors;
  uint64_t drain_errors;
  int64_t ring_buffer_total_drops; /* -1 if unavailable, >= 0 when measured */
  int64_t ring_buffer_per_type_drops[EPHIM_MAX_EVENT_TYPE]; /* per-event type drops (-1 if unavailable) */
  char ring_buffer_drops[64];
};

/* --- Bounded Binary Evidence Writer --- */

struct evidence_writer {
  int fd;
  enum evidence_mode mode;
  uint32_t target_pid;
  uint64_t session_start_ns;

  /* Bounded buffer */
  uint8_t *buffer;
  size_t buffer_cap;
  size_t buffer_len;

  /* Capacity bounds */
  uint64_t max_bytes;
  uint64_t max_records;

  /* State & diagnostics */
  bool error_occurred;
  struct evidence_stats stats;
  char path[256];
};

static inline int evidence_writer_flush(struct evidence_writer *w) {
  if (!w || w->fd < 0 || w->buffer_len == 0)
    return 0;

  size_t written = 0;
  while (written < w->buffer_len) {
    ssize_t n = write(w->fd, w->buffer + written, w->buffer_len - written);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      w->stats.write_errors++;
      w->error_occurred = true;
      return -1;
    }
    written += (size_t)n;
  }

  w->stats.storage_bytes += w->buffer_len;
  w->stats.flush_count++;
  w->buffer_len = 0;
  return 0;
}

static inline int evidence_writer_sync(struct evidence_writer *w) {
  if (!w || w->fd < 0)
    return -1;

  if (evidence_writer_flush(w) < 0)
    return -1;

  uint64_t t0 = evidence_time_now_ns();
  int rc = fdatasync(w->fd);
  uint64_t t1 = evidence_time_now_ns();
  if (t1 > t0)
    w->stats.sync_duration_ns += (t1 - t0);

  if (rc == 0) {
    w->stats.records_synced = w->stats.records_written;
  } else {
    w->stats.write_errors++;
    w->error_occurred = true;
  }
  return rc;
}

static inline int evidence_writer_init(struct evidence_writer *w,
                                       const char *path,
                                       enum evidence_mode mode,
                                       uint32_t target_pid, size_t buffer_cap,
                                       uint64_t max_bytes) {
  if (!w || !path)
    return -1;

  memset(w, 0, sizeof(*w));
  w->fd = -1;
  w->mode = mode;
  w->target_pid = target_pid;
  w->session_start_ns = evidence_time_now_ns();
  w->buffer_cap = buffer_cap ? buffer_cap : EVIDENCE_DEFAULT_BUFFER_SIZE;
  w->max_bytes = max_bytes ? max_bytes : EVIDENCE_DEFAULT_MAX_BYTES;
  w->max_records = 0;
  snprintf(w->path, sizeof(w->path), "%s", path);

  /* Reject if file, symlink, or hardlink already exists */
  struct stat st;
  if (lstat(path, &st) == 0) {
    w->error_occurred = true;
    w->stats.write_errors++;
    errno = EEXIST;
    return -1;
  }

  w->buffer = (uint8_t *)malloc(w->buffer_cap);
  if (!w->buffer) {
    w->error_occurred = true;
    w->stats.write_errors++;
    return -1;
  }

  /* Exclusive private evidence file with O_NOFOLLOW: fail if exists or symlink,
   * mode 0600 */
  w->fd =
      open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (w->fd < 0) {
    free(w->buffer);
    w->buffer = NULL;
    w->error_occurred = true;
    w->stats.write_errors++;
    return -1;
  }

  /* Initialize and write session header */
  struct evidence_file_header hdr;
  memset(&hdr, 0, sizeof(hdr));
  hdr.magic = EPHIM_EVIDENCE_FILE_MAGIC;
  hdr.version = EPHIM_EVIDENCE_VERSION;
  hdr.mode = (uint32_t)mode;
  hdr.target_pid = target_pid;
  hdr.session_start_ts_ns = w->session_start_ns;
  hdr.event_size = (uint32_t)sizeof(struct event);
  hdr.header_size = (uint32_t)sizeof(struct evidence_file_header);
  hdr.max_bytes = w->max_bytes;
  hdr.max_records = w->max_records;
  hdr.header_crc32 =
      ephim_crc32(&hdr, offsetof(struct evidence_file_header, header_crc32));

  /* Buffer the header */
  memcpy(w->buffer, &hdr, sizeof(hdr));
  w->buffer_len = sizeof(hdr);

  return 0;
}

static inline int evidence_writer_write(struct evidence_writer *w,
                                        const struct event *e,
                                        uint64_t reception_ts_ns) {
  if (!w || w->fd < 0)
    return -1;

  w->stats.records_received++;

  if (w->error_occurred) {
    w->stats.write_errors++;
    return -1;
  }

  size_t record_total =
      sizeof(struct evidence_record_frame) + sizeof(struct event);

  /* Storage bound check */
  if (w->stats.storage_bytes + w->buffer_len + record_total > w->max_bytes) {
    w->stats.write_errors++;
    w->error_occurred = true;
    return -1;
  }
  if (w->max_records > 0 && w->stats.records_written >= w->max_records) {
    w->stats.write_errors++;
    w->error_occurred = true;
    return -1;
  }

  /* If buffer cannot hold this record, flush first */
  if (w->buffer_len + record_total > w->buffer_cap) {
    if (evidence_writer_flush(w) < 0)
      return -1;
  }

  /* Frame construction */
  struct evidence_record_frame frame;
  frame.magic = EPHIM_EVIDENCE_RECORD_MAGIC;
  frame.flags = 0;
  frame.seq_num =
      w->stats.records_written; /* Strict monotonic reception order */
  frame.reception_ts_ns =
      reception_ts_ns ? reception_ts_ns : evidence_time_now_ns();
  frame.payload_len = (uint32_t)sizeof(struct event);
  frame.payload_crc32 = ephim_crc32(e, sizeof(struct event));

  /* Append frame and payload */
  memcpy(w->buffer + w->buffer_len, &frame, sizeof(frame));
  w->buffer_len += sizeof(frame);
  memcpy(w->buffer + w->buffer_len, e, sizeof(struct event));
  w->buffer_len += sizeof(struct event);

  w->stats.records_written++;
  return 0;
}

static inline int evidence_writer_close(struct evidence_writer *w) {
  if (!w || w->fd < 0)
    return 0;

  int sync_rc = evidence_writer_sync(w);
  int close_rc = close(w->fd);
  w->fd = -1;

  if (w->buffer) {
    free(w->buffer);
    w->buffer = NULL;
  }

  if (sync_rc != 0 || close_rc != 0) {
    w->stats.write_errors++;
    w->error_occurred = true;
    return -1;
  }
  return 0;
}

/* --- Session Manifest Parser Helpers & Loss Evaluation --- */

enum evidence_loss_status {
  EVIDENCE_LOSS_LOSSLESS = 0,
  EVIDENCE_LOSS_LOSSY = 1,
  EVIDENCE_LOSS_UNVERIFIED = 2,
  EVIDENCE_LOSS_INCONSISTENT = 3
};

/* --- RFC 8259 Recursive Descent JSON Parser & Validator --- */

enum ephim_json_type {
  EPHIM_JSON_INVALID = 0,
  EPHIM_JSON_OBJECT,
  EPHIM_JSON_ARRAY,
  EPHIM_JSON_STRING,
  EPHIM_JSON_NUMBER,
  EPHIM_JSON_BOOL,
  EPHIM_JSON_NULL
};

struct ephim_json_val {
  enum ephim_json_type type;
  const char *start;
  size_t len;
  bool bool_val;
  int first_child;
  int next_sibling;
  const char *key;
  size_t key_len;
};

static inline void ephim_json_skip_ws(const char **p, const char *end) {
  while (*p < end && (**p == ' ' || **p == '\t' || **p == '\r' || **p == '\n')) {
    (*p)++;
  }
}

static inline bool ephim_json_parse_string(const char **p, const char *end,
                                           const char **out_str, size_t *out_len) {
  if (*p >= end || **p != '"')
    return false;
  (*p)++; /* skip opening quote */
  const char *s = *p;
  while (*p < end) {
    char c = **p;
    if (c == '"') {
      *out_str = s;
      *out_len = (size_t)(*p - s);
      (*p)++; /* skip closing quote */
      return true;
    }
    if ((unsigned char)c < 0x20) {
      return false; /* Unescaped control characters illegal */
    }
    if (c == '\\') {
      (*p)++;
      if (*p >= end) return false;
      char esc = **p;
      if (esc == '"' || esc == '\\' || esc == '/' || esc == 'b' ||
          esc == 'f' || esc == 'n' || esc == 'r' || esc == 't') {
        (*p)++;
      } else if (esc == 'u') {
        (*p)++;
        for (int i = 0; i < 4; i++) {
          if (*p >= end) return false;
          char h = **p;
          if (!((h >= '0' && h <= '9') || (h >= 'a' && h <= 'f') || (h >= 'A' && h <= 'F')))
            return false;
          (*p)++;
        }
      } else {
        return false;
      }
    } else {
      (*p)++;
    }
  }
  return false;
}

static inline bool ephim_json_parse_number(const char **p, const char *end,
                                           const char **out_num, size_t *out_len) {
  const char *start = *p;
  if (*p < end && **p == '-') {
    (*p)++;
  }
  if (*p >= end) return false;
  if (**p == '0') {
    (*p)++;
    if (*p < end && (**p >= '0' && **p <= '9'))
      return false; /* Leading zero not allowed in JSON */
  } else if (**p >= '1' && **p <= '9') {
    while (*p < end && (**p >= '0' && **p <= '9'))
      (*p)++;
  } else {
    return false;
  }
  if (*p < end && **p == '.') {
    (*p)++;
    if (*p >= end || !(**p >= '0' && **p <= '9'))
      return false;
    while (*p < end && (**p >= '0' && **p <= '9'))
      (*p)++;
  }
  if (*p < end && (**p == 'e' || **p == 'E')) {
    (*p)++;
    if (*p < end && (**p == '+' || **p == '-'))
      (*p)++;
    if (*p >= end || !(**p >= '0' && **p <= '9'))
      return false;
    while (*p < end && (**p >= '0' && **p <= '9'))
      (*p)++;
  }
  *out_num = start;
  *out_len = (size_t)(*p - start);
  return true;
}

static inline int ephim_json_parse_val(const char **p, const char *end,
                                       struct ephim_json_val *nodes, int *node_count, int max_nodes);

static inline int ephim_json_parse_object(const char **p, const char *end,
                                         struct ephim_json_val *nodes, int *node_count, int max_nodes) {
  if (*p >= end || **p != '{') return -1;
  if (*node_count >= max_nodes) return -1;

  int obj_idx = (*node_count)++;
  nodes[obj_idx].type = EPHIM_JSON_OBJECT;
  nodes[obj_idx].start = *p;
  nodes[obj_idx].first_child = -1;
  nodes[obj_idx].next_sibling = -1;

  (*p)++; /* skip '{' */
  ephim_json_skip_ws(p, end);
  if (*p < end && **p == '}') {
    (*p)++;
    return obj_idx;
  }

  int prev_child = -1;
  while (*p < end) {
    ephim_json_skip_ws(p, end);
    const char *key = NULL;
    size_t key_len = 0;
    if (!ephim_json_parse_string(p, end, &key, &key_len))
      return -1;

    ephim_json_skip_ws(p, end);
    if (*p >= end || **p != ':')
      return -1;
    (*p)++; /* skip ':' */
    ephim_json_skip_ws(p, end);

    int val_idx = ephim_json_parse_val(p, end, nodes, node_count, max_nodes);
    if (val_idx < 0)
      return -1;

    nodes[val_idx].key = key;
    nodes[val_idx].key_len = key_len;

    if (prev_child < 0) {
      nodes[obj_idx].first_child = val_idx;
    } else {
      nodes[prev_child].next_sibling = val_idx;
    }
    prev_child = val_idx;

    ephim_json_skip_ws(p, end);
    if (*p < end && **p == ',') {
      (*p)++;
      ephim_json_skip_ws(p, end);
      if (*p < end && **p == '}')
        return -1; /* Trailing comma illegal */
    } else if (*p < end && **p == '}') {
      (*p)++;
      return obj_idx;
    } else {
      return -1;
    }
  }
  return -1;
}

static inline int ephim_json_parse_array(const char **p, const char *end,
                                        struct ephim_json_val *nodes, int *node_count, int max_nodes) {
  if (*p >= end || **p != '[') return -1;
  if (*node_count >= max_nodes) return -1;

  int arr_idx = (*node_count)++;
  nodes[arr_idx].type = EPHIM_JSON_ARRAY;
  nodes[arr_idx].start = *p;
  nodes[arr_idx].first_child = -1;
  nodes[arr_idx].next_sibling = -1;

  (*p)++;
  ephim_json_skip_ws(p, end);
  if (*p < end && **p == ']') {
    (*p)++;
    return arr_idx;
  }

  int prev_child = -1;
  while (*p < end) {
    int val_idx = ephim_json_parse_val(p, end, nodes, node_count, max_nodes);
    if (val_idx < 0)
      return -1;

    if (prev_child < 0) {
      nodes[arr_idx].first_child = val_idx;
    } else {
      nodes[prev_child].next_sibling = val_idx;
    }
    prev_child = val_idx;

    ephim_json_skip_ws(p, end);
    if (*p < end && **p == ',') {
      (*p)++;
      ephim_json_skip_ws(p, end);
      if (*p < end && **p == ']')
        return -1; /* Trailing comma illegal */
    } else if (*p < end && **p == ']') {
      (*p)++;
      return arr_idx;
    } else {
      return -1;
    }
  }
  return -1;
}

static inline int ephim_json_parse_val(const char **p, const char *end,
                                       struct ephim_json_val *nodes, int *node_count, int max_nodes) {
  ephim_json_skip_ws(p, end);
  if (*p >= end) return -1;
  if (*node_count >= max_nodes) return -1;

  char c = **p;
  if (c == '{') {
    return ephim_json_parse_object(p, end, nodes, node_count, max_nodes);
  }
  if (c == '[') {
    return ephim_json_parse_array(p, end, nodes, node_count, max_nodes);
  }
  if (c == '"') {
    const char *s = NULL;
    size_t len = 0;
    if (!ephim_json_parse_string(p, end, &s, &len))
      return -1;
    int idx = (*node_count)++;
    nodes[idx].type = EPHIM_JSON_STRING;
    nodes[idx].start = s;
    nodes[idx].len = len;
    nodes[idx].first_child = -1;
    nodes[idx].next_sibling = -1;
    return idx;
  }
  if (c == 't') {
    if (end - *p >= 4 && strncmp(*p, "true", 4) == 0) {
      *p += 4;
      int idx = (*node_count)++;
      nodes[idx].type = EPHIM_JSON_BOOL;
      nodes[idx].bool_val = true;
      nodes[idx].first_child = -1;
      nodes[idx].next_sibling = -1;
      return idx;
    }
    return -1;
  }
  if (c == 'f') {
    if (end - *p >= 5 && strncmp(*p, "false", 5) == 0) {
      *p += 5;
      int idx = (*node_count)++;
      nodes[idx].type = EPHIM_JSON_BOOL;
      nodes[idx].bool_val = false;
      nodes[idx].first_child = -1;
      nodes[idx].next_sibling = -1;
      return idx;
    }
    return -1;
  }
  if (c == 'n') {
    if (end - *p >= 4 && strncmp(*p, "null", 4) == 0) {
      *p += 4;
      int idx = (*node_count)++;
      nodes[idx].type = EPHIM_JSON_NULL;
      nodes[idx].first_child = -1;
      nodes[idx].next_sibling = -1;
      return idx;
    }
    return -1;
  }
  if (c == '-' || (c >= '0' && c <= '9')) {
    const char *num = NULL;
    size_t len = 0;
    if (!ephim_json_parse_number(p, end, &num, &len))
      return -1;
    int idx = (*node_count)++;
    nodes[idx].type = EPHIM_JSON_NUMBER;
    nodes[idx].start = num;
    nodes[idx].len = len;
    nodes[idx].first_child = -1;
    nodes[idx].next_sibling = -1;
    return idx;
  }
  return -1;
}

static inline int ephim_json_parse_doc(const char *buf, size_t len,
                                       struct ephim_json_val *nodes, int max_nodes) {
  if (!buf || len == 0) return -1;
  const char *p = buf;
  const char *end = buf + len;
  ephim_json_skip_ws(&p, end);
  if (p >= end || *p != '{') return -1;

  int node_count = 0;
  int root = ephim_json_parse_object(&p, end, nodes, &node_count, max_nodes);
  if (root < 0) return -1;

  ephim_json_skip_ws(&p, end);
  if (p != end) return -1; /* Trailing garbage */
  return root;
}

static inline const struct ephim_json_val *ephim_json_obj_get(const struct ephim_json_val *nodes,
                                                              int obj_idx, const char *key) {
  if (obj_idx < 0 || nodes[obj_idx].type != EPHIM_JSON_OBJECT)
    return NULL;
  size_t klen = strlen(key);
  int curr = nodes[obj_idx].first_child;
  while (curr >= 0) {
    if (nodes[curr].key && nodes[curr].key_len == klen &&
        strncmp(nodes[curr].key, key, klen) == 0) {
      return &nodes[curr];
    }
    curr = nodes[curr].next_sibling;
  }
  return NULL;
}

/* Checked numeric and boolean conversions */
static inline bool ephim_json_val_to_uint64(const struct ephim_json_val *v, uint64_t *out_val) {
  if (!v || v->type != EPHIM_JSON_NUMBER || !v->start || v->len == 0)
    return false;
  if (v->start[0] == '-')
    return false;
  char buf[64];
  if (v->len >= sizeof(buf))
    return false;
  memcpy(buf, v->start, v->len);
  buf[v->len] = '\0';
  char *end = NULL;
  errno = 0;
  unsigned long long val = strtoull(buf, &end, 10);
  if (end != buf + v->len || errno != 0)
    return false;
  if (out_val) *out_val = (uint64_t)val;
  return true;
}

static inline bool ephim_json_val_to_uint32(const struct ephim_json_val *v, uint32_t *out_val) {
  uint64_t val64 = 0;
  if (!ephim_json_val_to_uint64(v, &val64))
    return false;
  if (val64 > UINT32_MAX)
    return false;
  if (out_val) *out_val = (uint32_t)val64;
  return true;
}

static inline bool ephim_json_val_to_int64(const struct ephim_json_val *v, int64_t *out_val) {
  if (!v || v->type != EPHIM_JSON_NUMBER || !v->start || v->len == 0)
    return false;
  char buf[64];
  if (v->len >= sizeof(buf))
    return false;
  memcpy(buf, v->start, v->len);
  buf[v->len] = '\0';
  char *end = NULL;
  errno = 0;
  long long val = strtoll(buf, &end, 10);
  if (end != buf + v->len || errno != 0)
    return false;
  if (out_val) *out_val = (int64_t)val;
  return true;
}

static inline bool ephim_json_val_to_bool(const struct ephim_json_val *v, bool *out_val) {
  if (!v || v->type != EPHIM_JSON_BOOL)
    return false;
  if (out_val) *out_val = v->bool_val;
  return true;
}

static inline bool ephim_json_val_to_str(const struct ephim_json_val *v, char *out_buf, size_t max_len) {
  if (!v || v->type != EPHIM_JSON_STRING || !v->start)
    return false;
  size_t copy_len = v->len < max_len - 1 ? v->len : max_len - 1;
  memcpy(out_buf, v->start, copy_len);
  out_buf[copy_len] = '\0';
  return true;
}

static inline enum evidence_loss_status
evidence_manifest_evaluate_loss(const struct evidence_session_manifest *m,
                                int64_t *out_computed_drops,
                                const char **out_desc) {
  if (!m) {
    if (out_desc) *out_desc = "UNVERIFIED (No manifest provided)";
    if (out_computed_drops) *out_computed_drops = -1;
    return EVIDENCE_LOSS_UNVERIFIED;
  }

  static const uint32_t defined_types[] = {
    EVENT_EXECVE, EVENT_MEMFD_CREATE, EVENT_UNLINK, EVENT_UNLINKAT,
    EVENT_CONNECT, EVENT_FORK, EVENT_PROCESS_EXEC, EVENT_PROCESS_EXIT,
    EVENT_VFS_UNLINK_COMPLETED, EVENT_VFS_RMDIR_COMPLETED, EVENT_RMDIR,
    EVENT_MEMFD_COMPLETED, EVENT_MEMFD_DESTROYED, EVENT_MEMFD_FILE_RELEASED,
    EVENT_FD_INSTALLED, EVENT_FD_CLOSED, EVENT_MEMFD_WRITE,
    EVENT_MEMFD_EXEC_ATTEMPT, EVENT_MEMFD_EXEC_SUCCESS, EVENT_DEBUG
  };

  int64_t type_sum = 0;
  bool any_type_missing = false;
  bool any_type_drop = false;

  for (size_t i = 0; i < sizeof(defined_types)/sizeof(defined_types[0]); i++) {
    uint32_t t = defined_types[i];
    int64_t d = m->ring_buffer_per_type_drops[t];
    if (d < 0) {
      any_type_missing = true;
    } else if (d > 0) {
      any_type_drop = true;
      type_sum += d;
    }
  }

  int64_t total = (m->ring_buffer_total_drops > type_sum) ?
                   m->ring_buffer_total_drops : type_sum;
  if (out_computed_drops) *out_computed_drops = total;

  /* 1. Consistency check:
   * Total drops must equal sum of per-type drops when both are available.
   * If sum of per-type drops exceeds total drops, manifest is inconsistent.
   */
  if (m->ring_buffer_total_drops >= 0 && type_sum > m->ring_buffer_total_drops) {
    if (out_desc) *out_desc = "INCONSISTENT (Sum of per-event drops exceeds total ring buffer drops)";
    return EVIDENCE_LOSS_INCONSISTENT;
  }
  if (m->ring_buffer_total_drops >= 0 && !any_type_missing && m->ring_buffer_total_drops != type_sum) {
    if (out_desc) *out_desc = "INCONSISTENT (Discrepancy between total and per-type loss counters)";
    return EVIDENCE_LOSS_INCONSISTENT;
  }

  /* 2. Preserve known positive loss indications even when other counters are unavailable! */
  bool any_positive_loss = (m->ring_buffer_total_drops > 0 || any_type_drop ||
                            m->reg_map_full_drop > 0 || m->token_alloc_err > 0 ||
                            m->token_mismatch > 0);
  if (any_positive_loss) {
    if (out_desc) *out_desc = "LOSSY (Drops recorded in kernel ring buffer or registry)";
    return EVIDENCE_LOSS_LOSSY;
  }

  /* 3. Storage persistence sanity */
  if (!m->finalized || !m->synchronized ||
      m->sample_size_mismatches != 0 ||
      m->write_errors != 0 ||
      m->poll_errors != 0 ||
      m->drain_errors != 0) {
    if (out_desc) *out_desc = "UNVERIFIED (Storage persistence errors or unfinalized)";
    if (out_computed_drops) *out_computed_drops = -1;
    return EVIDENCE_LOSS_UNVERIFIED;
  }

  /* 4. Kernel counters availability: if any counter is missing/unavailable, lossless cannot be verified */
  if (any_type_missing) {
    if (out_desc) *out_desc = "UNVERIFIED (Per-event drop counters incomplete in manifest)";
    if (out_computed_drops) *out_computed_drops = -1;
    return EVIDENCE_LOSS_UNVERIFIED;
  }

  if (m->reg_map_full_drop < 0 || m->token_alloc_err < 0 || m->token_mismatch < 0 ||
      m->ring_buffer_total_drops < 0) {
    if (out_desc) *out_desc = "UNVERIFIED (Kernel loss counters missing or unavailable in manifest)";
    if (out_computed_drops) *out_computed_drops = -1;
    return EVIDENCE_LOSS_UNVERIFIED;
  }

  /* 5. Complete and lossless: all verified counters are zero */
  if (out_desc) *out_desc = "COMPLETE_LOSSLESS (0 drops recorded across all stages)";
  return EVIDENCE_LOSS_LOSSLESS;
}

/* --- Session Manifest Persistence & Verification --- */

static inline int
evidence_write_manifest(const char *evid_path,
                        const struct evidence_session_manifest *m) {
  if (!evid_path || !m)
    return -1;

  char manifest_path[512];
  int sn_rc =
      snprintf(manifest_path, sizeof(manifest_path), "%s.manifest", evid_path);
  if (sn_rc < 0 || (size_t)sn_rc >= sizeof(manifest_path))
    return -1;

  /* Refuse to overwrite an existing manifest file */
  struct stat st;
  if (lstat(manifest_path, &st) == 0) {
    errno = EEXIST;
    return -EEXIST;
  }

  int fd = open(manifest_path,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0)
    return -errno;

  const char *persist_status = (m->finalized && m->synchronized) ? "PERSISTED_CLEAN" : "PERSIST_FAILED";
  const char *capture_status = NULL;
  int64_t computed_drops = 0;
  enum evidence_loss_status loss_st = evidence_manifest_evaluate_loss(m, &computed_drops, &capture_status);
  bool telemetry_lossless = (loss_st == EVIDENCE_LOSS_LOSSLESS);

  char drops_str[64];
  if (m->ring_buffer_total_drops >= 0) {
    snprintf(drops_str, sizeof(drops_str), "%lld", (long long)m->ring_buffer_total_drops);
  } else if (m->ring_buffer_drops[0]) {
    snprintf(drops_str, sizeof(drops_str), "%s", m->ring_buffer_drops);
  } else {
    snprintf(drops_str, sizeof(drops_str), "unavailable via kernel ring_buffer API");
  }

  char buf[4096];
  int len = snprintf(
      buf, sizeof(buf),
      "{\n"
      "  \"manifest_version\": 1,\n"
      "  \"evidence_file\": \"%s\",\n"
      "  \"target_pid\": %u,\n"
      "  \"session_start_ns\": %llu,\n"
      "  \"session_end_ns\": %llu,\n"
      "  \"record_count\": %llu,\n"
      "  \"storage_bytes\": %llu,\n"
      "  \"finalization_status\": \"%s\",\n"
      "  \"synchronization_status\": \"%s\",\n"
      "  \"persistence_status\": \"%s\",\n"
      "  \"telemetry_capture_status\": \"%s\",\n"
      "  \"telemetry_loss_free\": %s,\n"
      "  \"finalized\": %s,\n"
      "  \"synchronized\": %s,\n"
      "  \"loss_counters\": {\n"
      "    \"reg_map_full_drop\": %lld,\n"
      "    \"token_alloc_err\": %lld,\n"
      "    \"token_mismatch\": %lld,\n"
      "    \"sample_size_mismatches\": %llu,\n"
      "    \"write_errors\": %llu,\n"
      "    \"poll_errors\": %llu,\n"
      "    \"drain_errors\": %llu,\n"
      "    \"ring_buffer_total_drops\": %lld,\n"
      "    \"ring_buffer_drops\": \"%s\",\n"
      "    \"ring_buffer_per_type_drops\": {\n"
      "      \"execve\": %lld,\n"
      "      \"memfd_create\": %lld,\n"
      "      \"unlink\": %lld,\n"
      "      \"unlinkat\": %lld,\n"
      "      \"connect\": %lld,\n"
      "      \"fork\": %lld,\n"
      "      \"process_exec\": %lld,\n"
      "      \"process_exit\": %lld,\n"
      "      \"vfs_unlink_completed\": %lld,\n"
      "      \"vfs_rmdir_completed\": %lld,\n"
      "      \"rmdir\": %lld,\n"
      "      \"memfd_completed\": %lld,\n"
      "      \"memfd_destroyed\": %lld,\n"
      "      \"memfd_file_released\": %lld,\n"
      "      \"fd_installed\": %lld,\n"
      "      \"fd_closed\": %lld,\n"
      "      \"memfd_write\": %lld,\n"
      "      \"memfd_exec_attempt\": %lld,\n"
      "      \"memfd_exec_success\": %lld,\n"
      "      \"debug\": %lld\n"
      "    }\n"
      "  }\n"
      "}\n",
      evid_path, m->target_pid, (unsigned long long)m->session_start_ns,
      (unsigned long long)m->session_end_ns,
      (unsigned long long)m->record_count, (unsigned long long)m->storage_bytes,
      m->finalized ? "COMPLETE" : "INCOMPLETE / FAILED",
      m->synchronized ? "SYNCED" : "FAILED",
      persist_status, capture_status,
      telemetry_lossless ? "true" : "false",
      m->finalized ? "true" : "false",
      m->synchronized ? "true" : "false",
      (long long)m->reg_map_full_drop,
      (long long)m->token_alloc_err, (long long)m->token_mismatch,
      (unsigned long long)m->sample_size_mismatches,
      (unsigned long long)m->write_errors, (unsigned long long)m->poll_errors,
      (unsigned long long)m->drain_errors,
      (long long)m->ring_buffer_total_drops,
      drops_str,
      (long long)m->ring_buffer_per_type_drops[EVENT_EXECVE],
      (long long)m->ring_buffer_per_type_drops[EVENT_MEMFD_CREATE],
      (long long)m->ring_buffer_per_type_drops[EVENT_UNLINK],
      (long long)m->ring_buffer_per_type_drops[EVENT_UNLINKAT],
      (long long)m->ring_buffer_per_type_drops[EVENT_CONNECT],
      (long long)m->ring_buffer_per_type_drops[EVENT_FORK],
      (long long)m->ring_buffer_per_type_drops[EVENT_PROCESS_EXEC],
      (long long)m->ring_buffer_per_type_drops[EVENT_PROCESS_EXIT],
      (long long)m->ring_buffer_per_type_drops[EVENT_VFS_UNLINK_COMPLETED],
      (long long)m->ring_buffer_per_type_drops[EVENT_VFS_RMDIR_COMPLETED],
      (long long)m->ring_buffer_per_type_drops[EVENT_RMDIR],
      (long long)m->ring_buffer_per_type_drops[EVENT_MEMFD_COMPLETED],
      (long long)m->ring_buffer_per_type_drops[EVENT_MEMFD_DESTROYED],
      (long long)m->ring_buffer_per_type_drops[EVENT_MEMFD_FILE_RELEASED],
      (long long)m->ring_buffer_per_type_drops[EVENT_FD_INSTALLED],
      (long long)m->ring_buffer_per_type_drops[EVENT_FD_CLOSED],
      (long long)m->ring_buffer_per_type_drops[EVENT_MEMFD_WRITE],
      (long long)m->ring_buffer_per_type_drops[EVENT_MEMFD_EXEC_ATTEMPT],
      (long long)m->ring_buffer_per_type_drops[EVENT_MEMFD_EXEC_SUCCESS],
      (long long)m->ring_buffer_per_type_drops[EVENT_DEBUG]);

  if (len < 0 || (size_t)len >= sizeof(buf)) {
    close(fd);
    unlink(manifest_path);
    return -1;
  }

  size_t total_written = 0;
  while (total_written < (size_t)len) {
    ssize_t n = write(fd, buf + total_written, (size_t)len - total_written);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      close(fd);
      unlink(manifest_path);
      return -1;
    }
    total_written += (size_t)n;
  }

  if (fdatasync(fd) != 0) {
    close(fd);
    unlink(manifest_path);
    return -1;
  }

  if (close(fd) != 0) {
    unlink(manifest_path);
    return -1;
  }

  return 0;
}

static inline int
evidence_read_manifest(const char *evid_path,
                       struct evidence_session_manifest *out_m) {
  if (!evid_path || !out_m)
    return -1;

  memset(out_m, 0, sizeof(*out_m));
  out_m->reg_map_full_drop = -1;
  out_m->token_alloc_err = -1;
  out_m->token_mismatch = -1;
  out_m->ring_buffer_total_drops = -1;
  for (int i = 0; i < EPHIM_MAX_EVENT_TYPE; i++) {
    out_m->ring_buffer_per_type_drops[i] = -1;
  }
  snprintf(out_m->ring_buffer_drops, sizeof(out_m->ring_buffer_drops),
           "unavailable via kernel ring_buffer API");
  char manifest_path[512];
  int sn_rc =
      snprintf(manifest_path, sizeof(manifest_path), "%s.manifest", evid_path);
  if (sn_rc < 0 || (size_t)sn_rc >= sizeof(manifest_path))
    return -1;

  struct stat st_m;
  if (lstat(manifest_path, &st_m) != 0) {
    if (errno == ENOENT)
      return 1; /* Manifest not present: legacy v1 file */
    return -1;
  }

  /* Must not be a symlink */
  if (S_ISLNK(st_m.st_mode))
    return -2; /* Symlink rejected */

  /* Must not have same inode as evidence file */
  struct stat st_e;
  if (stat(evid_path, &st_e) == 0) {
    if (st_m.st_dev == st_e.st_dev && st_m.st_ino == st_e.st_ino)
      return -2; /* Alias rejected */
  }

  int fd = open(manifest_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0)
    return -1;

  char buf[8192];
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  if (n <= 0)
    return -1;
  buf[n] = '\0';

  /* Complete JSON parsing and RFC 8259 syntax validation */
  struct ephim_json_val nodes[256];
  int root = ephim_json_parse_doc(buf, (size_t)n, nodes, 256);
  if (root < 0)
    return -1; /* Malformed JSON */

  /* 1. Required field: manifest_version == 1 */
  const struct ephim_json_val *v_ver = ephim_json_obj_get(nodes, root, "manifest_version");
  if (!v_ver || !ephim_json_val_to_uint32(v_ver, &out_m->version) || out_m->version != 1)
    return -1; /* Incompatible or missing manifest version */

  /* 2. Required fields: record_count and storage_bytes */
  const struct ephim_json_val *v_rec = ephim_json_obj_get(nodes, root, "record_count");
  if (!v_rec || !ephim_json_val_to_uint64(v_rec, &out_m->record_count))
    return -1;

  const struct ephim_json_val *v_stor = ephim_json_obj_get(nodes, root, "storage_bytes");
  if (!v_stor || !ephim_json_val_to_uint64(v_stor, &out_m->storage_bytes))
    return -1;

  /* 3. Required fields: finalized and synchronized */
  const struct ephim_json_val *v_fin = ephim_json_obj_get(nodes, root, "finalized");
  if (!v_fin || !ephim_json_val_to_bool(v_fin, &out_m->finalized))
    return -1;

  const struct ephim_json_val *v_syn = ephim_json_obj_get(nodes, root, "synchronized");
  if (!v_syn || !ephim_json_val_to_bool(v_syn, &out_m->synchronized))
    return -1;

  /* Top-level optional fields */
  const struct ephim_json_val *v_pid = ephim_json_obj_get(nodes, root, "target_pid");
  if (v_pid) ephim_json_val_to_uint32(v_pid, &out_m->target_pid);

  const struct ephim_json_val *v_t0 = ephim_json_obj_get(nodes, root, "session_start_ns");
  if (v_t0) ephim_json_val_to_uint64(v_t0, &out_m->session_start_ns);

  const struct ephim_json_val *v_t1 = ephim_json_obj_get(nodes, root, "session_end_ns");
  if (v_t1) ephim_json_val_to_uint64(v_t1, &out_m->session_end_ns);

  /* 4. Required sub-object: loss_counters */
  const struct ephim_json_val *v_lc = ephim_json_obj_get(nodes, root, "loss_counters");
  if (!v_lc || v_lc->type != EPHIM_JSON_OBJECT)
    return -1;

  int lc_idx = (int)(v_lc - nodes);

  const struct ephim_json_val *v_ssm = ephim_json_obj_get(nodes, lc_idx, "sample_size_mismatches");
  if (v_ssm) ephim_json_val_to_uint64(v_ssm, &out_m->sample_size_mismatches);

  const struct ephim_json_val *v_we = ephim_json_obj_get(nodes, lc_idx, "write_errors");
  if (v_we) ephim_json_val_to_uint64(v_we, &out_m->write_errors);

  const struct ephim_json_val *v_pe = ephim_json_obj_get(nodes, lc_idx, "poll_errors");
  if (v_pe) ephim_json_val_to_uint64(v_pe, &out_m->poll_errors);

  const struct ephim_json_val *v_de = ephim_json_obj_get(nodes, lc_idx, "drain_errors");
  if (v_de) ephim_json_val_to_uint64(v_de, &out_m->drain_errors);

  /* Loss accounting: checked numeric conversions */
  const struct ephim_json_val *v_map = ephim_json_obj_get(nodes, lc_idx, "reg_map_full_drop");
  if (v_map) ephim_json_val_to_int64(v_map, &out_m->reg_map_full_drop);

  const struct ephim_json_val *v_tok_a = ephim_json_obj_get(nodes, lc_idx, "token_alloc_err");
  if (v_tok_a) ephim_json_val_to_int64(v_tok_a, &out_m->token_alloc_err);

  const struct ephim_json_val *v_tok_m = ephim_json_obj_get(nodes, lc_idx, "token_mismatch");
  if (v_tok_m) ephim_json_val_to_int64(v_tok_m, &out_m->token_mismatch);

  const struct ephim_json_val *v_rb_tot = ephim_json_obj_get(nodes, lc_idx, "ring_buffer_total_drops");
  if (v_rb_tot) ephim_json_val_to_int64(v_rb_tot, &out_m->ring_buffer_total_drops);

  /* Parse string/number for ring_buffer_drops */
  const struct ephim_json_val *v_rb_d = ephim_json_obj_get(nodes, lc_idx, "ring_buffer_drops");
  if (v_rb_d) {
    if (v_rb_d->type == EPHIM_JSON_STRING) {
      ephim_json_val_to_str(v_rb_d, out_m->ring_buffer_drops, sizeof(out_m->ring_buffer_drops));
    } else if (v_rb_d->type == EPHIM_JSON_NUMBER) {
      int64_t vnum = 0;
      if (ephim_json_val_to_int64(v_rb_d, &vnum)) {
        snprintf(out_m->ring_buffer_drops, sizeof(out_m->ring_buffer_drops), "%lld", (long long)vnum);
      }
    }
  }

  /* Parse per-type drops */
  const struct ephim_json_val *v_pt = ephim_json_obj_get(nodes, lc_idx, "ring_buffer_per_type_drops");
  if (v_pt && v_pt->type == EPHIM_JSON_OBJECT) {
    int pt_idx = (int)(v_pt - nodes);
    static const struct {
      uint32_t type;
      const char *key;
    } type_keys[] = {
      {EVENT_EXECVE, "execve"},
      {EVENT_MEMFD_CREATE, "memfd_create"},
      {EVENT_UNLINK, "unlink"},
      {EVENT_UNLINKAT, "unlinkat"},
      {EVENT_CONNECT, "connect"},
      {EVENT_FORK, "fork"},
      {EVENT_PROCESS_EXEC, "process_exec"},
      {EVENT_PROCESS_EXIT, "process_exit"},
      {EVENT_VFS_UNLINK_COMPLETED, "vfs_unlink_completed"},
      {EVENT_VFS_RMDIR_COMPLETED, "vfs_rmdir_completed"},
      {EVENT_RMDIR, "rmdir"},
      {EVENT_MEMFD_COMPLETED, "memfd_completed"},
      {EVENT_MEMFD_DESTROYED, "memfd_destroyed"},
      {EVENT_MEMFD_FILE_RELEASED, "memfd_file_released"},
      {EVENT_FD_INSTALLED, "fd_installed"},
      {EVENT_FD_CLOSED, "fd_closed"},
      {EVENT_MEMFD_WRITE, "memfd_write"},
      {EVENT_MEMFD_EXEC_ATTEMPT, "memfd_exec_attempt"},
      {EVENT_MEMFD_EXEC_SUCCESS, "memfd_exec_success"},
      {EVENT_DEBUG, "debug"},
    };
    for (size_t i = 0; i < sizeof(type_keys)/sizeof(type_keys[0]); i++) {
      const struct ephim_json_val *v_type = ephim_json_obj_get(nodes, pt_idx, type_keys[i].key);
      if (v_type) {
        int64_t val = -1;
        if (ephim_json_val_to_int64(v_type, &val)) {
          out_m->ring_buffer_per_type_drops[type_keys[i].type] = val;
        }
      }
    }
  }

  return 0; /* Successfully read and parsed */
}

/* --- Binary Evidence Reader / Replayer --- */

struct evidence_reader {
  int fd;
  struct evidence_file_header header;
  uint64_t expected_seq;
  struct evidence_stats stats;
  char path[256];
};

static inline ssize_t evidence_safe_read_exact(int fd, void *buf,
                                               size_t count) {
  size_t total = 0;
  uint8_t *p = (uint8_t *)buf;
  while (total < count) {
    ssize_t n = read(fd, p + total, count - total);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    if (n == 0)
      return (ssize_t)total; /* Short read at EOF */
    total += (size_t)n;
  }
  return (ssize_t)total;
}

static inline int evidence_reader_open(struct evidence_reader *r,
                                       const char *path) {
  if (!r || !path)
    return -1;

  memset(r, 0, sizeof(*r));
  r->fd = open(path, O_RDONLY | O_CLOEXEC);
  if (r->fd < 0)
    return -1;

  snprintf(r->path, sizeof(r->path), "%s", path);

  /* Read header using safe exact reader */
  ssize_t rc = evidence_safe_read_exact(r->fd, &r->header,
                                        sizeof(struct evidence_file_header));
  if (rc != (ssize_t)sizeof(struct evidence_file_header)) {
    r->stats.incomplete_records++;
    close(r->fd);
    r->fd = -1;
    return -1;
  }

  /* Validate header magic & version */
  if (r->header.magic != EPHIM_EVIDENCE_FILE_MAGIC ||
      r->header.version != EPHIM_EVIDENCE_VERSION ||
      r->header.event_size != sizeof(struct event) ||
      r->header.header_size != sizeof(struct evidence_file_header)) {
    r->stats.corrupt_records++;
    close(r->fd);
    r->fd = -1;
    return -2;
  }

  /* Validate header CRC32 */
  uint32_t expected_crc = ephim_crc32(
      &r->header, offsetof(struct evidence_file_header, header_crc32));
  if (r->header.header_crc32 != expected_crc) {
    r->stats.corrupt_records++;
    close(r->fd);
    r->fd = -1;
    return -3;
  }

  r->expected_seq = 0;
  return 0;
}

/* Reads next record frame & payload. Returns:
 *  1: Successfully read and verified valid record
 *  0: Clean EOF
 * -1: Frame / payload corruption or CRC mismatch
 * -2: Truncated / incomplete record at EOF
 */
static inline int
evidence_reader_read_next(struct evidence_reader *r, struct event *out_event,
                          struct evidence_record_frame *out_frame) {
  if (!r || r->fd < 0)
    return -1;

  struct evidence_record_frame frame;
  ssize_t n = evidence_safe_read_exact(r->fd, &frame, sizeof(frame));
  if (n == 0)
    return 0; /* Clean EOF */
  if (n < 0 || n != (ssize_t)sizeof(frame)) {
    r->stats.incomplete_records++;
    return -2;
  }

  /* Validate frame magic */
  if (frame.magic != EPHIM_EVIDENCE_RECORD_MAGIC) {
    r->stats.corrupt_records++;
    return -1;
  }

  /* Validate sequence order */
  if (frame.seq_num != r->expected_seq) {
    if (frame.seq_num > r->expected_seq) {
      r->stats.seq_gaps += (frame.seq_num - r->expected_seq);
    } else {
      r->stats.corrupt_records++;
      return -1;
    }
    r->expected_seq = frame.seq_num;
  }

  /* Validate payload length */
  if (frame.payload_len != sizeof(struct event)) {
    r->stats.corrupt_records++;
    return -1;
  }

  /* Read event payload */
  n = evidence_safe_read_exact(r->fd, out_event, sizeof(struct event));
  if (n != (ssize_t)sizeof(struct event)) {
    r->stats.incomplete_records++;
    return -2;
  }

  /* Validate payload CRC32 */
  uint32_t calc_crc = ephim_crc32(out_event, sizeof(struct event));
  if (calc_crc != frame.payload_crc32) {
    r->stats.corrupt_records++;
    return -1;
  }

  if (out_frame)
    *out_frame = frame;

  r->stats.records_verified++;
  r->stats.records_replayed++;
  r->expected_seq++;
  return 1;
}

static inline void evidence_reader_close(struct evidence_reader *r) {
  if (!r)
    return;
  if (r->fd >= 0) {
    close(r->fd);
    r->fd = -1;
  }
}

#ifdef __cplusplus
}
#endif

#endif /* EPHIM_EVIDENCE_IO_H */
