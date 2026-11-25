#ifndef EPHIM_EVIDENCE_IO_H
#define EPHIM_EVIDENCE_IO_H

#include <errno.h>
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
  EVIDENCE_MODE_ONLINE = 1,   /* Model M: Receive -> Preserve -> Process -> Graph */
  EVIDENCE_MODE_DEFERRED = 2  /* Model P: Receive -> Preserve -> Complete -> Replay -> Graph */
};

#define EVIDENCE_DEFAULT_BUFFER_SIZE (64 * 1024)           /* 64 KiB bounded write buffer */
#define EVIDENCE_DEFAULT_MAX_BYTES   (1024ULL * 1024 * 1024) /* 1 GiB storage bound */

/* --- CRC32 Implementation (IEEE 802.3) --- */
static inline uint32_t ephim_crc32_update(uint32_t crc, const void *buf, size_t len) {
  static uint32_t table[256];
  static bool table_init = false;
  if (!table_init) {
    for (uint32_t i = 0; i < 256; i++) {
      uint32_t c = i;
      for (int j = 0; j < 8; j++) {
        if (c & 1)
          c = 0xEDB88320U ^ (c >> 1);
        else
          c >>= 1;
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
  uint32_t header_size;         /* 4 bytes: sizeof(struct evidence_file_header) = 64 */
  uint64_t max_bytes;           /* 8 bytes: configured storage ceiling */
  uint64_t max_records;         /* 8 bytes: configured record ceiling (0 = unlimited) */
  uint32_t reserved[3];         /* 12 bytes: reserved extension fields (zeroed) */
  uint32_t header_crc32;        /* 4 bytes: CRC32 of preceding 60 bytes in header */
};

struct evidence_record_frame {
  uint32_t magic;               /* 4 bytes: EPHIM_EVIDENCE_RECORD_MAGIC */
  uint32_t flags;               /* 4 bytes: status / framing flags */
  uint64_t seq_num;             /* 8 bytes: strict monotonic sequence (0, 1, 2, ...) */
  uint64_t reception_ts_ns;     /* 8 bytes: userspace reception monotonic ns */
  uint32_t payload_len;         /* 4 bytes: sizeof(struct event) = 664 */
  uint32_t payload_crc32;       /* 4 bytes: IEEE 802.3 CRC32 of payload */
};

#pragma pack(pop)

#ifndef __cplusplus
_Static_assert(sizeof(struct evidence_file_header) == 64, "Evidence file header must be 64 bytes");
_Static_assert(sizeof(struct evidence_record_frame) == 32, "Evidence record frame must be 32 bytes");
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
  uint64_t persist_drain_latency_ns; /* Latency from collection done to persistence sync */
  uint64_t replay_duration_ns;       /* Duration of replay phase in Model P */
  uint64_t total_time_to_graph_ns;   /* Total duration from workload start to graph complete */
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

  /* Metrics & accounting */
  struct evidence_stats stats;
  bool error_occurred;
  char path[256];
};

static inline int evidence_writer_flush(struct evidence_writer *w) {
  if (!w || w->fd < 0)
    return -1;
  if (w->buffer_len == 0)
    return 0;

  size_t written = 0;
  while (written < w->buffer_len) {
    ssize_t rc = write(w->fd, w->buffer + written, w->buffer_len - written);
    if (rc < 0) {
      if (errno == EINTR)
        continue;
      if (written > 0) {
        memmove(w->buffer, w->buffer + written, w->buffer_len - written);
        w->buffer_len -= written;
        w->stats.storage_bytes += written;
      }
      w->stats.write_errors++;
      w->error_occurred = true;
      return -1;
    }
    written += (size_t)rc;
  }
  w->stats.storage_bytes += written;
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
  if (rc == 0) {
    w->stats.sync_duration_ns += (t1 - t0);
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
                                       uint32_t target_pid,
                                       size_t buffer_cap,
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

  w->buffer = (uint8_t *)malloc(w->buffer_cap);
  if (!w->buffer) {
    w->error_occurred = true;
    w->stats.write_errors++;
    return -1;
  }

  /* Exclusive private evidence file: fail if file already exists (prevent overwrite), mode 0600 */
  w->fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
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
  hdr.header_crc32 = ephim_crc32(&hdr, offsetof(struct evidence_file_header, header_crc32));

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

  size_t record_total = sizeof(struct evidence_record_frame) + sizeof(struct event);

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
  frame.seq_num = w->stats.records_written; /* Strict monotonic reception order */
  frame.reception_ts_ns = reception_ts_ns ? reception_ts_ns : evidence_time_now_ns();
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

/* --- Binary Evidence Reader / Replayer --- */

struct evidence_reader {
  int fd;
  struct evidence_file_header header;
  uint64_t expected_seq;
  struct evidence_stats stats;
  char path[256];
};

static inline ssize_t evidence_safe_read_exact(int fd, void *buf, size_t count) {
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

static inline int evidence_reader_open(struct evidence_reader *r, const char *path) {
  if (!r || !path)
    return -1;

  memset(r, 0, sizeof(*r));
  r->fd = open(path, O_RDONLY | O_CLOEXEC);
  if (r->fd < 0)
    return -1;

  snprintf(r->path, sizeof(r->path), "%s", path);

  /* Read header using safe exact reader */
  ssize_t rc = evidence_safe_read_exact(r->fd, &r->header, sizeof(struct evidence_file_header));
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
  uint32_t expected_crc = ephim_crc32(&r->header, offsetof(struct evidence_file_header, header_crc32));
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
static inline int evidence_reader_read_next(struct evidence_reader *r,
                                            struct event *out_event,
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
