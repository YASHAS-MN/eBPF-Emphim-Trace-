#ifndef EPHIMTRACE_PROVENANCE_H
#define EPHIMTRACE_PROVENANCE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Node types */
enum prov_node_type {
  NODE_PROCESS = 1,
  NODE_MEMFD = 2,
  NODE_FS_OBJECT = 3,
  NODE_NET_ENDPOINT = 4,
};

/* Edge types */
enum prov_edge_type {
  EDGE_FORK = 1,
  EDGE_MEMFD_CREATE = 2,
  EDGE_FD_INSTALLED = 3,
  EDGE_FD_CLOSED = 4,
  EDGE_MEMFD_WRITE = 5,
  EDGE_MEMFD_EXEC_ATTEMPT = 6,
  EDGE_MEMFD_EXEC_SUCCESS = 7,
  EDGE_UNLINK = 8,
  EDGE_CONNECT = 9,
};

/* Node structures */
struct prov_node_process {
  uint32_t pid;
  uint32_t ppid;
  char comm[256];
  uint64_t start_time_ns;
  int32_t exit_code;
  bool is_alive;
};

struct prov_node_memfd {
  uint64_t object_token;
  uint32_t creator_pid;
  uint64_t creator_start_time;
  char name[256];
  uint64_t inode_no;
  uint64_t dev_id;
  bool is_destroyed;
};

struct prov_node_fs {
  uint64_t inode_no;
  uint64_t dev_id;
  uint32_t mnt_ns_id;
  char path[256];
  bool is_unlinked;
};

struct prov_node_net {
  uint16_t family;
  char ip_str[64];
  uint16_t port;
};

/* Edge attributes */
struct prov_edge_attr {
  uint64_t timestamp_ns;
  int32_t fd;
  union {
    struct {
      char install_type[16]; /* CREATION, REOPEN, DUP */
    } fd_installed;
    struct {
      uint64_t duration_ns;
    } fd_closed;
    struct {
      int64_t offset;
      uint64_t bytes;
    } write;
    struct {
      char filename[256];
    } exec_attempt;
    struct {
      char binary_comm[256];
    } exec_success;
    struct {
      char status[32];
      char path[256];
    } unlink;
    struct {
      int32_t result;
    } connect;
  };
};

/* Forward declarations */
struct prov_edge;

struct prov_node {
  enum prov_node_type type;
  char id[128];
  union {
    struct prov_node_process proc;
    struct prov_node_memfd memfd;
    struct prov_node_fs fs;
    struct prov_node_net net;
  };
  struct prov_edge *out_edges;   /* Adjacency list for outbound edges */
  struct prov_edge *in_edges;    /* Adjacency list for inbound edges */
  struct prov_node *next_hash;   /* Next in hash bucket */
  struct prov_node *next_global; /* Next in global node list */
  bool filter_marked;            /* Marker for subgraph filtering */
};

struct prov_edge {
  enum prov_edge_type type;
  struct prov_node *src;
  struct prov_node *dst;
  struct prov_edge_attr attr;
  struct prov_edge *next_out;    /* Next in src's adjacency list */
  struct prov_edge *next_in;     /* Next in dst's in-edges list */
  struct prov_edge *next_global; /* Next in global edge list */
};

/* Filtered Subgraph Structure */
struct prov_graph {
  struct prov_node **nodes;
  size_t node_count;
  struct prov_edge **edges;
  size_t edge_count;
};

#ifndef EVENT_TYPE_DEFINED
#define EVENT_TYPE_DEFINED
enum event_type {
  EVENT_EXECVE = 1,
  EVENT_MEMFD_CREATE = 2,
  EVENT_UNLINK = 3,
  EVENT_UNLINKAT = 4,
  EVENT_CONNECT = 5,
  EVENT_FORK = 6,
  EVENT_PROCESS_EXEC = 7,
  EVENT_PROCESS_EXIT = 8,
  EVENT_VFS_UNLINK_COMPLETED = 9,
  EVENT_VFS_RMDIR_COMPLETED = 10,
  EVENT_RMDIR = 11,
  EVENT_MEMFD_COMPLETED = 12,
  EVENT_MEMFD_DESTROYED = 13,
  EVENT_MEMFD_FILE_RELEASED = 14,
  EVENT_FD_INSTALLED = 15,
  EVENT_FD_CLOSED = 16,
  EVENT_MEMFD_WRITE = 17,
  EVENT_MEMFD_EXEC_ATTEMPT = 18,
  EVENT_MEMFD_EXEC_SUCCESS = 19,
  EVENT_DEBUG = 99
};
#endif

#ifndef EVENT_STRUCT_DEFINED
#define EVENT_STRUCT_DEFINED
struct event {
  uint32_t type;
  uint32_t pid;
  uint32_t tid;
  uint32_t ppid;
  uint32_t flags;
  int32_t dirfd;
  uint32_t reserved;
  uint64_t timestamp_ns;
  int32_t fd;
  uint16_t family;
  uint16_t port;
  uint8_t address[16];
  char name[256];
  uint32_t child_pid;
  uint32_t old_pid;
  uint32_t child_tgid;
  uint64_t start_time_ns;
  uint64_t child_start_time_ns;
  uint64_t inode_no;
  uint64_t dev_id;
  uint32_t mnt_ns_id;
  int32_t ret_val;
  uint32_t op_type;
  uint32_t syscall_flags;
  uint64_t entry_ts_ns;
  uint32_t path_status;
  char path[256];
  uint32_t pad;
  uint64_t object_token;
};
#endif

/* Engine API */
int prov_engine_init(void);
void prov_engine_process_event(const struct event *e);
int prov_engine_export_dot(const char *filepath);
int prov_engine_export_json(const char *filepath);
void prov_engine_get_counts(size_t *node_count, size_t *edge_count);
void prov_engine_destroy(void);

/* Milestone 6 Phase 2: Filtering & Timeline API */
int prov_engine_filter_subgraph(uint32_t target_pid, uint64_t target_token,
                                struct prov_graph *out_filtered);
void prov_graph_free(struct prov_graph *graph);
int prov_engine_export_timeline(const char *filepath, uint32_t target_pid,
                                uint64_t target_token);
int prov_engine_export_filtered_dot(const char *filepath, uint32_t target_pid,
                                    uint64_t target_token);
int prov_engine_export_filtered_json(const char *filepath, uint32_t target_pid,
                                     uint64_t target_token);

/* Node and Edge lookup helpers */
struct prov_node *prov_find_node(const char *id);
struct prov_node *prov_upsert_process(uint32_t pid, uint64_t start_time_ns,
                                      uint32_t ppid, const char *comm);
struct prov_node *prov_upsert_memfd(uint64_t object_token, uint32_t creator_pid,
                                    uint64_t creator_start_time,
                                    const char *name, uint64_t inode_no,
                                    uint64_t dev_id);
struct prov_node *prov_upsert_fs(uint64_t inode_no, uint64_t dev_id,
                                 uint32_t mnt_ns_id, const char *path);
struct prov_node *prov_upsert_net(uint16_t family, const char *ip_str,
                                  uint16_t port);
struct prov_edge *prov_add_edge(struct prov_node *src, struct prov_node *dst,
                                enum prov_edge_type type,
                                const struct prov_edge_attr *attr);

#ifdef __cplusplus
}
#endif

#endif /* EPHIMTRACE_PROVENANCE_H */
