#ifndef EVENT_QUEUE_H
#define EVENT_QUEUE_H

#include "provenance.h"
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>

#define EVENT_QUEUE_CAPACITY 65536

struct queue_entry {
  struct event e;
  int cap_idx;
};

struct event_queue {
  struct queue_entry *entries;
  uint32_t capacity;
  uint32_t head;
  uint32_t tail;
  uint32_t count;
  uint32_t high_water_mark;
  uint64_t admission_attempts;
  uint64_t enqueued;
  uint64_t dequeued;
  uint64_t drops;
  int shutdown;
  pthread_mutex_t lock;
  pthread_cond_t not_empty;
};

static inline struct event_queue *event_queue_create(uint32_t capacity) {
  struct event_queue *q = (struct event_queue *)calloc(1, sizeof(*q));
  if (!q)
    return NULL;
  q->entries =
      (struct queue_entry *)calloc(capacity, sizeof(struct queue_entry));
  if (!q->entries) {
    free(q);
    return NULL;
  }
  q->capacity = capacity;
  pthread_mutex_init(&q->lock, NULL);
  pthread_cond_init(&q->not_empty, NULL);
  return q;
}

static inline void event_queue_destroy(struct event_queue *q) {
  if (!q)
    return;
  pthread_mutex_destroy(&q->lock);
  pthread_cond_destroy(&q->not_empty);
  free(q->entries);
  free(q);
}

static inline int event_queue_push(struct event_queue *q, const struct event *e,
                                   int cap_idx) {
  if (!q)
    return -1;
  pthread_mutex_lock(&q->lock);
  q->admission_attempts++;
  if (q->count >= q->capacity) {
    q->drops++;
    pthread_mutex_unlock(&q->lock);
    return -1;
  }
  q->entries[q->tail].e = *e;
  q->entries[q->tail].cap_idx = cap_idx;
  q->tail = (q->tail + 1) % q->capacity;
  q->count++;
  q->enqueued++;
  if (q->count > q->high_water_mark)
    q->high_water_mark = q->count;
  pthread_cond_signal(&q->not_empty);
  pthread_mutex_unlock(&q->lock);
  return 0;
}

static inline int event_queue_pop(struct event_queue *q,
                                  struct queue_entry *out) {
  if (!q)
    return -1;
  pthread_mutex_lock(&q->lock);
  while (q->count == 0 && !q->shutdown) {
    pthread_cond_wait(&q->not_empty, &q->lock);
  }
  if (q->count == 0 && q->shutdown) {
    pthread_mutex_unlock(&q->lock);
    return -1;
  }
  *out = q->entries[q->head];
  q->head = (q->head + 1) % q->capacity;
  q->count--;
  q->dequeued++;
  pthread_mutex_unlock(&q->lock);
  return 0;
}

static inline void event_queue_shutdown(struct event_queue *q) {
  if (!q)
    return;
  pthread_mutex_lock(&q->lock);
  q->shutdown = 1;
  pthread_cond_broadcast(&q->not_empty);
  pthread_mutex_unlock(&q->lock);
}

#endif /* EVENT_QUEUE_H */
