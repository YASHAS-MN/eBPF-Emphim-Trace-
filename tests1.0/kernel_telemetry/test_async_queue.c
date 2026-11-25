#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <unistd.h>
#include "src/user/event_queue.h"

static void test_queue_fifo_order(void) {
    printf("\n[TEST 1] Testing basic FIFO ordering...\n");
    struct event_queue *q = event_queue_create(1024);
    assert(q != NULL);

    const int N = 500;
    for (int i = 0; i < N; i++) {
        struct event ev = {0};
        ev.type = EVENT_MEMFD_CREATE;
        ev.pid = 1000 + i;
        ev.object_token = 5000 + i;
        int rc = event_queue_push(q, &ev, i);
        assert(rc == 0);
    }
    assert(q->count == (uint32_t)N);
    assert(q->admission_attempts == (uint64_t)N);
    assert(q->enqueued == (uint64_t)N);
    assert(q->drops == 0);
    assert(q->high_water_mark == (uint32_t)N);

    for (int i = 0; i < N; i++) {
        struct queue_entry out = {0};
        int rc = event_queue_pop(q, &out);
        assert(rc == 0);
        assert(out.e.pid == (uint32_t)(1000 + i));
        assert(out.e.object_token == (uint64_t)(5000 + i));
        assert(out.cap_idx == i);
    }
    assert(q->count == 0);
    assert(q->dequeued == (uint64_t)N);

    event_queue_destroy(q);
    printf("  [PASS] %d events pushed and popped in strict FIFO order\n", N);
}

static void test_queue_saturation_and_drops(void) {
    printf("\n[TEST 2] Testing queue saturation and drop accounting...\n");
    const uint32_t CAP = 100;
    struct event_queue *q = event_queue_create(CAP);
    assert(q != NULL);

    const int TOTAL_ATTEMPTS = 160;
    for (int i = 0; i < TOTAL_ATTEMPTS; i++) {
        struct event ev = {0};
        ev.pid = i + 1;
        int rc = event_queue_push(q, &ev, -1);
        if (i < (int)CAP) {
            assert(rc == 0);
        } else {
            assert(rc == -1);  // Dropped!
        }
    }

    assert(q->admission_attempts == TOTAL_ATTEMPTS);
    assert(q->enqueued == CAP);
    assert(q->drops == (TOTAL_ATTEMPTS - CAP));
    assert(q->count == CAP);
    assert(q->high_water_mark == CAP);

    // Verify existing queued events are not corrupted
    for (uint32_t i = 0; i < CAP; i++) {
        struct queue_entry out = {0};
        int rc = event_queue_pop(q, &out);
        assert(rc == 0);
        assert(out.e.pid == i + 1);
    }
    assert(q->count == 0);
    assert(q->dequeued == CAP);

    event_queue_destroy(q);
    printf("  [PASS] Queue capacity (%u) respected: %d attempts -> %u enqueued, %u dropped\n",
           CAP, TOTAL_ATTEMPTS, CAP, TOTAL_ATTEMPTS - CAP);
}

static void test_queue_shutdown_drain(void) {
    printf("\n[TEST 3] Testing thread-safe shutdown and complete drain...\n");
    struct event_queue *q = event_queue_create(1024);
    assert(q != NULL);

    const int N = 75;
    for (int i = 0; i < N; i++) {
        struct event ev = {0};
        ev.pid = 2000 + i;
        event_queue_push(q, &ev, -1);
    }

    // Signal shutdown while queue still holds elements
    event_queue_shutdown(q);
    assert(q->shutdown == 1);

    // Verify all pre-shutdown elements can still be drained
    for (int i = 0; i < N; i++) {
        struct queue_entry out = {0};
        int rc = event_queue_pop(q, &out);
        assert(rc == 0);
        assert(out.e.pid == (uint32_t)(2000 + i));
    }

    // When empty, subsequent pop must return -1
    struct queue_entry out = {0};
    int rc = event_queue_pop(q, &out);
    assert(rc == -1);

    event_queue_destroy(q);
    printf("  [PASS] Queue drained all %d items after shutdown signal, then returned EOF (-1)\n", N);
}

struct thread_arg {
    struct event_queue *q;
    int worker_id;
    int count;
};

static void *producer_fn(void *arg) {
    struct thread_arg *ta = (struct thread_arg *)arg;
    for (int i = 0; i < ta->count; i++) {
        struct event ev = {0};
        ev.pid = ta->worker_id;
        ev.object_token = (uint64_t)i;
        while (event_queue_push(ta->q, &ev, -1) != 0) {
            usleep(10);
        }
    }
    return NULL;
}

static void test_concurrent_producers(void) {
    printf("\n[TEST 4] Testing concurrent producers with single consumer...\n");
    const int NUM_PRODUCERS = 4;
    const int OPS_PER_PRODUCER = 5000;
    const int TOTAL_OPS = NUM_PRODUCERS * OPS_PER_PRODUCER;

    struct event_queue *q = event_queue_create(EVENT_QUEUE_CAPACITY);
    assert(q != NULL);

    pthread_t producers[NUM_PRODUCERS];
    struct thread_arg args[NUM_PRODUCERS];
    for (int i = 0; i < NUM_PRODUCERS; i++) {
        args[i].q = q;
        args[i].worker_id = 100 + i;
        args[i].count = OPS_PER_PRODUCER;
        pthread_create(&producers[i], NULL, producer_fn, &args[i]);
    }

    // Consumer drains in background
    int consumed = 0;
    int per_worker_counts[4] = {0};
    while (consumed < TOTAL_OPS) {
        struct queue_entry out = {0};
        int rc = event_queue_pop(q, &out);
        if (rc == 0) {
            int wid = out.e.pid - 100;
            assert(wid >= 0 && wid < 4);
            per_worker_counts[wid]++;
            consumed++;
        }
    }

    for (int i = 0; i < NUM_PRODUCERS; i++) {
        pthread_join(producers[i], NULL);
        assert(per_worker_counts[i] == OPS_PER_PRODUCER);
    }

    assert(consumed == TOTAL_OPS);
    assert(q->dequeued == (uint64_t)TOTAL_OPS);
    assert(q->drops == 0);

    event_queue_shutdown(q);
    event_queue_destroy(q);
    printf("  [PASS] 4 producers generated %d concurrent events; consumer drained 100%% without loss\n",
           TOTAL_OPS);
}

int main(void) {
    printf("=================================================================\n");
    printf("=== EphimTrace: Architecture B Asynchronous Queue Unit Tests  ===\n");
    printf("=================================================================\n");
    test_queue_fifo_order();
    test_queue_saturation_and_drops();
    test_queue_shutdown_drain();
    test_concurrent_producers();
    printf("\n=================================================================\n");
    printf("=== [SUCCESS] ALL ARCHITECTURE B QUEUE INVARIANTS VERIFIED    ===\n");
    printf("=================================================================\n");
    return 0;
}
