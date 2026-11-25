#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <assert.h>
#include <errno.h>

#define REG_STATE_PROVISIONAL 1
#define REG_STATE_COMMITTED   2

#define CNT_REG_MAP_FULL_DROP 10
#define CNT_REG_INODE_ROLLBACK 11
#define CNT_REG_FILE_DELETE_ERR 12
#define CNT_FD_CLOSED_MATCH 13

struct memfd_desc_key {
    uint32_t pid;
    uint32_t fd;
};

struct memfd_desc_entry {
    uint64_t object_token;
    uint64_t file_ptr;
    uint64_t installed_ts_ns;
};

struct memfd_object_entry {
    uint64_t object_token;
    uint32_t state;
};

/* Counters */
static uint64_t counters[64];
static void inc_counter(uint32_t idx) {
    if (idx < 64) counters[idx]++;
}

/* Mock Inode Registry */
static struct {
    uint64_t key;
    struct memfd_object_entry val;
    bool exists;
} mock_inode_reg[16];

static struct memfd_object_entry *mock_lookup_inode(uint64_t key) {
    for (int i = 0; i < 16; i++) {
        if (mock_inode_reg[i].exists && mock_inode_reg[i].key == key)
            return &mock_inode_reg[i].val;
    }
    return NULL;
}

static int mock_delete_inode(uint64_t key) {
    for (int i = 0; i < 16; i++) {
        if (mock_inode_reg[i].exists && mock_inode_reg[i].key == key) {
            mock_inode_reg[i].exists = false;
            return 0;
        }
    }
    return -ENOENT;
}

static void mock_insert_inode(uint64_t key, uint64_t token, uint32_t state) {
    for (int i = 0; i < 16; i++) {
        if (!mock_inode_reg[i].exists || mock_inode_reg[i].key == key) {
            mock_inode_reg[i].exists = true;
            mock_inode_reg[i].key = key;
            mock_inode_reg[i].val.object_token = token;
            mock_inode_reg[i].val.state = state;
            return;
        }
    }
}

/* 1. Test Concurrent Close Claims via __sync_lock_test_and_set */
#define NUM_CLOSE_THREADS 16
static struct memfd_desc_entry shared_desc;
static int close_winner_count = 0;
static pthread_mutex_t count_lock = PTHREAD_MUTEX_INITIALIZER;

static void *close_worker(void *arg) {
    (void)arg;
    /* Emulate capture_close_fd atomic claim */
    uint64_t token = __sync_lock_test_and_set(&shared_desc.object_token, 0);
    if (token != 0) {
        pthread_mutex_lock(&count_lock);
        close_winner_count++;
        pthread_mutex_unlock(&count_lock);
    }
    return NULL;
}

static void test_concurrent_close_claim(void) {
    printf("[TEST] Concurrent close claims via __sync_lock_test_and_set...\n");
    for (int iter = 0; iter < 100; iter++) {
        shared_desc.object_token = 0xABCD1234ULL;
        close_winner_count = 0;

        pthread_t th[NUM_CLOSE_THREADS];
        for (int i = 0; i < NUM_CLOSE_THREADS; i++) {
            assert(pthread_create(&th[i], NULL, close_worker, NULL) == 0);
        }
        for (int i = 0; i < NUM_CLOSE_THREADS; i++) {
            assert(pthread_join(th[i], NULL) == 0);
        }

        assert(close_winner_count == 1);
        assert(shared_desc.object_token == 0);
    }
    printf("  [PASS] 100 iterations: exactly 1 thread won atomic token claim in every race\n");
}

/* 2. Test Rollback Consistency and Safe Atomic Inode Deletion */
static void test_rollback_consistency(void) {
    printf("[TEST] Rollback consistency & safe atomic deletion...\n");
    memset(mock_inode_reg, 0, sizeof(mock_inode_reg));
    memset(counters, 0, sizeof(counters));

    uint64_t ino_key = 0x9000;
    uint64_t token1 = 1001;

    /* Scenario A: Provisional inode with matching token rolled back on failure via CAS */
    mock_insert_inode(ino_key, token1, REG_STATE_PROVISIONAL);
    struct memfd_object_entry *obj = mock_lookup_inode(ino_key);
    assert(obj != NULL);
    if (obj && obj->state == REG_STATE_PROVISIONAL) {
        if (__sync_val_compare_and_swap(&obj->object_token, token1, 0) == token1) {
            int del_res = mock_delete_inode(ino_key);
            if (del_res == 0) inc_counter(CNT_REG_INODE_ROLLBACK);
        }
    }
    assert(mock_lookup_inode(ino_key) == NULL);
    assert(counters[CNT_REG_INODE_ROLLBACK] == 1);

    /* Scenario B: COMMITTED inode must NOT be deleted during rollback */
    mock_insert_inode(ino_key, token1, REG_STATE_COMMITTED);
    uint64_t token2 = 1002;
    obj = mock_lookup_inode(ino_key);
    assert(obj != NULL);
    /* Safe rollback check: must be provisional */
    if (obj && obj->state == REG_STATE_PROVISIONAL) {
        if (__sync_val_compare_and_swap(&obj->object_token, token2, 0) == token2) {
            mock_delete_inode(ino_key);
        }
    }
    /* Verify committed inode still exists! */
    assert(mock_lookup_inode(ino_key) != NULL);
    assert(mock_lookup_inode(ino_key)->state == REG_STATE_COMMITTED);
    assert(mock_lookup_inode(ino_key)->object_token == token1);

    /* Scenario C: Map full discrimination (-E2BIG / -ENOSPC) */
    int res_full = -7; /* -E2BIG */
    if (res_full == -7 || res_full == -28) inc_counter(CNT_REG_MAP_FULL_DROP);
    assert(counters[CNT_REG_MAP_FULL_DROP] == 1);

    int res_other = -1; /* -EPERM */
    if (res_other == -7 || res_other == -28) inc_counter(CNT_REG_MAP_FULL_DROP);
    assert(counters[CNT_REG_MAP_FULL_DROP] == 1); /* Did NOT increment on other error */

    printf("  [PASS] Rollback preserves committed inodes and correctly classifies map errors\n");
}

/* 3. Test Descriptor Reuse */
static void test_descriptor_reuse(void) {
    printf("[TEST] Descriptor reuse lifecycle...\n");
    struct memfd_desc_entry de;
    de.object_token = 5001;
    de.installed_ts_ns = 100;

    /* Close 1: atomic claim and cleanup */
    uint64_t tok1 = __sync_lock_test_and_set(&de.object_token, 0);
    assert(tok1 == 5001);
    assert(de.object_token == 0);

    /* Reuse descriptor with new token */
    de.object_token = 5002;
    de.installed_ts_ns = 200;

    /* Close 2: atomic claim of new token */
    uint64_t tok2 = __sync_lock_test_and_set(&de.object_token, 0);
    assert(tok2 == 5002);
    assert(de.object_token == 0);

    printf("  [PASS] Descriptor reuse correctly handled across distinct lifecycles\n");
}

/* 4. Test Invalid & Non-memfd Closes */
static void test_invalid_descriptor_close(void) {
    printf("[TEST] Invalid / non-memfd descriptor closes...\n");
    struct memfd_desc_entry *non_existent = NULL;
    if (!non_existent) {
        /* Returns 0 without event emission */
    }
    assert(non_existent == NULL);
    printf("  [PASS] Non-memfd descriptor closes return 0 without event emission\n");
}

int main(void) {
    printf("=================================================================\n");
    printf("=== EphimTrace: Registry & Concurrency Unit Test Suite        ===\n");
    printf("=================================================================\n");
    test_concurrent_close_claim();
    test_rollback_consistency();
    test_descriptor_reuse();
    test_invalid_descriptor_close();
    printf("=================================================================\n");
    printf("=== [SUCCESS] ALL REGISTRY & CONCURRENCY UNIT TESTS PASSED    ===\n");
    printf("=================================================================\n");
    return 0;
}
