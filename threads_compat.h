#ifndef THREADS_COMPAT_H
#define THREADS_COMPAT_H

#include <pthread.h>
#include <sched.h>     // for sched_yield()
#include <stdatomic.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

// --- Thread Types ---
typedef pthread_t thrd_t;
typedef pthread_mutex_t mtx_t;
typedef pthread_cond_t cnd_t;

// --- Mutex Types ---
#define mtx_plain     0
#define mtx_timed     1
#define mtx_recursive 2

// --- Return Codes ---
#define thrd_success 0
#define thrd_error   1

// --- Mutex API ---
static inline int mtx_init(mtx_t *mtx, int type) {
    (void)type; // ignoring type for now (could handle recursive if needed)
    return pthread_mutex_init(mtx, NULL);
}
#define mtx_lock(m)    pthread_mutex_lock(m)
#define mtx_unlock(m)  pthread_mutex_unlock(m)
#define mtx_destroy(m) pthread_mutex_destroy(m)

// --- Thread API ---
typedef struct {
    int (*func)(void *);
    void *arg;
} thrd_start_wrapper_t;

static void *thrd_start_adapter(void *arg) {
    thrd_start_wrapper_t *wrapper = arg;
    int ret = wrapper->func(wrapper->arg);
    free(wrapper);
    return (void *)(intptr_t)ret; // store int in void*
}

static inline int thrd_create(thrd_t *thr, int (*func)(void*), void *arg) {
    thrd_start_wrapper_t *wrapper = malloc(sizeof(*wrapper));
    if (!wrapper) return thrd_error;
    wrapper->func = func;
    wrapper->arg = arg;
    return pthread_create(thr, NULL, thrd_start_adapter, wrapper);
}
#define thrd_join(thr, res) pthread_join(thr, (void**)(res))

// --- Condition Variable API ---
static inline int cnd_init(cnd_t *cond) {
    return pthread_cond_init(cond, NULL);
}
#define cnd_signal(c)     pthread_cond_signal(c)
#define cnd_broadcast(c)  pthread_cond_broadcast(c)
#define cnd_wait(c, m)    pthread_cond_wait(c, m)
#define cnd_destroy(c)    pthread_cond_destroy(c)

typedef struct {
    char direction[2];
    double rel_time;
    char cwnd[11];
    char ssthresh[11];
    char srtt[7];
    char data_sz[5];
} record_t;

typedef struct {
    record_t            buffer[QUEUE_SIZE];
    atomic_size_t       head;   // consumer reads from head
    atomic_size_t       tail;   // producer writes to tail
    atomic_bool         done;   // producer sets to true when finished
} queue_t;

static inline void queue_init(queue_t *q) {
    atomic_init(&q->head, 0);
    atomic_init(&q->tail, 0);
    atomic_init(&q->done, false);
}

// Returns false if the buffer is full (no push performed)
static inline bool queue_push(queue_t *q, const record_t *rec) {
    size_t tail = atomic_load_explicit(&q->tail, memory_order_relaxed);
    size_t head = atomic_load_explicit(&q->head, memory_order_acquire);

    // Compute next tail in modulo space (power-of-two wrap)
    size_t next = (tail + 1) & QUEUE_MASK;
    if (next == (head & QUEUE_MASK)) {
        return false; // full
    }

    q->buffer[tail & QUEUE_MASK] = *rec;
    // Release publish so consumer sees data before tail moves
    atomic_store_explicit(&q->tail, tail + 1, memory_order_release);
    return true;
}

// Returns false if the buffer is empty (no pop performed)
static inline bool queue_pop(queue_t *q, record_t *rec) {
    size_t head = atomic_load_explicit(&q->head, memory_order_relaxed);
    size_t tail = atomic_load_explicit(&q->tail, memory_order_acquire);

    if (head == tail) {
        return false; // empty
    }

    *rec = q->buffer[head & QUEUE_MASK];
    // Release consume so producer can overwrite the slot after this
    atomic_store_explicit(&q->head, head + 1, memory_order_release);
    return true;
}

static inline void queue_set_done(queue_t *q) {
    atomic_store_explicit(&q->done, true, memory_order_release);
}

static inline bool queue_is_done(queue_t *q) {
    return atomic_load_explicit(&q->done, memory_order_acquire);
}

static inline bool queue_is_empty(queue_t *q) {
    size_t head = atomic_load_explicit(&q->head, memory_order_relaxed);
    size_t tail = atomic_load_explicit(&q->tail, memory_order_relaxed);
    return head == tail;
}

#endif // THREADS_COMPAT_H
