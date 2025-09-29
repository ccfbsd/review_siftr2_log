#ifndef THREADS_COMPAT_H
#define THREADS_COMPAT_H

#include <pthread.h>
#include <stdatomic.h>

// --- Thread Types ---
typedef pthread_t thrd_t;

// --- Return Codes ---
#define thrd_success 0
#define thrd_error   1

// --- Thread API ---
typedef struct {
    int (*func)(void *);
    void *arg;
} thrd_start_wrapper_t;

static void *
thrd_start_adapter(void *arg)
{
    thrd_start_wrapper_t *wrapper = arg;
    int ret = wrapper->func(wrapper->arg);
    free(wrapper);
    return (void *)(intptr_t)ret; // store int in void*
}

static inline int
thrd_create(thrd_t *thr, int (*func)(void*), void *arg)
{
    thrd_start_wrapper_t *wrapper = malloc(sizeof(*wrapper));
    if (!wrapper) return thrd_error;
    wrapper->func = func;
    wrapper->arg = arg;
    return pthread_create(thr, NULL, thrd_start_adapter, wrapper);
}
#define thrd_join(thr, res) pthread_join(thr, (void**)(res))

typedef struct {
    char        direction;  // 'i' or 'o'
    double      rel_time;
    uint32_t    cwnd;
    uint32_t    ssthresh;
    uint32_t    srtt;
    uint32_t    data_sz;
} record_t;

typedef struct {
    record_t            buffer[QUEUE_SIZE];
    atomic_size_t       head;   // consumer reads from head
    atomic_size_t       tail;   // producer writes to tail
    atomic_bool         done;   // producer sets to true when finished
} queue_t;

static inline void
queue_init(queue_t *q) {
    atomic_init(&q->head, 0);
    atomic_init(&q->tail, 0);
    atomic_init(&q->done, false);
}

// Returns false if the buffer is full (no push performed)
static inline bool
queue_push(queue_t *q, const record_t *rec)
{
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
static inline bool
queue_pop(queue_t *q, record_t *rec)
{
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

static inline void
queue_set_done(queue_t *q)
{
    atomic_store_explicit(&q->done, true, memory_order_release);
}

static inline bool
queue_is_done(queue_t *q)
{
    return atomic_load_explicit(&q->done, memory_order_acquire);
}

static inline bool
queue_is_empty(queue_t *q)
{
    size_t head = atomic_load_explicit(&q->head, memory_order_relaxed);
    size_t tail = atomic_load_explicit(&q->tail, memory_order_relaxed);
    return head == tail;
}

#endif // THREADS_COMPAT_H
