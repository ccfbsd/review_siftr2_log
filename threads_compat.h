#ifndef THREADS_COMPAT_H
#define THREADS_COMPAT_H

#include <pthread.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>

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

#endif // THREADS_COMPAT_H
