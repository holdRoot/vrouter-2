#ifndef MUTEX_H
#define MUTEX_H

#include <pthread.h>

struct mutex {
    pthread_mutex_t lock;
};

static inline void mutex_init(struct mutex* mtx)
{
    pthread_mutex_init(&mtx->lock, NULL);
}

static inline void mutex_lock(struct mutex* mtx)
{
    pthread_mutex_lock(&mtx->lock);
}
static inline void mutex_unlock(struct mutex* mtx)
{
    pthread_mutex_unlock(&mtx->lock);
}

#endif

