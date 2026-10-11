#pragma once
#include "FreeRTOS.h"
typedef pthread_mutex_t StaticSemaphore_t;
typedef pthread_mutex_t *SemaphoreHandle_t;
static inline SemaphoreHandle_t xSemaphoreCreateMutexStatic(StaticSemaphore_t *m) {
    return pthread_mutex_init(m, NULL) == 0 ? m : NULL;
}
static inline int xSemaphoreTake(SemaphoreHandle_t m, uint32_t timeout) {
    (void)timeout;
    return pthread_mutex_lock(m) == 0;
}
static inline void xSemaphoreGive(SemaphoreHandle_t m) { pthread_mutex_unlock(m); }
