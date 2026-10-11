#ifndef WIREGUARD_TIMESTAMP_H
#define WIREGUARD_TIMESTAMP_H

#include <stdbool.h>
#include <stdint.h>

#define WG_TAI64_OFFSET UINT64_C(0x400000000000000a)
#define WG_TIMESTAMP_MAX_EPOCH (UINT64_MAX - WG_TAI64_OFFSET)
#define WG_TIMESTAMP_SEQUENCE_LIMIT UINT32_C(1000000000)

typedef bool (*wg_timestamp_reserve_fn)(uint64_t minimum, uint64_t *epoch, void *context);

typedef struct {
    bool ready;
    uint64_t epoch;
    uint32_t sequence;
    wg_timestamp_reserve_fn reserve;
    void *context;
} wg_timestamp_t;

/* The caller serializes access. Reserve must persist an epoch before returning success. */
bool wg_timestamp_init(wg_timestamp_t *state, uint64_t clock_seconds,
                       wg_timestamp_reserve_fn reserve, void *context);
bool wg_timestamp_next(wg_timestamp_t *state, uint8_t output[12]);

#endif
