#include "wireguard-timestamp.h"

bool wg_timestamp_init(wg_timestamp_t *state, uint64_t clock_seconds,
                       wg_timestamp_reserve_fn reserve, void *context) {
    if (state->ready) return true;
    uint64_t epoch;
    if (!reserve || clock_seconds > WG_TIMESTAMP_MAX_EPOCH ||
        !reserve(clock_seconds, &epoch, context) || epoch < clock_seconds ||
        epoch > WG_TIMESTAMP_MAX_EPOCH) return false;
    state->epoch = epoch;
    state->sequence = 0;
    state->reserve = reserve;
    state->context = context;
    state->ready = true;
    return true;
}

bool wg_timestamp_next(wg_timestamp_t *state, uint8_t output[12]) {
    if (!state->ready) return false;
    if (state->sequence == WG_TIMESTAMP_SEQUENCE_LIMIT) {
        uint64_t epoch;
        if (state->epoch == WG_TIMESTAMP_MAX_EPOCH ||
            !state->reserve(state->epoch + 1, &epoch, state->context) ||
            epoch <= state->epoch || epoch > WG_TIMESTAMP_MAX_EPOCH) return false;
        state->epoch = epoch;
        state->sequence = 0;
    }
    uint64_t seconds = state->epoch + WG_TAI64_OFFSET;
    uint32_t sequence = state->sequence++;
    for (unsigned i = 0; i < 8; ++i) output[i] = (uint8_t)(seconds >> (56 - 8 * i));
    for (unsigned i = 0; i < 4; ++i) output[8 + i] = (uint8_t)(sequence >> (24 - 8 * i));
    return true;
}
