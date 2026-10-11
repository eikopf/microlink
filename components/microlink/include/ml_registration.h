#pragma once

#include "cJSON.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    ML_REGISTER_INVALID,
    ML_REGISTER_REFUSED,
    ML_REGISTER_UNSUPPORTED_SIGNATURE,
    ML_REGISTER_EXPIRED,
    ML_REGISTER_PENDING,
    ML_REGISTER_ACCEPTED,
} ml_registration_status_t;

/* Classify a complete response received over the authenticated Noise session. */
ml_registration_status_t ml_registration_status(const cJSON *response);

/* Extract stream 1 DATA only when the complete HTTP/2 response fits.
 * consumed ends at END_STREAM; the caller retains any trailing transport bytes. */
bool ml_registration_body(const uint8_t *frames, size_t length,
                          uint8_t *body, size_t capacity, size_t *body_length, size_t *consumed);
