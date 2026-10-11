#include "ml_registration.h"
#include <string.h>

bool ml_registration_body(const uint8_t *frames, size_t length,
                          uint8_t *body, size_t capacity, size_t *body_length, size_t *consumed) {
    if (!frames || !body || !body_length || !consumed || !capacity) return false;
    *body_length = 0;
    *consumed = 0;
    size_t total = length;
    size_t used = 0;
    bool ended = false;
    while (length) {
        if (length < 9) return false;
        size_t payload = ((size_t)frames[0] << 16) | ((size_t)frames[1] << 8) | frames[2];
        uint8_t type = frames[3], flags = frames[4];
        uint32_t stream = ((uint32_t)(frames[5] & 0x7f) << 24) |
                          ((uint32_t)frames[6] << 16) | ((uint32_t)frames[7] << 8) | frames[8];
        frames += 9;
        length -= 9;
        if (payload > length) return false;
        if (stream == 1) {
            if (type == 3) return false; /* RST_STREAM is not acceptance. */
            if (type == 0) {
                size_t offset = 0, data_length = payload;
                if (flags & 8) {
                    if (!payload || frames[0] >= payload) return false;
                    offset = 1;
                    data_length -= 1 + frames[0];
                }
                if (data_length >= capacity - used) return false;
                memcpy(body + used, frames + offset, data_length);
                used += data_length;
            }
            if ((type == 0 || type == 1) && (flags & 1)) ended = true;
        }
        frames += payload;
        length -= payload;
        if (ended) break;
    }
    if (!ended || !used) return false;
    body[used] = 0;
    *body_length = used;
    *consumed = total - length;
    return true;
}

static int optional_string(const cJSON *value) {
    return !value || cJSON_IsNull(value) ||
           (cJSON_IsString(value) && value->valuestring);
}

ml_registration_status_t ml_registration_status(const cJSON *response) {
    if (!cJSON_IsObject(response)) return ML_REGISTER_INVALID;
    const cJSON *error = cJSON_GetObjectItemCaseSensitive(response, "Error");
    if (!optional_string(error)) return ML_REGISTER_INVALID;
    /* A refusal overrides all other status fields. */
    if (cJSON_IsString(error) && error->valuestring[0]) return ML_REGISTER_REFUSED;

    const cJSON *expired = cJSON_GetObjectItemCaseSensitive(response, "NodeKeyExpired");
    const cJSON *url = cJSON_GetObjectItemCaseSensitive(response, "AuthURL");
    const cJSON *signature = cJSON_GetObjectItemCaseSensitive(response, "NodeKeySignature");
    if (!optional_string(url) || !optional_string(signature) ||
        (expired && !cJSON_IsNull(expired) && !cJSON_IsBool(expired)))
        return ML_REGISTER_INVALID;
    if (cJSON_IsString(signature) && signature->valuestring[0])
        return ML_REGISTER_UNSUPPORTED_SIGNATURE;
    if (cJSON_IsTrue(expired)) return ML_REGISTER_EXPIRED;
    if (cJSON_IsString(url) && url->valuestring[0]) return ML_REGISTER_PENDING;
    return ML_REGISTER_ACCEPTED;
}
