#include "ml_registration.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void framing(void) {
    uint8_t frames[] = {
        0,0,2, 0,0, 0,0,0,1, '{','}',
        0,0,0, 0,1, 0,0,0,1,
    };
    uint8_t body[16];
    size_t length, consumed;
    assert(ml_registration_body(frames, sizeof(frames), body, sizeof(body), &length, &consumed));
    assert(length == 2 && !strcmp((char *)body, "{}"));
    for (size_t cut = 0; cut < sizeof(frames); ++cut)
        assert(!ml_registration_body(frames, cut, body, sizeof(body), &length, &consumed));
    assert(!ml_registration_body(frames, sizeof(frames), body, 2, &length, &consumed));
    assert(ml_registration_body(frames, sizeof(frames), body, 3, &length, &consumed));
    frames[4] = 1;
    assert(ml_registration_body(frames, 11, body, sizeof(body), &length, &consumed));
    assert(ml_registration_body(frames, sizeof(frames), body, sizeof(body), &length, &consumed));
    assert(consumed == 11);
    frames[4] = 0;
    frames[14] = 3; /* Reset after the body. */
    assert(!ml_registration_body(frames, sizeof(frames), body, sizeof(body), &length, &consumed));
    uint8_t trailing[32] = {0};
    frames[14] = 0;
    memcpy(trailing, frames, sizeof(frames));
    trailing[22] = 8; /* Partial connection-level PING header. */
    trailing[23] = 6;
    assert(ml_registration_body(trailing, sizeof(frames) + 5, body, sizeof(body), &length, &consumed));
    assert(consumed == sizeof(frames));
    const uint8_t window_update[] = {0,0,4, 8,0, 0,0,0,1, 0,0,0,1};
    uint8_t with_update[sizeof(frames) + sizeof(window_update)];
    memcpy(with_update, frames, sizeof(frames));
    memcpy(with_update + sizeof(frames), window_update, sizeof(window_update));
    assert(ml_registration_body(with_update, sizeof(with_update), body, sizeof(body), &length, &consumed));
    assert(consumed == sizeof(frames));
    uint8_t padded[] = {0,0,5, 0,9, 0,0,0,1, 2,'{','}',0,0};
    assert(ml_registration_body(padded, sizeof(padded), body, sizeof(body), &length, &consumed));
    assert(length == 2 && !strcmp((char *)body, "{}"));
    padded[9] = 5;
    assert(!ml_registration_body(padded, sizeof(padded), body, sizeof(body), &length, &consumed));
    const uint8_t headers_only[] = {0,0,0, 1,1, 0,0,0,1};
    assert(!ml_registration_body(headers_only, sizeof(headers_only), body, sizeof(body), &length, &consumed));
}

static void check(const char *json, ml_registration_status_t expected) {
    cJSON *response = cJSON_ParseWithOpts(json, NULL, 1);
    assert(ml_registration_status(response) == expected);
    cJSON_Delete(response);
}

int main(void) {
    framing();
    check("{}", ML_REGISTER_ACCEPTED);
    check("{\"Error\":null,\"AuthURL\":\"\",\"NodeKeyExpired\":false}", ML_REGISTER_ACCEPTED);
    check("{\"User\":{\"ID\":0},\"Login\":{}}", ML_REGISTER_ACCEPTED);
    check("{\"NodeKeyExpired\":true}", ML_REGISTER_EXPIRED);
    check("{\"AuthURL\":\"https://example.invalid/approve\"}", ML_REGISTER_PENDING);
    check("{\"NodeKeyExpired\":true,\"AuthURL\":\"pending\"}", ML_REGISTER_EXPIRED);
    check("{\"Error\":\"refused\",\"NodeKeyExpired\":true}", ML_REGISTER_REFUSED);
    check("{\"Error\":\"refused\",\"AuthURL\":42}", ML_REGISTER_REFUSED);
    check("{\"NodeKeySignature\":\"signature\",\"NodeKeyExpired\":true}", ML_REGISTER_UNSUPPORTED_SIGNATURE);
    check("{\"NodeKeySignature\":\"\"}", ML_REGISTER_ACCEPTED);
    const char *invalid[] = {"", "{", "{}trailing", "null", "[]", "true", "42",
        "{\"Error\":true}", "{\"AuthURL\":42}", "{\"NodeKeyExpired\":\"true\"}",
        "{\"NodeKeySignature\":{}}"};
    for (unsigned i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
        check(invalid[i], ML_REGISTER_INVALID);
    puts("registration status tests passed");
    return 0;
}
