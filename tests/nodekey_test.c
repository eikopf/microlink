#include "ml_nodekey.h"
#include "ml_x25519.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static uint8_t legacy[32], stored[68], pending_write[68];
static size_t stored_len;
static bool has_write, durable_on_commit_error;
static int fail_open, fail_read, fail_set, fail_commit;
static unsigned random_calls, write_calls, open_handles;

esp_err_t nvs_open(const char *name, int mode, nvs_handle_t *handle) {
    assert(!strcmp(name, "microlink") && mode == NVS_READWRITE);
    if (fail_open) return ESP_FAIL;
    *handle = ++open_handles;
    return ESP_OK;
}
void nvs_close(nvs_handle_t handle) {
    assert(handle && open_handles == 1);
    --open_handles;
    has_write = false;
}
esp_err_t nvs_get_blob(nvs_handle_t handle, const char *name, void *value, size_t *length) {
    (void)handle;
    if (fail_read) return ESP_FAIL;
    const uint8_t *data = stored;
    size_t size = stored_len;
    if (!strcmp(name, "wg_private")) { data = legacy; size = sizeof(legacy); }
    else assert(!strcmp(name, "wg_rotation"));
    if (!size) return ESP_ERR_NVS_NOT_FOUND;
    if (*length < size) return ESP_ERR_NVS_INVALID_LENGTH;
    memcpy(value, data, size);
    *length = size;
    return ESP_OK;
}
esp_err_t nvs_set_blob(nvs_handle_t handle, const char *name, const void *value, size_t length) {
    (void)handle;
    /* No machine key, discovery key, preferences, or legacy key may be written. */
    assert(!strcmp(name, "wg_rotation") && length == sizeof(stored));
    ++write_calls;
    if (fail_set) return ESP_FAIL;
    memcpy(pending_write, value, length);
    has_write = true;
    return ESP_OK;
}
esp_err_t nvs_commit(nvs_handle_t handle) {
    (void)handle;
    if ((!fail_commit || durable_on_commit_error) && has_write) {
        memcpy(stored, pending_write, sizeof(stored));
        stored_len = sizeof(stored);
    }
    return fail_commit ? ESP_FAIL : ESP_OK;
}
void esp_fill_random(void *buffer, size_t length) {
    ++random_calls;
    for (size_t i = 0; i < length; ++i) ((uint8_t *)buffer)[i] = (uint8_t)(random_calls * 19 + i);
}

static void reset(void) {
    memset(legacy, 0x28, sizeof(legacy));
    legacy[31] = 0x68;
    memset(stored, 0, sizeof(stored));
    stored_len = 0;
    has_write = durable_on_commit_error = false;
    fail_open = fail_read = fail_set = fail_commit = 0;
    random_calls = write_calls = open_handles = 0;
}

int main(void) {
    uint8_t original_public[32], next_private[32], next_public[32], previous_public[32];
    bool pending = false;
    reset();
    ml_x25519_base(original_public, legacy, 1);
    assert(ml_nodekey_load(1, next_private, next_public, previous_public, &pending) == ESP_ERR_NVS_NOT_FOUND);
    assert(ml_nodekey_stage(legacy, original_public) == ESP_OK);
    assert(random_calls == 1 && open_handles == 0);
    assert(ml_nodekey_load(1, next_private, next_public, previous_public, &pending) == ESP_OK && pending);
    assert(memcmp(next_private, legacy, 32) && memcmp(next_public, original_public, 32));
    assert(!memcmp(previous_public, original_public, 32));
    uint8_t snapshot[68]; memcpy(snapshot, stored, sizeof(snapshot));
    assert(ml_nodekey_stage(legacy, original_public) == ESP_ERR_INVALID_STATE);
    assert(random_calls == 1 && !memcmp(snapshot, stored, sizeof(snapshot)));
    assert(ml_nodekey_accept(legacy) == ESP_ERR_INVALID_STATE);
    assert(ml_nodekey_accept(next_private) == ESP_OK);
    unsigned writes = write_calls;
    assert(ml_nodekey_accept(next_private) == ESP_OK && write_calls == writes);
    assert(ml_nodekey_load(1, next_private, next_public, previous_public, &pending) == ESP_OK && !pending);
    const uint8_t zeros[32] = {0};
    assert(!memcmp(previous_public, zeros, 32));
    assert(ml_nodekey_stage(next_private, next_public) == ESP_OK);
    assert(random_calls == 2); /* A later expiry can rotate an accepted key. */

    for (unsigned failure = 0; failure < 4; ++failure) {
        reset();
        if (failure == 0) fail_open = 1;
        if (failure == 1) fail_read = 1;
        if (failure == 2) fail_set = 1;
        if (failure == 3) fail_commit = 1;
        assert(ml_nodekey_stage(legacy, original_public) == ESP_FAIL);
        assert(stored_len == 0 && open_handles == 0);
    }
    reset();
    fail_commit = 1; durable_on_commit_error = true;
    assert(ml_nodekey_stage(legacy, original_public) == ESP_FAIL);
    fail_commit = 0;
    assert(ml_nodekey_load(1, next_private, next_public, previous_public, &pending) == ESP_OK && pending);
    assert(ml_nodekey_stage(legacy, original_public) == ESP_ERR_INVALID_STATE && random_calls == 1);
    fail_set = 1;
    assert(ml_nodekey_accept(next_private) == ESP_FAIL);
    fail_set = 0;
    assert(ml_nodekey_load(1, next_private, next_public, previous_public, &pending) == ESP_OK && pending);

    memcpy(snapshot, stored, sizeof(snapshot));
    for (size_t length = 1; length < sizeof(stored); ++length) {
        stored_len = length;
        assert(ml_nodekey_load(1, next_private, next_public, previous_public, &pending) != ESP_OK);
    }
    stored_len = sizeof(stored);
    const unsigned invalid_offsets[] = {0, 1, 2, 3, 4, 35};
    for (unsigned i = 0; i < sizeof(invalid_offsets) / sizeof(invalid_offsets[0]); ++i) {
        memcpy(stored, snapshot, sizeof(stored));
        stored[invalid_offsets[i]] = 0xff;
        assert(ml_nodekey_load(1, next_private, next_public, previous_public, &pending) == ESP_ERR_INVALID_STATE);
    }
    assert(open_handles == 0);
    puts("node-key persistence tests passed");
    return 0;
}
