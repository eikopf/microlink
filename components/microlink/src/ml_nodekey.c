#include "ml_nodekey.h"
#include "ml_x25519.h"
#include "esp_random.h"
#include <string.h>

#define NODEKEY_NAMESPACE "microlink"
#define NODEKEY_RECORD "wg_rotation"

/* One blob keeps the replacement and its predecessor together across resets. */
typedef struct {
    uint8_t version;
    uint8_t pending;
    uint8_t reserved[2];
    uint8_t private_key[32];
    uint8_t old_public_key[32];
} nodekey_record_t;
_Static_assert(sizeof(nodekey_record_t) == 68, "Unexpected node-key record layout");

static void clear_record(nodekey_record_t *record) {
    volatile uint8_t *bytes = (volatile uint8_t *)record;
    for (size_t i = 0; i < sizeof(*record); ++i) bytes[i] = 0;
}

static esp_err_t read_record(nvs_handle_t nvs, nodekey_record_t *record) {
    size_t length = sizeof(*record);
    esp_err_t result = nvs_get_blob(nvs, NODEKEY_RECORD, record, &length);
    if (result != ESP_OK) return result;
    if (length != sizeof(*record) || record->version != 1 || record->pending > 1 ||
        record->reserved[0] || record->reserved[1] || (record->private_key[0] & 7) ||
        (record->private_key[31] & 0xc0) != 0x40) return ESP_ERR_INVALID_STATE;
    return ESP_OK;
}

static esp_err_t write_record(nvs_handle_t nvs, const nodekey_record_t *record) {
    esp_err_t result = nvs_set_blob(nvs, NODEKEY_RECORD, record, sizeof(*record));
    return result == ESP_OK ? nvs_commit(nvs) : result;
}

esp_err_t ml_nodekey_load(nvs_handle_t nvs, uint8_t private_key[32],
                         uint8_t public_key[32], uint8_t old_public_key[32], bool *pending) {
    nodekey_record_t record = {0};
    esp_err_t result = read_record(nvs, &record);
    if (result == ESP_OK) {
        memcpy(private_key, record.private_key, 32);
        ml_x25519_base(public_key, private_key, 1);
        *pending = record.pending != 0;
        if (*pending) memcpy(old_public_key, record.old_public_key, 32);
        else memset(old_public_key, 0, 32);
    }
    clear_record(&record);
    return result;
}

esp_err_t ml_nodekey_stage(const uint8_t private_key[32], const uint8_t public_key[32]) {
    uint8_t expected_public[32];
    ml_x25519_base(expected_public, private_key, 1);
    if (memcmp(expected_public, public_key, 32)) return ESP_ERR_INVALID_ARG;
    nvs_handle_t nvs;
    esp_err_t result = nvs_open(NODEKEY_NAMESPACE, NVS_READWRITE, &nvs);
    if (result != ESP_OK) return result;
    nodekey_record_t record = {0};
    result = read_record(nvs, &record);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        size_t length = 32;
        result = nvs_get_blob(nvs, "wg_private", record.private_key, &length);
        if (result == ESP_OK && length != 32) result = ESP_ERR_INVALID_STATE;
    }
    if (result == ESP_OK && (record.pending || memcmp(record.private_key, private_key, 32))) {
        result = ESP_ERR_INVALID_STATE;
    }
    if (result == ESP_OK) {
        record.version = 1;
        record.pending = 1;
        memcpy(record.old_public_key, public_key, 32);
        esp_fill_random(record.private_key, 32);
        record.private_key[0] &= 248;
        record.private_key[31] &= 127;
        record.private_key[31] |= 64;
        result = write_record(nvs, &record);
    }
    clear_record(&record);
    nvs_close(nvs);
    return result;
}

esp_err_t ml_nodekey_accept(const uint8_t private_key[32]) {
    nvs_handle_t nvs;
    esp_err_t result = nvs_open(NODEKEY_NAMESPACE, NVS_READWRITE, &nvs);
    if (result != ESP_OK) return result;
    nodekey_record_t record = {0};
    result = read_record(nvs, &record);
    if (result == ESP_OK && memcmp(record.private_key, private_key, 32)) result = ESP_ERR_INVALID_STATE;
    if (result == ESP_OK && record.pending) {
        record.pending = 0;
        memset(record.old_public_key, 0, 32);
        result = write_record(nvs, &record);
    }
    clear_record(&record);
    nvs_close(nvs);
    return result;
}
