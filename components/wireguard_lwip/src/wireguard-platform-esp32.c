/**
 * @file wireguard-platform-esp32.c
 * @brief ESP32 platform implementation for wireguard-lwip
 */

#include "wireguard-platform.h"
#include "esp_random.h"
#include "wireguard-timestamp.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "nvs.h"
#include <time.h>
#include "lwip/sys.h"
#include <string.h>

/* ============================================================================
 * Time Functions
 * ========================================================================== */

uint32_t wireguard_sys_now() {
    // Use lwIP's built-in time function
    return sys_now();
}

/* One durable epoch per boot; client recreation must not reset the sequence. */
static wg_timestamp_t timestamp_state;
static StaticSemaphore_t timestamp_mutex_storage;
static SemaphoreHandle_t timestamp_mutex;
static portMUX_TYPE timestamp_init_lock = portMUX_INITIALIZER_UNLOCKED;

static SemaphoreHandle_t get_timestamp_mutex(void) {
    portENTER_CRITICAL(&timestamp_init_lock);
    if (!timestamp_mutex) timestamp_mutex = xSemaphoreCreateMutexStatic(&timestamp_mutex_storage);
    portEXIT_CRITICAL(&timestamp_init_lock);
    return timestamp_mutex;
}

static bool reserve_epoch(uint64_t minimum, uint64_t *epoch, void *context) {
    (void)context;
    nvs_handle_t nvs;
    if (nvs_open("microlink", NVS_READWRITE, &nvs) != ESP_OK) return false;
    uint64_t previous = 0;
    size_t size = sizeof(previous);
    esp_err_t result = nvs_get_blob(nvs, "wg_tai_epoch", &previous, &size);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        size = sizeof(previous);
        result = nvs_get_blob(nvs, "wg_tai_base", &previous, &size);
    }
    if (result == ESP_ERR_NVS_NOT_FOUND) previous = 0;
    else if (result != ESP_OK || size != sizeof(previous)) {
        nvs_close(nvs);
        return false;
    }
    if (previous >= WG_TIMESTAMP_MAX_EPOCH || minimum > WG_TIMESTAMP_MAX_EPOCH) {
        nvs_close(nvs);
        return false;
    }
    uint64_t next = previous + 1;
    if (next < minimum) next = minimum;
    result = nvs_set_blob(nvs, "wg_tai_epoch", &next, sizeof(next));
    if (result == ESP_OK) result = nvs_commit(nvs);
    nvs_close(nvs);
    if (result != ESP_OK) return false;
    *epoch = next;
    return true;
}

bool wireguard_tai64n_init(void) {
    SemaphoreHandle_t mutex = get_timestamp_mutex();
    if (!mutex || xSemaphoreTake(mutex, portMAX_DELAY) != pdTRUE) return false;
    time_t now = time(NULL);
    bool result = wg_timestamp_init(&timestamp_state, now > 0 ? (uint64_t)now : 0,
                                    reserve_epoch, NULL);
    xSemaphoreGive(mutex);
    return result;
}

bool wireguard_tai64n_now(uint8_t *output) {
    SemaphoreHandle_t mutex = get_timestamp_mutex();
    if (!mutex || xSemaphoreTake(mutex, portMAX_DELAY) != pdTRUE) return false;
    bool result = wg_timestamp_next(&timestamp_state, output);
    xSemaphoreGive(mutex);
    return result;
}

/* ============================================================================
 * Random Number Generation
 * ========================================================================== */

void wireguard_random_bytes(void *bytes, size_t size) {
    // Use ESP32 hardware RNG
    esp_fill_random(bytes, size);
}

/* ============================================================================
 * Load Management
 * ========================================================================== */

bool wireguard_is_under_load() {
    // For now, always return false (not under load)
    // Could be enhanced to check:
    // - Free heap memory
    // - CPU usage
    // - Number of active connections
    return false;
}
