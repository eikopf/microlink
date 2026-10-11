#include <string.h>
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_netif_sntp.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "microlink.h"
#include "nvs_flash.h"

static EventGroupHandle_t network_events;
static const char *TAG = "minimal";

static void network_event(void *arg, esp_event_base_t base, int32_t id, void *data) {
    if (base == WIFI_EVENT && (id == WIFI_EVENT_STA_START || id == WIFI_EVENT_STA_DISCONNECTED)) {
        xEventGroupClearBits(network_events, BIT0);
        ESP_ERROR_CHECK(esp_wifi_connect());
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        xEventGroupSetBits(network_events, BIT0);
    }
}

void app_main(void) {
    if (!strlen(CONFIG_ML_WIFI_SSID)) {
        ESP_LOGE(TAG, "Configure Wi-Fi credentials in menuconfig before running");
        return;
    }
    // Preserve stored identity if NVS initialization fails.
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    configASSERT(esp_netif_create_default_wifi_sta());
    network_events = xEventGroupCreate();
    configASSERT(network_events);
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, network_event, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, network_event, NULL));
    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&init));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    wifi_config_t wifi = {0};
    _Static_assert(sizeof(CONFIG_ML_WIFI_SSID) - 1 <= sizeof(wifi.sta.ssid), "SSID too long");
    _Static_assert(sizeof(CONFIG_ML_WIFI_PASSWORD) - 1 <= sizeof(wifi.sta.password), "Password too long");
    memcpy(wifi.sta.ssid, CONFIG_ML_WIFI_SSID, strlen(CONFIG_ML_WIFI_SSID));
    memcpy(wifi.sta.password, CONFIG_ML_WIFI_PASSWORD, strlen(CONFIG_ML_WIFI_PASSWORD));
    wifi.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi));
    ESP_ERROR_CHECK(esp_wifi_start());
    xEventGroupWaitBits(network_events, BIT0, pdFALSE, pdTRUE, portMAX_DELAY);

    esp_sntp_config_t clock = ESP_NETIF_SNTP_DEFAULT_CONFIG("pool.ntp.org");
    ESP_ERROR_CHECK(esp_netif_sntp_init(&clock));
    esp_err_t result = esp_netif_sntp_sync_wait(pdMS_TO_TICKS(30000));
    if (result != ESP_OK) {
        ESP_LOGE(TAG, "Clock synchronization failed: %s", esp_err_to_name(result));
        esp_netif_sntp_deinit();
        return;
    }
    microlink_config_t config = {
        .auth_key = CONFIG_ML_TAILSCALE_AUTH_KEY,
        .device_name = CONFIG_ML_DEVICE_NAME,
        .max_peers = CONFIG_ML_MAX_PEERS,
        .enable_derp = true,
        .enable_stun = true,
        .enable_disco = true,
    };
    microlink_t *vpn = microlink_init(&config);
    if (!vpn) {
        ESP_LOGE(TAG, "Client initialization failed");
        return;
    }
    ESP_ERROR_CHECK(microlink_start(vpn));
    // The example retains the client for the lifetime of the firmware.
    // Applications that stop it must follow the checked-shutdown contract.
}
