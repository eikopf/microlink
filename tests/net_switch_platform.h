#pragma once
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#define CONFIG_ML_ENABLE_NET_SWITCH 1
#define CONFIG_ML_CELLULAR_TX_PIN 1
#define CONFIG_ML_CELLULAR_RX_PIN 2
#define CONFIG_ML_CELLULAR_PPP_USER ""
#define CONFIG_ML_CELLULAR_PPP_PASS ""
#define CONFIG_ML_MAX_PEERS 16
#define BIT0 1u
#define BIT1 2u
#define BIT2 4u
#define BIT3 8u
#define BIT4 16u
#define BIT5 32u
#define BIT6 64u
#define pdTRUE 1
#define pdFALSE 0
#define pdPASS 1
#define portMAX_DELAY UINT32_MAX
#define pdMS_TO_TICKS(x) (x)
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_INVALID_STATE 1
#define ESP_ERR_INVALID_ARG 2
#define ESP_ERR_NO_MEM 3
#define ESP_ERR_TIMEOUT 4
#define ESP_ERROR_CHECK(x) assert((x) == ESP_OK)
static inline void test_log(const char *tag, const char *format, ...) { (void)tag; (void)format; }
#define ESP_LOGI(...) test_log(__VA_ARGS__)
#define ESP_LOGW(...) test_log(__VA_ARGS__)
#define ESP_LOGE(...) test_log(__VA_ARGS__)
static inline const char *esp_err_to_name(int error) { return "test"; }
typedef int BaseType_t;
typedef void *TaskHandle_t;
typedef void *TimerHandle_t;
typedef uint32_t EventBits_t;
typedef struct { uint32_t bits; bool alive; } *EventGroupHandle_t;
typedef void (*TimerCallbackFunction_t)(TimerHandle_t);
typedef void (*PendedFunction_t)(void *, uint32_t);
static unsigned destroyed, started, wifi_stops, cell_stops, drain_queued, event_deletes;
static unsigned health_reads;
static esp_err_t stop_result;
static PendedFunction_t drain_callback;
static void *drain_arg;
static EventGroupHandle_t xEventGroupCreate(void) {
    EventGroupHandle_t group = calloc(1, sizeof(*group)); assert(group); group->alive = true; return group;
}
static uint32_t xEventGroupSetBits(EventGroupHandle_t group, uint32_t bits) {
    assert(group && group->alive); return group->bits |= bits;
}
static uint32_t xEventGroupClearBits(EventGroupHandle_t group, uint32_t bits) {
    assert(group && group->alive); uint32_t old = group->bits; group->bits &= ~bits; return old;
}
static uint32_t xEventGroupWaitBits(EventGroupHandle_t group, uint32_t bits, int clear, int all, uint32_t timeout) {
    assert(group && group->alive); uint32_t old = group->bits;
    if (clear) group->bits &= ~bits;
    return old;
}
static void vEventGroupDelete(EventGroupHandle_t group) {
    assert(group && group->alive && !drain_callback); ++event_deletes; group->alive = false; free(group);
}
static int xTaskCreate(void (*task)(void *), const char *name, unsigned stack, void *arg, unsigned priority, TaskHandle_t *handle) {
    *handle = (void *)1; return pdPASS;
}
static TaskHandle_t xTaskGetCurrentTaskHandle(void) { return (void *)2; }
static void vTaskDelay(uint32_t ticks) {}
static void vTaskDelete(TaskHandle_t task) {}
static TimerHandle_t xTimerCreate(const char *name, unsigned ticks, int repeat, void *id, TimerCallbackFunction_t cb) { return (void *)1; }
static int xTimerStart(TimerHandle_t timer, unsigned timeout) { return pdPASS; }
static int xTimerStop(TimerHandle_t timer, unsigned timeout) { return pdPASS; }
static int xTimerDelete(TimerHandle_t timer, unsigned timeout) { return pdPASS; }
static int xTimerPendFunctionCall(PendedFunction_t cb, void *arg, uint32_t value, unsigned timeout) {
    assert(!drain_callback); ++drain_queued; drain_callback = cb; drain_arg = arg; return pdPASS;
}
typedef struct { int unused; } microlink_t;
typedef void microlink_udp_socket_t;
typedef struct { const char *auth_key, *device_name; bool enable_derp, enable_stun, enable_disco; unsigned max_peers; } microlink_config_t;
static microlink_t fake_ml;
static microlink_t *microlink_init(const microlink_config_t *config) { ++started; return &fake_ml; }
static int microlink_start(microlink_t *ml) { return ESP_OK; }
static int microlink_stop(microlink_t *ml) { return stop_result; }
static void microlink_destroy(microlink_t *ml) { assert(stop_result == ESP_OK); ++destroyed; }
static bool microlink_is_connected(microlink_t *ml) { ++health_reads; return false; }
static uint32_t microlink_get_vpn_ip(microlink_t *ml) { return 0; }
static void microlink_ip_to_str(uint32_t ip, char *text) { text[0] = 0; }
static const char *microlink_imei_device_name(void) { return "test"; }
static const char *microlink_default_device_name(void) { return "test"; }
typedef struct { int tx_pin, rx_pin, baud_rate; const char *apn, *sim_pin, *ppp_user, *ppp_pass; } ml_cellular_config_t;
typedef int ml_cellular_data_mode_t;
#define ML_DATA_MODE_PPP 1
static int ml_cellular_init(const ml_cellular_config_t *config) { return ESP_OK; }
static int ml_cellular_connect(void) { return ESP_OK; }
static int ml_cellular_get_data_mode(void) { return ML_DATA_MODE_PPP; }
static void ml_cellular_data_stop(void) { ++cell_stops; }
static void ml_cellular_deinit(void) {}
static bool ml_config_get_nvs_apn(char *apn, size_t size) { return false; }
static bool ml_config_get_nvs_ppp(char *user, size_t ulen, char *pass, size_t plen) { return false; }
typedef void esp_netif_t;
typedef const void *esp_event_base_t;
typedef void *esp_event_handler_instance_t;
#define WIFI_EVENT ((void *)1)
#define IP_EVENT ((void *)2)
#define WIFI_EVENT_STA_START 1
#define WIFI_EVENT_STA_DISCONNECTED 2
#define IP_EVENT_STA_GOT_IP 3
#define ESP_EVENT_ANY_ID -1
#define WIFI_AUTH_WPA2_PSK 1
#define WIFI_MODE_STA 1
#define WIFI_IF_STA 1
#define WIFI_PS_NONE 0
#define IPSTR "%d"
#define IP2STR(x) 0
typedef struct { struct { int ip; } ip_info; } ip_event_got_ip_t;
typedef struct { int unused; } wifi_init_config_t;
#define WIFI_INIT_CONFIG_DEFAULT() ((wifi_init_config_t){0})
typedef struct { struct { char ssid[32], password[64]; struct { int authmode; } threshold; } sta; } wifi_config_t;
static esp_netif_t *esp_netif_create_default_wifi_sta(void) { return (void *)1; }
static void esp_netif_destroy_default_wifi(esp_netif_t *netif) {}
static int esp_wifi_connect(void) { return ESP_OK; }
static int esp_wifi_disconnect(void) { return ESP_OK; }
static int esp_wifi_stop(void) { ++wifi_stops; return ESP_OK; }
static int esp_wifi_start(void) { return ESP_OK; }
static int esp_wifi_deinit(void) { return ESP_OK; }
static int esp_wifi_init(const wifi_init_config_t *config) { return ESP_OK; }
static int esp_wifi_set_config(int interface, const wifi_config_t *config) { return ESP_OK; }
static int esp_wifi_set_mode(int mode) { return ESP_OK; }
static int esp_wifi_set_ps(int mode) { return ESP_OK; }
static int esp_event_handler_instance_register(esp_event_base_t base, int id, void (*cb)(void *, esp_event_base_t, int32_t, void *), void *arg, void **instance) {
    *instance = (void *)1; return ESP_OK;
}
static int esp_event_handler_instance_unregister(esp_event_base_t base, int id, void *instance) { return ESP_OK; }
