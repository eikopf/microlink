/**
 * @file ml_net_switch.c
 * @brief MicroLink Network Switching — WiFi Primary + Cellular Fallback
 *
 * Full stop/start cycle approach:
 *   1. Try WiFi first (with timeout)
 *   2. If WiFi fails → tear down WiFi, init cellular, start MicroLink over cellular
 *   3. Periodic health check → if VPN drops, trigger switch
 *   4. When on cellular, periodically check if WiFi has recovered → failback
 */

#include "sdkconfig.h"

#ifdef CONFIG_ML_ENABLE_NET_SWITCH

#include "ml_net_switch.h"
#include "ml_cellular.h"
#include "ml_at_socket.h"
#include "ml_config_httpd.h"
#include "microlink.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "freertos/timers.h"
#include <string.h>

static const char *TAG = "ml_net_sw";

/* ============================================================================
 * Internal State
 * ========================================================================== */

#define WIFI_CONNECTED_BIT  BIT0
#define WIFI_FAIL_BIT       BIT1
#define NET_SW_STACK_SIZE   6144
#define HEALTH_CHECK_BIT   BIT2
#define FAILBACK_CHECK_BIT BIT3
#define TASK_EXITED_BIT    BIT4
#define STOP_REQUEST_BIT   BIT5
#define TIMERS_DRAINED_BIT BIT6

typedef struct {
    /* Config (copied) */
    char wifi_ssid[64];
    char wifi_password[64];
    char sim_pin[16];
    char apn[64];
    char ppp_user[32];
    char ppp_pass[32];
    char tailscale_auth_key[128];
    char device_name[64];

    uint32_t wifi_timeout_ms;
    uint32_t health_check_interval_ms;
    uint32_t health_fail_count;
    uint32_t failback_check_ms;

    /* Callbacks */
    void (*on_connected)(ml_net_type_t type, void *user_data);
    void (*on_disconnected)(void *user_data);
    void (*on_switching)(ml_net_type_t from, ml_net_type_t to, void *user_data);
    void *user_data;

    /* State */
    ml_net_switch_state_t state;
    ml_net_type_t active_transport;
    microlink_t *ml;
    bool initialized;
    bool deinitializing;
    bool timer_drain_queued;
    bool running;

    /* WiFi */
    esp_netif_t *wifi_netif;
    EventGroupHandle_t wifi_events;
    int wifi_retry_count;
    bool wifi_active;
    esp_event_handler_instance_t wifi_handler;
    esp_event_handler_instance_t ip_handler;

    /* Health monitoring */
    TimerHandle_t health_timer;
    uint32_t health_fail_counter;

    /* Failback */
    TimerHandle_t failback_timer;

    /* Task */
    TaskHandle_t task_handle;
} ml_net_switch_ctx_t;

static ml_net_switch_ctx_t s_ctx = {0};

static bool net_running(void) {
    return __atomic_load_n(&s_ctx.running, __ATOMIC_ACQUIRE);
}

static void set_running(bool running) {
    __atomic_store_n(&s_ctx.running, running, __ATOMIC_RELEASE);
}

/* ============================================================================
 * WiFi Management
 * ========================================================================== */

static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                                int32_t event_id, void *event_data)
{
    if (!net_running() || !__atomic_load_n(&s_ctx.wifi_active, __ATOMIC_ACQUIRE)) return;
    if (event_base == WIFI_EVENT) {
        if (event_id == WIFI_EVENT_STA_START) {
            esp_wifi_connect();
        } else if (event_id == WIFI_EVENT_STA_DISCONNECTED) {
            if (s_ctx.wifi_retry_count < 5) {
                s_ctx.wifi_retry_count++;
                ESP_LOGI(TAG, "WiFi disconnected, retry %d/5", s_ctx.wifi_retry_count);
                esp_wifi_connect();
            } else {
                xEventGroupSetBits(s_ctx.wifi_events, WIFI_FAIL_BIT);
            }
        }
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG, "WiFi connected, IP: " IPSTR, IP2STR(&event->ip_info.ip));
        s_ctx.wifi_retry_count = 0;
        xEventGroupSetBits(s_ctx.wifi_events, WIFI_CONNECTED_BIT);
    }
}

static esp_err_t wifi_start(void)
{
    ESP_LOGI(TAG, "Starting WiFi (%s)...", s_ctx.wifi_ssid);

    s_ctx.wifi_retry_count = 0;
    xEventGroupClearBits(s_ctx.wifi_events, WIFI_CONNECTED_BIT | WIFI_FAIL_BIT);

    if (!s_ctx.wifi_netif) {
        s_ctx.wifi_netif = esp_netif_create_default_wifi_sta();
        wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
        ESP_ERROR_CHECK(esp_wifi_init(&cfg));
        ESP_ERROR_CHECK(esp_event_handler_instance_register(
            WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_event_handler, NULL, &s_ctx.wifi_handler));
        ESP_ERROR_CHECK(esp_event_handler_instance_register(
            IP_EVENT, IP_EVENT_STA_GOT_IP, wifi_event_handler, NULL, &s_ctx.ip_handler));
    }

    wifi_config_t wifi_config = {0};
    strncpy((char *)wifi_config.sta.ssid, s_ctx.wifi_ssid, sizeof(wifi_config.sta.ssid) - 1);
    strncpy((char *)wifi_config.sta.password, s_ctx.wifi_password, sizeof(wifi_config.sta.password) - 1);
    wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    __atomic_store_n(&s_ctx.wifi_active, true, __ATOMIC_RELEASE);
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));

    /* Wait for connection */
    EventBits_t bits = xEventGroupWaitBits(s_ctx.wifi_events,
                                            WIFI_CONNECTED_BIT | WIFI_FAIL_BIT | STOP_REQUEST_BIT,
                                            pdFALSE, pdFALSE,
                                            pdMS_TO_TICKS(s_ctx.wifi_timeout_ms));

    if (!net_running()) return ESP_ERR_INVALID_STATE;
    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "WiFi connected");
        return ESP_OK;
    }

    ESP_LOGW(TAG, "WiFi connection failed (timeout=%lums)", (unsigned long)s_ctx.wifi_timeout_ms);
    return ESP_ERR_TIMEOUT;
}

static void wifi_stop(void)
{
    __atomic_store_n(&s_ctx.wifi_active, false, __ATOMIC_RELEASE);
    ESP_LOGI(TAG, "Stopping WiFi...");
    esp_wifi_disconnect();
    esp_wifi_stop();
}

/* ============================================================================
 * Cellular Management
 * ========================================================================== */

static esp_err_t cellular_start(void)
{
    ESP_LOGI(TAG, "Starting cellular modem...");

    ml_cellular_config_t cell_config = {
        .tx_pin = CONFIG_ML_CELLULAR_TX_PIN,
        .rx_pin = CONFIG_ML_CELLULAR_RX_PIN,
        .baud_rate = 115200,
        .apn = s_ctx.apn[0] ? s_ctx.apn : NULL,
        .sim_pin = s_ctx.sim_pin[0] ? s_ctx.sim_pin : NULL,
    };

    /* Apply APN: NVS (web UI) > config struct > Kconfig */
    static char nvs_apn[32] = "";
    if (ml_config_get_nvs_apn(nvs_apn, sizeof(nvs_apn))) {
        cell_config.apn = nvs_apn;
    }

    /* Apply PPP credentials: NVS (web UI) > Kconfig */
    char nvs_ppp_user[32] = "", nvs_ppp_pass[32] = "";
    if (ml_config_get_nvs_ppp(nvs_ppp_user, sizeof(nvs_ppp_user),
                               nvs_ppp_pass, sizeof(nvs_ppp_pass))) {
        cell_config.ppp_user = nvs_ppp_user;
        cell_config.ppp_pass = nvs_ppp_pass;
    } else {
        const char *ppp_u = CONFIG_ML_CELLULAR_PPP_USER;
        if (ppp_u && ppp_u[0]) cell_config.ppp_user = ppp_u;
        const char *ppp_p = CONFIG_ML_CELLULAR_PPP_PASS;
        if (ppp_p && ppp_p[0]) cell_config.ppp_pass = ppp_p;
    }

    esp_err_t err = ml_cellular_init(&cell_config);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Cellular init failed: %s", esp_err_to_name(err));
        return err;
    }

    err = ml_cellular_connect();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Cellular data connection failed: %s", esp_err_to_name(err));
        ml_cellular_deinit();
        return err;
    }

    ml_cellular_data_mode_t mode = ml_cellular_get_data_mode();
    ESP_LOGI(TAG, "Cellular connected via %s",
             mode == ML_DATA_MODE_PPP ? "PPP" : "AT socket bridge");
    return ESP_OK;
}

static void cellular_stop(void)
{
    ESP_LOGI(TAG, "Stopping cellular...");
    ml_cellular_data_stop();
    ml_cellular_deinit();
}

/* ============================================================================
 * MicroLink VPN Management
 * ========================================================================== */

static esp_err_t vpn_stop(void);

static esp_err_t vpn_start(void)
{
    if (s_ctx.ml || !net_running()) return ESP_ERR_INVALID_STATE;
    const char *name = s_ctx.device_name[0] ? s_ctx.device_name : NULL;

    /* For cellular, prefer IMEI-based name */
    if (s_ctx.active_transport == ML_NET_CELLULAR && !name) {
        name = microlink_imei_device_name();
    }
    if (!name) {
        name = microlink_default_device_name();
    }

    microlink_config_t ml_config = {
        .auth_key = s_ctx.tailscale_auth_key,
        .device_name = name,
        .enable_derp = true,
        .enable_stun = (s_ctx.active_transport == ML_NET_WIFI),
        .enable_disco = true,
        .max_peers = CONFIG_ML_MAX_PEERS,
    };

    s_ctx.ml = microlink_init(&ml_config);
    if (!s_ctx.ml) {
        ESP_LOGE(TAG, "microlink_init failed");
        return ESP_FAIL;
    }

    esp_err_t err = microlink_start(s_ctx.ml);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "microlink_start failed: %s", esp_err_to_name(err));
        esp_err_t cleanup = vpn_stop();
        return cleanup == ESP_OK ? err : cleanup;
    }

    /* Wait for connection — large tailnets (200+ peers) over cellular can take
     * 3-4 minutes to download the full MapResponse via AT socket bridge.
     * Use 180s for cellular, 60s for WiFi. */
    int timeout_ticks = (s_ctx.active_transport == ML_NET_WIFI) ? 120 : 360;
    int timeout_secs = timeout_ticks / 2;
    for (int i = 0; i < timeout_ticks && net_running(); i++) {
        if (microlink_is_connected(s_ctx.ml)) {
            uint32_t ip = microlink_get_vpn_ip(s_ctx.ml);
            char ip_str[16];
            microlink_ip_to_str(ip, ip_str);
            ESP_LOGI(TAG, "VPN connected via %s (IP: %s)",
                     s_ctx.active_transport == ML_NET_WIFI ? "WiFi" : "Cellular",
                     ip_str);
            return ESP_OK;
        }
        vTaskDelay(pdMS_TO_TICKS(500));
    }

    ESP_LOGW(TAG, "VPN connection timeout (%ds)", timeout_secs);
    esp_err_t cleanup = vpn_stop();
    return cleanup == ESP_OK ? ESP_ERR_TIMEOUT : cleanup;
}

static esp_err_t vpn_stop(void)
{
    if (!s_ctx.ml) return ESP_OK;
    esp_err_t err = microlink_stop(s_ctx.ml);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "VPN cleanup incomplete; instance and transport retained: %s", esp_err_to_name(err));
        s_ctx.state = ML_NET_SW_ERROR;
        return err;
    }
    microlink_destroy(s_ctx.ml);
    s_ctx.ml = NULL;
    return ESP_OK;
}

/* ============================================================================
 * Health Check Timer
 * ========================================================================== */

static void health_timer_cb(TimerHandle_t timer)
{
    xEventGroupSetBits(s_ctx.wifi_events, HEALTH_CHECK_BIT);
}

static void check_health(void)
{
    if (!s_ctx.ml) return;

    if (!microlink_is_connected(s_ctx.ml)) {
        s_ctx.health_fail_counter++;
        ESP_LOGW(TAG, "Health check failed (%lu/%lu)",
                 (unsigned long)s_ctx.health_fail_counter,
                 (unsigned long)s_ctx.health_fail_count);

        if (s_ctx.health_fail_counter >= s_ctx.health_fail_count) {
            ESP_LOGE(TAG, "Health check threshold reached — triggering network switch");
            s_ctx.health_fail_counter = 0;

            if (s_ctx.active_transport == ML_NET_WIFI) {
                s_ctx.state = ML_NET_SW_SWITCHING_TO_CELL;
            } else {
                s_ctx.state = ML_NET_SW_SWITCHING_TO_WIFI;
            }

        }
    } else {
        s_ctx.health_fail_counter = 0;
    }
}

/* ============================================================================
 * Failback Timer (check if WiFi recovered while on cellular)
 * ========================================================================== */

static void failback_timer_cb(TimerHandle_t timer)
{
    xEventGroupSetBits(s_ctx.wifi_events, FAILBACK_CHECK_BIT);
}

/* ============================================================================
 * Main State Machine Task
 * ========================================================================== */

static void net_switch_task(void *arg)
{
    ESP_LOGI(TAG, "Network switch task started");

    /* Step 1: Try WiFi */
    s_ctx.state = ML_NET_SW_WIFI_CONNECTING;
    s_ctx.active_transport = ML_NET_WIFI;

    esp_err_t err = wifi_start();
    if (!net_running()) goto task_exit;
    if (err == ESP_OK) {
        /* WiFi connected, start VPN */
        err = vpn_start();
        if (err == ESP_OK) {
            s_ctx.state = ML_NET_SW_WIFI_VPN_UP;
            if (s_ctx.on_connected) {
                s_ctx.on_connected(ML_NET_WIFI, s_ctx.user_data);
            }
            /* Start health check timer */
            xTimerStart(s_ctx.health_timer, 0);
            goto state_loop;
        }
    }

    if (s_ctx.ml) goto cleanup_failed;
    if (!net_running()) goto task_exit;

    /* WiFi failed — try cellular */
    ESP_LOGW(TAG, "WiFi path failed, falling back to cellular");
    wifi_stop();
    goto try_cellular;

try_cellular:
    if (!net_running()) goto task_exit;
    s_ctx.state = ML_NET_SW_CELL_CONNECTING;
    s_ctx.active_transport = ML_NET_CELLULAR;

    if (s_ctx.on_switching) {
        s_ctx.on_switching(ML_NET_WIFI, ML_NET_CELLULAR, s_ctx.user_data);
    }

    err = cellular_start();
    if (!net_running()) goto task_exit;
    if (err == ESP_OK) {
        err = vpn_start();
        if (err == ESP_OK) {
            s_ctx.state = ML_NET_SW_CELL_VPN_UP;
            if (s_ctx.on_connected) {
                s_ctx.on_connected(ML_NET_CELLULAR, s_ctx.user_data);
            }
            /* Start health check + failback timers */
            xTimerStart(s_ctx.health_timer, 0);
            if (s_ctx.failback_check_ms > 0 && s_ctx.failback_timer) {
                xTimerStart(s_ctx.failback_timer, 0);
            }
            goto state_loop;
        }
    }

    if (s_ctx.ml) goto cleanup_failed;
    if (!net_running()) goto task_exit;

    /* Both failed */
    ESP_LOGE(TAG, "Both WiFi and cellular failed!");
    s_ctx.state = ML_NET_SW_ERROR;
    if (s_ctx.on_disconnected) {
        s_ctx.on_disconnected(s_ctx.user_data);
    }

    /* Retry after 30s */
    xEventGroupWaitBits(s_ctx.wifi_events, STOP_REQUEST_BIT, pdFALSE, pdFALSE, pdMS_TO_TICKS(30000));
    if (net_running()) {
        cellular_stop();
        s_ctx.state = ML_NET_SW_WIFI_CONNECTING;
        s_ctx.active_transport = ML_NET_WIFI;
        /* Fall through to state_loop which will handle reconnection */
    }

state_loop:
    while (net_running()) {
        EventBits_t pending = xEventGroupWaitBits(s_ctx.wifi_events,
            HEALTH_CHECK_BIT | FAILBACK_CHECK_BIT | STOP_REQUEST_BIT,
            pdTRUE, pdFALSE, pdMS_TO_TICKS(5000));
        if (!net_running()) break;
        if (pending & HEALTH_CHECK_BIT) check_health();
        if ((pending & FAILBACK_CHECK_BIT) && s_ctx.active_transport == ML_NET_CELLULAR)
            s_ctx.state = ML_NET_SW_SWITCHING_TO_WIFI;

        switch (s_ctx.state) {
            case ML_NET_SW_SWITCHING_TO_CELL: {
                ESP_LOGI(TAG, "Switching WiFi → Cellular");
                xTimerStop(s_ctx.health_timer, 0);

                if (s_ctx.on_disconnected) {
                    s_ctx.on_disconnected(s_ctx.user_data);
                }

                /* Tear down WiFi VPN */
                if (vpn_stop() != ESP_OK) goto cleanup_failed;
                wifi_stop();

                goto try_cellular;
            }

            case ML_NET_SW_SWITCHING_TO_WIFI: {
                ESP_LOGI(TAG, "Attempting failback: Cellular → WiFi");
                xTimerStop(s_ctx.health_timer, 0);
                if (s_ctx.failback_timer) {
                    xTimerStop(s_ctx.failback_timer, 0);
                }

                /* Try WiFi without tearing down cellular yet */
                s_ctx.state = ML_NET_SW_WIFI_CONNECTING;

                /* Temporarily try WiFi — if it fails, stay on cellular */
                esp_err_t wifi_err = wifi_start();
                if (!net_running()) goto task_exit;
                if (wifi_err == ESP_OK) {
                    /* WiFi is back! Tear down cellular and switch */
                    ESP_LOGI(TAG, "WiFi recovered! Switching back from cellular");

                    if (s_ctx.on_switching) {
                        s_ctx.on_switching(ML_NET_CELLULAR, ML_NET_WIFI, s_ctx.user_data);
                    }

                    if (vpn_stop() != ESP_OK) goto cleanup_failed;
                    cellular_stop();

                    s_ctx.active_transport = ML_NET_WIFI;
                    esp_err_t vpn_err = vpn_start();
                    if (vpn_err == ESP_OK) {
                        s_ctx.state = ML_NET_SW_WIFI_VPN_UP;
                        if (s_ctx.on_connected) {
                            s_ctx.on_connected(ML_NET_WIFI, s_ctx.user_data);
                        }
                        xTimerStart(s_ctx.health_timer, 0);
                    } else {
                        if (s_ctx.ml) goto cleanup_failed;
                        if (!net_running()) goto task_exit;
                        /* WiFi VPN failed, go back to cellular */
                        ESP_LOGW(TAG, "WiFi VPN failed, reverting to cellular");
                        wifi_stop();
                        goto try_cellular;
                    }
                } else {
                    /* WiFi still down, stay on cellular */
                    ESP_LOGI(TAG, "WiFi still unavailable, staying on cellular");
                    wifi_stop();
                    s_ctx.state = ML_NET_SW_CELL_VPN_UP;
                    xTimerStart(s_ctx.health_timer, 0);
                    if (s_ctx.failback_check_ms > 0 && s_ctx.failback_timer) {
                        xTimerStart(s_ctx.failback_timer, 0);
                    }
                }
                break;
            }

            default:
                break;
        }
    }

    goto task_exit;

cleanup_failed:
    s_ctx.state = ML_NET_SW_ERROR;
    set_running(false);
task_exit:
    ESP_LOGI(TAG, "Network switch task exiting");
    xEventGroupSetBits(s_ctx.wifi_events, TASK_EXITED_BIT);
    vTaskDelete(NULL);
}

/* ============================================================================
 * Public API
 * ========================================================================== */

esp_err_t ml_net_switch_init(const ml_net_switch_config_t *config)
{
    if (s_ctx.initialized) return ESP_ERR_INVALID_STATE;
    if (!config || !config->tailscale_auth_key) return ESP_ERR_INVALID_ARG;

    memset(&s_ctx, 0, sizeof(s_ctx));

    /* Copy strings */
    if (config->wifi_ssid) strncpy(s_ctx.wifi_ssid, config->wifi_ssid, sizeof(s_ctx.wifi_ssid) - 1);
    if (config->wifi_password) strncpy(s_ctx.wifi_password, config->wifi_password, sizeof(s_ctx.wifi_password) - 1);
    if (config->sim_pin) strncpy(s_ctx.sim_pin, config->sim_pin, sizeof(s_ctx.sim_pin) - 1);
    if (config->apn) strncpy(s_ctx.apn, config->apn, sizeof(s_ctx.apn) - 1);
    strncpy(s_ctx.tailscale_auth_key, config->tailscale_auth_key, sizeof(s_ctx.tailscale_auth_key) - 1);
    if (config->device_name) strncpy(s_ctx.device_name, config->device_name, sizeof(s_ctx.device_name) - 1);

    /* Timing defaults */
    s_ctx.wifi_timeout_ms = config->wifi_timeout_ms ? config->wifi_timeout_ms : 30000;
    s_ctx.health_check_interval_ms = config->health_check_interval_ms ? config->health_check_interval_ms : 30000;
    s_ctx.health_fail_count = config->health_fail_count ? config->health_fail_count : 3;
    s_ctx.failback_check_ms = config->failback_check_ms ? config->failback_check_ms : 120000;

    /* Callbacks */
    s_ctx.on_connected = config->on_connected;
    s_ctx.on_disconnected = config->on_disconnected;
    s_ctx.on_switching = config->on_switching;
    s_ctx.user_data = config->user_data;

    /* Create event group for WiFi */
    s_ctx.wifi_events = xEventGroupCreate();
    if (!s_ctx.wifi_events) return ESP_ERR_NO_MEM;

    /* Create health check timer */
    s_ctx.health_timer = xTimerCreate("net_health",
                                       pdMS_TO_TICKS(s_ctx.health_check_interval_ms),
                                       pdTRUE, NULL, health_timer_cb);
    if (!s_ctx.health_timer) return ESP_ERR_NO_MEM;

    /* Create failback timer */
    if (s_ctx.failback_check_ms > 0) {
        s_ctx.failback_timer = xTimerCreate("net_failback",
                                             pdMS_TO_TICKS(s_ctx.failback_check_ms),
                                             pdTRUE, NULL, failback_timer_cb);
    }

    s_ctx.state = ML_NET_SW_IDLE;
    s_ctx.initialized = true;

    ESP_LOGI(TAG, "Net switch initialized (wifi_timeout=%lums, health=%lums, failback=%lums)",
             (unsigned long)s_ctx.wifi_timeout_ms,
             (unsigned long)s_ctx.health_check_interval_ms,
             (unsigned long)s_ctx.failback_check_ms);

    return ESP_OK;
}

static void timers_drained(void *arg, uint32_t unused)
{
    xEventGroupSetBits((EventGroupHandle_t)arg, TIMERS_DRAINED_BIT);
}

void ml_net_switch_deinit(void)
{
    if (!s_ctx.initialized) return;

    if (ml_net_switch_stop() != ESP_OK) {
        ESP_LOGE(TAG, "Deinit deferred until shutdown completes");
        return;
    }
    s_ctx.deinitializing = true;

    if (s_ctx.health_timer) {
        if (xTimerDelete(s_ctx.health_timer, portMAX_DELAY) != pdPASS) return;
        s_ctx.health_timer = NULL;
    }
    if (s_ctx.failback_timer) {
        if (xTimerDelete(s_ctx.failback_timer, portMAX_DELAY) != pdPASS) return;
        s_ctx.failback_timer = NULL;
    }
    /* Timer deletion is queued; wait behind both commands before freeing events. */
    if (!s_ctx.timer_drain_queued) {
        xEventGroupClearBits(s_ctx.wifi_events, TIMERS_DRAINED_BIT);
        if (xTimerPendFunctionCall(timers_drained, s_ctx.wifi_events, 0, portMAX_DELAY) != pdPASS) return;
        s_ctx.timer_drain_queued = true;
    }
    if (!(xEventGroupWaitBits(s_ctx.wifi_events, TIMERS_DRAINED_BIT,
                              pdFALSE, pdTRUE, pdMS_TO_TICKS(15000)) & TIMERS_DRAINED_BIT)) return;
    if (s_ctx.wifi_handler) {
        if (esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, s_ctx.wifi_handler) != ESP_OK) return;
        s_ctx.wifi_handler = NULL;
    }
    if (s_ctx.ip_handler) {
        if (esp_event_handler_instance_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, s_ctx.ip_handler) != ESP_OK) return;
        s_ctx.ip_handler = NULL;
    }
    if (s_ctx.wifi_netif) {
        if (esp_wifi_deinit() != ESP_OK) return;
        esp_netif_destroy_default_wifi(s_ctx.wifi_netif);
        s_ctx.wifi_netif = NULL;
    }
    if (s_ctx.wifi_events) {
        vEventGroupDelete(s_ctx.wifi_events);
    }

    memset(&s_ctx, 0, sizeof(s_ctx));
}

esp_err_t ml_net_switch_start(void)
{
    if (!s_ctx.initialized || s_ctx.deinitializing) return ESP_ERR_INVALID_STATE;
    if (net_running() || s_ctx.task_handle || s_ctx.ml) return ESP_ERR_INVALID_STATE;

    xEventGroupClearBits(s_ctx.wifi_events, TASK_EXITED_BIT | STOP_REQUEST_BIT | HEALTH_CHECK_BIT | FAILBACK_CHECK_BIT);
    set_running(true);

    BaseType_t ret = xTaskCreate(net_switch_task, "net_sw",
                                  NET_SW_STACK_SIZE, NULL, 5, &s_ctx.task_handle);
    if (ret != pdPASS) {
        set_running(false);
        return ESP_ERR_NO_MEM;
    }

    return ESP_OK;
}

esp_err_t ml_net_switch_stop(void)
{
    if (!s_ctx.initialized) return ESP_OK;
    if (s_ctx.task_handle && xTaskGetCurrentTaskHandle() == s_ctx.task_handle)
        return ESP_ERR_INVALID_STATE;
    set_running(false);
    if (s_ctx.health_timer) xTimerStop(s_ctx.health_timer, portMAX_DELAY);
    if (s_ctx.failback_timer) xTimerStop(s_ctx.failback_timer, portMAX_DELAY);
    xEventGroupSetBits(s_ctx.wifi_events, STOP_REQUEST_BIT);

    if (s_ctx.task_handle) {
        EventBits_t bits = xEventGroupWaitBits(s_ctx.wifi_events, TASK_EXITED_BIT,
                                              pdFALSE, pdTRUE, pdMS_TO_TICKS(15000));
        if (!(bits & TASK_EXITED_BIT)) return ESP_ERR_TIMEOUT;
        s_ctx.task_handle = NULL;
    }
    esp_err_t err = vpn_stop();
    if (err != ESP_OK) return err;
    wifi_stop();
    cellular_stop();
    s_ctx.state = ML_NET_SW_IDLE;
    return ESP_OK;
}

ml_net_type_t ml_net_switch_get_active(void)
{
    return s_ctx.active_transport;
}

ml_net_switch_state_t ml_net_switch_get_state(void)
{
    return s_ctx.state;
}

microlink_t *ml_net_switch_get_handle(void)
{
    return s_ctx.ml;
}

const char *ml_net_switch_state_str(ml_net_switch_state_t state)
{
    switch (state) {
        case ML_NET_SW_IDLE:              return "IDLE";
        case ML_NET_SW_WIFI_CONNECTING:   return "WIFI_CONNECTING";
        case ML_NET_SW_WIFI_VPN_UP:       return "WIFI_VPN_UP";
        case ML_NET_SW_SWITCHING_TO_CELL: return "SWITCHING_TO_CELL";
        case ML_NET_SW_CELL_CONNECTING:   return "CELL_CONNECTING";
        case ML_NET_SW_CELL_VPN_UP:       return "CELL_VPN_UP";
        case ML_NET_SW_SWITCHING_TO_WIFI: return "SWITCHING_TO_WIFI";
        case ML_NET_SW_ERROR:             return "ERROR";
        default:                          return "UNKNOWN";
    }
}

#endif /* CONFIG_ML_ENABLE_NET_SWITCH */
