#include "../components/microlink/src/ml_net_switch.c"

int main(void) {
    ml_net_switch_config_t config = {.tailscale_auth_key = "test"};
    assert(ml_net_switch_init(&config) == ESP_OK);
    s_ctx.ml = &fake_ml;
    s_ctx.task_handle = (void *)1;
    set_running(true);
    assert(ml_net_switch_stop() == ESP_ERR_TIMEOUT);
    assert(s_ctx.ml == &fake_ml && s_ctx.task_handle && !destroyed && !wifi_stops && !cell_stops);
    assert(ml_net_switch_start() == ESP_ERR_INVALID_STATE);
    ml_net_switch_deinit();
    assert(s_ctx.initialized && !event_deletes);

    xEventGroupSetBits(s_ctx.wifi_events, TASK_EXITED_BIT);
    stop_result = ESP_ERR_TIMEOUT;
    assert(ml_net_switch_stop() == ESP_ERR_TIMEOUT);
    assert(s_ctx.ml == &fake_ml && !s_ctx.task_handle && !destroyed && !wifi_stops && !cell_stops);
    set_running(true); /* A failover attempt must not replace the retained owner. */
    assert(vpn_start() == ESP_ERR_INVALID_STATE && !started);
    set_running(false);
    health_timer_cb(NULL);
    failback_timer_cb(NULL);
    assert(!health_reads); /* Timer callbacks cannot touch the retained owner. */
    assert(s_ctx.wifi_events->bits & HEALTH_CHECK_BIT);
    assert(s_ctx.wifi_events->bits & FAILBACK_CHECK_BIT);

    stop_result = ESP_OK;
    assert(ml_net_switch_stop() == ESP_OK);
    assert(!s_ctx.ml && destroyed == 1 && wifi_stops == 1 && cell_stops == 1);
    ml_net_switch_deinit(); /* Timer daemon has not executed the drain callback. */
    assert(s_ctx.initialized && drain_queued == 1 && !event_deletes);
    assert(ml_net_switch_start() == ESP_ERR_INVALID_STATE);
    ml_net_switch_deinit();
    assert(s_ctx.initialized && drain_queued == 1 && !event_deletes);
    PendedFunction_t cb = drain_callback;
    drain_callback = NULL;
    cb(drain_arg, 0);
    ml_net_switch_deinit();
    assert(!s_ctx.initialized && event_deletes == 1 && drain_queued == 1);
    puts("network-switch shutdown and delayed-drain tests passed");
    return 0;
}
