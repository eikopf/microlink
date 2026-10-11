#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "../components/wireguard_lwip/src/wireguard-platform-esp32.c"

static uint64_t stored, legacy, pending;
static bool present, legacy_present, durable_error;
static unsigned commits, handles;
static int failure;
static time_t wallclock = 1800000000;

time_t time(time_t *output) { if (output) *output = wallclock; return wallclock; }
uint32_t sys_now(void) { return 0; }
void esp_fill_random(void *bytes, size_t size) { memset(bytes, 0, size); }
esp_err_t nvs_open(const char *name, int mode, nvs_handle_t *h) {
    assert(!strcmp(name, "microlink") && mode == NVS_READWRITE);
    if (failure == 1) return ESP_FAIL;
    assert(!handles); *h = ++handles; return ESP_OK;
}
void nvs_close(nvs_handle_t h) { assert(h && handles == 1); --handles; }
esp_err_t nvs_get_blob(nvs_handle_t h, const char *name, void *out, size_t *size) {
    assert(h && *size == 8);
    if (failure == 2) return ESP_FAIL;
    if (!strcmp(name, "wg_tai_epoch")) {
        if (!present) return ESP_ERR_NVS_NOT_FOUND;
        memcpy(out, &stored, 8);
    } else {
        assert(!strcmp(name, "wg_tai_base"));
        if (!legacy_present) return ESP_ERR_NVS_NOT_FOUND;
        memcpy(out, &legacy, 8);
    }
    *size = failure == 5 ? 7 : 8;
    return ESP_OK;
}
esp_err_t nvs_set_blob(nvs_handle_t h, const char *name, const void *in, size_t size) {
    assert(h && size == 8 && !strcmp(name, "wg_tai_epoch"));
    if (failure == 3) return ESP_FAIL;
    memcpy(&pending, in, 8); return ESP_OK;
}
esp_err_t nvs_commit(nvs_handle_t h) {
    assert(h); ++commits;
    if (failure != 4 || durable_error) { stored = pending; present = true; }
    return failure == 4 ? ESP_FAIL : ESP_OK;
}
static void reboot(void) { memset(&timestamp_state, 0, sizeof(timestamp_state)); }
static void next(uint8_t *out) { assert(wireguard_tai64n_now(out)); }
static uint8_t concurrent[8][1000][12];
static void *generate(void *arg) {
    size_t thread = (size_t)arg;
    for (unsigned i = 0; i < 1000; ++i) next(concurrent[thread][i]);
    return NULL;
}
static int compare(const void *a, const void *b) { return memcmp(a, b, 12); }
int main(void) {
    uint8_t previous[12], current[12], sentinel[12];
    memset(sentinel, 0xab, 12); memcpy(current, sentinel, 12);
    assert(!wireguard_tai64n_now(current) && !memcmp(current, sentinel, 12));
    for (failure = 1; failure <= 4; ++failure) {
        assert(!wireguard_tai64n_init() && !handles);
        assert(!wireguard_tai64n_now(current) && !memcmp(current, sentinel, 12));
    }
    failure = 0;
    assert(wireguard_tai64n_init()); next(previous);
    unsigned initial_commits = commits;
    wallclock -= 3600;
    assert(wireguard_tai64n_init()); next(current);
    assert(memcmp(current, previous, 12) > 0 && commits == initial_commits);
    memcpy(previous, current, 12);
    reboot(); wallclock = 0;
    assert(wireguard_tai64n_init()); next(current);
    assert(memcmp(current, previous, 12) > 0);
    memcpy(previous, current, 12);
    reboot(); failure = 4; durable_error = true;
    assert(!wireguard_tai64n_init());
    uint64_t ambiguous_epoch = stored;
    failure = 0;
    assert(wireguard_tai64n_init() && stored > ambiguous_epoch); next(current);
    assert(memcmp(current, previous, 12) > 0);
    for (unsigned i = 0; i < 50; ++i) {
        memcpy(previous, current, 12); reboot();
        assert(wireguard_tai64n_init()); next(current);
        assert(memcmp(current, previous, 12) > 0);
    }
    timestamp_state.sequence = WG_TIMESTAMP_SEQUENCE_LIMIT - 1;
    next(previous);
    failure = 4;
    memcpy(current, sentinel, 12);
    assert(!wireguard_tai64n_now(current) && !memcmp(current, sentinel, 12));
    failure = 0; next(current);
    assert(memcmp(current, previous, 12) > 0);
    initial_commits = commits;
    pthread_t threads[8];
    for (size_t i = 0; i < 8; ++i) assert(!pthread_create(&threads[i], NULL, generate, (void *)i));
    for (unsigned i = 0; i < 8; ++i) assert(!pthread_join(threads[i], NULL));
    qsort(concurrent, 8000, 12, compare);
    const uint8_t *flat = (const uint8_t *)concurrent;
    for (unsigned i = 1; i < 8000; ++i) assert(memcmp(flat + 12 * i, flat + 12 * (i - 1), 12) > 0);
    assert(commits == initial_commits);
    reboot(); failure = 5;
    assert(!wireguard_tai64n_init() && !handles);
    failure = 0; stored = UINT64_MAX;
    assert(!wireguard_tai64n_init() && !handles);
    present = false; legacy_present = true; legacy = 1900000000;
    assert(wireguard_tai64n_init() && stored > legacy);
    /* Legacy firmware could emit base + uptime without persisting that value.
     * Migration cannot recover that missing history from the stored base. */
    uint64_t legacy_emitted = legacy + 3600;
    assert(timestamp_state.epoch < legacy_emitted);
    reboot(); wallclock = (time_t)(legacy_emitted + 1);
    assert(wireguard_tai64n_init() && timestamp_state.epoch > legacy_emitted);
    timestamp_state.epoch = WG_TIMESTAMP_MAX_EPOCH;
    timestamp_state.sequence = WG_TIMESTAMP_SEQUENCE_LIMIT;
    memcpy(current, sentinel, 12);
    assert(!wireguard_tai64n_now(current) && !memcmp(current, sentinel, 12));
    puts("PASS: restart, clock rollback, concurrent timestamps, persistence failures, corrupt state, rollover, exhaustion, legacy migration boundary");
}
