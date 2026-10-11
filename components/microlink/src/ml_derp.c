/**
 * @file ml_derp.c
 * @brief DERP reader, writer, and connection management.
 *
 * The reader receives frames. The writer owns connection setup, teardown,
 * and every TLS write, including control replies queued by the reader.
 * Teardown waits for the reader to stop accessing the connection.
 *
 * Backpressure strategy (from tailscaled):
 * When queue is full, dequeue oldest packet and retry up to 3 times.
 * If still full, drop the new packet.
 *
 * Reference: tailscale/wgengine/magicsock/derp.go (runDerpWriter)
 *            tailscale/derp/derphttp/derphttp_client.go
 */

#include "microlink_internal.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "esp_crt_bundle.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "nacl_box.h"
#include <string.h>
#include <errno.h>
#include <fcntl.h>

static const char *TAG = "ml_derp";

/* Timeout for DERP connection handshake operations */
#define DERP_CONNECT_TIMEOUT_MS  10000

/* ============================================================================
 * Custom BIO callbacks for non-blocking TLS I/O
 *
 * These wrap lwIP recv/send with guaranteed timeout behavior.
 * We don't trust mbedtls_net_recv_timeout on lwIP because lwIP's select()
 * can sometimes block indefinitely on ESP32.
 * ========================================================================== */

/**
 * Custom recv with timeout for mbedtls BIO.
 * Uses SO_RCVTIMEO on the socket as the timeout mechanism (simpler than select).
 * Returns bytes read, WANT_READ for an idle socket, or a fatal socket error.
 */
static int ml_derp_bio_recv_timeout(void *ctx, unsigned char *buf, size_t len,
                                      uint32_t timeout) {
    int fd = *(int *)ctx;
    if (fd < 0) return MBEDTLS_ERR_NET_INVALID_CONTEXT;

    /* Set SO_RCVTIMEO to the requested timeout.
     * If timeout is 0 (mbedTLS default = "no timeout"), use 10s as a sane
     * default to avoid indefinite blocking on AT sockets. */
    uint32_t effective_timeout = (timeout > 0) ? timeout : DERP_CONNECT_TIMEOUT_MS;
    struct timeval tv;
    tv.tv_sec = effective_timeout / 1000;
    tv.tv_usec = (effective_timeout % 1000) * 1000;
    ml_setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    int ret = (int)ml_read_sock(fd, buf, len);
    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return MBEDTLS_ERR_SSL_WANT_READ;
        }
        if (errno == EPIPE || errno == ECONNRESET) {
            return MBEDTLS_ERR_NET_CONN_RESET;
        }
        if (errno == EINTR) {
            return MBEDTLS_ERR_SSL_WANT_READ;
        }
        return MBEDTLS_ERR_NET_RECV_FAILED;
    }
    return ret;
}

/**
 * Custom send for mbedtls BIO.
 */
static int ml_derp_bio_send(void *ctx, const unsigned char *buf, size_t len) {
    int fd = *(int *)ctx;
    if (fd < 0) return MBEDTLS_ERR_NET_INVALID_CONTEXT;

    int ret = (int)ml_write_sock(fd, buf, len);
    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        }
        if (errno == EPIPE || errno == ECONNRESET) {
            return MBEDTLS_ERR_NET_CONN_RESET;
        }
        if (errno == EINTR) {
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        }
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }
    return ret;
}

/* DERP frame types */
#define DERP_FRAME_SERVER_KEY   0x01
#define DERP_FRAME_CLIENT_INFO  0x02
#define DERP_FRAME_SERVER_INFO  0x03
#define DERP_FRAME_SEND_PACKET  0x04
#define DERP_FRAME_RECV_PACKET  0x05
#define DERP_FRAME_KEEP_ALIVE   0x06
#define DERP_FRAME_NOTE_PREFERRED 0x07
#define DERP_FRAME_PEER_GONE    0x08
#define DERP_FRAME_PING         0x12
#define DERP_FRAME_PONG         0x13

/* DISCO magic bytes: "TS" + sparkles emoji UTF-8 */
static const uint8_t DISCO_MAGIC[6] = { 'T', 'S', 0xf0, 0x9f, 0x92, 0xac };

/* ============================================================================
 * TLS Read/Write Helpers
 * ========================================================================== */

static bool derp_tls_retryable(int result) {
    return result == MBEDTLS_ERR_SSL_WANT_READ || result == MBEDTLS_ERR_SSL_WANT_WRITE;
}

static int derp_ssl_read(ml_derp_conn_t *conn, uint8_t *data, size_t len) {
    xSemaphoreTake(conn->io_mutex, portMAX_DELAY);
    int result = conn->tls_failed ? MBEDTLS_ERR_NET_CONN_RESET :
                 mbedtls_ssl_read(&conn->ssl, data, len);
    if (result <= 0 && !derp_tls_retryable(result)) conn->tls_failed = true;
    xSemaphoreGive(conn->io_mutex);
    return result;
}

static int derp_ssl_write(ml_derp_conn_t *conn, const uint8_t *data, size_t len) {
    xSemaphoreTake(conn->io_mutex, portMAX_DELAY);
    int result = conn->tls_failed ? MBEDTLS_ERR_NET_CONN_RESET :
                 mbedtls_ssl_write(&conn->ssl, data, len);
    if (result == 0) result = MBEDTLS_ERR_NET_CONN_RESET;
    if (result < 0 && !derp_tls_retryable(result)) conn->tls_failed = true;
    xSemaphoreGive(conn->io_mutex);
    return result;
}

/**
 * Read exactly `len` bytes via TLS with timeout and WANT_READ retry.
 * Returns number of bytes read on success, -1 on error, -2 on timeout.
 */
static int derp_tls_read_all(ml_derp_conn_t *conn, uint8_t *data, size_t len, int timeout_ms) {
    size_t received = 0;
    uint64_t start_ms = ml_get_time_ms();

    while (received < len) {
        if (timeout_ms > 0 && (ml_get_time_ms() - start_ms) > (uint64_t)timeout_ms) {
            ESP_LOGW(TAG, "derp_tls_read_all timeout (%d/%d bytes in %dms)",
                     (int)received, (int)len, timeout_ms);
            return -2;
        }

        int ret = derp_ssl_read(conn, data + received, len - received);
        if (ret < 0) {
            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                vTaskDelay(pdMS_TO_TICKS(10));
                continue;
            }
            if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
                ESP_LOGW(TAG, "DERP server closed connection");
                return -1;
            }
            ESP_LOGE(TAG, "TLS read failed: -0x%04x", -ret);
            return -1;
        }
        if (ret == 0) {
            ESP_LOGW(TAG, "TLS connection closed by peer (%d/%d bytes)",
                     (int)received, (int)len);
            return -1;
        }
        received += ret;
    }
    return (int)received;
}

/* Discard setup extensions within a fixed size and time budget. */
static int derp_discard_setup_payload(ml_derp_conn_t *conn, uint32_t len) {
    if (len > 65536) return -1;
    uint8_t scratch[128];
    uint64_t deadline = ml_get_time_ms() + DERP_CONNECT_TIMEOUT_MS;
    while (len > 0) {
        uint64_t now = ml_get_time_ms();
        if (now >= deadline) return -1;
        size_t chunk = len > sizeof(scratch) ? sizeof(scratch) : len;
        if (derp_tls_read_all(conn, scratch, chunk, (int)(deadline - now)) < 0) return -1;
        len -= chunk;
    }
    return 0;
}

/**
 * Read a DERP frame header (5 bytes: type + 4-byte BE length) with timeout.
 */
static esp_err_t derp_recv_frame_header(ml_derp_conn_t *conn, uint8_t *type,
                                          uint32_t *len, int timeout_ms) {
    uint8_t header[5];
    int ret = derp_tls_read_all(conn, header, 5, timeout_ms);
    if (ret < 0) {
        return (ret == -2) ? ESP_ERR_TIMEOUT : ESP_FAIL;
    }

    *type = header[0];
    *len = ((uint32_t)header[1] << 24) |
           ((uint32_t)header[2] << 16) |
           ((uint32_t)header[3] << 8) |
           (uint32_t)header[4];

    return ESP_OK;
}

/**
 * Write exactly `len` bytes via TLS with WANT_WRITE retry.
 * Returns bytes written on success, -1 on error.
 * Only the writer task submits frames; the connection lock excludes TLS reads.
 */
static int derp_tls_write_all(ml_derp_conn_t *conn, const uint8_t *data, size_t len) {
    size_t written = 0;
    int retries = 0;
    /* 300 * 10ms = 3s max (was 1s). A full TLS send buffer under a burst is
     * BACKPRESSURE, not a dead link — the canonical Tailscale DERP client never
     * tears down on a slow write (Go blocks). Here the timeout forces a full
     * reconnect (a half-written frame desyncs the TLS stream and can't be
     * continued), which drops ALL relayed traffic for ~1.5s + reconnect — far
     * worse than just waiting for the buffer to drain. A genuinely dead link
     * still returns a REAL mbedtls error (not WANT_WRITE) and tears down at
     * once via the ESP_LOGE path below; only buffer-full congestion rides the
     * 3s budget. Each retry vTaskDelay(10ms)s, so the IDLE/TWDT never starve.
     * Cost: up to 3s of delayed RX servicing under sustained congestion, which
     * only delays (never drops) incoming frames — TCP buffers them. */
    const int max_retries = 300;

    while (written < len) {
        int ret = derp_ssl_write(conn, data + written, len - written);
        if (ret < 0) {
            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                vTaskDelay(pdMS_TO_TICKS(10));
                if (++retries > max_retries) {
                    ESP_LOGW(TAG, "TLS write timeout after %d retries", retries);
                    return -1;
                }
                continue;
            }
            ESP_LOGE(TAG, "TLS write failed: -0x%04x", -ret);
            return -1;
        }
        written += ret;
        retries = 0;
    }
    return (int)written;
}

/* Write a complete DERP frame via TLS.
 * Header + payload go out as ONE buffer / one write so the 5-byte header never
 * becomes its own tiny TCP segment (which, with the prior two-write split,
 * fragmented every frame and fed the Nagle stall). 2026-05-27. */
static int derp_write_frame(ml_derp_conn_t *conn, uint8_t type,
                             const uint8_t *payload, uint32_t len) {
    uint32_t total = 5 + len;
    uint8_t *buf = ml_psram_malloc(total);
    if (!buf) return -1;
    buf[0] = type;
    buf[1] = (len >> 24) & 0xFF;
    buf[2] = (len >> 16) & 0xFF;
    buf[3] = (len >> 8) & 0xFF;
    buf[4] = len & 0xFF;
    if (len > 0 && payload) memcpy(buf + 5, payload, len);
    int ret = derp_tls_write_all(conn, buf, total);
    free(buf);
    return ret < 0 ? -1 : 0;
}

/* Send a packet to a peer via DERP.
 * Builds the whole SendPacket frame [5-byte header][32-byte dest key][payload]
 * in ONE buffer and writes it once — single TLS record, single TCP segment, no
 * tiny-header fragment. (Bypasses derp_write_frame to avoid a second alloc+copy
 * on this hot path.) 2026-05-27. */
static int derp_send_packet(ml_derp_conn_t *conn, const uint8_t *dest_key,
                              const uint8_t *data, size_t len) {
    uint32_t body = 32 + (uint32_t)len;          /* dest key + payload */
    uint32_t total = 5 + body;                    /* + DERP frame header */
    uint8_t *frame = ml_psram_malloc(total);
    if (!frame) return -1;

    frame[0] = DERP_FRAME_SEND_PACKET;
    frame[1] = (body >> 24) & 0xFF;
    frame[2] = (body >> 16) & 0xFF;
    frame[3] = (body >> 8) & 0xFF;
    frame[4] = body & 0xFF;
    memcpy(frame + 5, dest_key, 32);
    memcpy(frame + 5 + 32, data, len);

    int ret = derp_tls_write_all(conn, frame, total);
    if (ret >= 0) ret = 0;
    if (ret < 0) {
        ESP_LOGW(TAG, "derp_send_packet FAILED: dest=%02x%02x%02x%02x len=%d",
                 dest_key[0], dest_key[1], dest_key[2], dest_key[3], (int)len);
    }
    free(frame);
    return ret;
}

/* ============================================================================
 * DERP Frame Reading and Dispatch (runs on the reader task)
 * ========================================================================== */

/* Packet classification */
typedef enum {
    PKT_DISCO,
    PKT_STUN,
    PKT_WIREGUARD,
    PKT_UNKNOWN,
} pkt_type_t;

static pkt_type_t classify_packet(const uint8_t *data, size_t len) {
    if (len >= 20 && (data[0] == 0x00 || data[0] == 0x01) && data[1] == 0x01) {
        return PKT_STUN;
    }
    if (len >= 62 && memcmp(data, DISCO_MAGIC, 6) == 0) {
        return PKT_DISCO;
    }
    if (len >= 4) {
        return PKT_WIREGUARD;
    }
    return PKT_UNKNOWN;
}

static void route_derp_packet(microlink_t *ml, uint8_t *data, size_t len,
                               const uint8_t *src_pubkey) {
    pkt_type_t type = classify_packet(data, len);

    ml_rx_packet_t pkt = {
        .data = data,
        .len = len,
        .via_derp = true,
    };
    memcpy(pkt.src_pubkey, src_pubkey, 32);

    QueueHandle_t target = (type == PKT_DISCO) ? ml->disco_rx_queue : ml->wg_rx_queue;
    if (xQueueSend(target, &pkt, 0) != pdTRUE) {
        /* Download-direction RX drop: frames arrive faster than the consumer
         * (wg_rx_queue depth) can decrypt/forward. Rate-limited so a flood
         * doesn't itself spam the SD recorder. */
        static uint32_t derp_rx_drops = 0;
        if ((++derp_rx_drops & 0x1F) == 1)
            ESP_LOGW(TAG, "DERP-RX queue full: dropped %lu (type=%d)",
                     (unsigned long)derp_rx_drops, (int)type);
        free(data);
    }
}

/* Dispatch a received DERP frame */
static void dispatch_derp_frame(microlink_t *ml, ml_derp_conn_t *conn, uint8_t frame_type,
                                 uint8_t *src_key, uint8_t *payload, size_t payload_len) {
    switch (frame_type) {
    case DERP_FRAME_RECV_PACKET:
        if (payload) {
            ESP_LOGD(TAG, "DERP RecvPacket: %d bytes from %02x%02x%02x%02x, hdr=%02x",
                     (int)payload_len,
                     src_key[0], src_key[1], src_key[2], src_key[3],
                     payload_len > 0 ? payload[0] : 0xFF);
            route_derp_packet(ml, payload, payload_len, src_key);
            return;  /* payload ownership transferred */
        }
        break;

    case DERP_FRAME_KEEP_ALIVE:
        ESP_LOGD(TAG, "DERP KeepAlive received");
        break;

    case DERP_FRAME_PING:
        if (payload && payload_len == 8) {
            ml_derp_tx_item_t reply = {
                .data = payload,
                .len = payload_len,
                .frame_type = DERP_FRAME_PONG,
                .region = conn->region,
                .generation = conn->generation,
            };
            if (xQueueSendToFront(ml->derp_tx_queue, &reply, 0) == pdTRUE) {
                return; /* The writer owns the payload and all TLS writes. */
            }
            ESP_LOGW(TAG, "DERP PONG queue full");
        }
        break;

    case DERP_FRAME_PONG:
        ESP_LOGD(TAG, "DERP PONG received");
        break;

    case DERP_FRAME_PEER_GONE:
        if (payload && payload_len >= 32) {
            ESP_LOGI(TAG, "DERP PeerGone: %02x%02x%02x%02x (len=%d)",
                     payload[0], payload[1], payload[2], payload[3],
                     (int)payload_len);
        }
        break;

    default:
        ESP_LOGD(TAG, "DERP frame type 0x%02x ignored (%d bytes)",
                 frame_type, (int)payload_len);
        break;
    }

    if (payload) free(payload);
}

/**
 * Try to read one DERP frame.
 * Uses mbedtls recv_timeout (100ms) so ssl_read never blocks indefinitely.
 * Returns: 1 = frame read and dispatched, 0 = timeout (no data), <0 = error
 */
static int poll_derp_read(microlink_t *ml, ml_derp_conn_t *conn) {
    if (!ml_derp_connected(conn) || conn->sockfd < 0) return -1;

    /* Read 5-byte frame header.
     * SO_RCVTIMEO=100ms ensures read() returns within 100ms if no data. */
    uint8_t header[5];
    int n = derp_ssl_read(conn, header, 5);
    if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE) {
        return 0;  /* No data available / timeout */
    }
    if (n <= 0) {
        ESP_LOGW(TAG, "DERP header read returned %d (0x%04x)", n, n < 0 ? -n : 0);
        return n;
    }
    if (n < 5) {
        ESP_LOGW(TAG, "DERP partial header: got %d of 5 bytes", n);
        return -1;
    }

    uint8_t frame_type = header[0];
    uint32_t len = (header[1] << 24) | (header[2] << 16) | (header[3] << 8) | header[4];

    uint8_t src_key[32] = {0};
    uint8_t *payload = NULL;
    size_t payload_len = 0;

    if (len == 0) {
        dispatch_derp_frame(ml, conn, frame_type, src_key, NULL, 0);
        return 1;
    }

    if (len > 65536) {
        ESP_LOGW(TAG, "DERP frame too large: %lu", (unsigned long)len);
        return -1;
    }

    /* Read frame payload - we already got the header so payload should follow.
     * Use longer timeout (2s) since we KNOW data is coming. */
    uint8_t *buf = ml_psram_malloc(len);
    if (!buf) return -1;

    size_t total_read = 0;
    uint64_t payload_start = ml_get_time_ms();
    while (total_read < len) {
        /* Safety timeout: 5 seconds for payload */
        if (ml_get_time_ms() - payload_start > 5000) {
            ESP_LOGW(TAG, "DERP payload timeout at %d/%lu bytes",
                     (int)total_read, (unsigned long)len);
            free(buf);
            return -1;
        }
        n = derp_ssl_read(conn, buf + total_read, len - total_read);
        if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE) {
            vTaskDelay(pdMS_TO_TICKS(5));
            continue;
        }
        if (n <= 0) {
            ESP_LOGW(TAG, "DERP payload read error: %d (0x%04x) at %d/%lu bytes",
                     n, n < 0 ? -n : 0, (int)total_read, (unsigned long)len);
            free(buf);
            return n;
        }
        total_read += n;
    }

    /* For RecvPacket (0x05): first 32 bytes are sender's public key */
    if (frame_type == DERP_FRAME_RECV_PACKET && len > 32) {
        memcpy(src_key, buf, 32);
        payload = malloc(len - 32);
        if (payload) {
            memcpy(payload, buf + 32, len - 32);
            payload_len = len - 32;
        }
        free(buf);
    } else {
        payload = buf;
        payload_len = len;
    }

    dispatch_derp_frame(ml, conn, frame_type, src_key, payload, payload_len);
    return 1;
}

/* ============================================================================
 * DERP TX Queue Processing
 * ========================================================================== */

void ml_derp_update_route(microlink_t *ml, int slot, const uint8_t *key, uint16_t region) {
    if (slot < 0 || slot >= ML_MAX_PEERS) return;
    xSemaphoreTake(ml->derp_map_mutex, portMAX_DELAY);
    if (key) memcpy(ml->derp_routes[slot].key, key, 32);
    else memset(ml->derp_routes[slot].key, 0, 32);
    ml->derp_routes[slot].region = key ? region : 0;
    xSemaphoreGive(ml->derp_map_mutex);
}

bool ml_derp_region_endpoint(microlink_t *ml, uint16_t region, char host[64], int *port) {
    bool found = false;
    xSemaphoreTake(ml->derp_map_mutex, portMAX_DELAY);
    for (int i = 0; i < ml->derp_region_count && !found; ++i) {
        if (ml->derp_regions[i].region_id != region) continue;
        for (int j = 0; j < ml->derp_regions[i].node_count; ++j) {
            const ml_derp_node_t *node = &ml->derp_regions[i].nodes[j];
            if (node->stun_only || !node->hostname[0]) continue;
            memcpy(host, node->hostname, 64);
            host[63] = 0;
            *port = node->derp_port ? node->derp_port : ML_DERP_PORT;
            found = true;
            break;
        }
    }
    xSemaphoreGive(ml->derp_map_mutex);
    return found;
}

/* Queue a packet for DERP TX with backpressure */
esp_err_t ml_derp_queue_send(microlink_t *ml, const uint8_t *dest_key,
                              const uint8_t *data, size_t len) {
    if (!ml || !dest_key || !data || len == 0) return ESP_ERR_INVALID_ARG;

    /* Relay buffer goes to SPIRAM (not DMA, not latency-critical): with a
     * deeper TX queue this can hold ~64 × ~1.3KB in-flight — keep it off the
     * chronically-tight internal DRAM. Freed with plain free() (heap_caps). */
    uint8_t *pkt_data = ml_psram_malloc(len);
    if (!pkt_data) return ESP_ERR_NO_MEM;
    memcpy(pkt_data, data, len);

    ml_derp_tx_item_t item = {
        .data = pkt_data,
        .len = len,
        .frame_type = DERP_FRAME_SEND_PACKET,
    };
    memcpy(item.dest_pubkey, dest_key, 32);
    xSemaphoreTake(ml->derp_map_mutex, portMAX_DELAY);
    for (int i = 0; i < ML_MAX_PEERS; ++i) {
        if (memcmp(ml->derp_routes[i].key, dest_key, 32) == 0) {
            item.region = ml->derp_routes[i].region;
            break;
        }
    }
    xSemaphoreGive(ml->derp_map_mutex);

    /* WG handshake packets (type 1=init, 2=response) get priority — front of queue.
     * This ensures handshake responses aren't delayed behind DISCO pings. */
    bool is_wg_handshake = (len >= 4 && (data[0] == 0x01 || data[0] == 0x02));

    /* Try to send to queue */
    if ((is_wg_handshake ? xQueueSendToFront(ml->derp_tx_queue, &item, 0)
                         : xQueueSend(ml->derp_tx_queue, &item, 0)) == pdTRUE) {
        return ESP_OK;
    }

    /* Queue full - backpressure: drop oldest, retry up to 3 times */
    for (int i = 0; i < 3; i++) {
        ml_derp_tx_item_t dropped;
        if (xQueueReceive(ml->derp_tx_queue, &dropped, 0) == pdTRUE) {
            free(dropped.data);  /* Drop oldest */
        }
        if (xQueueSend(ml->derp_tx_queue, &item, 0) == pdTRUE) {
            return ESP_OK;
        }
    }

    /* Still full after 3 attempts, drop new packet (upload-direction loss:
     * forwarded packets enqueued faster than the DERP task can TLS-write). */
    static uint32_t derp_tx_drops = 0;
    if ((++derp_tx_drops & 0x1F) == 1)
        ESP_LOGW(TAG, "DERP-TX queue full: dropped %lu", (unsigned long)derp_tx_drops);
    free(pkt_data);
    return ESP_ERR_TIMEOUT;
}

/* ============================================================================
 * Unified DERP I/O Task
 * ========================================================================== */

/* RX frame counter: incremented by the reader task (ml_derp_rx_task), read by
 * the writer task's heartbeat/status logs. File-scope so both tasks see it. */
static volatile uint32_t s_derp_frames_rx = 0;

static esp_err_t derp_connect_endpoint(microlink_t *ml, ml_derp_conn_t *conn,
                                       const char *derp_host, int derp_port, bool is_home);
static void derp_disconnect_conn(ml_derp_conn_t *conn);

static ml_derp_conn_t *derp_extra_for_region(microlink_t *ml, uint16_t region) {
    for (int i = 0; i < ML_DERP_EXTRA_CONNECTIONS; ++i)
        if (ml->derp_extra[i].region == region) return &ml->derp_extra[i];
    return NULL;
}

static ml_derp_conn_t *derp_destination(microlink_t *ml, uint16_t region, bool wireguard) {
    if (!region || region == ml->derp.region) return &ml->derp;
    uint64_t now = ml_get_time_ms();
    ml_derp_conn_t *conn = derp_extra_for_region(ml, region);
    if (!conn) {
        for (int i = 0; i < ML_DERP_EXTRA_CONNECTIONS; ++i) {
            ml_derp_conn_t *candidate = &ml->derp_extra[i];
            if (!candidate->region || now - candidate->last_send_ms >= 60000) {
                conn = candidate;
                break;
            }
            if (wireguard && (!conn || candidate->last_send_ms < conn->last_send_ms)) conn = candidate;
        }
    }
    if (!conn) return NULL;
    if (conn->region == region && ml_derp_connected(conn)) {
        conn->last_send_ms = now;
        return conn;
    }
    if (!wireguard) return NULL;
    if (conn->region == region && now < conn->next_retry_ms) return NULL;
    if (now < ml->derp_next_extra_dial_ms) return NULL;
    char host[64];
    int port;
    if (!ml_derp_region_endpoint(ml, region, host, &port)) return NULL;
    ml_derp_set_connected(conn, false);
    while (!ml_derp_rx_is_parked(conn)) vTaskDelay(pdMS_TO_TICKS(10));
    derp_disconnect_conn(conn);
    if (xEventGroupGetBits(ml->events) & ML_EVT_SHUTDOWN_REQUEST) return NULL;
    conn->region = region;
    conn->last_send_ms = now;
    ESP_LOGI(TAG, "Opening destination DERP region %u (home %u)", region, ml->derp.region);
    esp_err_t result = derp_connect_endpoint(ml, conn, host, port, false);
    ml->derp_next_extra_dial_ms = ml_get_time_ms() + 5000;
    if (result != ESP_OK) {
        conn->next_retry_ms = ml->derp_next_extra_dial_ms;
        return NULL;
    }
    conn->next_retry_ms = 0;
    return conn;
}

void ml_derp_tx_task(void *arg) {
    microlink_t *ml = (microlink_t *)arg;
    ESP_LOGI(TAG, "DERP I/O task started (Core %d)", xPortGetCoreID());

    uint32_t frames_tx = 0;
    uint64_t last_status_ms = 0;
    uint32_t loop_count = 0;
    uint64_t last_heartbeat_ms = 0;
    uint64_t connected_since_ms = 0;
    bool verbose_phase = false;  /* verbose logging for first 15s after connect */

    /* #33: persistent reconnect state. derp_wanted latches once a connect
     * has ever been requested — from then on a disconnected relay is a fault
     * to recover from, not an idle state to park in. */
    bool derp_wanted = false;
    uint64_t derp_next_retry_ms = 0;
    uint32_t derp_backoff_ms = ML_DERP_RETRY_MIN_MS;

    while (!(xEventGroupGetBits(ml->events) & ML_EVT_SHUTDOWN_REQUEST)) {
        loop_count++;
        uint64_t loop_start = ml_get_time_ms();

        /* Liveness stamp for external diagnostics: refreshed every loop so
         * the age stays small while the task runs and climbs without bound
         * the instant it blocks in a socket call. */
        ml->derp_last_heartbeat_ms = loop_start;

        /* Unconditional heartbeat - proves task is alive. Was ESP_LOGW so
         * it would survive any default-log-level filter while debugging
         * the DERP-stall issue; now downgraded to INFO since the /log
         * ring + /tailscale diag panel cover that need and the W-spam
         * was drowning real warnings. */
        /* TEMP 2026-05-27: WARN + 2s so the SD recorder captures the DERP frame
         * rate during the exit-node throughput hunt (loop_count vs frames_tx/rx
         * tells us if the loop spins without progress or is genuinely starved). */
        if (loop_start - last_heartbeat_ms > 2000) {
            ESP_LOGW(TAG, "HEARTBEAT: loop=%lu conn=%d rx=%lu tx=%lu stack_free=%lu",
                     (unsigned long)loop_count, ml_derp_connected(&ml->derp),
                     (unsigned long)s_derp_frames_rx, (unsigned long)frames_tx,
                     (unsigned long)uxTaskGetStackHighWaterMark(NULL));
            last_heartbeat_ms = loop_start;
        }

        /* ---- Periodic status logging (always, even when disconnected) ---- */
        {
            uint64_t now_ms = loop_start;
            if (now_ms - last_status_ms > 10000) {
                ESP_LOGW(TAG, "DERP status: connected=%d fd=%d rx=%lu tx=%lu loops=%lu",
                         ml_derp_connected(&ml->derp), ml->derp.sockfd,
                         (unsigned long)s_derp_frames_rx, (unsigned long)frames_tx,
                         (unsigned long)loop_count);
                last_status_ms = now_ms;
            }
        }

        /* ---- Handle DERP connect request from coord task ---- */
        {
            EventBits_t bits = xEventGroupGetBits(ml->events);
            if ((bits & ML_EVT_DERP_CONNECT_REQ) && !(bits & ML_EVT_DERP_RECONNECT) &&
                !ml_derp_connected(&ml->derp)) {
                xEventGroupClearBits(ml->events, ML_EVT_DERP_CONNECT_REQ);
                derp_wanted = true;
                /* Retry up to 3 times with 2s backoff */
                for (int attempt = 0; attempt < 3 && !ml_derp_connected(&ml->derp); attempt++) {
                    if (attempt > 0) {
                        ESP_LOGW(TAG, "DERP connect retry %d/3 in 2s...", attempt + 1);
                        vTaskDelay(pdMS_TO_TICKS(2000));
                    } else {
                        ESP_LOGI(TAG, "DERP connect requested, connecting from I/O task");
                    }
                    if (ml_derp_connect(ml) == ESP_OK) {
                        connected_since_ms = ml_get_time_ms();
                        verbose_phase = true;
                        break;
                    }
                    ESP_LOGW(TAG, "DERP connect attempt %d failed", attempt + 1);
                }
            }
            if (bits & ML_EVT_DERP_RECONNECT) {
                xEventGroupClearBits(ml->events, ML_EVT_DERP_RECONNECT | ML_EVT_DERP_CONNECT_REQ);
                derp_wanted = true;
                ESP_LOGW(TAG, "DERP reconnect requested (was %s)",
                         ml_derp_connected(&ml->derp) ? "connected" : "disconnected");
                /* A partial frame can keep the reader busy beyond 200 ms.
                 * Retain the context until the reader acknowledges the stop. */
                ml_derp_set_connected(&ml->derp, false);
                while (!ml_derp_rx_is_parked(&ml->derp))
                    vTaskDelay(pdMS_TO_TICKS(10));
                ml_derp_disconnect(ml);
                if (xEventGroupGetBits(ml->events) & ML_EVT_SHUTDOWN_REQUEST) break;
                verbose_phase = false;
                /* Auto-reconnect after disconnect. Backoff softened 2026-05-27
                 * (1s+3×2s ≈ 7s outage → 200ms+3×500ms) so a transient flap
                 * costs sub-second, not multi-second, of dropped relay traffic. */
                vTaskDelay(pdMS_TO_TICKS(200));
                for (int attempt = 0; attempt < 3 && !ml_derp_connected(&ml->derp); attempt++) {
                    if (attempt > 0) {
                        ESP_LOGW(TAG, "DERP reconnect retry %d/3 in 500ms...", attempt + 1);
                        vTaskDelay(pdMS_TO_TICKS(500));
                    }
                    if (ml_derp_connect(ml) == ESP_OK) {
                        connected_since_ms = ml_get_time_ms();
                        verbose_phase = true;
                        break;
                    }
                    ESP_LOGW(TAG, "DERP reconnect attempt %d failed", attempt + 1);
                }
            }
        }

        /* Disable verbose logging after 15s */
        if (verbose_phase && ml_get_time_ms() - connected_since_ms > 15000) {
            verbose_phase = false;
        }

        if (!ml_derp_connected(&ml->derp)) {
            /* #33: nothing external re-arms a failed connect while coord sits
             * in COORD_LONG_POLL — recovery must happen here. Retry forever
             * on exponential backoff (cap matches the coord reconnect
             * policy's never-give-up shape). */
            if (derp_wanted) {
                uint64_t now = ml_get_time_ms();
                if (derp_next_retry_ms == 0) {
                    derp_next_retry_ms = now + derp_backoff_ms;
                } else if (now >= derp_next_retry_ms) {
                    ESP_LOGW(TAG, "DERP down — retrying connect (backoff %lus)",
                             (unsigned long)(derp_backoff_ms / 1000));
                    if (ml_derp_connect(ml) == ESP_OK) {
                        connected_since_ms = ml_get_time_ms();
                        verbose_phase = true;
                    } else {
                        derp_backoff_ms *= 2;
                        if (derp_backoff_ms > ML_DERP_RETRY_MAX_MS) {
                            derp_backoff_ms = ML_DERP_RETRY_MAX_MS;
                        }
                        derp_next_retry_ms = ml_get_time_ms() + derp_backoff_ms;
                    }
                }
            }
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }

        /* Connected: reset the retry ladder so the next outage starts fresh. */
        derp_backoff_ms = ML_DERP_RETRY_MIN_MS;
        derp_next_retry_ms = 0;

        /* #33: RX-liveness watchdog. last_recv_ms advances on every received
         * frame (server keepalives arrive every ~15-60s), so prolonged
         * silence on a "connected" socket means the relay is gone even
         * though TCP looks alive — same self-fed-liveness class as #32. */
        if (ml->derp.last_recv_ms &&
            loop_start > ml->derp.last_recv_ms &&
            loop_start - ml->derp.last_recv_ms > ML_DERP_STALE_MS) {
            ESP_LOGW(TAG, "DERP RX silent for %lu s — relay presumed dead, reconnecting",
                     (unsigned long)((loop_start - ml->derp.last_recv_ms) / 1000));
            xEventGroupSetBits(ml->events, ML_EVT_DERP_RECONNECT);
            continue;
        }

        /* ---- Phase 1: Drain TX queue (writer's only I/O work now) ----
         * Batch raised 8->32 (2026-05-27) so a single loop can clear a burst
         * instead of dribbling 8 packets per RX-timeout window. The writer no
         * longer does RX (moved to ml_derp_rx_task), so the first receive now
         * BLOCKS up to 50ms instead of spinning: this paces the loop and still
         * wakes within 50ms to re-check events/connected. Remaining items in
         * the batch use timeout 0 to clear the burst in one pass. */
        {
            for (int tx_count = 0; tx_count < 32; tx_count++) {
                ml_derp_tx_item_t item;
                /* First item: block up to 50ms so the writer paces itself
                 * (no RX work to fill idle loops anymore) and wakes within
                 * 50ms to re-check events/connected. Rest of the batch:
                 * timeout 0 to clear a burst in one pass. */
                TickType_t wait = (tx_count == 0) ? pdMS_TO_TICKS(50) : 0;
                if (xQueueReceive(ml->derp_tx_queue, &item, wait) != pdTRUE) {
                    break;
                }
                if (!ml_derp_connected(&ml->derp)) {
                    free(item.data);
                    continue;
                }
                ml_derp_conn_t *conn = &ml->derp;
                if (item.frame_type == DERP_FRAME_SEND_PACKET) {
                    bool wireguard = item.len >= 4 && item.data[0] >= 1 && item.data[0] <= 4 &&
                                     item.data[1] == 0 && item.data[2] == 0 && item.data[3] == 0;
                    conn = derp_destination(ml, item.region, wireguard);
                } else if (item.frame_type == DERP_FRAME_PONG && item.region != ml->derp.region) {
                    conn = derp_extra_for_region(ml, item.region);
                }
                if (!conn || !ml_derp_connected(conn) ||
                    (item.frame_type == DERP_FRAME_PONG && item.generation != conn->generation)) {
                    free(item.data);
                    continue;
                }
                int ret = item.frame_type == DERP_FRAME_SEND_PACKET
                    ? derp_send_packet(conn, item.dest_pubkey, item.data, item.len)
                    : derp_write_frame(conn, item.frame_type, item.data, item.len);
                if (ret < 0) {
                    ESP_LOGW(TAG, "DERP write failed (region %u)", conn->region);
                    ml_derp_set_connected(conn, false);
                    if (conn == &ml->derp) xEventGroupSetBits(ml->events, ML_EVT_DERP_RECONNECT);
                } else {
                    frames_tx++;
                }
                free(item.data);
            }
        }
        /* Writer paces naturally by blocking up to 50ms on the queue above;
         * RX (and its hot-spin pacing) now lives in ml_derp_rx_task. */
    }

    ESP_LOGI(TAG, "DERP I/O task exiting");
    ml_task_exiting(ml);
    vTaskDelete(NULL);
}

/* ============================================================================
 * DERP RX Task (reader) — owns mbedtls_ssl_read exclusively.
 * TLS calls use the connection lock. The reader never calls connect or
 * disconnect; it parks (rx_parked=true) whenever it is
 * not touching the ssl context so the writer can tear it down safely.
 * ========================================================================== */

void ml_derp_rx_task(void *arg) {
    microlink_t *ml = (microlink_t *)arg;
    ESP_LOGI(TAG, "DERP RX task started (Core %d)", xPortGetCoreID());
    while (!(xEventGroupGetBits(ml->events) & ML_EVT_SHUTDOWN_REQUEST)) {
        bool got = false;
        for (int slot = 0; slot <= ML_DERP_EXTRA_CONNECTIONS; ++slot) {
            ml_derp_conn_t *conn = slot == 0 ? &ml->derp : &ml->derp_extra[slot - 1];
            if (!ml_derp_connected(conn)) {
                ml_derp_rx_set_parked(conn, true);
                continue;
            }
            ml_derp_rx_set_parked(conn, false);
            for (int burst = 0; burst < 8; ++burst) {
                if (!ml_derp_connected(conn)) break;
                int ret = poll_derp_read(ml, conn);
                if (ret > 0) {
                    s_derp_frames_rx++;
                    conn->last_recv_ms = ml_get_time_ms();
                    got = true;
                } else if (ret == 0) {
                    break;
                } else {
                    ESP_LOGW(TAG, "DERP read error: %d (region %u)", ret, conn->region);
                    ml_derp_set_connected(conn, false);
                    if (slot == 0) xEventGroupSetBits(ml->events, ML_EVT_DERP_RECONNECT);
                    break;
                }
            }
            ml_derp_rx_set_parked(conn, true);
        }
        if (!got) vTaskDelay(pdMS_TO_TICKS(10));
    }
    ml_derp_rx_set_parked(&ml->derp, true);
    for (int i = 0; i < ML_DERP_EXTRA_CONNECTIONS; ++i)
        ml_derp_rx_set_parked(&ml->derp_extra[i], true);
    ESP_LOGI(TAG, "DERP RX task exiting");
    ml_task_exiting(ml);
    vTaskDelete(NULL);
}

/* ============================================================================
 * DERP Connection Management (owned by the writer task)
 * ========================================================================== */

static esp_err_t derp_connect_endpoint(microlink_t *ml, ml_derp_conn_t *conn,
                                       const char *derp_host, int derp_port, bool is_home);

esp_err_t ml_derp_connect(microlink_t *ml) {
    if (xEventGroupGetBits(ml->events) & ML_EVT_SHUTDOWN_REQUEST) {
        return ESP_ERR_INVALID_STATE;
    }
    if (ml_derp_connected(&ml->derp)) return ESP_OK;
    if (ml->derp.sockfd >= 0) {
        /* Connect requests and reconnect requests can arrive together. */
        while (ml->derp_rx_task && !ml_derp_rx_is_parked(&ml->derp)) {
            vTaskDelay(pdMS_TO_TICKS(10));
        }
        ml_derp_disconnect(ml);
        if (xEventGroupGetBits(ml->events) & ML_EVT_SHUTDOWN_REQUEST) {
            return ESP_ERR_INVALID_STATE;
        }
    }
    /* Determine DERP host/port from DERPMap with node failover.
     * Always start from node 0 (the first/preferred node in the DERPMap).
     * Only rotate to a different node after a SUCCESSFUL connection drops,
     * NOT on connection failure (to avoid bouncing between nodes). */
    xSemaphoreTake(ml->derp_map_mutex, portMAX_DELAY);
    const char *derp_host = ML_DERP_HOST;
    int derp_port = ML_DERP_PORT;
    bool region_in_map = false;

    if (ml->derp_region_count > 0 && ml->derp_home_region > 0) {
        for (int i = 0; i < ml->derp_region_count; i++) {
            if (ml->derp_regions[i].region_id == ml->derp_home_region) {
                /* Always use the first non-stun-only node (preferred node).
                 * This ensures we connect to the same node as most peers. */
                for (int attempt = 0; attempt < ml->derp_regions[i].node_count; attempt++) {
                    if (!ml->derp_regions[i].nodes[attempt].stun_only &&
                        ml->derp_regions[i].nodes[attempt].hostname[0]) {
                        derp_host = ml->derp_regions[i].nodes[attempt].hostname;
                        if (ml->derp_regions[i].nodes[attempt].derp_port > 0) {
                            derp_port = ml->derp_regions[i].nodes[attempt].derp_port;
                        }
                        region_in_map = true;
                        break;
                    }
                }
                break;
            }
        }
    }

    /* Home region absent from this tailnet's DERPMap — typical on
     * self-hosted Headscale where only the embedded region (999) exists
     * while our default is a public Tailscale region. Dialing the hardcoded
     * public fallback would connect us to infrastructure none of our peers
     * use, so pick the map's first usable region instead and make it home
     * (peers on such tailnets live in that region too). */
    if (!region_in_map && ml->derp_region_count > 0) {
        for (int i = 0; i < ml->derp_region_count && !region_in_map; i++) {
            for (int j = 0; j < ml->derp_regions[i].node_count; j++) {
                if (!ml->derp_regions[i].nodes[j].stun_only &&
                    ml->derp_regions[i].nodes[j].hostname[0]) {
                    derp_host = ml->derp_regions[i].nodes[j].hostname;
                    if (ml->derp_regions[i].nodes[j].derp_port > 0) {
                        derp_port = ml->derp_regions[i].nodes[j].derp_port;
                    }
                    ESP_LOGW(TAG, "Home DERP region %u not in DERPMap — using region %u (%s)",
                             ml->derp_home_region, ml->derp_regions[i].region_id, derp_host);
                    ml->derp_home_region = ml->derp_regions[i].region_id;
                    region_in_map = true;
                    break;
                }
            }
        }
    }

    ml->derp.region = ml->derp_home_region ? ml->derp_home_region : ML_DERP_REGION;
    char host[64];
    snprintf(host, sizeof(host), "%s", derp_host);
    xSemaphoreGive(ml->derp_map_mutex);
    return derp_connect_endpoint(ml, &ml->derp, host, derp_port, true);
}

static esp_err_t derp_connect_endpoint(microlink_t *ml, ml_derp_conn_t *conn,
                                       const char *derp_host, int derp_port, bool is_home) {
    int64_t t_derp_start = esp_timer_get_time();

    ESP_LOGI(TAG, "Connecting to DERP %s:%d (region %d)",
             derp_host, derp_port, conn->region);

    /* DNS resolve — accept IPv4 or IPv6 (carrier may be IPv6-only) */
    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM };
    struct addrinfo *res = NULL;
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%d", derp_port);

    if (ml_getaddrinfo(derp_host, port_str, &hints, &res) != 0 || !res) {
        ESP_LOGE(TAG, "DNS resolve failed for %s", derp_host);
        return ESP_FAIL;
    }

    int64_t t_derp_dns = esp_timer_get_time();
    ESP_LOGI(TAG, "[TIMING] DERP DNS: %lld ms", (t_derp_dns - t_derp_start) / 1000);

    /* TCP connect — use address family from DNS result */
    int sock = ml_socket(res->ai_family, SOCK_STREAM, 0);
    if (sock < 0) {
        ml_freeaddrinfo(res);
        return ESP_FAIL;
    }

    /* Set connect timeout */
    struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };
    ml_setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    ml_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Keep the DERP socket off the exit-node tunnel (self-origin must use the
     * physical uplink, not the WG default route — see ml_bind_sock_to_upstream). */
    ml_bind_sock_to_upstream(ml, sock);

    if (ml_connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        ESP_LOGE(TAG, "TCP connect failed: %d", errno);
        ml_close_sock(sock);
        ml_freeaddrinfo(res);
        return ESP_FAIL;
    }
    ml_freeaddrinfo(res);

    int64_t t_derp_tcp = esp_timer_get_time();
    ESP_LOGI(TAG, "[TIMING] DERP TCP connect: %lld ms", (t_derp_tcp - t_derp_dns) / 1000);

    conn->io_mutex = xSemaphoreCreateMutex();
    if (!conn->io_mutex) {
        ml_close_sock(sock);
        return ESP_ERR_NO_MEM;
    }
    conn->tls_failed = false;

    /* TLS setup runs before publishing the connection to the reader. */
    mbedtls_ssl_init(&conn->ssl);
    mbedtls_ssl_config_init(&conn->ssl_conf);
    mbedtls_entropy_init(&conn->entropy);
    mbedtls_ctr_drbg_init(&conn->ctr_drbg);

    int ret = mbedtls_ctr_drbg_seed(&conn->ctr_drbg, mbedtls_entropy_func,
                                   &conn->entropy, NULL, 0);
    if (ret != 0) {
        ESP_LOGE(TAG, "TLS random generator initialization failed: -0x%x", -ret);
        goto fail_tls;
    }

    ret = mbedtls_ssl_config_defaults(&conn->ssl_conf,
                                 MBEDTLS_SSL_IS_CLIENT,
                                 MBEDTLS_SSL_TRANSPORT_STREAM,
                                 MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        ESP_LOGE(TAG, "TLS configuration failed: -0x%x", -ret);
        goto fail_tls;
    }
    if (esp_crt_bundle_attach(&conn->ssl_conf) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to attach DERP TLS trust anchors");
        goto fail_tls;
    }
    mbedtls_ssl_conf_authmode(&conn->ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_rng(&conn->ssl_conf, mbedtls_ctr_drbg_random, &conn->ctr_drbg);
    mbedtls_ssl_conf_read_timeout(&conn->ssl_conf, DERP_CONNECT_TIMEOUT_MS);

    if (mbedtls_ssl_setup(&conn->ssl, &conn->ssl_conf) != 0) {
        /* Typically alloc failure — without this check the handshake below
         * dies with SSL_BAD_INPUT_DATA and the real cause stays hidden. */
        ESP_LOGE(TAG, "mbedtls_ssl_setup failed (out of memory?)");
        goto fail_tls;
    }
    ret = mbedtls_ssl_set_hostname(&conn->ssl, derp_host);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to set DERP TLS hostname: -0x%x", -ret);
        goto fail_tls;
    }
    /* Store socket fd BEFORE setting bio.
     * Use custom BIO callbacks that route through ml_read_sock/ml_write_sock,
     * which transparently support both lwIP and AT socket backends.
     * Timeout is handled via SO_RCVTIMEO. */
    conn->sockfd = sock;
    mbedtls_ssl_set_bio(&conn->ssl, &conn->sockfd,
                         ml_derp_bio_send, NULL, ml_derp_bio_recv_timeout);

    /* TLS handshake - socket has 10s SO_RCVTIMEO from connect phase. */
    uint64_t handshake_start = ml_get_time_ms();
    while ((ret = mbedtls_ssl_handshake(&conn->ssl)) != 0) {
        if (ml_get_time_ms() - handshake_start >= DERP_CONNECT_TIMEOUT_MS) {
            ESP_LOGE(TAG, "DERP TLS handshake timeout");
            goto fail_tls;
        }
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }
        char err_buf[128];
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        ESP_LOGE(TAG, "TLS handshake failed: %s (verify_flags=0x%08lx)",
                 err_buf, (unsigned long)mbedtls_ssl_get_verify_result(&conn->ssl));
        goto fail_tls;
    }

    int64_t t_derp_tls = esp_timer_get_time();
    ESP_LOGI(TAG, "[TIMING] DERP TLS handshake: %lld ms", (t_derp_tls - t_derp_tcp) / 1000);
    ESP_LOGI(TAG, "TLS connected to DERP");

    /* HTTP Upgrade: GET /derp with Upgrade: DERP header */
    char upgrade_req[256];
    snprintf(upgrade_req, sizeof(upgrade_req),
             "GET /derp HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Connection: Upgrade\r\n"
             "Upgrade: DERP\r\n"
             "\r\n",
             derp_host);

    ret = mbedtls_ssl_write(&conn->ssl, (const uint8_t *)upgrade_req, strlen(upgrade_req));
    if (ret < 0) {
        ESP_LOGE(TAG, "Failed to send HTTP upgrade");
        goto fail_tls;
    }

    /* Read HTTP response byte-by-byte until \r\n\r\n to avoid over-reading
     * into the DERP binary frame stream (matching v1 approach) */
    {
        uint8_t resp_buf[512];
        int resp_len = 0;
        bool found_end = false;
        uint64_t http_start = ml_get_time_ms();

        while (resp_len < (int)sizeof(resp_buf) - 1) {
            if (ml_get_time_ms() - http_start > DERP_CONNECT_TIMEOUT_MS) {
                ESP_LOGE(TAG, "HTTP upgrade response timeout");
                goto fail_tls;
            }

            ret = mbedtls_ssl_read(&conn->ssl, resp_buf + resp_len, 1);
            if (ret < 0) {
                if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                    vTaskDelay(pdMS_TO_TICKS(10));
                    continue;
                }
                ESP_LOGE(TAG, "HTTP upgrade read failed: -0x%04x", -ret);
                goto fail_tls;
            }
            if (ret == 0) {
                ESP_LOGE(TAG, "Connection closed during HTTP upgrade");
                goto fail_tls;
            }
            resp_len++;

            /* Check for \r\n\r\n */
            if (resp_len >= 4 &&
                resp_buf[resp_len - 4] == '\r' && resp_buf[resp_len - 3] == '\n' &&
                resp_buf[resp_len - 2] == '\r' && resp_buf[resp_len - 1] == '\n') {
                found_end = true;
                break;
            }
        }

        resp_buf[resp_len] = '\0';

        if (!found_end || strstr((char *)resp_buf, "101") == NULL) {
            ESP_LOGE(TAG, "DERP upgrade rejected: %.100s", resp_buf);
            goto fail_tls;
        }
        ESP_LOGI(TAG, "HTTP 101 Switching Protocols received");
    }

    /* Match v1 exactly: O_NONBLOCK + short SO_RCVTIMEO + SO_SNDTIMEO.
     * O_NONBLOCK ensures read()/write() never block indefinitely.
     * SO_RCVTIMEO provides 100ms polling rhythm for reads.
     * SO_SNDTIMEO prevents writes from blocking too long. */
    {
        int flags = ml_fcntl(sock, F_GETFL, 0);
        if (flags >= 0) {
            ml_fcntl(sock, F_SETFL, flags | O_NONBLOCK);
        }
        struct timeval io_tv = { .tv_sec = 0, .tv_usec = 100000 };  /* 100ms */
        ml_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &io_tv, sizeof(io_tv));
        ml_setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &io_tv, sizeof(io_tv));
        /* TCP_NODELAY — CRITICAL for a relay carrying many ~1.3KB packets.
         * Without it Nagle's algorithm holds partial segments until the prior
         * segment is ACKed, and Nagle×delayed-ACK stalls each packet ~40-200ms
         * → the classic small-packet throughput collapse (~0.1 Mbit). A phone
         * on the SAME DERP+exit-node gets 25 Mbit, and the canonical Tailscale
         * DERP client sets NODELAY — so the bottleneck was purely here. 2026-05-27 */
        int nodelay = 1;
        ml_setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
    }

    /* ========================================================
     * DERP Handshake: ServerKey -> ClientInfo -> ServerInfo
     * ======================================================== */

    /* Step 1: Read ServerKey frame header using reliable read helper */
    uint8_t frame_type;
    uint32_t frame_len;
    esp_err_t err = derp_recv_frame_header(conn, &frame_type, &frame_len, DERP_CONNECT_TIMEOUT_MS);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to read ServerKey frame header (err=%d)", err);
        goto fail_tls;
    }

    if (frame_type != DERP_FRAME_SERVER_KEY || frame_len < 40 || frame_len > 65536) {
        ESP_LOGE(TAG, "Expected ServerKey frame (0x01), got 0x%02x len=%lu",
                 frame_type, (unsigned long)frame_len);
        goto fail_tls;
    }

    /* Read and verify 8-byte magic */
    uint8_t magic[8];
    static const uint8_t DERP_MAGIC[8] = {0x44, 0x45, 0x52, 0x50, 0xf0, 0x9f, 0x94, 0x91};
    if (derp_tls_read_all(conn, magic, 8, DERP_CONNECT_TIMEOUT_MS) < 0) {
        ESP_LOGE(TAG, "Failed to read ServerKey magic");
        goto fail_tls;
    }

    if (memcmp(magic, DERP_MAGIC, 8) != 0) {
        ESP_LOGE(TAG, "Invalid DERP magic: %02x%02x%02x%02x%02x%02x%02x%02x",
                 magic[0], magic[1], magic[2], magic[3],
                 magic[4], magic[5], magic[6], magic[7]);
        goto fail_tls;
    }
    ESP_LOGI(TAG, "DERP magic verified");

    /* Read 32-byte server public key */
    uint8_t derp_server_key[32];
    if (derp_tls_read_all(conn, derp_server_key, 32, DERP_CONNECT_TIMEOUT_MS) < 0) {
        ESP_LOGE(TAG, "Failed to read server key");
        goto fail_tls;
    }

    ESP_LOGI(TAG, "DERP server key received (first 8): %02x%02x%02x%02x%02x%02x%02x%02x",
             derp_server_key[0], derp_server_key[1], derp_server_key[2], derp_server_key[3],
             derp_server_key[4], derp_server_key[5], derp_server_key[6], derp_server_key[7]);

    if (derp_discard_setup_payload(conn, frame_len - 40) < 0) goto fail_tls;

    /* Step 2: Send ClientInfo frame (type 0x02)
     * Payload: [our_nodekey(32)][nonce(24)][nacl_box(JSON)] */
    {
        const char *client_info_json = "{\"Version\":2,\"CanAckPings\":true,\"IsProber\":false}";
        size_t json_len = strlen(client_info_json);

        /* Generate random nonce */
        uint8_t nonce[NACL_BOX_NONCEBYTES];
        esp_fill_random(nonce, NACL_BOX_NONCEBYTES);

        /* Encrypt JSON with NaCl box: our WG private key -> DERP server public key */
        size_t ciphertext_len = json_len + NACL_BOX_MACBYTES;
        uint8_t *ciphertext = malloc(ciphertext_len);
        if (!ciphertext) {
            goto fail_tls;
        }

        if (nacl_box(ciphertext,
                     (const uint8_t *)client_info_json, json_len,
                     nonce,
                     derp_server_key,       /* recipient: DERP server */
                     ml->wg_private_key     /* sender: our WG node key */
                     ) != 0) {
            ESP_LOGE(TAG, "NaCl box encrypt failed");
            free(ciphertext);
            goto fail_tls;
        }

        /* Build ClientInfo frame payload: nodekey(32) + nonce(24) + ciphertext */
        size_t ci_payload_len = 32 + NACL_BOX_NONCEBYTES + ciphertext_len;
        uint8_t *ci_payload = malloc(ci_payload_len);
        if (!ci_payload) {
            free(ciphertext);
            goto fail_tls;
        }

        memcpy(ci_payload, ml->wg_public_key, 32);
        memcpy(ci_payload + 32, nonce, NACL_BOX_NONCEBYTES);
        memcpy(ci_payload + 32 + NACL_BOX_NONCEBYTES, ciphertext, ciphertext_len);
        free(ciphertext);

        ESP_LOGI(TAG, "DERP ClientInfo node_key=%02x%02x%02x%02x%02x%02x%02x%02x",
                 ml->wg_public_key[0], ml->wg_public_key[1],
                 ml->wg_public_key[2], ml->wg_public_key[3],
                 ml->wg_public_key[4], ml->wg_public_key[5],
                 ml->wg_public_key[6], ml->wg_public_key[7]);

        /* Send ClientInfo frame */
        if (derp_write_frame(conn, DERP_FRAME_CLIENT_INFO, ci_payload, ci_payload_len) < 0) {
            ESP_LOGE(TAG, "Failed to send ClientInfo");
            free(ci_payload);
            goto fail_tls;
        }
        free(ci_payload);

        ESP_LOGI(TAG, "ClientInfo sent");
    }

    /* Step 3: Read ServerInfo frame (type 0x03) */
    {
        uint8_t si_type;
        uint32_t si_len;
        err = derp_recv_frame_header(conn, &si_type, &si_len, DERP_CONNECT_TIMEOUT_MS);
        if (err != ESP_OK || si_type != DERP_FRAME_SERVER_INFO || si_len == 0) {
            ESP_LOGE(TAG, "Invalid or missing ServerInfo frame");
            goto fail_tls;
        }
        if (derp_discard_setup_payload(conn, si_len) < 0) goto fail_tls;
        ESP_LOGI(TAG, "ServerInfo received (discarded)");
    }

    /* Send NotePreferred (type 0x07): this is our preferred DERP */
    {
        uint8_t preferred = is_home ? 0x01 : 0x00;
        if (derp_write_frame(conn, DERP_FRAME_NOTE_PREFERRED, &preferred, 1) < 0) {
            goto fail_tls;
        }
    }

    /* Bound each polling read so the writer can acquire the TLS mutex. */
    {
        struct timeval tv = { .tv_sec = 0, .tv_usec = 20000 };  /* 20ms */
        ml_setsockopt(conn->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        mbedtls_ssl_conf_read_timeout(&conn->ssl_conf, 20);
    }

    ++conn->generation;
    ml_derp_set_connected(conn, true);
    conn->last_recv_ms = ml_get_time_ms();
    if (is_home) xEventGroupSetBits(ml->events, ML_EVT_DERP_CONNECTED);

    int64_t t_derp_done = esp_timer_get_time();
    ESP_LOGI(TAG, "[TIMING] DERP total: %lld ms (DNS=%lld, TCP=%lld, TLS=%lld, proto=%lld)",
             (t_derp_done - t_derp_start) / 1000,
             (t_derp_dns - t_derp_start) / 1000,
             (t_derp_tcp - t_derp_dns) / 1000,
             (t_derp_tls - t_derp_tcp) / 1000,
             (t_derp_done - t_derp_tls) / 1000);
    ESP_LOGI(TAG, "DERP handshake complete, connected");
    return ESP_OK;

fail_tls:
    /* Every failure after mbedtls init lands here (#33). Closing only the
     * socket used to leak the full TLS state (~17 KB per attempt via
     * mbedtls_ssl_setup) — enough failed retries exhausted the heap and
     * every later handshake died instantly with SSL_BAD_INPUT_DATA, which
     * would have defeated the endless-retry recovery entirely. */
    mbedtls_ssl_free(&conn->ssl);
    mbedtls_ssl_config_free(&conn->ssl_conf);
    mbedtls_ctr_drbg_free(&conn->ctr_drbg);
    mbedtls_entropy_free(&conn->entropy);
    vSemaphoreDelete(conn->io_mutex);
    conn->io_mutex = NULL;
    ml_close_sock(sock);
    conn->sockfd = -1;
    return ESP_FAIL;
}

static void derp_disconnect_conn(ml_derp_conn_t *conn) {
    if (conn->sockfd >= 0) {
        if (!conn->tls_failed) mbedtls_ssl_close_notify(&conn->ssl);
        mbedtls_ssl_free(&conn->ssl);
        mbedtls_ssl_config_free(&conn->ssl_conf);
        mbedtls_ctr_drbg_free(&conn->ctr_drbg);
        mbedtls_entropy_free(&conn->entropy);
        vSemaphoreDelete(conn->io_mutex);
        conn->io_mutex = NULL;
        ml_close_sock(conn->sockfd);
        conn->sockfd = -1;
    }

}

void ml_derp_disconnect(microlink_t *ml) {
    ml_derp_set_connected(&ml->derp, false);
    xEventGroupClearBits(ml->events, ML_EVT_DERP_CONNECTED);

    derp_disconnect_conn(&ml->derp);
    for (int i = 0; i < ML_DERP_EXTRA_CONNECTIONS; ++i) {
        ml_derp_conn_t *conn = &ml->derp_extra[i];
        ml_derp_set_connected(conn, false);
        while (ml->derp_rx_task && !ml_derp_rx_is_parked(conn))
            vTaskDelay(pdMS_TO_TICKS(10));
        derp_disconnect_conn(conn);
    }

    /* Drain TX queue */
    ml_derp_tx_item_t item;
    while (xQueueReceive(ml->derp_tx_queue, &item, 0) == pdTRUE) {
        free(item.data);
    }

    ESP_LOGI(TAG, "DERP disconnected");
}
