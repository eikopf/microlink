#include "wireguard.h"
#include "crypto.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static uint32_t now;
static bool timestamp_ready;
static unsigned index_calls;
static bool scripted_indices;
static uint32_t next_index = 10;
static uint32_t timestamp_sequence;
uint32_t wireguard_sys_now(void) { return now; }
void wireguard_random_bytes(void *p, size_t n) {
    if (n == 4 && scripted_indices) {
        const uint32_t candidates[] = {0, UINT32_MAX, 7, 8};
        assert(index_calls < 4);
        uint32_t candidate = candidates[index_calls++];
        U32TO8_LITTLE((uint8_t *)p, candidate);
    } else if (n == 4) {
        uint32_t value = next_index++;
        U32TO8_LITTLE((uint8_t *)p, value);
    } else memset(p, 7, n);
}
bool wireguard_is_under_load(void) { return false; }
bool wireguard_tai64n_now(uint8_t *p) {
    if (!timestamp_ready) return false;
    memset(p, 1, 12);
    uint32_t value = timestamp_sequence++;
    U32TO8_BIG(p + 8, value);
    return true;
}

static bool receive(struct wireguard_keypair *key, uint64_t nonce, size_t length, bool tamper) {
    uint8_t plain[32] = {0}, encrypted[48], decoded[32];
    wireguard_aead_encrypt(encrypted, plain, length, NULL, 0, nonce, key->receiving_key);
    if (tamper) encrypted[length] ^= 1;
    return wireguard_decrypt_packet(decoded, encrypted, length + 16, nonce, key);
}

int main(void) {
    struct wireguard_keypair k = {0};
    assert(receive(&k, 0, 32, false));
    assert(receive(&k, 100, 32, false));
    assert(receive(&k, (UINT64_C(1) << 32) + 1, 32, false));
    assert(!receive(&k, 0, 32, false));
    assert(!receive(&k, (UINT64_C(1) << 32) + 1, 32, false));

    memset(&k, 0, sizeof(k));
    assert(receive(&k, 0, 0, false));
    assert(!receive(&k, 0, 0, false));
    assert(receive(&k, 32, 0, false));
    assert(receive(&k, 1, 0, false));
    assert(!receive(&k, 0, 0, false));
    assert(!receive(&k, 31, 32, true));
    assert(receive(&k, 31, 32, false));
    assert(!receive(&k, 31, 32, false));
    uint64_t saved = k.replay_counter;
    assert(!receive(&k, REJECT_AFTER_MESSAGES, 32, false));
    assert(!receive(&k, UINT64_MAX, 0, false));
    assert(k.replay_counter == saved);
    assert(receive(&k, REJECT_AFTER_MESSAGES - 1, 32, false));
    assert(!receive(&k, 0, 32, false));
    uint8_t short_packet[15] = {0}, output[32];
    assert(!wireguard_decrypt_packet(output, short_packet, sizeof(short_packet), 0, &k));

    struct wireguard_peer peer = {0};
    peer.next_keypair.valid = true;
    peer.next_keypair.receiving_valid = true;
    assert(receive(&peer.next_keypair, 0, 0, false));
    assert(keypair_update(&peer, &peer.next_keypair) == &peer.curr_keypair);
    assert(peer.curr_keypair.valid && !peer.next_keypair.valid);
    assert(!receive(&peer.curr_keypair, 0, 0, false));

    now = 179999;
    peer.prev_keypair = peer.next_keypair = peer.curr_keypair;
    wireguard_expire_keys(&peer);
    assert(peer.prev_keypair.valid && peer.next_keypair.valid && peer.curr_keypair.valid);
    now = 180000;
    wireguard_expire_keys(&peer);
    struct wireguard_keypair empty = {0};
    assert(!memcmp(&peer.prev_keypair, &empty, sizeof(empty)));
    assert(!memcmp(&peer.curr_keypair, &empty, sizeof(empty)));
    assert(!memcmp(&peer.next_keypair, &empty, sizeof(empty)));
    peer.prev_keypair.valid = true;
    peer.prev_keypair.keypair_millis = UINT32_MAX - 1000;
    now = 179000;
    wireguard_expire_keys(&peer);
    assert(!peer.prev_keypair.valid);
    peer.curr_keypair.valid = true;
    peer.curr_keypair.keypair_millis = now;
    peer.curr_keypair.sending_counter = REJECT_AFTER_MESSAGES;
    wireguard_expire_keys(&peer);
    assert(!peer.curr_keypair.valid);

    struct wireguard_device device = {0};
    struct message_handshake_initiation message;
    memset(&message, 0xab, sizeof(message));
    assert(!wireguard_create_handshake_initiation(&device, &peer, &message));
    assert(message.type == 0xab && !peer.handshake.valid);
    wireguard_init();
    uint8_t private_key[32] = {1}, public_key[32] = {9};
    assert(wireguard_device_init(&device, private_key));
    assert(wireguard_peer_init(&device, &device.peers[0], public_key, NULL));
    device.peers[0].curr_keypair.local_index = 7;
    timestamp_ready = true;
    scripted_indices = true;
    assert(wireguard_create_handshake_initiation(&device, &device.peers[0], &message));
    assert(message.sender == 8 && index_calls == 4);
    scripted_indices = false;
    struct wireguard_device initiator = {0}, responder = {0};
    assert(wireguard_device_init(&initiator, private_key));
    private_key[1] = 10;
    assert(wireguard_device_init(&responder, private_key));
    assert(wireguard_peer_init(&initiator, &initiator.peers[0], responder.public_key, NULL));
    assert(wireguard_peer_init(&responder, &responder.peers[0], initiator.public_key, NULL));
    now = 0;
    assert(wireguard_create_handshake_initiation(&initiator, &initiator.peers[0], &message));
    assert(wireguard_process_initiation_message(&responder, &message) == &responder.peers[0]);
    now = 1;
    assert(wireguard_create_handshake_initiation(&initiator, &initiator.peers[0], &message));
    assert(!wireguard_process_initiation_message(&responder, &message));
    now = 500;
    assert(wireguard_process_initiation_message(&responder, &message) == &responder.peers[0]);
    now = UINT32_MAX - 100;
    assert(wireguard_create_handshake_initiation(&initiator, &initiator.peers[0], &message));
    assert(wireguard_process_initiation_message(&responder, &message) == &responder.peers[0]);
    now = 50;
    assert(wireguard_create_handshake_initiation(&initiator, &initiator.peers[0], &message));
    assert(!wireguard_process_initiation_message(&responder, &message));
    now = 399;
    assert(wireguard_process_initiation_message(&responder, &message) == &responder.peers[0]);
    struct message_handshake_response response;
    assert(wireguard_create_handshake_response(&responder, &responder.peers[0], &response));
    uint32_t created = initiator.peers[0].handshake.created_millis;
    initiator.peers[0].handshake_attempts = MAX_HANDSHAKE_ATTEMPTS;
    now = created + 539999;
    wireguard_expire_keys(&initiator.peers[0]);
    assert(initiator.peers[0].handshake.valid);
    now++;
    assert(!wireguard_process_handshake_response(&initiator, &initiator.peers[0], &response));
    struct wireguard_handshake empty_handshake = {0};
    assert(!memcmp(&initiator.peers[0].handshake, &empty_handshake, sizeof(empty_handshake)));
    assert(!wireguard_start_session(&initiator.peers[0], true));
    assert(!initiator.peers[0].curr_keypair.valid);
    now = UINT32_MAX - 100;
    assert(wireguard_create_handshake_initiation(&initiator, &initiator.peers[0], &message));
    initiator.peers[0].curr_keypair.valid = true;
    initiator.peers[0].curr_keypair.keypair_millis = now;
    now += 180000;
    wireguard_expire_keys(&initiator.peers[0]);
    assert(!initiator.peers[0].curr_keypair.valid && initiator.peers[0].handshake.valid);
    now += 360000;
    assert(!peer_lookup_by_handshake(&initiator, message.sender));
    assert(!memcmp(&initiator.peers[0].handshake, &empty_handshake, sizeof(empty_handshake)));
    assert(wireguard_create_handshake_initiation(&initiator, &initiator.peers[0], &message));
    assert(wireguard_process_initiation_message(&responder, &message));
    assert(wireguard_create_handshake_response(&responder, &responder.peers[0], &response));
    assert(wireguard_process_handshake_response(&initiator, &initiator.peers[0], &response));
    assert(wireguard_start_session(&initiator.peers[0], true));
    assert(initiator.peers[0].curr_keypair.valid);
    assert(!memcmp(&initiator.peers[0].handshake, &empty_handshake, sizeof(empty_handshake)));
    now += 500;
    assert(wireguard_create_handshake_initiation(&initiator, &initiator.peers[0], &message));
    assert(wireguard_process_initiation_message(&responder, &message));
    assert(wireguard_create_handshake_response(&responder, &responder.peers[0], &response));
    now += 539999;
    assert(wireguard_process_handshake_response(&initiator, &initiator.peers[0], &response));
    now++;
    assert(!wireguard_start_session(&initiator.peers[0], true));
    assert(!memcmp(&initiator.peers[0].handshake, &empty_handshake, sizeof(empty_handshake)));
    puts("PASS: authenticated replay boundaries, keepalives, key promotion, expiry, and unavailable timestamps");
}
