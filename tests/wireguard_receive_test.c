#include "wireguard.h"
#include "crypto.h"
#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

#define LWIP_IPV4 1
#define LWIP_IPV6 0
#define WG_DEBUG(...) ((void)0)
#define PBUF_TRANSPORT 0
#define PBUF_RAM 0
#define ERR_OK 0
#define PP_NTOHS(x) ntohs(x)
struct pbuf { void *payload; uint16_t tot_len; };
struct ip_hdr { uint8_t vhl, tos; uint16_t len, id, offset; uint8_t ttl, proto; uint16_t checksum; ip_addr_t src, dest; };
#define IPH_V(h) ((h)->vhl >> 4)
#define IPH_LEN(h) ((h)->len)
#define ip_addr_copy_from_ip4(dst, src) ((dst) = (src))
#define IP_ADDR_NETCMP_COMPAT(a, b, m) (((a)->addr & (m)->addr) == ((b)->addr & (m)->addr))
static unsigned allocations, delivered, endpoint_updates;
static uint32_t now;
uint32_t wireguard_sys_now(void) { return now; }
void wireguard_random_bytes(void *p, size_t n) { memset(p, 7, n); }
bool wireguard_is_under_load(void) { return false; }
bool wireguard_tai64n_now(uint8_t *p) { (void)p; return false; }
static struct pbuf *pbuf_alloc(int layer, size_t size, int type) {
    (void)layer; (void)type;
    struct pbuf *p = malloc(sizeof(*p)); assert(p);
    p->payload = malloc(size ? size : 1); assert(p->payload);
    p->tot_len = size; ++allocations; return p;
}
static void pbuf_free(struct pbuf *p) { free(p->payload); free(p); --allocations; }
static void netif_set_link_up(struct netif *n) { n->link_up = 1; }
static void update_peer_addr(struct wireguard_peer *p, const ip_addr_t *ip, u16_t port) {
    p->ip = *ip; p->port = port; ++endpoint_updates;
}
/* This generated include contains the production receive function without edits. */
#include "wireguard_receive_function.inc"

static err_t input(struct pbuf *p, struct netif *netif) {
    (void)netif; ++delivered; pbuf_free(p); return ERR_OK;
}
static void receive(struct wireguard_device *device, struct wireguard_peer *peer,
                    uint64_t nonce, size_t length, bool tamper, uint32_t address) {
    uint8_t plain[64] = {0}, packet[128] = {0};
    struct ip_hdr *ip = (struct ip_hdr *)plain;
    ip->vhl = 0x45; ip->len = htons(length); ip->src.addr = 1; ip->dest.addr = 2;
    struct message_transport_data *message = (struct message_transport_data *)packet;
    message->receiver = 7;
    U64TO8_LITTLE(message->counter, nonce);
    wireguard_aead_encrypt(message->enc_packet, plain, length, NULL, 0, nonce, peer->curr_keypair.receiving_key);
    if (tamper) message->enc_packet[length] ^= 1;
    ip_addr_t source = { .addr = address };
    wireguardif_process_data_message(device, peer, message, length + 16, &source, 123);
    assert(!allocations);
}
int main(void) {
    struct netif netif = { .input = input };
    struct wireguard_device device = { .netif = &netif };
    struct wireguard_peer peer = {0};
    peer.curr_keypair.valid = peer.curr_keypair.receiving_valid = true;
    peer.curr_keypair.local_index = 7;
    peer.allowed_source_ips[0].valid = true;
    peer.allowed_source_ips[0].ip.addr = 1;
    peer.allowed_source_ips[0].mask.addr = UINT32_MAX;
    now = 100;
    receive(&device, &peer, 0, 32, false, 11);
    assert(delivered == 1 && endpoint_updates == 1 && peer.last_rx == now && netif.link_up);
    now = 200; netif.link_up = 0;
    receive(&device, &peer, 0, 32, false, 12);
    assert(delivered == 1 && endpoint_updates == 1 && peer.ip.addr == 11 && peer.last_rx == 100 && !netif.link_up);
    receive(&device, &peer, 1, 0, true, 13);
    assert(endpoint_updates == 1 && peer.last_rx == 100 && !netif.link_up);
    receive(&device, &peer, 1, 0, false, 14);
    assert(endpoint_updates == 2 && peer.last_rx == 200 && delivered == 1);
    now = 300; netif.link_up = 0;
    receive(&device, &peer, 1, 0, false, 15);
    assert(endpoint_updates == 2 && peer.ip.addr == 14 && peer.last_rx == 200 && !netif.link_up);
    for (size_t n = 1; n < 20; ++n) receive(&device, &peer, n + 1, n, false, 16);
    assert(delivered == 1);
    unsigned saved = endpoint_updates;
    receive(&device, &peer, REJECT_AFTER_MESSAGES, 32, false, 17);
    assert(endpoint_updates == saved && peer.curr_keypair.valid);

    memset(&peer.curr_keypair, 0, sizeof(peer.curr_keypair));
    peer.next_keypair.valid = peer.next_keypair.receiving_valid = true;
    peer.next_keypair.local_index = 7;
    receive(&device, &peer, 0, 0, false, 18);
    assert(peer.curr_keypair.valid && !peer.next_keypair.valid);
    saved = endpoint_updates;
    receive(&device, &peer, 0, 0, false, 19);
    assert(endpoint_updates == saved && peer.ip.addr == 18);
    puts("PASS: authenticated receive rejects replay before endpoint, timer, link, and key-promotion mutations; short packets stay bounded");
}
