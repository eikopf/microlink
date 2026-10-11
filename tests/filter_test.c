#include "ml_filter.h"
#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

#define RULE "{\"SrcIPs\":[\"100.64.0.0/10\"],\"DstPorts\":[{\"IP\":\"100.97.223.73\",\"Ports\":{\"First\":80,\"Last\":80}}],\"IPProto\":[6]}"
#define ALLOW "{\"PacketFilter\":[" RULE "]}"
#define EMPTY "{\"PacketFilter\":[]}"

static void update(ml_filter_t *f, const char *json, bool expected) {
    cJSON *map = cJSON_Parse(json);
    assert(map);
    assert(ml_filter_update(f, map) == expected);
    cJSON_Delete(map);
}

static void put16(uint8_t *p, unsigned value) {
    p[0] = value >> 8; p[1] = value;
}

/* Source 100.98.63.7, destination 100.97.223.73. */
static size_t packet(uint8_t p[64], unsigned proto, unsigned port) {
    memset(p, 0, 64);
    p[0] = 0x45; p[8] = 64; p[9] = proto;
    memcpy(p + 12, (uint8_t[]){100, 98, 63, 7, 100, 97, 223, 73}, 8);
    size_t len = proto == 6 ? 40 : proto == 132 ? 32 : 28;
    put16(p + 2, len);
    put16(p + 20, 34567); put16(p + 22, port);
    if (proto == 6) { p[32] = 0x50; p[33] = 2; }
    if (proto == 17) put16(p + 24, 8);
    if (proto == 1) p[20] = 8;
    return len;
}

static bool accept(ml_filter_t *f, uint8_t *p, size_t len, uint64_t time) {
    return ml_filter_accept(f, p, len, len, true, time);
}

static void policy_tests(ml_filter_t *f) {
    uint8_t p[64]; size_t len = packet(p, 6, 80);
    assert(!accept(f, p, len, 0));
    update(f, "{}", true);
    assert(!accept(f, p, len, 0));
    update(f, ALLOW, true);
    assert(accept(f, p, len, 0));
    assert(!ml_filter_accept(f, p, len, len, false, 0));
    put16(p + 22, 81); assert(!accept(f, p, len, 0));
    put16(p + 22, 80);
    p[12] = 99; assert(!accept(f, p, len, 0)); p[12] = 100;
    p[19] = 74; assert(!accept(f, p, len, 0)); p[19] = 73;
    update(f, "{\"KeepAlive\":true,\"PacketFilter\":null,\"PacketFilters\":null}", true);
    assert(accept(f, p, len, 0));
    update(f, EMPTY, true);
    assert(!accept(f, p, len, 0));
    p[33] = 0x12; assert(accept(f, p, len, 0)); /* SYN+ACK reply */
    p[33] = 0x10; assert(accept(f, p, len, 0)); /* TCP continuation */
    p[33] = 2;
    update(f, "{\"PacketFilters\":{\"books\":[" RULE "]}}", true);
    assert(accept(f, p, len, 0));
    update(f, "{\"PacketFilters\":{\"books\":null}}", true);
    assert(!accept(f, p, len, 0));
    update(f, ALLOW, true);
    update(f, "{\"PacketFilter\":[" RULE "],\"PacketFilters\":{\"*\":null}}", true);
    assert(!accept(f, p, len, 0));
    update(f, "{\"PacketFilters\":{\"books\":[" RULE "],\"*\":null}}", true);
    assert(accept(f, p, len, 0));
    update(f, "{\"PacketFilters\":{\"books\":[]}}", true);
    assert(!accept(f, p, len, 0));
    update(f, "{\"PacketFilter\":[{\"SrcIPs\":[\"100.98.63.0\"],\"SrcBits\":[24],\"DstPorts\":[{\"IP\":\"100.97.223.0\",\"Bits\":24,\"Ports\":{\"First\":0,\"Last\":65535}}]}]}", true);
    assert(accept(f, p, len, 0));
    update(f, "{\"PacketFilter\":[{\"SrcIPs\":[\"100.98.63.7-100.98.63.9\",\"fd7a:115c:a1e0::/48\"],\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":80,\"Last\":81}}]}]}", true);
    assert(accept(f, p, len, 0));
    p[15] = 6; assert(!accept(f, p, len, 0)); p[15] = 9;
    assert(accept(f, p, len, 0)); p[15] = 10;
    assert(!accept(f, p, len, 0));
}

static void malformed_tests(ml_filter_t *f) {
    const char *invalid[] = {
        "[]", "{\"PacketFilter\":{}}", "{\"PacketFilters\":[]}",
        "{\"PacketFilter\":[],\"PacketFilter\":[]}",
        "{\"PacketFilters\":{},\"PacketFilters\":{}}",
        "{\"PacketFilters\":{\"*\":[]}}",
        "{\"PacketFilters\":{\"x\":[],\"x\":null}}",
        "{\"PacketFilter\":[{\"SrcIPs\":[\"*\"],\"SrcIPs\":[\"*\"],\"DstPorts\":[]}]}",
        "{\"PacketFilter\":[{\"UnknownConstraint\":true,\"SrcIPs\":[],\"DstPorts\":[]}]}",
        "{\"PacketFilter\":[{\"SrcIPs\":[\"cap:example\"],\"DstPorts\":[]}]}",
        "{\"PacketFilter\":[{\"SrcIPs\":[\"100.64.0.0/33\"],\"DstPorts\":[]}]}",
        "{\"PacketFilter\":[{\"SrcIPs\":[],\"DstPorts\":[],\"IPProto\":[6.5]}]}",
        "{\"PacketFilter\":[{\"SrcIPs\":[],\"DstPorts\":[],\"IPProto\":[256]}]}",
    };
    uint8_t p[64]; size_t len = packet(p, 6, 80);
    for (unsigned i = 0; i < sizeof(invalid) / sizeof(*invalid); ++i) {
        update(f, ALLOW, true);
        update(f, invalid[i], false);
        assert(!accept(f, p, len, 0));
        p[33] = 0x12; assert(!accept(f, p, len, 0)); p[33] = 2;
    }
    cJSON *map = cJSON_Parse(ALLOW);
    cJSON *rule = cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(map, "PacketFilter"), 0);
    cJSON *protocols = cJSON_GetObjectItemCaseSensitive(rule, "IPProto");
    cJSON_GetArrayItem(protocols, 0)->valuedouble = NAN;
    assert(!ml_filter_update(f, map));
    cJSON_Delete(map);
    update(f, ALLOW, true);
    for (size_t n = 0; n < len; ++n) assert(!ml_filter_accept(f, p, n, len, true, 0));
    assert(!ml_filter_accept(f, p, len, len - 1, true, 0));
    p[0] = 0x46; assert(!accept(f, p, len, 0));
    p[0] = 0x60; assert(!accept(f, p, len, 0)); p[0] = 0x45;
    p[6] = 0x20; assert(!accept(f, p, len, 0)); /* More fragments */
    p[6] = 0x80; assert(!accept(f, p, len, 0)); /* Reserved flag */
    p[6] = 0; p[7] = 1; assert(!accept(f, p, len, 0));
    p[7] = 0; p[6] = 0x40; assert(accept(f, p, len, 0));
    p[32] = 0x40; assert(!accept(f, p, len, 0));
    p[32] = 0x60; assert(!accept(f, p, len, 0));
}

static void reply_tests(ml_filter_t *f) {
    uint8_t p[64], out[64];
    for (unsigned proto = 17; proto <= 132; proto += 115) {
        update(f, EMPTY, true);
        size_t len = packet(p, proto, 5555);
        assert(!accept(f, p, len, 0));
        memcpy(out, p, len);
        memcpy(out + 12, p + 16, 4); memcpy(out + 16, p + 12, 4);
        memcpy(out + 20, p + 22, 2); memcpy(out + 22, p + 20, 2);
        ml_filter_record_outbound(f, out, len, len, 100);
        assert(accept(f, p, len, 101));
        p[15]++; assert(!accept(f, p, len, 102)); p[15]--;
        p[23]++; assert(!accept(f, p, len, 102)); p[23]--;
        assert(accept(f, p, len, 30100)); /* Reply refreshes expiry. */
        assert(!accept(f, p, len, 60100));
        ml_filter_record_outbound(f, out, len, len, 70000);
        update(f, "{}", true);
        assert(accept(f, p, len, 70001));
        update(f, EMPTY, true);
        assert(!accept(f, p, len, 70002));
    }
    size_t len = packet(p, 1, 0);
    assert(!accept(f, p, len, 0));
    p[20] = 0; assert(accept(f, p, len, 0));
    p[20] = 3; assert(accept(f, p, len, 0));
    p[20] = 8; update(f, ALLOW, true);
    assert(accept(f, p, len, 0)); /* ICMP allowed when any port is open. */
    ml_filter_reset(f);
    p[20] = 0; assert(!accept(f, p, len, 0));
}

static void capacity_tests(ml_filter_t *f) {
    cJSON *map = cJSON_Parse(EMPTY);
    cJSON *rules = cJSON_GetObjectItemCaseSensitive(map, "PacketFilter");
    for (unsigned i = 0; i < 128; ++i) cJSON_AddItemToArray(rules, cJSON_Parse(RULE));
    assert(ml_filter_update(f, map));
    cJSON_AddItemToArray(rules, cJSON_Parse(RULE));
    assert(!ml_filter_update(f, map));
    cJSON_Delete(map);
    uint8_t p[64]; size_t len = packet(p, 6, 80);
    assert(!accept(f, p, len, 0));
    map = cJSON_Parse("{\"PacketFilters\":{}}");
    cJSON *groups = cJSON_GetObjectItemCaseSensitive(map, "PacketFilters");
    for (unsigned i = 0; i < 8; ++i) {
        char name[2] = {'a' + i, 0};
        cJSON_AddItemToObject(groups, name, cJSON_CreateArray());
    }
    assert(ml_filter_update(f, map));
    cJSON_AddItemToObject(groups, "overflow", cJSON_CreateArray());
    assert(!ml_filter_update(f, map));
    cJSON_Delete(map);
}

static void protocol_tests(ml_filter_t *f) {
    uint8_t p[64];
    update(f, "{\"PacketFilter\":[{\"SrcIPs\":[\"*\"],\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":0,\"Last\":65535}}],\"IPProto\":[47]}]}", true);
    size_t len = packet(p, 47, 0);
    assert(accept(f, p, len, 0));
    p[9] = 50; assert(!accept(f, p, len, 0));
    update(f, "{\"PacketFilter\":[{\"SrcIPs\":[\"*\"],\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":0,\"Last\":80}}],\"IPProto\":[47]}]}", true);
    p[9] = 47; assert(!accept(f, p, len, 0));
    update(f, "{\"PacketFilter\":[{\"SrcIPs\":[\"*\"],\"CapGrant\":[{\"Dsts\":[\"*\"],\"Caps\":[\"example\"]}]}]}", true);
    len = packet(p, 6, 80); assert(!accept(f, p, len, 0));
    update(f, "{\"PacketFilter\":[{\"SrcIPs\":[\"*\"],\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":0,\"Last\":65535}}]}]}", true);
    len = packet(p, 17, 53); assert(accept(f, p, len, 0));
    put16(p + 24, 7); assert(!accept(f, p, len, 0));
    put16(p + 24, 9); assert(!accept(f, p, len, 0));
}

static void packet_bounds_tests(ml_filter_t *f) {
    /* Exercise header/packet length combinations with deterministic random bytes. */
    update(f, ALLOW, true);
    uint32_t state = 1;
    uint8_t p[64];
    for (unsigned i = 0; i < 20000; ++i) {
        for (unsigned j = 0; j < sizeof(p); ++j) {
            state = state * 1664525u + 1013904223u;
            p[j] = state >> 24;
        }
        if (i & 1) p[0] = 0x45;
        size_t len = i % 65;
        (void)ml_filter_accept(f, p, len, (i / 65) % 65, true, i);
        ml_filter_record_outbound(f, p, len, (i / 65) % 65, i);
    }
}

int main(void) {
    assert(ml_filter_local_destination(0x6461df49, 0x6461df49, ""));
    assert(!ml_filter_local_destination(0, 0, ""));
    assert(!ml_filter_local_destination(0x6461df50, 0x6461df49, ""));
    assert(ml_filter_local_destination(0xc0a80105, 0x6461df49, " \t192.168.1.0/24 \r\n10.0.0.0/8\n"));
    assert(!ml_filter_local_destination(0xc0a80205, 0x6461df49, "192.168.1.0/24"));
    assert(!ml_filter_local_destination(0xc0a80105, 0x6461df49, "192.168.1.0/33\n*\nmalformed"));
    assert(!ml_filter_local_destination(0xc0a80105, 0x6461df49, "fd7a:115c:a1e0::/48\n"));
    assert(ml_filter_local_destination(0xc0a80105, 0x6461df49, "0.0.0.0/0"));
    ml_filter_t *f = ml_filter_create();
    assert(f);
    policy_tests(f);
    malformed_tests(f);
    reply_tests(f);
    capacity_tests(f);
    protocol_tests(f);
    packet_bounds_tests(f);
    ml_filter_destroy(f);
    puts("filter tests passed");
    return 0;
}
