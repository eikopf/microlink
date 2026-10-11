#include "ml_filter.h"
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <math.h>
#ifdef ESP_PLATFORM
#include "esp_heap_caps.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"
#else
#include <arpa/inet.h>
#endif

#define FILTER_GROUPS 8
#define FILTER_ROWS 128
#define FILTER_FLOWS 32
#define FLOW_TTL_MS 30000

typedef struct { uint32_t first, last; } ip_range_t;
typedef struct {
    ip_range_t src, dst;
    uint16_t first_port, last_port;
    uint8_t protocols[32];
    uint8_t group;
} filter_row_t;
typedef struct {
    char groups[FILTER_GROUPS][64];
    filter_row_t rows[FILTER_ROWS];
    unsigned count;
} filter_policy_t;
typedef struct {
    uint32_t src, dst;
    uint16_t sport, dport;
    uint8_t proto, flags, icmp;
} packet_t;
typedef struct { packet_t packet; uint64_t time; bool used; } filter_flow_t;
struct ml_filter {
    filter_policy_t *policy;
    filter_flow_t flows[FILTER_FLOWS];
};

static void *allocate(size_t size) {
#ifdef ESP_PLATFORM
    return heap_caps_calloc_prefer(1, size, 2, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT,
                                  MALLOC_CAP_DEFAULT);
#else
    return calloc(1, size);
#endif
}

ml_filter_t *ml_filter_create(void) { return allocate(sizeof(ml_filter_t)); }
void ml_filter_reset(ml_filter_t *filter) {
    if (!filter) return;
    free(filter->policy);
    filter->policy = NULL;
    memset(filter->flows, 0, sizeof(filter->flows));
}
void ml_filter_destroy(ml_filter_t *filter) {
    ml_filter_reset(filter);
    free(filter);
}

static bool integer(const cJSON *value, unsigned maximum, unsigned *out) {
    if (!cJSON_IsNumber(value) || !isfinite(value->valuedouble) || value->valuedouble < 0 ||
        value->valuedouble > maximum) return false;
    *out = (unsigned)value->valuedouble;
    return value->valuedouble == *out;
}

/* Returns 4 or 6 for valid addresses, 0 for malformed/unsupported expressions. */
static int address(const char *text, ip_range_t *range, const cJSON *legacy_bits) {
    if (!text || strlen(text) >= 100) return 0;
    if (strcmp(text, "*") == 0) {
        range->first = 0; range->last = UINT32_MAX;
        return 4;
    }
    char copy[100];
    strcpy(copy, text);
    char *slash = strchr(copy, '/');
    char *dash = strchr(copy, '-');
    if (slash && dash) return 0;
    unsigned bits = strchr(copy, ':') ? 128 : 32;
    if (slash) {
        *slash++ = '\0';
        if (!*slash) return 0;
        char *end;
        unsigned long parsed = strtoul(slash, &end, 10);
        if (*end || parsed > bits || *slash < '0' || *slash > '9') return 0;
        bits = (unsigned)parsed;
    } else if (legacy_bits && !cJSON_IsNull(legacy_bits)) {
        if (!integer(legacy_bits, bits, &bits) || dash) return 0;
    }
    if (dash) *dash++ = '\0';
    struct in_addr first, last;
    if (inet_pton(AF_INET, copy, &first) == 1) {
        range->first = ntohl(first.s_addr);
        if (dash) {
            if (inet_pton(AF_INET, dash, &last) != 1) return 0;
            range->last = ntohl(last.s_addr);
            return range->first <= range->last ? 4 : 0;
        }
        uint32_t mask = bits ? UINT32_MAX << (32 - bits) : 0;
        range->first &= mask;
        range->last = range->first | ~mask;
        return 4;
    }
    struct in6_addr first6, last6;
    if (inet_pton(AF_INET6, copy, &first6) != 1) return 0;
    if (dash && (inet_pton(AF_INET6, dash, &last6) != 1 ||
                 memcmp(&first6, &last6, sizeof(first6)) > 0)) return 0;
    return 6;
}

static bool known_fields(const cJSON *object, const char *const *names) {
    if (!cJSON_IsObject(object)) return false;
    const cJSON *field;
    cJSON_ArrayForEach(field, object) {
        bool found = false;
        for (unsigned i = 0; names[i]; ++i) {
            if (strcmp(field->string, names[i]) == 0) found = true;
        }
        if (!found) return false;
        for (const cJSON *prior = object->child; prior != field; prior = prior->next) {
            if (strcmp(prior->string, field->string) == 0) return false;
        }
    }
    return true;
}

bool ml_filter_local_destination(uint32_t destination, uint32_t local_ip,
                                 const char *routes) {
    if (local_ip && destination == local_ip) return true;
    if (!routes) return false;
    while (*routes) {
        const char *end = routes + strcspn(routes, "\r\n");
        const char *next = *end ? end + 1 : end;
        while (routes < end && (*routes == ' ' || *routes == '\t')) ++routes;
        while (end > routes && (end[-1] == ' ' || end[-1] == '\t')) --end;
        size_t len = (size_t)(end - routes);
        if (len && len < 100) {
            char prefix[100];
            memcpy(prefix, routes, len); prefix[len] = '\0';
            ip_range_t range;
            if (strchr(prefix, '/') && address(prefix, &range, NULL) == 4 &&
                destination >= range.first && destination <= range.last) return true;
        }
        routes = next;
    }
    return false;
}

static bool compile_rules(filter_policy_t *policy, unsigned group, const cJSON *rules) {
    if (!cJSON_IsArray(rules)) return false;
    const char *const rule_fields[] = {"SrcIPs", "SrcBits", "DstPorts", "IPProto", "CapGrant", NULL};
    const char *const dest_fields[] = {"IP", "Bits", "Ports", NULL};
    const char *const port_fields[] = {"First", "Last", NULL};
    const cJSON *rule;
    cJSON_ArrayForEach(rule, rules) {
        if (!known_fields(rule, rule_fields)) return false;
        const cJSON *sources = cJSON_GetObjectItemCaseSensitive(rule, "SrcIPs");
        const cJSON *destinations = cJSON_GetObjectItemCaseSensitive(rule, "DstPorts");
        const cJSON *caps = cJSON_GetObjectItemCaseSensitive(rule, "CapGrant");
        const cJSON *legacy = cJSON_GetObjectItemCaseSensitive(rule, "SrcBits");
        const cJSON *protocols = cJSON_GetObjectItemCaseSensitive(rule, "IPProto");
        if (caps && !cJSON_IsNull(caps)) {
            if (!cJSON_IsArray(caps) || (destinations && !cJSON_IsNull(destinations))) return false;
            continue; /* Application capabilities grant no IP access. */
        }
        if (!cJSON_IsArray(sources) || !cJSON_IsArray(destinations)) return false;
        if (legacy && !cJSON_IsNull(legacy) && !cJSON_IsArray(legacy)) return false;
        filter_row_t row = {.group = group};
        if (!protocols || cJSON_IsNull(protocols) || (cJSON_IsArray(protocols) && !protocols->child)) {
            row.protocols[1 / 8] |= 1u << (1 % 8);
            row.protocols[6 / 8] |= 1u << (6 % 8);
            row.protocols[17 / 8] |= 1u << (17 % 8);
        } else {
            if (!cJSON_IsArray(protocols)) return false;
            const cJSON *proto;
            cJSON_ArrayForEach(proto, protocols) {
                unsigned number;
                if (!integer(proto, 255, &number)) return false;
                row.protocols[number / 8] |= 1u << (number % 8);
            }
        }
        unsigned source_index = 0;
        const cJSON *src, *dst;
        cJSON_ArrayForEach(src, sources) {
            const cJSON *bits = cJSON_GetArrayItem(legacy, source_index++);
            if (!cJSON_IsString(src)) return false;
            int src_family = address(src->valuestring, &row.src, bits);
            if (!src_family) return false;
            cJSON_ArrayForEach(dst, destinations) {
                if (!known_fields(dst, dest_fields)) return false;
                const cJSON *ip = cJSON_GetObjectItemCaseSensitive(dst, "IP");
                const cJSON *ports = cJSON_GetObjectItemCaseSensitive(dst, "Ports");
                const cJSON *dst_bits = cJSON_GetObjectItemCaseSensitive(dst, "Bits");
                if (!cJSON_IsString(ip) || !known_fields(ports, port_fields)) return false;
                int dst_family = address(ip->valuestring, &row.dst, dst_bits);
                unsigned first, last;
                if (!dst_family || !integer(cJSON_GetObjectItemCaseSensitive(ports, "First"), 65535, &first) ||
                    !integer(cJSON_GetObjectItemCaseSensitive(ports, "Last"), 65535, &last) || first > last) return false;
                row.first_port = first; row.last_port = last;
                if (src_family == 6 || dst_family == 6) continue;
                if (policy->count == FILTER_ROWS) return false;
                policy->rows[policy->count++] = row;
            }
        }
    }
    return true;
}

static bool replace_group(filter_policy_t *policy, const char *name, const cJSON *rules) {
    if (!name || !*name || strlen(name) >= sizeof(policy->groups[0]) || strcmp(name, "*") == 0) return false;
    unsigned group;
    for (group = 0; group < FILTER_GROUPS; ++group) {
        if (strcmp(policy->groups[group], name) == 0) break;
    }
    if (group < FILTER_GROUPS) {
        unsigned count = 0;
        for (unsigned i = 0; i < policy->count; ++i) {
            if (policy->rows[i].group != group) policy->rows[count++] = policy->rows[i];
        }
        policy->count = count;
        policy->groups[group][0] = '\0';
    } else {
        if (cJSON_IsNull(rules)) return true;
        for (group = 0; group < FILTER_GROUPS && policy->groups[group][0]; ++group) {}
    }
    if (cJSON_IsNull(rules)) return true;
    if (group == FILTER_GROUPS) return false;
    strcpy(policy->groups[group], name);
    return compile_rules(policy, group, rules);
}

bool ml_filter_update(ml_filter_t *filter, const cJSON *map) {
    if (!filter) return false;
    if (!cJSON_IsObject(map)) { ml_filter_reset(filter); return false; }
    unsigned base_count = 0, groups_count = 0;
    const cJSON *field;
    cJSON_ArrayForEach(field, map) {
        if (strcmp(field->string, "PacketFilter") == 0) ++base_count;
        if (strcmp(field->string, "PacketFilters") == 0) ++groups_count;
    }
    if (base_count > 1 || groups_count > 1) { ml_filter_reset(filter); return false; }
    const cJSON *base = cJSON_GetObjectItemCaseSensitive(map, "PacketFilter");
    const cJSON *groups = cJSON_GetObjectItemCaseSensitive(map, "PacketFilters");
    if (cJSON_IsNull(base)) base = NULL;
    if (cJSON_IsNull(groups)) groups = NULL;
    if (!base && !groups) return true;
    filter_policy_t *next = allocate(sizeof(*next));
    if (!next) { ml_filter_reset(filter); return false; }
    if (filter->policy) *next = *filter->policy;
    if (base && !replace_group(next, "base", base)) goto fail;
    if (groups) {
        if (!cJSON_IsObject(groups)) goto fail;
        const cJSON *clear = cJSON_GetObjectItemCaseSensitive(groups, "*");
        if (clear) {
            if (!cJSON_IsNull(clear)) goto fail;
            memset(next, 0, sizeof(*next));
        }
        const cJSON *entry;
        cJSON_ArrayForEach(entry, groups) {
            for (const cJSON *prior = groups->child; prior != entry; prior = prior->next) {
                if (strcmp(prior->string, entry->string) == 0) goto fail;
            }
            if (strcmp(entry->string, "*") == 0) continue;
            if (!replace_group(next, entry->string, entry)) goto fail;
        }
    }
    ml_filter_reset(filter);
    filter->policy = next;
    return true;
fail:
    free(next);
    ml_filter_reset(filter);
    return false;
}

static uint16_t read16(const uint8_t *p) { return (uint16_t)p[0] << 8 | p[1]; }
static uint32_t read32(const uint8_t *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }

static bool decode(packet_t *packet, const uint8_t *header, size_t header_len, size_t packet_len) {
    if (!header || header_len < 20 || header[0] != 0x45) return false;
    size_t length = read16(header + 2);
    /* No IPv6, IP options, or fragments can bypass the transport checks. */
    if (length < 20 || length > packet_len || (read16(header + 6) & 0xbfff)) return false;
    memset(packet, 0, sizeof(*packet));
    packet->src = read32(header + 12); packet->dst = read32(header + 16);
    packet->proto = header[9];
    size_t needed = 20;
    if (packet->proto == 6) needed += 20;
    else if (packet->proto == 17 || packet->proto == 1) needed += 8;
    else if (packet->proto == 132) needed += 12;
    if (length < needed || header_len < needed) return false;
    if (packet->proto == 6 || packet->proto == 17 || packet->proto == 132) {
        packet->sport = read16(header + 20); packet->dport = read16(header + 22);
    }
    if (packet->proto == 6) {
        unsigned tcp_len = (header[32] >> 4) * 4;
        if (tcp_len < 20 || tcp_len > length - 20) return false;
        packet->flags = header[33];
    }
    if (packet->proto == 17 && (read16(header + 24) < 8 || read16(header + 24) != length - 20)) return false;
    if (packet->proto == 1) packet->icmp = header[20];
    return true;
}

static bool same_flow(const packet_t *a, const packet_t *b) {
    return a->src == b->src && a->dst == b->dst && a->sport == b->sport &&
           a->dport == b->dport && a->proto == b->proto;
}

void ml_filter_record_outbound(ml_filter_t *filter, const uint8_t *header,
                               size_t header_len, size_t packet_len, uint64_t now_ms) {
    packet_t packet;
    if (!filter || !filter->policy || !decode(&packet, header, header_len, packet_len) ||
        (packet.proto != 17 && packet.proto != 132)) return;
    uint32_t ip = packet.src; packet.src = packet.dst; packet.dst = ip;
    uint16_t port = packet.sport; packet.sport = packet.dport; packet.dport = port;
    unsigned slot = 0;
    for (unsigned i = 0; i < FILTER_FLOWS; ++i) {
        if (!filter->flows[i].used || same_flow(&filter->flows[i].packet, &packet)) { slot = i; break; }
        if (filter->flows[i].time < filter->flows[slot].time) slot = i;
    }
    filter->flows[slot] = (filter_flow_t){.packet = packet, .time = now_ms, .used = true};
}

bool ml_filter_accept(ml_filter_t *filter, const uint8_t *header, size_t header_len,
                      size_t packet_len, bool local_destination, uint64_t now_ms) {
    packet_t packet;
    if (!filter || !filter->policy || !local_destination || !decode(&packet, header, header_len, packet_len)) return false;
    /* Match Tailscale's TCP continuation and ICMP response semantics. */
    if (packet.proto == 6 && (packet.flags & 0x12) != 0x02) return true;
    if (packet.proto == 1 && (packet.icmp == 0 || packet.icmp == 3 || packet.icmp == 11 || packet.icmp == 12)) return true;
    if (packet.proto == 17 || packet.proto == 132) {
        for (unsigned i = 0; i < FILTER_FLOWS; ++i) {
            filter_flow_t *flow = &filter->flows[i];
            if (flow->used && now_ms >= flow->time && now_ms - flow->time < FLOW_TTL_MS && same_flow(&flow->packet, &packet)) {
                flow->time = now_ms;
                return true;
            }
        }
    }
    for (unsigned i = 0; i < filter->policy->count; ++i) {
        const filter_row_t *row = &filter->policy->rows[i];
        if (packet.src < row->src.first || packet.src > row->src.last || packet.dst < row->dst.first || packet.dst > row->dst.last) continue;
        if (packet.proto == 1) return true;
        if (!(row->protocols[packet.proto / 8] & (1u << (packet.proto % 8)))) continue;
        if (packet.proto == 6 || packet.proto == 17 || packet.proto == 132) {
            if (packet.dport >= row->first_port && packet.dport <= row->last_port) return true;
        } else if (row->first_port == 0 && row->last_port == 65535) return true;
    }
    return false;
}
