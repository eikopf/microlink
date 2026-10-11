#ifndef ML_FILTER_H
#define ML_FILTER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

/* IPv4 receive policy. Callers serialize updates and packet processing. */
typedef struct ml_filter ml_filter_t;

ml_filter_t *ml_filter_create(void);
void ml_filter_destroy(ml_filter_t *filter);
void ml_filter_reset(ml_filter_t *filter);
/* Omitted/null policy fields preserve the current policy. Invalid updates deny all. */
bool ml_filter_update(ml_filter_t *filter, const cJSON *map);
bool ml_filter_accept(ml_filter_t *filter, const uint8_t *header, size_t header_len,
                      size_t packet_len, bool local_destination, uint64_t now_ms);
void ml_filter_record_outbound(ml_filter_t *filter, const uint8_t *header,
                               size_t header_len, size_t packet_len, uint64_t now_ms);
/* Addresses use host byte order. Routes are newline-separated IPv4 CIDRs. */
bool ml_filter_local_destination(uint32_t destination, uint32_t local_ip,
                                 const char *routes);

#ifdef __cplusplus
}
#endif

#endif
