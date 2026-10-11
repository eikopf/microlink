/*
 * Copyright (c) 2021 Daniel Hope (www.floorsense.nz)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *  list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 *  list of conditions and the following disclaimer in the documentation and/or
 *  other materials provided with the distribution.
 *
 * 3. Neither the name of "Floorsense Ltd", "Agile Workspace Ltd" nor the names of
 *  its contributors may be used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Author: Daniel Hope <daniel.hope@smartalock.com>
 */

#ifndef _WIREGUARD_PLATFORM_H_
#define _WIREGUARD_PLATFORM_H_

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include "sdkconfig.h"

// Peers are allocated statically inside the device structure to avoid malloc.
// The cap MUST match microlink's peer table (CONFIG_ML_MAX_PEERS, driven by the
// ESPHome `max_peers:` option): a smaller WG table silently strands peers 17+
// in a discovered-but-sessionless state — DISCO ping still pongs, but every
// TCP connection to/from them times out (wireguardif_add_peer -> ERR_MEM,
// wg_peer_index stays -1). Each slot costs ~0.9 KB inside wireguard_device.
#ifdef CONFIG_ML_MAX_PEERS
#define WIREGUARD_MAX_PEERS CONFIG_ML_MAX_PEERS
#else
#define WIREGUARD_MAX_PEERS 16
#endif
#define WIREGUARD_MAX_SRC_IPS 2

// Per device limit on accepting (valid) initiation requests - per peer
#define MAX_INITIATIONS_PER_SECOND	(2)

//
// Your platform integration needs to provide implementations of these functions
//

// The number of milliseconds since system boot - for LwIP systems this could be sys_now()
uint32_t wireguard_sys_now();

// Fill the supplied buffer with random data - random data is used for generating new session keys periodically
void wireguard_random_bytes(void *bytes, size_t size);

// Reserve a persistent boot epoch before any handshake can be emitted.
bool wireguard_tai64n_init(void);

// Emit a strictly increasing 12-byte TAI64N value; false leaves output unchanged.
bool wireguard_tai64n_now(uint8_t *output);

// Is the system under load - i.e. should we generate cookie reply message in response to initiation messages
bool wireguard_is_under_load();


#endif /* _WIREGUARD_PLATFORM_H_ */
