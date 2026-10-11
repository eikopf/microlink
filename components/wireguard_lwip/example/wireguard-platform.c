#include "wireguard-platform.h"

#include <stdlib.h>
#include "crypto.h"
#include "lwip/sys.h"

// This file contains a sample Wireguard platform integration

// DO NOT USE THIS FUNCTION - IMPLEMENT A BETTER RANDOM BYTE GENERATOR IN YOUR IMPLEMENTATION
void wireguard_random_bytes(void *bytes, size_t size) {
	int x;
	uint8_t *out = (uint8_t *)bytes;
	for (x=0; x < size; x++) {
		out[x] = rand() % 0xFF;
	}
}

uint32_t wireguard_sys_now() {
	// Default to the LwIP system time
	return sys_now();
}

// A port must supply durable monotonic timestamps before enabling handshakes.
bool wireguard_tai64n_init(void) { return false; }
bool wireguard_tai64n_now(uint8_t *output) {
    (void)output;
    return false;
}

bool wireguard_is_under_load() {
	return false;
}

