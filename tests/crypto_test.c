#include "crypto.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void unhex32(const char *hex, uint8_t out[32]) {
    for (unsigned i = 0; i < 32; ++i) {
        unsigned value;
        assert(sscanf(hex + 2 * i, "%2x", &value) == 1);
        out[i] = (uint8_t)value;
    }
}

static void known_answers(void) {
    /* RFC 7748 section 6.1, https://www.rfc-editor.org/rfc/rfc7748#section-6.1 */
    uint8_t secret[32], public_key[32], expected[32], actual[32];
    unhex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", secret);
    unhex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", expected);
    memset(public_key, 0, sizeof(public_key)); public_key[0] = 9;
    assert(wireguard_x25519(actual, secret, public_key) == 0);
    assert(!memcmp(actual, expected, 32));
    unhex32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", public_key);
    unhex32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", expected);
    assert(wireguard_x25519(actual, secret, public_key) == 0);
    assert(!memcmp(actual, expected, 32));
    public_key[31] |= 0x80;
    assert(wireguard_x25519(actual, secret, public_key) == 0);
    assert(!memcmp(actual, expected, 32));
    _Alignas(uint32_t) uint8_t unaligned[33];
    memcpy(unaligned + 1, public_key, 32);
    assert(wireguard_x25519(actual, secret, unaligned + 1) == 0);
    assert(!memcmp(actual, expected, 32));
    memset(public_key, 0, sizeof(public_key));
    assert(wireguard_x25519(actual, secret, public_key) != 0);
    unhex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", expected);
    memset(public_key, 0xff, sizeof(public_key));
    public_key[0] = 0xf6; public_key[31] = 0x7f; /* p + 9 */
    assert(wireguard_x25519(actual, secret, public_key) == 0);
    assert(!memcmp(actual, expected, 32));
    /* RFC 7748 section 5.2 includes a coordinate with bit 255 set. */
    unhex32("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d", secret);
    unhex32("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493", public_key);
    unhex32("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957", expected);
    assert(wireguard_x25519(actual, secret, public_key) == 0);
    assert(!memcmp(actual, expected, 32));
    /* RFC 7693 appendix B, https://www.rfc-editor.org/rfc/rfc7693#appendix-B */
    unhex32("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982", expected);
    assert(wireguard_blake2s(actual, 32, NULL, 0, "abc", 3) == 0);
    assert(!memcmp(actual, expected, 32));
}

int main(void) {
    known_answers();
    puts("PASS: RFC X25519 and BLAKE2s vectors, coordinate aliases, alignment, and zero-secret rejection");
}
