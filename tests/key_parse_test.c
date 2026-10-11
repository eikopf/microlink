#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "key_parse_functions.inc"

int main(void) {
    char key[66];
    uint8_t out[32], sentinel[32];
    memset(key, 'a', 64); key[64] = 0;
    assert(hex_to_bytes32(key, out) == 0);
    for (unsigned i = 0; i < 32; ++i) assert(out[i] == 0xaa);
    memset(sentinel, 0x5a, sizeof(sentinel));
    const char invalid[] = "gG+- \n\t";
    for (unsigned pos = 0; pos < 64; ++pos) {
        for (unsigned j = 0; j < sizeof(invalid); ++j) {
            memcpy(out, sentinel, sizeof(out));
            key[pos] = invalid[j];
            assert(hex_to_bytes32(key, out) == -1);
            assert(!memcmp(out, sentinel, sizeof(out)));
        }
        key[pos] = 'a';
    }
    key[64] = 'a'; key[65] = 0;
    assert(hex_to_bytes32(key, out) == -1);
    assert(hex_to_bytes32(NULL, out) == -1);
    key[64] = 0;
    assert(hex_to_bytes(key, NULL, 32) == -1);
    assert(hex_to_bytes(key, out, 31) == -1);
    memcpy(key, "0123456789abcdefABCDEF", 22);
    assert(hex_to_bytes32(key, out) == 0);
    assert(out[0] == 0x01 && out[7] == 0xef && out[8] == 0xab && out[10] == 0xef);
    puts("PASS: exact-length key decoding rejects malformed input without partial writes");
}
