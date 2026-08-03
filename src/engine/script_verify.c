/**
 * @file script_verify.c
 * @brief SHA-256 pin verification for the staged hash_aggregator.py (I-19).
 *
 * Runtime integrity gate shared with security_test_script_pin: the updater
 * must never execute a planted or tampered aggregator script.
 */

#include "script_verify.h"

#include "aggregator_hash.h"
#include "hash_util.h"

#include <string.h>

static void hex_bytes_to_string(const unsigned char *bytes, size_t len,
                                char out[SHA256_SIZE * 2 + 1]) {
    static const char k_hex_digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = k_hex_digits[bytes[i] >> 4];
        out[i * 2 + 1] = k_hex_digits[bytes[i] & 0x0F];
    }
    out[len * 2] = '\0';
}

int signature_script_verify(const char *path) {
    unsigned char script_hash[SHA256_SIZE];
    char script_hash_hex[SHA256_SIZE * 2 + 1];

    /* Compute the hash FIRST, then hex-encode the result. (FOS bugfix:
     * the original runtime check hex-encoded the still-uninitialized
     * buffer, so the compare always failed with UPDATE_ERR_SCRIPT_TAMPERED.) */
    if (compute_file_sha256(path, script_hash) != 0) {
        return -1;
    }
    hex_bytes_to_string(script_hash, SHA256_SIZE, script_hash_hex);
    if (_stricmp(script_hash_hex, AGGREGATOR_SHA256_HEX) != 0) {
        return -1;
    }
    return 0;
}
