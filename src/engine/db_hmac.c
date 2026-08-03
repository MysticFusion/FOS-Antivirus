/**
 * @file db_hmac.c
 * @brief HMAC-SHA256 integrity protection for the signature database (I-22/R-09).
 */
#define _CRT_SECURE_NO_WARNINGS
#include "db_hmac.h"
#include "path_utils.h"
#include "sha2.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Keyed HMAC-SHA256 over the raw database bytes.
 *
 * The key is embedded in the binary at build time (generated once; the
 * attacker cannot derive it from the DB or the .hmac file). Rotate by
 * regenerating this constant and re-releasing the application. */
static const uint8_t k_db_hmac_key[DB_HMAC_SIZE] = {
    0xc2, 0x68, 0x66, 0xef, 0xf7, 0x29, 0xd4, 0xe7, 0x5e, 0x1e, 0x23, 0xa6,
    0x0a, 0xf4, 0x07, 0x42, 0x04, 0x38, 0x83, 0xe4, 0x2a, 0x04, 0xec, 0x7c,
    0x9e, 0x32, 0xa2, 0xc4, 0xac, 0x6e, 0x57, 0xf0,
};

#define HMAC_BLOCK_SIZE 64

int db_hmac_compute_file(const char *db_path, uint8_t out[DB_HMAC_SIZE])
{
    if (!db_path || !out) return -1;

    fos_path_t fp;
    if (!fos_path_init(&fp, db_path)) return -1;
    FILE *f = fos_fopen(&fp, "rb");
    if (!f) return -1;

    sha256_ctx ctx;
    sha256_init(&ctx);
    uint8_t inner[DB_HMAC_SIZE];
    /* First update: HMAC inner hash = H(ipad_key || message). */
    uint8_t ipad_key[HMAC_BLOCK_SIZE] = {0};
    uint8_t opad_key[HMAC_BLOCK_SIZE] = {0};
    memcpy(ipad_key, k_db_hmac_key, DB_HMAC_SIZE);
    memcpy(opad_key, ipad_key, HMAC_BLOCK_SIZE);
    for (int i = 0; i < HMAC_BLOCK_SIZE; i++) {
        ipad_key[i] ^= 0x36;
        opad_key[i] ^= 0x5c;
    }
    sha256_update(&ctx, ipad_key, HMAC_BLOCK_SIZE);

    uint8_t buf[65536];
    size_t got;
    while ((got = fread(buf, 1, sizeof(buf), f)) > 0) {
        sha256_update(&ctx, buf, got);
    }
    int read_err = ferror(f);
    fclose(f);
    if (read_err) return -1;

    sha256_final(&ctx, inner);

    sha256_ctx outer;
    sha256_init(&outer);
    sha256_update(&outer, opad_key, HMAC_BLOCK_SIZE);
    sha256_update(&outer, inner, sizeof(inner));
    sha256_final(&outer, out);
    return 0;
}

static int read_hmac_file(const char *db_path, uint8_t expected[DB_HMAC_SIZE])
{
    char hmac_path[FOS_MAX_PATH];
    if (strlen(db_path) + 5 >= FOS_MAX_PATH) return -1;
    snprintf(hmac_path, sizeof(hmac_path), "%s.hmac", db_path);

    fos_path_t fp;
    if (!fos_path_init(&fp, hmac_path)) return -1;
    FILE *f = fos_fopen(&fp, "rb");
    if (!f) return -1;
    size_t got = fread(expected, 1, DB_HMAC_SIZE, f);
    int extra = (int)(fgetc(f) != EOF);
    fclose(f);
    if (got != DB_HMAC_SIZE || extra != 0) return -1;
    return 0;
}

int db_hmac_verify_file(const char *db_path)
{
    if (!db_path) return -1;
    uint8_t expected[DB_HMAC_SIZE];
    if (read_hmac_file(db_path, expected) != 0) return -1;

    uint8_t actual[DB_HMAC_SIZE];
    if (db_hmac_compute_file(db_path, actual) != 0) return -1;

    /* Constant-time comparison. */
    unsigned diff = 0;
    for (int i = 0; i < DB_HMAC_SIZE; i++) diff |= (unsigned)(actual[i] ^ expected[i]);
    return diff == 0 ? 0 : -1;
}

int db_hmac_write_file(const char *db_path)
{
    if (!db_path) return -1;
    uint8_t hmac[DB_HMAC_SIZE];
    if (db_hmac_compute_file(db_path, hmac) != 0) return -1;

    char hmac_path[FOS_MAX_PATH];
    if (strlen(db_path) + 5 >= FOS_MAX_PATH) return -1;
    snprintf(hmac_path, sizeof(hmac_path), "%s.hmac", db_path);

    fos_path_t fp;
    if (!fos_path_init(&fp, hmac_path)) return -1;
    FILE *f = fos_fopen(&fp, "wb");
    if (!f) return -1;
    size_t wrote = fwrite(hmac, 1, sizeof(hmac), f);
    int write_err = ferror(f);
    fclose(f);
    if (wrote != sizeof(hmac) || write_err) return -1;
    return 0;
}
