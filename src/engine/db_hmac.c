/**
 * @file db_hmac.c
 * @brief HMAC-SHA256 integrity protection for the signature database (I-22/R-09).
 *
 * MAP-04: the HMAC key is no longer a compile-time constant embedded in the
 * binary (recoverable with `strings`/disassembly). It is now derived at
 * runtime from a DPAPI-protected blob (CryptProtectData,
 * CRYPTPROTECT_LOCAL_MACHINE), so the key material never appears in the
 * image and an attacker needs the machine's DPAPI master key (or process
 * memory) to forge a valid HMAC. The derived key is cached in memory after
 * first derivation. If DPAPI fails, the operation FAILS CLOSED — the DB is
 * refused rather than verified with a weaker/absent key.
 */
#define _CRT_SECURE_NO_WARNINGS
#include "db_hmac.h"
#include "path_utils.h"
#include "sha2.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <windows.h>
#include <wincrypt.h>

#define HMAC_BLOCK_SIZE 64

/* ============================================================================
 * MAP-04: DPAPI-derived key (machine-bound, cached in memory)
 * ========================================================================== */

static SRWLOCK g_db_key_lock = SRWLOCK_INIT;
static uint8_t g_db_key[DB_HMAC_SIZE];
static bool    g_db_key_ready = false;

/**
 * @brief Derive (once) and return the 32-byte DB-HMAC key.
 *
 * CryptProtectData() binds a small label blob to the machine SID; the
 * 32-byte key is SHA-256 of that protected blob. Because the protected
 * blob is deterministic for a given machine, the same key is derived on
 * write (update) and verify (load) without any key file being stored.
 *
 * @return 0 on success, -1 on DPAPI failure (fail-closed).
 */
static int derive_db_key(uint8_t out[DB_HMAC_SIZE])
{
    if (!out) return -1;

    AcquireSRWLockExclusive(&g_db_key_lock);
    if (g_db_key_ready) {
        memcpy(out, g_db_key, DB_HMAC_SIZE);
        ReleaseSRWLockExclusive(&g_db_key_lock);
        return 0;
    }

    /* Fixed label: not secret, but required to make the DPAPI blob
     * machine-deterministic and context-bound to this application. */
    static const BYTE k_seed[] = "FOS-Antivirus-SigDB-HMAC-v1";
    DATA_BLOB in  = { (DWORD)(sizeof(k_seed) - 1), (BYTE *)k_seed };
    DATA_BLOB blob = { 0, NULL };

    BOOL ok = CryptProtectData(&in, L"FOS-Antivirus Signature Database Integrity",
                               NULL, NULL, NULL,
                               CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
                               &blob);

    if (!ok || blob.pbData == NULL || blob.cbData == 0) {
        ReleaseSRWLockExclusive(&g_db_key_lock);
        return -1; /* fail-closed: never verify with a weak/absent key */
    }

    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, blob.pbData, blob.cbData);
    sha256_final(&ctx, g_db_key);
    LocalFree(blob.pbData);

    g_db_key_ready = true;
    memcpy(out, g_db_key, DB_HMAC_SIZE);
    ReleaseSRWLockExclusive(&g_db_key_lock);
    return 0;
}

/* ============================================================================
 * HMAC-SHA256 (keyed) over the raw database bytes
 * ========================================================================== */

int db_hmac_compute_file(const char *db_path, uint8_t out[DB_HMAC_SIZE])
{
    if (!db_path || !out) return -1;

    uint8_t db_key[DB_HMAC_SIZE];
    if (derive_db_key(db_key) != 0) return -1; /* fail-closed */

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
    memcpy(ipad_key, db_key, DB_HMAC_SIZE);
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
