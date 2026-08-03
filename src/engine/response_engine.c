/**
 * @file response_engine.c
 * @brief Threat Response & Remediation Implementation
 *
 * v2 (MAP P0.1 — issues I-01, I-02, I-11, I-18):
 *   - Replaces the XOR "encryption" (key stored beside the ciphertext) with
 *     AES-256-GCM authenticated encryption via Windows CNG (bcrypt.h).
 *   - Removes the `rand()` fallback for key generation: keys come only from
 *     BCryptGenRandom.
 *   - A 256-bit master key is protected with Windows DPAPI
 *     (CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN) and stored in the vault
 *     as `vault.key`. The key is bound to the user profile (machine-bound if
 *     CRYPTPROTECT_LOCAL_MACHINE semantics are desired later).
 *   - A per-file key is derived via HKDF-SHA256(master_key, file_uuid) and
 *     the file body is encrypted as `[nonce(12)][ciphertext][tag(16)]`.
 *   - Quarantine metadata (original path, threat label, timestamp, size) is
 *     authenticated-encrypted with the same per-file key (separate nonce).
 *   - Secure delete: the original file is overwritten 3 times
 *     (random, zeros, random) with FILE_FLAG_WRITE_THROUGH before removal.
 *   - Legacy `.vir` files (magic 0xDEADCAFE) remain restorable with a
 *     security warning.
 */

#define _CRT_SECURE_NO_WARNINGS

#include "response_engine.h"
#include "app_paths.h"
#include "path_utils.h"

#include <bcrypt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <windows.h>
#include <wincrypt.h>

/* ============================================================================
 * Configuration & Storage Constants
 * ========================================================================== */

#define Q_MAGIC_V2           0xFEEDFACE /* current AES-256-GCM format */
#define Q_MAGIC_V1           0xDEADCAFE /* legacy XOR format */
#define Q_FORMAT_VERSION     2
#define Q_VAULT_KEY_FILE     "vault.key"
#define Q_KEY_MASTER_LEN     32
#define Q_NONCE_LEN          12
#define Q_TAG_LEN            16
#define Q_READ_BUFFER_SIZE   (1024 * 1024) /* 1 MB streaming chunks */
#define Q_SECURE_DELETE_PASSES 3

/* ============================================================================
 * v2 Quarantine File Layout (magic 0xFEEDFACE, version 2)
 *
 *   u32 magic = Q_MAGIC_V2
 *   u32 version = Q_FORMAT_VERSION
 *   u8  nonce_meta[12]
 *   u8  nonce_body[12]
 *   u32 meta_cipher_len
 *   u8  meta_cipher[meta_cipher_len]
 *   u8  meta_tag[16]
 *   u64 body_len
 *   u8  body_cipher[body_len]
 *   u8  body_tag[16]
 *
 * Metadata plaintext (authenticated-encrypted):
 *   u64 timestamp | u32 path_len | u32 label_len | u64 orig_size
 *   u8  path[path_len] | u8  label[label_len]
 * ========================================================================== */

#pragma pack(push, 1)
typedef struct {
    uint64_t timestamp;
    uint32_t path_len;
    uint32_t label_len;
    uint64_t orig_size;
} Qv2MetaHeader;

/* Legacy v1 header (XOR). Kept for backward-compatible restore only. */
typedef struct {
    uint32_t magic;
    uint64_t timestamp;
    uint32_t path_len;
    uint8_t  key[32];
    char     threat_name[64];
} QuarantineHeaderV1;
#pragma pack(pop)

/* ============================================================================
 * Global State
 * ========================================================================== */

static BCRYPT_ALG_HANDLE g_aes_alg = NULL;
static BCRYPT_ALG_HANDLE g_sha256_alg = NULL;
static BCRYPT_ALG_HANDLE g_hmac_sha256_alg = NULL;
static uint8_t g_master_key[Q_KEY_MASTER_LEN];
static bool g_master_key_ready = false;
static CRITICAL_SECTION g_vault_lock;
static INIT_ONCE g_vault_once = INIT_ONCE_STATIC_INIT;

static BOOL CALLBACK init_vault_lock_cb(PINIT_ONCE o, PVOID p, PVOID *c)
{
    (void)o; (void)p; (void)c;
    InitializeCriticalSection(&g_vault_lock);
    return TRUE;
}

/* ============================================================================
 * Crypto Primitives (Windows CNG)
 * ========================================================================== */

static int crypto_ensure_loaded(void)
{
    if (g_aes_alg == NULL &&
        BCryptOpenAlgorithmProvider(&g_aes_alg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) {
        return -1;
    }
    if (BCryptSetProperty(g_aes_alg, BCRYPT_CHAINING_MODE,
                          (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                          sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != 0) {
        return -1;
    }
    if (g_sha256_alg == NULL &&
        BCryptOpenAlgorithmProvider(&g_sha256_alg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0) {
        return -1;
    }
    if (g_hmac_sha256_alg == NULL &&
        BCryptOpenAlgorithmProvider(&g_hmac_sha256_alg, BCRYPT_SHA256_ALGORITHM, NULL,
                                    BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0) {
        return -1;
    }
    return 0;
}

/**
 * @brief HMAC-SHA256 (used to build HKDF). Returns 0 on success.
 */
static int hmac_sha256(const uint8_t *key, size_t key_len,
                       const uint8_t *data, size_t data_len,
                       uint8_t out[32])
{
    BCRYPT_HASH_HANDLE h = NULL;
    if (BCryptCreateHash(g_hmac_sha256_alg, &h, NULL, 0,
                         (PUCHAR)key, (ULONG)key_len, 0) != 0) {
        return -1;
    }
    NTSTATUS s = BCryptHashData(h, (PUCHAR)data, (ULONG)data_len, 0);
    if (s == 0) {
        s = BCryptFinishHash(h, out, 32, 0);
    }
    BCryptDestroyHash(h);
    return (s == 0) ? 0 : -1;
}

/**
 * @brief HKDF-SHA256 (RFC 5869). Returns 0 on success.
 */
static int hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                       const uint8_t *salt, size_t salt_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *out, size_t out_len)
{
    if (out_len > 32 * 255) {
        return -1;
    }

    /* Extract: PRK = HMAC(salt, IKM) */
    uint8_t prk[32];
    if (hmac_sha256(salt, salt_len, ikm, ikm_len, prk) != 0) {
        return -1;
    }

    /* Expand: T(i) = HMAC(PRK, T(i-1) || info || i) */
    uint8_t t_block[32];
    uint8_t prev[32];
    size_t  prev_len = 0;
    size_t  done = 0;
    uint8_t counter = 1;

    while (done < out_len) {
        BCRYPT_HASH_HANDLE h = NULL;
        if (BCryptCreateHash(g_hmac_sha256_alg, &h, NULL, 0, prk, 32, 0) != 0) {
            return -1;
        }
        NTSTATUS s = 0;
        if (prev_len > 0) {
            s = BCryptHashData(h, prev, (ULONG)prev_len, 0);
        }
        if (s == 0 && info_len > 0) {
            s = BCryptHashData(h, (PUCHAR)info, (ULONG)info_len, 0);
        }
        if (s == 0) {
            s = BCryptHashData(h, &counter, 1, 0);
        }
        if (s == 0) {
            s = BCryptFinishHash(h, t_block, 32, 0);
        }
        BCryptDestroyHash(h);
        if (s != 0) {
            return -1;
        }

        size_t take = (out_len - done < 32) ? (out_len - done) : 32;
        memcpy(out + done, t_block, take);
        memcpy(prev, t_block, 32);
        prev_len = 32;
        done += take;
        counter++;
    }

    return 0;
}

/**
 * @brief AES-256-GCM streaming encryption over one message.
 *
 * Uses the CNG chained-call pattern: every call except the last carries
 * BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG and must be a multiple of the block
 * size; the last call clears the flag, may be any length, and produces
 * the authentication tag covering the entire message.
 *
 * @return 0 on success.
 */
static int gcm_encrypt_stream(BCRYPT_KEY_HANDLE key,
                              const uint8_t nonce[Q_NONCE_LEN],
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *in, size_t in_len,
                              uint8_t *out, uint8_t tag[Q_TAG_LEN])
{
    uint8_t mac_ctx[Q_TAG_LEN];
    uint8_t iv_ctx[16];
    memset(iv_ctx, 0, sizeof(iv_ctx));

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = (PUCHAR)nonce;
    info.cbNonce = Q_NONCE_LEN;
    info.pbAuthData = (PUCHAR)aad;
    info.cbAuthData = (ULONG)aad_len;
    info.pbTag = tag;
    info.cbTag = Q_TAG_LEN;
    info.pbMacContext = mac_ctx;
    info.cbMacContext = sizeof(mac_ctx);

    size_t off = 0;
    ULONG cb = 0;
    while (off < in_len) {
        size_t chunk = in_len - off;
        int last = (off + chunk >= in_len);
        if (!last) {
            chunk = (chunk / 16) * 16; /* intermediate calls must be block-aligned */
            if (chunk == 0) {
                return -1;
            }
            info.dwFlags = BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;
        } else {
            info.dwFlags = 0;
        }
        NTSTATUS s = BCryptEncrypt(key, (PUCHAR)(in + off), (ULONG)chunk,
                                   &info, iv_ctx, sizeof(iv_ctx),
                                   out + off, (ULONG)chunk, &cb, 0);
        if (s != 0) {
            return -1;
        }
        off += chunk;
    }
    return 0;
}

/**
 * @brief AES-256-GCM streaming decryption + authentication.
 * @return 0 on success, -1 if the message is invalid/tampered.
 */
static int gcm_decrypt_stream(BCRYPT_KEY_HANDLE key,
                              const uint8_t nonce[Q_NONCE_LEN],
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *in, size_t in_len,
                              uint8_t *out, const uint8_t tag[Q_TAG_LEN])
{
    uint8_t mac_ctx[Q_TAG_LEN];
    uint8_t iv_ctx[16];
    memset(iv_ctx, 0, sizeof(iv_ctx));

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = (PUCHAR)nonce;
    info.cbNonce = Q_NONCE_LEN;
    info.pbAuthData = (PUCHAR)aad;
    info.cbAuthData = (ULONG)aad_len;
    info.pbTag = (PUCHAR)tag;
    info.cbTag = Q_TAG_LEN;
    info.pbMacContext = mac_ctx;
    info.cbMacContext = sizeof(mac_ctx);

    /* The final (last-data) call verifies the tag and returns
     * STATUS_AUTH_TAG_MISMATCH on tampering. */
    size_t off = 0;
    ULONG cb = 0;
    while (off < in_len) {
        size_t chunk = in_len - off;
        int last = (off + chunk >= in_len);
        if (!last) {
            chunk = (chunk / 16) * 16;
            if (chunk == 0) {
                return -1;
            }
            info.dwFlags = BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;
        } else {
            info.dwFlags = 0;
        }
        NTSTATUS s = BCryptDecrypt(key, (PUCHAR)(in + off), (ULONG)chunk,
                                   &info, iv_ctx, sizeof(iv_ctx),
                                   out + off, (ULONG)chunk, &cb, 0);
        if (s != 0) {
            return -1;
        }
        off += chunk;
    }
    return 0;
}

/* ============================================================================
 * DPAPI Master-Key Vault
 * ========================================================================== */

static int dpapi_protect(const uint8_t *data, DWORD data_len,
                         uint8_t **out, DWORD *out_len)
{
    DATA_BLOB in = {(DWORD)data_len, (BYTE *)data};
    DATA_BLOB enc = {0, NULL};
    if (!CryptProtectData(&in, L"FOS-Antivirus Quarantine Vault Key",
                          NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &enc)) {
        return -1;
    }
    *out = enc.pbData;
    *out_len = enc.cbData;
    return 0;
}

static int dpapi_unprotect(const uint8_t *data, DWORD data_len,
                           uint8_t **out, DWORD *out_len)
{
    DATA_BLOB in = {(DWORD)data_len, (BYTE *)data};
    DATA_BLOB dec = {0, NULL};
    if (!CryptUnprotectData(&in, NULL, NULL, NULL, NULL,
                            CRYPTPROTECT_UI_FORBIDDEN, &dec)) {
        return -1;
    }
    *out = dec.pbData;
    *out_len = dec.cbData;
    return 0;
}

/**
 * @brief Load or lazily create the DPAPI-protected vault master key.
 *
 * The key lives at <quarantine_dir>\vault.key and is never stored in
 * plaintext on disk. Returns 0 on success.
 */
static int vault_load_or_create(const char *quarantine_dir, uint8_t key[Q_KEY_MASTER_LEN])
{
    char key_path[MAX_PATH];
    snprintf(key_path, sizeof(key_path), "%s\\%s", quarantine_dir, Q_VAULT_KEY_FILE);

    FILE *f = fopen(key_path, "rb");
    if (f != NULL) {
        uint8_t blob[4096];
        size_t  got = fread(blob, 1, sizeof(blob), f);
        fclose(f);
        if (got == 0 || got == sizeof(blob)) {
            return -1;
        }
        uint8_t *plain = NULL;
        DWORD plain_len = 0;
        if (dpapi_unprotect(blob, (DWORD)got, &plain, &plain_len) != 0) {
            return -1;
        }
        if (plain_len != Q_KEY_MASTER_LEN) {
            LocalFree(plain);
            return -1;
        }
        memcpy(key, plain, Q_KEY_MASTER_LEN);
        LocalFree(plain);
        return 0;
    }

    /* Generate a fresh master key and protect it with DPAPI. */
    uint8_t fresh[Q_KEY_MASTER_LEN];
    if (BCryptGenRandom(NULL, fresh, Q_KEY_MASTER_LEN,
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        return -1;
    }

    uint8_t *blob = NULL;
    DWORD blob_len = 0;
    if (dpapi_protect(fresh, sizeof(fresh), &blob, &blob_len) != 0) {
        return -1;
    }

    f = fopen(key_path, "wb");
    if (f == NULL) {
        LocalFree(blob);
        return -1;
    }
    int ok = (fwrite(blob, 1, blob_len, f) == blob_len) && (fflush(f) == 0);
    fclose(f);
    LocalFree(blob);

    if (!ok) {
        DeleteFileA(key_path);
        return -1;
    }

    memcpy(key, fresh, Q_KEY_MASTER_LEN);
    return 0;
}

/**
 * @brief Get the vault master key (thread-safe, cached).
 */
static int vault_get_master_key(const uint8_t **key)
{
    InitOnceExecuteOnce(&g_vault_once, init_vault_lock_cb, NULL, NULL);
    EnterCriticalSection(&g_vault_lock);

    if (!g_master_key_ready) {
        if (crypto_ensure_loaded() != 0) {
            LeaveCriticalSection(&g_vault_lock);
            return -1;
        }
        const char *qdir = app_path_quarantine_dir();
        if (qdir == NULL ||
            vault_load_or_create(qdir, g_master_key) != 0) {
            LeaveCriticalSection(&g_vault_lock);
            return -1;
        }
        g_master_key_ready = true;
    }

    *key = g_master_key;
    LeaveCriticalSection(&g_vault_lock);
    return 0;
}

/**
 * @brief Derive the per-file AES-256 key: HKDF-SHA256(master, file_uuid).
 *
 * `file_uuid` is the quarantine artifact's file name without extension,
 * which makes every quarantined file use a unique key.
 */
static int vault_derive_file_key(const char *file_uuid, uint8_t key[32])
{
    const uint8_t *master = NULL;
    if (vault_get_master_key(&master) != 0) {
        return -1;
    }
    static const uint8_t info[] = "FOS-Antivirus-Quarantine-v2";
    return hkdf_sha256(master, Q_KEY_MASTER_LEN,
                       (const uint8_t *)file_uuid, strlen(file_uuid),
                       info, sizeof(info) - 1, key, 32);
}

/* ============================================================================
 * Internal Helpers
 * ========================================================================== */

static void log_to_history(
    const char *threat_label,
    const char *orig_path,
    const char *q_path)
{
    FILE *f = fopen(app_path_history_log(), "a");
    if (f == NULL) {
        return;
    }
    time_t now = time(NULL);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));
    fprintf(f, "%s|%s|%s|%s\n", time_str, threat_label, orig_path, q_path);
    fclose(f);
}

static void log_security_warning(const char *msg)
{
    FILE *f = fopen(app_path_heuristics_log(), "a");
    if (f == NULL) {
        return;
    }
    time_t now = time(NULL);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));
    fprintf(f, "[%s] SECURITY-WARNING=%s\n", time_str, msg);
    fclose(f);
}

static void create_parent_dirs(const char *path)
{
    char tmp[MAX_PATH];
    strncpy(tmp, path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    for (char *p = tmp; *p; ++p) {
        if (*p != '\\' && *p != '/') {
            continue;
        }
        if (p == tmp || (p > tmp && p[-1] == ':')) {
            continue;
        }
        char old = *p;
        *p = '\0';
        CreateDirectoryA(tmp, NULL);
        *p = old;
    }
}

/**
 * @brief Overwrite a file 3 times (random, zeros, random) with
 *        FILE_FLAG_WRITE_THROUGH, then delete it.
 * @return 0 on success.
 */
static int secure_delete(const fos_path_t *src)
{
    HANDLE h = fos_create_file(src, GENERIC_WRITE, 0, OPEN_EXISTING,
                               FILE_FLAG_WRITE_THROUGH | FILE_FLAG_SEQUENTIAL_SCAN);
    if (h == INVALID_HANDLE_VALUE) {
        /* Nothing to overwrite — just try to remove it. */
        return fos_delete_file(src) ? 0 : -1;
    }

    LARGE_INTEGER size;
    if (!GetFileSizeEx(h, &size)) {
        CloseHandle(h);
        return fos_delete_file(src) ? 0 : -1;
    }

    uint8_t buffer[65536];
    uint8_t zeros[65536];
    memset(zeros, 0, sizeof(zeros));

    for (int pass = 0; pass < Q_SECURE_DELETE_PASSES; pass++) {
        BOOL random = (pass != 1); /* pass 1 = zeros */
        LARGE_INTEGER remaining = size;
        SetFilePointerEx(h, remaining, NULL, FILE_BEGIN);
        while (remaining.QuadPart > 0) {
            DWORD chunk = (remaining.QuadPart > (LONGLONG)sizeof(buffer))
                              ? (DWORD)sizeof(buffer) : (DWORD)remaining.QuadPart;
            if (random) {
                BCryptGenRandom(NULL, buffer, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            } else {
                memcpy(buffer, zeros, chunk);
            }
            DWORD written = 0;
            if (!WriteFile(h, buffer, chunk, &written, NULL) || written != chunk) {
                CloseHandle(h);
                fos_delete_file(src);
                return -1;
            }
            remaining.QuadPart -= (LONGLONG)written;
        }
        if (!FlushFileBuffers(h)) {
            CloseHandle(h);
            fos_delete_file(src);
            return -1;
        }
    }

    CloseHandle(h);
    return fos_delete_file(src) ? 0 : -1;
}

/* ============================================================================
 * Public Functions
 * ========================================================================== */

int response_quarantine_file(const char *src_path, const char *threat_label)
{
    if (src_path == NULL || threat_label == NULL || src_path[0] == '\0') {
        return RESP_ERR_INVALID_ARGS;
    }
    if (crypto_ensure_loaded() != 0) {
        return RESP_ERR_KEY;
    }

    /* Ensure the vault directory exists */
    const char *quarantine_dir = app_path_quarantine_dir();
    if (quarantine_dir == NULL) {
        return RESP_ERR_IO;
    }
    create_parent_dirs(quarantine_dir);

    /* Force vault key materialisation up front (fail closed). */
    const uint8_t *unused = NULL;
    if (vault_get_master_key(&unused) != 0) {
        return RESP_ERR_KEY;
    }

    /* Generate an isolated filename in the vault */
    const char *orig_filename = strrchr(src_path, '\\');
    orig_filename = (orig_filename != NULL) ? orig_filename + 1 : src_path;

    fos_path_t src, dst;
    if (!fos_path_init(&src, src_path)) {
        return RESP_ERR_INVALID_ARGS;
    }

    char dst_utf8[MAX_PATH];
    snprintf(dst_utf8, sizeof(dst_utf8), "%s\\%llu_%s.vir",
             quarantine_dir, GetTickCount64(), orig_filename);
    if (!fos_path_init(&dst, dst_utf8)) {
        return RESP_ERR_IO;
    }

    /* Per-file key, salted with the vault artifact file name (the UUID). */
    char uuid[256];
    strncpy(uuid, dst_utf8 + strlen(quarantine_dir) + 1, sizeof(uuid) - 1);
    uuid[sizeof(uuid) - 1] = '\0';
    char *dot = strrchr(uuid, '.');
    if (dot) *dot = '\0';

    uint8_t file_key[32];
    if (vault_derive_file_key(uuid, file_key) != 0) {
        return RESP_ERR_KEY;
    }

    HANDLE fin = fos_create_file(&src, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, 0);
    if (fin == INVALID_HANDLE_VALUE) {
        return RESP_ERR_IO;
    }
    HANDLE fout = fos_create_file(&dst, GENERIC_WRITE, 0, CREATE_ALWAYS,
                                  FILE_ATTRIBUTE_NORMAL);
    if (fout == INVALID_HANDLE_VALUE) {
        CloseHandle(fin);
        return RESP_ERR_IO;
    }

    LARGE_INTEGER fs;
    if (!GetFileSizeEx(fin, &fs) || fs.QuadPart < 0) {
        CloseHandle(fin);
        CloseHandle(fout);
        DeleteFileW(fos_path_w(&dst));
        return RESP_ERR_IO;
    }
    uint64_t body_len = (uint64_t)fs.QuadPart;

    /* --- Encrypt metadata --- */
    size_t path_len = strlen(src_path);
    size_t label_len = strlen(threat_label);
    if (path_len > 32760 || label_len > 255) {
        CloseHandle(fin);
        CloseHandle(fout);
        DeleteFileW(fos_path_w(&dst));
        return RESP_ERR_INVALID_ARGS;
    }

    Qv2MetaHeader meta_hdr;
    memset(&meta_hdr, 0, sizeof(meta_hdr));
    meta_hdr.timestamp = (uint64_t)time(NULL);
    meta_hdr.path_len = (uint32_t)path_len;
    meta_hdr.label_len = (uint32_t)label_len;
    meta_hdr.orig_size = body_len;

    size_t meta_plain_len = sizeof(meta_hdr) + path_len + label_len;
    uint8_t *meta_plain = (uint8_t *)malloc(meta_plain_len);
    if (meta_plain == NULL) {
        CloseHandle(fin);
        CloseHandle(fout);
        DeleteFileW(fos_path_w(&dst));
        return RESP_ERR_IO;
    }
    memcpy(meta_plain, &meta_hdr, sizeof(meta_hdr));
    memcpy(meta_plain + sizeof(meta_hdr), src_path, path_len);
    memcpy(meta_plain + sizeof(meta_hdr) + path_len, threat_label, label_len);

    uint8_t nonce_meta[Q_NONCE_LEN], nonce_body[Q_NONCE_LEN];
    BCryptGenRandom(NULL, nonce_meta, sizeof(nonce_meta), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    BCryptGenRandom(NULL, nonce_body, sizeof(nonce_body), BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    /* AAD binds the header to the ciphertexts. */
    uint8_t aad[8];
    uint32_t magic = Q_MAGIC_V2;
    uint32_t version = Q_FORMAT_VERSION;
    memcpy(aad, &magic, 4);
    memcpy(aad + 4, &version, 4);

    uint8_t meta_tag[Q_TAG_LEN];
    uint8_t *meta_cipher = (uint8_t *)malloc(meta_plain_len);
    if (meta_cipher == NULL) {
        free(meta_plain);
        CloseHandle(fin);
        CloseHandle(fout);
        DeleteFileW(fos_path_w(&dst));
        return RESP_ERR_IO;
    }

    BCRYPT_KEY_HANDLE bkey = NULL;
    if (BCryptGenerateSymmetricKey(g_aes_alg, &bkey, NULL, 0, file_key, 32, 0) != 0) {
        free(meta_plain);
        free(meta_cipher);
        CloseHandle(fin);
        CloseHandle(fout);
        DeleteFileW(fos_path_w(&dst));
        return RESP_ERR_KEY;
    }

    int ok = 0;
    if (gcm_encrypt_stream(bkey, nonce_meta, aad, sizeof(aad),
                           meta_plain, meta_plain_len, meta_cipher, meta_tag) != 0) {
        ok = -1;
    }

    /* --- Encrypt body (streamed) --- */
    uint32_t meta_cipher_len = (uint32_t)meta_plain_len;
    uint8_t body_tag[Q_TAG_LEN];
    memset(body_tag, 0, sizeof(body_tag));

    /* Persist header + encrypted metadata first, so the body can be streamed
     * straight to disk. Layout:
     * [magic(4)][version(4)][nonce_meta(12)][nonce_body(12)]
     * [meta_cipher_len(4)][meta_cipher][meta_tag(16)]
     * [body_len(8)][body_cipher][body_tag(16)] */
    uint32_t out_magic = Q_MAGIC_V2;
    uint32_t out_version = Q_FORMAT_VERSION;

    if (ok == 0) {
        DWORD wrote = 0;
        ok = -1;
        if (WriteFile(fout, &out_magic, 4, &wrote, NULL) && wrote == 4 &&
            WriteFile(fout, &out_version, 4, &wrote, NULL) && wrote == 4 &&
            WriteFile(fout, nonce_meta, sizeof(nonce_meta), &wrote, NULL) && wrote == sizeof(nonce_meta) &&
            WriteFile(fout, nonce_body, sizeof(nonce_body), &wrote, NULL) && wrote == sizeof(nonce_body) &&
            WriteFile(fout, &meta_cipher_len, 4, &wrote, NULL) && wrote == 4 &&
            WriteFile(fout, meta_cipher, meta_cipher_len, &wrote, NULL) && wrote == meta_cipher_len &&
            WriteFile(fout, meta_tag, sizeof(meta_tag), &wrote, NULL) && wrote == sizeof(meta_tag) &&
            WriteFile(fout, &body_len, 8, &wrote, NULL) && wrote == 8) {
            ok = 0;
        }
    }

    if (ok == 0 && body_len > 0) {
        /* CNG chained multi-part GCM: intermediate calls carry
         * BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG and must be block-aligned;
         * the final call clears the flag and computes the tag that
         * authenticates the entire body. */
        uint8_t mac_ctx[Q_TAG_LEN];
        uint8_t iv_ctx[16];
        memset(iv_ctx, 0, sizeof(iv_ctx));

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
        BCRYPT_INIT_AUTH_MODE_INFO(info);
        info.pbNonce = nonce_body;
        info.cbNonce = sizeof(nonce_body);
        info.pbAuthData = aad;
        info.cbAuthData = sizeof(aad);
        info.pbTag = body_tag;
        info.cbTag = sizeof(body_tag);
        info.pbMacContext = mac_ctx;
        info.cbMacContext = sizeof(mac_ctx);

        uint8_t *chunk_in = (uint8_t *)malloc(Q_READ_BUFFER_SIZE);
        uint8_t *chunk_out = (uint8_t *)malloc(Q_READ_BUFFER_SIZE);
        if (chunk_in == NULL || chunk_out == NULL) {
            ok = -1;
        }
        uint64_t remaining = body_len;
        while (ok == 0 && remaining > 0) {
            DWORD chunk = (remaining > Q_READ_BUFFER_SIZE)
                              ? (DWORD)Q_READ_BUFFER_SIZE : (DWORD)remaining;
            int last = (chunk == remaining);
            if (!last) {
                chunk = (chunk / 16) * 16; /* intermediate calls must be aligned */
                info.dwFlags = BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;
            } else {
                info.dwFlags = 0;
            }
            DWORD got = 0;
            if (!ReadFile(fin, chunk_in, chunk, &got, NULL) || got != chunk) {
                ok = -1;
                break;
            }
            ULONG cb = 0;
            NTSTATUS s = BCryptEncrypt(bkey, chunk_in, got, &info,
                                       iv_ctx, sizeof(iv_ctx),
                                       chunk_out, got, &cb, 0);
            if (s != 0) {
                ok = -1;
                break;
            }
            DWORD wrote = 0;
            if (cb != got || !WriteFile(fout, chunk_out, cb, &wrote, NULL) || wrote != cb) {
                ok = -1;
                break;
            }
            remaining -= got;
        }
        if (ok == 0) {
            DWORD wrote = 0;
            if (!WriteFile(fout, body_tag, sizeof(body_tag), &wrote, NULL) || wrote != sizeof(body_tag)) {
                ok = -1;
            }
        }
        free(chunk_in);
        free(chunk_out);
    }
    if (ok == 0 && !FlushFileBuffers(fout)) {
        ok = -1;
    }

    free(meta_plain);
    free(meta_cipher);
    BCryptDestroyKey(bkey);
    CloseHandle(fin);
    CloseHandle(fout);

    if (ok != 0) {
        DeleteFileW(fos_path_w(&dst));
        return RESP_ERR_IO;
    }

    /* Securely delete the original file (3-pass overwrite). */
    if (secure_delete(&src) != 0) {
        /* The vault copy is intact; report the failure but keep the copy. */
        log_security_warning("secure delete failed; original left in place");
        return RESP_ERR_IO;
    }

    log_to_history(threat_label, src_path, dst_utf8);
    return RESP_ERR_OK;
}

/* ============================================================================
 * Restore
 * ========================================================================== */

int response_restore_file(const char *q_path, const char *dest_override)
{
    if (q_path == NULL || q_path[0] == '\0') {
        return RESP_ERR_INVALID_ARGS;
    }
    if (crypto_ensure_loaded() != 0) {
        return RESP_ERR_KEY;
    }

    fos_path_t q;
    if (!fos_path_init(&q, q_path)) {
        return RESP_ERR_INVALID_ARGS;
    }

    HANDLE fin = fos_create_file(&q, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, 0);
    if (fin == INVALID_HANDLE_VALUE) {
        return RESP_ERR_IO;
    }

    uint32_t magic = 0;
    DWORD got = 0;
    if (!ReadFile(fin, &magic, 4, &got, NULL) || got != 4) {
        CloseHandle(fin);
        return RESP_ERR_FORMAT;
    }

    /* ---- Legacy XOR format (0xDEADCAFE) ---- */
    if (magic == Q_MAGIC_V1) {
        SetFilePointer(fin, 0, NULL, FILE_BEGIN);
        QuarantineHeaderV1 header;
        if (!ReadFile(fin, &header, sizeof(header), &got, NULL) ||
            got != sizeof(header) || header.magic != Q_MAGIC_V1) {
            CloseHandle(fin);
            return RESP_ERR_FORMAT;
        }
        if (header.path_len == 0 || header.path_len > 32768) {
            CloseHandle(fin);
            return RESP_ERR_FORMAT;
        }

        char *stored_path = (char *)malloc(header.path_len + 1);
        if (stored_path == NULL) {
            CloseHandle(fin);
            return RESP_ERR_IO;
        }
        if (!ReadFile(fin, stored_path, header.path_len, &got, NULL) ||
            got != header.path_len) {
            free(stored_path);
            CloseHandle(fin);
            return RESP_ERR_FORMAT;
        }
        stored_path[header.path_len] = '\0';

        log_security_warning(
            "restoring legacy XOR-quarantined file (insecure v1 format)");

        const char *target_dest = (dest_override != NULL) ? dest_override : stored_path;
        if (target_dest[0] == '\0') {
            free(stored_path);
            CloseHandle(fin);
            return RESP_ERR_DENIED;
        }
        create_parent_dirs(target_dest);

        fos_path_t dst;
        if (!fos_path_init(&dst, target_dest)) {
            free(stored_path);
            CloseHandle(fin);
            return RESP_ERR_DENIED;
        }
        HANDLE fout = fos_create_file(&dst, GENERIC_WRITE, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL);
        if (fout == INVALID_HANDLE_VALUE) {
            free(stored_path);
            CloseHandle(fin);
            return RESP_ERR_DENIED;
        }

        int restore_ok = 1;
        uint8_t buffer[Q_READ_BUFFER_SIZE];
        while (ReadFile(fin, buffer, sizeof(buffer), &got, NULL) && got > 0) {
            for (DWORD i = 0; i < got; i++) {
                buffer[i] ^= header.key[i % 32];
            }
            DWORD wrote = 0;
            if (!WriteFile(fout, buffer, got, &wrote, NULL) || wrote != got) {
                restore_ok = 0;
                break;
            }
        }
        if (restore_ok && !FlushFileBuffers(fout)) {
            restore_ok = 0;
        }
        CloseHandle(fout);
        CloseHandle(fin);
        free(stored_path);

        if (!restore_ok) {
            return RESP_ERR_IO;
        }
        fos_delete_file(&q);
        return RESP_ERR_OK;
    }

    /* ---- Current AES-256-GCM format (0xFEEDFACE) ---- */
    if (magic != Q_MAGIC_V2) {
        CloseHandle(fin);
        return RESP_ERR_FORMAT;
    }

    uint32_t version = 0;
    uint8_t nonce_meta[Q_NONCE_LEN], nonce_body[Q_NONCE_LEN];
    uint32_t meta_cipher_len = 0;
    if (!ReadFile(fin, &version, 4, &got, NULL) || got != 4 ||
        !ReadFile(fin, nonce_meta, sizeof(nonce_meta), &got, NULL) || got != sizeof(nonce_meta) ||
        !ReadFile(fin, nonce_body, sizeof(nonce_body), &got, NULL) || got != sizeof(nonce_body) ||
        !ReadFile(fin, &meta_cipher_len, 4, &got, NULL) || got != 4) {
        CloseHandle(fin);
        return RESP_ERR_FORMAT;
    }
    if (version != Q_FORMAT_VERSION || meta_cipher_len == 0 || meta_cipher_len > 1024 * 1024) {
        CloseHandle(fin);
        return RESP_ERR_FORMAT;
    }

    uint8_t *meta_cipher = (uint8_t *)malloc(meta_cipher_len);
    uint8_t meta_tag[Q_TAG_LEN];
    uint64_t body_len = 0;
    if (meta_cipher == NULL) {
        CloseHandle(fin);
        return RESP_ERR_IO;
    }
    if (!ReadFile(fin, meta_cipher, meta_cipher_len, &got, NULL) || got != meta_cipher_len ||
        !ReadFile(fin, meta_tag, sizeof(meta_tag), &got, NULL) || got != sizeof(meta_tag) ||
        !ReadFile(fin, &body_len, 8, &got, NULL) || got != 8) {
        free(meta_cipher);
        CloseHandle(fin);
        return RESP_ERR_FORMAT;
    }

    /* Derive the file key from the vault artifact name (UUID). */
    char uuid[256];
    {
        const char *name = strrchr(q_path, '\\');
        name = (name != NULL) ? name + 1 : q_path;
        strncpy(uuid, name, sizeof(uuid) - 1);
        uuid[sizeof(uuid) - 1] = '\0';
        char *dot = strrchr(uuid, '.');
        if (dot) *dot = '\0';
    }

    uint8_t file_key[32];
    if (vault_derive_file_key(uuid, file_key) != 0) {
        free(meta_cipher);
        CloseHandle(fin);
        return RESP_ERR_KEY;
    }

    BCRYPT_KEY_HANDLE bkey = NULL;
    if (BCryptGenerateSymmetricKey(g_aes_alg, &bkey, NULL, 0, file_key, 32, 0) != 0) {
        free(meta_cipher);
        CloseHandle(fin);
        return RESP_ERR_KEY;
    }

    uint8_t aad[8];
    memcpy(aad, &magic, 4);
    memcpy(aad + 4, &version, 4);

    uint8_t *meta_plain = (uint8_t *)malloc(meta_cipher_len);
    if (meta_plain == NULL) {
        BCryptDestroyKey(bkey);
        free(meta_cipher);
        CloseHandle(fin);
        return RESP_ERR_IO;
    }

    if (gcm_decrypt_stream(bkey, nonce_meta, aad, sizeof(aad),
                           meta_cipher, meta_cipher_len, meta_plain, meta_tag) != 0) {
        BCryptDestroyKey(bkey);
        free(meta_cipher);
        free(meta_plain);
        CloseHandle(fin);
        return RESP_ERR_TAMPERED;
    }

    Qv2MetaHeader meta_hdr;
    memcpy(&meta_hdr, meta_plain, sizeof(meta_hdr));
    if (meta_hdr.path_len > 32760 || meta_hdr.label_len > 255 ||
        sizeof(meta_hdr) + (size_t)meta_hdr.path_len + meta_hdr.label_len != (size_t)meta_cipher_len) {
        BCryptDestroyKey(bkey);
        free(meta_cipher);
        free(meta_plain);
        CloseHandle(fin);
        return RESP_ERR_FORMAT;
    }

    char *stored_path = (char *)malloc((size_t)meta_hdr.path_len + 1);
    if (stored_path == NULL) {
        BCryptDestroyKey(bkey);
        free(meta_cipher);
        free(meta_plain);
        CloseHandle(fin);
        return RESP_ERR_IO;
    }
    memcpy(stored_path, meta_plain + sizeof(meta_hdr), meta_hdr.path_len);
    stored_path[meta_hdr.path_len] = '\0';

    const char *target_dest = (dest_override != NULL) ? dest_override : stored_path;
    if (target_dest[0] == '\0') {
        free(stored_path);
        BCryptDestroyKey(bkey);
        free(meta_cipher);
        free(meta_plain);
        CloseHandle(fin);
        return RESP_ERR_DENIED;
    }
    create_parent_dirs(target_dest);

    fos_path_t dst;
    if (!fos_path_init(&dst, target_dest)) {
        free(stored_path);
        BCryptDestroyKey(bkey);
        free(meta_cipher);
        free(meta_plain);
        CloseHandle(fin);
        return RESP_ERR_DENIED;
    }
    HANDLE fout = fos_create_file(&dst, GENERIC_WRITE, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL);
    if (fout == INVALID_HANDLE_VALUE) {
        free(stored_path);
        BCryptDestroyKey(bkey);
        free(meta_cipher);
        free(meta_plain);
        CloseHandle(fin);
        return RESP_ERR_DENIED;
    }

    /* Stream body: read body_len ciphertext + 16-byte tag, decrypt+verify. */
    int restore_ok = 0;
    uint8_t body_tag[Q_TAG_LEN];
    if (body_len > 0) {
        uint8_t *body_cipher = (uint8_t *)malloc((size_t)body_len);
        if (body_cipher != NULL) {
            ULONGLONG total = 0;
            DWORD chunk = (DWORD)((body_len > Q_READ_BUFFER_SIZE) ? Q_READ_BUFFER_SIZE : body_len);
            while (total < body_len) {
                if (chunk > body_len - (uint64_t)total) chunk = (DWORD)(body_len - (uint64_t)total);
                if (!ReadFile(fin, body_cipher + total, chunk, &got, NULL) || got != chunk) {
                    break;
                }
                total += chunk;
            }
            if (total == body_len &&
                ReadFile(fin, body_tag, sizeof(body_tag), &got, NULL) && got == sizeof(body_tag)) {
                uint8_t *body_plain = (uint8_t *)malloc((size_t)body_len);
                if (body_plain != NULL) {
                    if (gcm_decrypt_stream(bkey, nonce_body, aad, sizeof(aad),
                                           body_cipher, (size_t)body_len,
                                           body_plain, body_tag) == 0) {
                        ULONGLONG off = 0;
                        while (off < body_len) {
                            DWORD c = (DWORD)((body_len - off > Q_READ_BUFFER_SIZE) ? Q_READ_BUFFER_SIZE : body_len - off);
                            DWORD wrote = 0;
                            if (!WriteFile(fout, body_plain + off, c, &wrote, NULL) || wrote != c) {
                                break;
                            }
                            off += c;
                        }
                        if (off == body_len) restore_ok = 1;
                    } else {
                        restore_ok = -1; /* tampered */
                    }
                    free(body_plain);
                }
            }
            free(body_cipher);
        }
    } else {
        restore_ok = 1;
    }

    free(stored_path);
    BCryptDestroyKey(bkey);
    free(meta_cipher);
    free(meta_plain);
    CloseHandle(fin);

    if (restore_ok == -1) {
        CloseHandle(fout);
        fos_delete_file(&dst);
        return RESP_ERR_TAMPERED;
    }
    if (restore_ok != 1 || !FlushFileBuffers(fout)) {
        CloseHandle(fout);
        fos_delete_file(&dst);
        return RESP_ERR_IO;
    }
    CloseHandle(fout);

    fos_delete_file(&q);
    return RESP_ERR_OK;
}

int restore_file_from_quarantine(const char *q_path, const char *dest_override)
{
    return response_restore_file(q_path, dest_override);
}
