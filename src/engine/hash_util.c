#define _CRT_SECURE_NO_WARNINGS
#include "hash_util.h"
#include "path_utils.h"
#include "sha2.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <bcrypt.h>

#define HASH_READ_BUFFER_SIZE 8192
#define MAX_FILE_SIZE_FOR_HASH (500ULL*1024*1024)

int compute_file_sha256_wide(const fos_path_t *path, unsigned char out_hash[SHA256_SIZE]) {
  if (!path || !out_hash) return -1;

  HANDLE hFile = CreateFileW(path->wide, GENERIC_READ, FILE_SHARE_READ,
                             NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile == INVALID_HANDLE_VALUE) return -1;

  // Check file size to prevent huge file DoS
  LARGE_INTEGER fsize;
  if (!GetFileSizeEx(hFile, &fsize) || fsize.QuadPart < 0 ||
      (unsigned long long)fsize.QuadPart > MAX_FILE_SIZE_FOR_HASH) {
    CloseHandle(hFile);
    return -1;
  }

  sha256_ctx ctx;
  sha256_init(&ctx);
  unsigned char buffer[HASH_READ_BUFFER_SIZE];
  DWORD bytes_read;
  while (ReadFile(hFile, buffer, sizeof(buffer), &bytes_read, NULL) && bytes_read > 0) {
    sha256_update(&ctx, buffer, bytes_read);
  }
  DWORD read_err = GetLastError();
  CloseHandle(hFile);
  if (read_err != ERROR_HANDLE_EOF && read_err != ERROR_SUCCESS) return -1;
  sha256_final(&ctx, out_hash);
  return 0;
}

int compute_file_sha256(const char *path, unsigned char out_hash[SHA256_SIZE]) {
  if (!path || !out_hash) return -1;
  fos_path_t fp;
  if (!fos_path_init(&fp, path)) return -1;
  return compute_file_sha256_wide(&fp, out_hash);
}

/* ============================================================================
 * U-15: keyed SipHash-2-4 bucket indexing (anti hash-flooding)
 *
 * The legacy FNV-1a index was attacker-modelable: a crafted signature file
 * could pile every entry into one bucket, degrading lookups from O(1) to
 * O(n). SipHash-2-4 with a per-process random key (BCryptGenRandom, cached
 * after first use) makes the bucket distribution unpredictable. Collisions
 * are still resolved by full 32-byte memcmp, so lookups stay exact; only
 * the DoS amplification is removed. Key generation failure fails CLOSED:
 * table init returns NULL and the DB is refused rather than indexed with a
 * predictable key.
 * ========================================================================== */

#define SIPROUND           \
  do {                     \
    v0 += v1;              \
    v1 = ROTL64(v1, 13);   \
    v1 ^= v0;              \
    v0 = ROTL64(v0, 32);   \
    v2 += v3;              \
    v3 = ROTL64(v3, 16);   \
    v3 ^= v2;              \
    v0 += v3;              \
    v3 = ROTL64(v3, 21);   \
    v3 ^= v0;              \
    v2 += v1;              \
    v1 = ROTL64(v1, 17);   \
    v1 ^= v2;              \
    v2 = ROTL64(v2, 32);   \
  } while (0)

#define ROTL64(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))

static uint64_t u8to64_le(const unsigned char *p) {
  uint64_t v = 0;
  for (int i = 7; i >= 0; i--)
    v = (v << 8) | (uint64_t)p[i];
  return v;
}

/* SipHash-2-4 with a 128-bit key (RFC-compatible reference construction). */
static uint64_t siphash24(const unsigned char *in, size_t len,
                          uint64_t k0, uint64_t k1) {
  uint64_t b = (uint64_t)len << 56;
  uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
  uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
  uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
  uint64_t v3 = 0x7465646279746573ULL ^ k1;

  while (len >= 8) {
    uint64_t m = u8to64_le(in);
    v3 ^= m;
    SIPROUND;
    SIPROUND;
    v0 ^= m;
    in += 8;
    len -= 8;
  }
  for (size_t i = 0; i < len; i++)
    b |= (uint64_t)in[i] << (8 * i);

  v3 ^= b;
  SIPROUND;
  SIPROUND;
  v0 ^= b;

  v2 ^= 0xff;
  SIPROUND;
  SIPROUND;
  SIPROUND;
  SIPROUND;

  return v0 ^ v1 ^ v2 ^ v3;
}

static SRWLOCK g_sipkey_lock = SRWLOCK_INIT;
static uint64_t g_sip_k0 = 0, g_sip_k1 = 0;
static bool g_sip_ready = false;

static bool siphash_key_ready(void) {
  AcquireSRWLockShared(&g_sipkey_lock);
  bool ready = g_sip_ready;
  ReleaseSRWLockShared(&g_sipkey_lock);
  if (ready) return true;

  AcquireSRWLockExclusive(&g_sipkey_lock);
  if (!g_sip_ready) {
    unsigned char key[16];
    NTSTATUS st = BCryptGenRandom(NULL, key, sizeof(key),
                                  BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (st == 0) {
      g_sip_k0 = u8to64_le(key);
      g_sip_k1 = u8to64_le(key + 8);
      g_sip_ready = true;
    }
    /* RNG failure leaves g_sip_ready false -> callers fail closed. */
  }
  bool ok = g_sip_ready;
  ReleaseSRWLockExclusive(&g_sipkey_lock);
  return ok;
}

static uint64_t bucket_index(const unsigned char *data, size_t len,
                             size_t bucket_count) {
  if (!siphash_key_ready()) return UINT64_MAX; /* fail closed */
  return siphash24(data, len, g_sip_k0, g_sip_k1) % (uint64_t)bucket_count;
}

SigHashTable *sig_hash_table_init(size_t bucket_count) {
  if (bucket_count==0 || bucket_count> (1<<24)) return NULL;
  /* U-15: derive the per-process SipHash key up front so a failed CSPRNG
   * surfaces HERE (as a NULL return), not lazily mid-insert. */
  if (!siphash_key_ready()) return NULL;
  SigHashTable *table = calloc(1, sizeof(SigHashTable));
  if (!table) return NULL;
  table->buckets = calloc(bucket_count, sizeof(SigHashItem *));
  if (!table->buckets) { free(table); return NULL; }
  table->bucket_count = bucket_count;
  table->item_count = 0;
  return table;
}

int sig_hash_table_add(SigHashTable *table, const unsigned char hash[SHA256_SIZE], const char *label) {
  if (!table || !hash || !label) return -1;
  if (strlen(label) > 128) return -1;
  uint64_t index = bucket_index(hash, SHA256_SIZE, table->bucket_count);
  if (index == UINT64_MAX) return -1;
  SigHashItem *item = malloc(sizeof(SigHashItem));
  if (!item) return -1;
  memcpy(item->hash, hash, SHA256_SIZE);
  item->label = _strdup(label);
  if (!item->label) { free(item); return -1; }
  item->next = table->buckets[index];
  table->buckets[index] = item;
  table->item_count++;
  return 0;
}

const char *sig_hash_table_lookup(SigHashTable *table, const unsigned char hash[SHA256_SIZE]) {
  if (!table || !hash) return NULL;
  uint64_t index = bucket_index(hash, SHA256_SIZE, table->bucket_count);
  if (index == UINT64_MAX) return NULL;
  SigHashItem *curr = table->buckets[index];
  while (curr) {
    if (memcmp(curr->hash, hash, SHA256_SIZE) == 0) return curr->label;
    curr = curr->next;
  }
  return NULL;
}

void sig_hash_table_free(SigHashTable *table) {
  if (!table) return;
  for (size_t i = 0; i < table->bucket_count; i++) {
    SigHashItem *curr = table->buckets[i];
    while (curr) {
      SigHashItem *temp = curr;
      curr = curr->next;
      free(temp->label);
      free(temp);
    }
  }
  free(table->buckets);
  free(table);
}
