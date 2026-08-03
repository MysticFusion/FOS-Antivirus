#define _CRT_SECURE_NO_WARNINGS

#include "hash_util.h"
#include "sha2.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * Configuration
 * ========================================================================== */

/** @brief Size of the read buffer for hashing (8 KB) */
#define HASH_READ_BUFFER_SIZE 8192

/* ============================================================================
 * Public Functions
 * ========================================================================== */

int compute_file_sha256(const char *path, unsigned char out_hash[SHA256_SIZE]) {
  FILE *f = fopen(path, "rb");
  if (f == NULL) {
    return -1;
  }

  sha256_ctx ctx;
  sha256_init(&ctx);

  unsigned char buffer[HASH_READ_BUFFER_SIZE];
  size_t bytes_read;

  /* Read and update hash in chunks to preserve memory */
  while ((bytes_read = fread(buffer, 1, sizeof(buffer), f)) > 0) {
    sha256_update(&ctx, buffer, bytes_read);
  }

  fclose(f);

  /* Finalize hash calculation */
  sha256_final(&ctx, out_hash);

  return 0;
}

/* ============================================================================
 * Hash Table Implementation
 * ========================================================================== */

/**
 * @brief FNV-1a Hash implementation specifically for the 32-byte SHA256 key.
 */
static uint64_t fnv1a_hash(const unsigned char *data, size_t len) {
  uint64_t hash = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < len; i++) {
    hash ^= (uint64_t)data[i];
    hash *= 0x100000001b3ULL;
  }
  return hash;
}

SigHashTable *sig_hash_table_init(size_t bucket_count) {
  SigHashTable *table = calloc(1, sizeof(SigHashTable));
  if (!table)
    return NULL;

  table->buckets = calloc(bucket_count, sizeof(SigHashItem *));
  if (!table->buckets) {
    free(table);
    return NULL;
  }

  table->bucket_count = bucket_count;
  table->item_count = 0;
  return table;
}

int sig_hash_table_add(SigHashTable *table,
                       const unsigned char hash[SHA256_SIZE],
                       const char *label) {
  if (!table || !hash || !label)
    return -1;

  uint64_t h = fnv1a_hash(hash, SHA256_SIZE);
  size_t index = h % table->bucket_count;

  SigHashItem *item = malloc(sizeof(SigHashItem));
  if (!item)
    return -1;

  memcpy(item->hash, hash, SHA256_SIZE);
  item->label = _strdup(label);
  item->next = table->buckets[index];
  table->buckets[index] = item;

  table->item_count++;
  return 0;
}

const char *sig_hash_table_lookup(SigHashTable *table,
                                  const unsigned char hash[SHA256_SIZE]) {
  if (!table || !hash)
    return NULL;

  uint64_t h = fnv1a_hash(hash, SHA256_SIZE);
  size_t index = h % table->bucket_count;

  SigHashItem *curr = table->buckets[index];
  while (curr) {
    if (memcmp(curr->hash, hash, SHA256_SIZE) == 0) {
      return curr->label;
    }
    curr = curr->next;
  }

  return NULL;
}

void sig_hash_table_free(SigHashTable *table) {
  if (!table)
    return;

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
