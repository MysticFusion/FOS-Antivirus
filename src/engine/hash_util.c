#define _CRT_SECURE_NO_WARNINGS
#include "hash_util.h"
#include "path_utils.h"
#include "sha2.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static uint64_t fnv1a_hash(const unsigned char *data, size_t len) {
  uint64_t hash = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < len; i++) {
    hash ^= (uint64_t)data[i];
    hash *= 0x100000001b3ULL;
  }
  return hash;
}

SigHashTable *sig_hash_table_init(size_t bucket_count) {
  if (bucket_count==0 || bucket_count> (1<<24)) return NULL;
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
  uint64_t h = fnv1a_hash(hash, SHA256_SIZE);
  size_t index = h % table->bucket_count;
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
  uint64_t h = fnv1a_hash(hash, SHA256_SIZE);
  size_t index = h % table->bucket_count;
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
