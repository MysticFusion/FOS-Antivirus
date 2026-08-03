/**
 * @file hash_util.h
 * @brief Hashing Utility Interface
 *
 * Provides functions for calculating file hashes (SHA-256) used for
 * signature matching and file identification.
 *
 */

#ifndef HASH_UTIL_H
#define HASH_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/* ============================================================================
 * Constants
 * ========================================================================== */

/** @brief Size of SHA-256 hash in bytes */
#define SHA256_SIZE 32

/* ============================================================================
 * Public Functions
 * ========================================================================== */

/**
 * @brief Calculate the SHA-256 hash of a file.
 *
 * @param[in]  path     Absolute path to the file.
 * @param[out] out_hash Pointer to buffer to receive the 32-byte hash.
 *
 * @return 0 on success, -1 on failure (e.g., file not found or inaccessible).
 */
int compute_file_sha256(
    const char    *path,
    unsigned char  out_hash[SHA256_SIZE]
);

/* ============================================================================
 * Hash Table for Malware Signatures (O(1) Lookups)
 * ========================================================================== */

/** @brief Single entry in the signature hash table */
typedef struct SigHashItem {
    unsigned char       hash[SHA256_SIZE];
    char               *label;
    struct SigHashItem *next; /* Collision chain */
} SigHashItem;

/** @brief The hash table structure */
typedef struct {
    SigHashItem **buckets;
    size_t        bucket_count;
    size_t        item_count;
} SigHashTable;

/**
 * @brief Initialize a signature hash table.
 * @param bucket_count Number of buckets (should be a power of 2 for optimal speed)
 */
SigHashTable* sig_hash_table_init(size_t bucket_count);

/**
 * @brief Add a signature to the hash table.
 */
int sig_hash_table_add(SigHashTable *table, const unsigned char hash[SHA256_SIZE], const char *label);

/**
 * @brief Lookup a signature in the hash table.
 * @return The label if found, NULL otherwise.
 */
const char* sig_hash_table_lookup(SigHashTable *table, const unsigned char hash[SHA256_SIZE]);

/**
 * @brief Free all memory associated with the hash table.
 */
void sig_hash_table_free(SigHashTable *table);

#ifdef __cplusplus
}
#endif

#endif /* HASH_UTIL_H */
