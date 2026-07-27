/**
 * @file signature_scan_sqlite.h
 * @brief SQLite-based signature database interface
 *
 * Provides SQLite support for fast lookups of malware signatures.
 * Maintains backward compatibility with text-based signature files.
 */

#ifndef SIGNATURE_SCAN_SQLITE_H
#define SIGNATURE_SCAN_SQLITE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>
#include <sqlite3.h>

/* ============================================================================
 * Constants
 * ========================================================================== */

#define SHA256_SIZE 32
#define HASH_DB_PATH_MAX 260

/* ============================================================================
 * Database Handle
 * ========================================================================== */

typedef struct {
    sqlite3 *db;
    sqlite3_stmt *lookup_stmt;
    bool is_open;
} SigHashDb;

/* ============================================================================
 * SQLite Database Operations
 * ========================================================================== */

/**
 * @brief Open or create a SQLite malware hash database.
 * @param db_path Path to the SQLite database file.
 * @return Pointer to SigHashDb on success, NULL on failure.
 */
SigHashDb* sig_db_open(const char *db_path);

/**
 * @brief Close and free a SQLite database handle.
 */
void sig_db_close(SigHashDb *db);

/**
 * @brief Lookup a SHA-256 hash in the SQLite database.
 * @param db Database handle.
 * @param hash The 32-byte SHA-256 hash.
 * @param out_label Pointer to store the threat label (caller must not free).
 * @return 1 if found, 0 if not found, -1 on error.
 */
int sig_db_lookup_hash(SigHashDb *db, const unsigned char hash[SHA256_SIZE],
                       const char **out_label);

/**
 * @brief Get statistics about the database.
 * @param db Database handle.
 * @return Number of unique hashes, or -1 on error.
 */
int sig_db_get_hash_count(SigHashDb *db);

/**
 * @brief Validate a SQLite database file.
 * @param db_path Path to the database file.
 * @return 0 if valid, -1 if invalid or not a valid database.
 */
int sig_db_validate(const char *db_path);

#ifdef __cplusplus
}
#endif

#endif /* SIGNATURE_SCAN_SQLITE_H */
