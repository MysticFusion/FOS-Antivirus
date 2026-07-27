#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#define _CRT_SECURE_NO_WARNINGS

#include "signature_scan_sqlite.h"
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

/* ============================================================================
 * Database Initialization
 * ========================================================================== */

SigHashDb* sig_db_open(const char *db_path) {
    if (db_path == NULL)
        return NULL;

    SigHashDb *db = (SigHashDb *)malloc(sizeof(SigHashDb));
    if (!db)
        return NULL;

    db->db = NULL;
    db->lookup_stmt = NULL;
    db->is_open = false;

    /* Use sqlite3_open with URI filename + readonly flag for read-only access */
    char uri[1024];
    snprintf(uri, sizeof(uri), "file:%s?mode=ro", db_path);
    
    int rc = sqlite3_open_v2(uri, &db->db, 
                             SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db->db);
        free(db);
        return NULL;
    }

    /* Prepare the lookup statement for reuse */
    const char *sql = "SELECT threat_label FROM malware_hashes WHERE sha256 = ? LIMIT 1";
    rc = sqlite3_prepare_v2(db->db, sql, -1, &db->lookup_stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db->db);
        free(db);
        return NULL;
    }

    db->is_open = true;
    return db;
}

void sig_db_close(SigHashDb *db) {
    if (!db)
        return;

    if (db->lookup_stmt) {
        sqlite3_finalize(db->lookup_stmt);
        db->lookup_stmt = NULL;
    }

    if (db->db) {
        sqlite3_close(db->db);
        db->db = NULL;
    }

    db->is_open = false;
    free(db);
}

/* ============================================================================
 * Hash Lookup
 * ========================================================================== */

/**
 * @brief Convert 32-byte binary SHA-256 to lowercase hex string.
 * @param bytes The 32-byte hash.
 * @param out_hex The output buffer (must be at least 65 bytes for null terminator).
 */
static void binary_to_hex(const unsigned char bytes[32], char out_hex[65]) {
    for (int i = 0; i < 32; i++) {
        snprintf(&out_hex[i * 2], 3, "%02x", bytes[i]);
    }
    out_hex[64] = '\0';
}

int sig_db_lookup_hash(SigHashDb *db, const unsigned char hash[SHA256_SIZE],
                       const char **out_label) {
    if (!db || !db->is_open || !hash || !out_label)
        return -1;

    /* Convert binary hash to hex string for database lookup */
    char hex_hash[65];
    binary_to_hex(hash, hex_hash);

    /* Bind the hex hash to the prepared statement */
    int rc = sqlite3_bind_text(db->lookup_stmt, 1, hex_hash, 64, SQLITE_STATIC);
    if (rc != SQLITE_OK)
        return -1;

    /* Execute and check for results */
    rc = sqlite3_step(db->lookup_stmt);

    int result = 0;
    if (rc == SQLITE_ROW) {
        *out_label = (const char *)sqlite3_column_text(db->lookup_stmt, 0);
        result = 1;  /* Match found */
    } else if (rc == SQLITE_DONE) {
        *out_label = NULL;
        result = 0;  /* No match */
    } else {
        result = -1;  /* Error */
    }

    sqlite3_reset(db->lookup_stmt);
    return result;
}

int sig_db_get_hash_count(SigHashDb *db) {
    if (!db || !db->is_open)
        return -1;

    sqlite3_stmt *stmt;
    const char *sql = "SELECT COUNT(*) FROM malware_hashes";

    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
        return -1;

    rc = sqlite3_step(stmt);
    int count = -1;

    if (rc == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }

    sqlite3_finalize(stmt);
    return count;
}

/* ============================================================================
 * Database Validation
 * ========================================================================== */

int sig_db_validate(const char *db_path) {
    if (db_path == NULL)
        return -1;

    sqlite3 *db;
    char uri[1024];
    snprintf(uri, sizeof(uri), "file:%s?mode=ro", db_path);
    
    int rc = sqlite3_open_v2(uri, &db, 
                             SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }

    /* Check for required table */
    sqlite3_stmt *stmt;
    const char *sql = "SELECT 1 FROM malware_hashes LIMIT 1";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);

    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
}
