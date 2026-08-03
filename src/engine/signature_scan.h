/**
 * @file signature_scan.h
 * @brief Signature Detection Engine Interface
 *
 * This module provides the interface for loading malware signature databases
 * and performing high-speed hash lookups to identify known threats.
 *
 * As of v1.1, the update mechanism shells out to scripts/hash_aggregator.py
 * instead of using WinINet to download directly. The Python aggregator pulls
 * from 5 public no-auth sources (MalwareBazaar, URLhaus, ThreatFox, ESET,
 * TweetFeed) into a single SQLite database. See scripts/hash_aggregator.py
 * for details.
 */

#ifndef SIGNATURE_SCAN_H
#define SIGNATURE_SCAN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>   /* for size_t */
#include <stdint.h>

/* ============================================================================
 * Constants
 * ========================================================================== */

#define SHA256_SIZE 32

/* ============================================================================
 * Data Structures
 * ========================================================================== */

/**
 * @brief Result of a signature database lookup.
 */
typedef struct {
    bool        matched; /**< True if the hash was found in the database */
    const char *label;   /**< Threat classification label (e.g., "Trojan.Agent") */
} SignatureResult;

/* ============================================================================
 * Database Lifecycle
 * ========================================================================== */

/**
 * @brief Load the signature database into memory from a file.
 * @param sigdb_path Path to the signature database file (SQLite or text).
 * @return 0 on success, -1 on failure.
 */
int signature_db_load(const char *sigdb_path);

/**
 * @brief Force-reload the signature database from disk.
 *
 * Replaces any already-loaded in-memory table after a successful update.
 */
int signature_db_reload(const char *sigdb_path);

/**
 * @brief Release the signature database from memory.
 */
void signature_db_unload(void);

/* ============================================================================
 * Public Functions
 * ========================================================================== */

/**
 * @brief Search for a file hash in the loaded signature database.
 * @param[in]  hash       The 32-byte SHA-256 hash to search for.
 * @param[out] out_result Pointer to the result structure to be populated.
 * @return 0 on success, -1 if no database is loaded.
 */
int signature_scan_hash(
    const unsigned char  hash[SHA256_SIZE],
    SignatureResult     *out_result
);

/**
 * @brief Trigger a background download and update of the signature database.
 *
 * As of v1.1 this shells out to scripts/hash_aggregator.py. Progress is
 * reported via the JSONL stream from the Python script's stdout, parsed
 * here and reflected into the update_progress / update_error_code globals.
 *
 * @param db_path Local path where the updated database should be saved.
 * @return 0 on success, non-zero error code on failure.
 */
int update_signature_db(const char *db_path);

/**
 * @brief Check if a SQLite database exists and is valid.
 * @param db_path Path to the SQLite database.
 * @return true if valid SQLite database, false otherwise.
 */
bool signature_db_is_sqlite(const char *db_path);

typedef enum {
    UPDATE_ERR_NONE = 0,
    UPDATE_ERR_NET_INIT,          /**< (legacy) network init failed              */
    UPDATE_ERR_NET_OPEN_URL,      /**< (legacy) URL open failed                   */
    UPDATE_ERR_NET_READ,          /**< (legacy) network read error                */
    UPDATE_ERR_IO_WRITE,          /**< (legacy) file write error                  */
    UPDATE_ERR_EMPTY_DOWNLOAD,    /**< (legacy) server returned empty data        */
    UPDATE_ERR_TRUNCATED_DOWNLOAD,/**< (legacy) incomplete download               */
    UPDATE_ERR_INVALID_ARCHIVE,   /**< (legacy) unsupported archive format        */
    UPDATE_ERR_INVALID_FORMAT,    /**< Database file format invalid               */
    UPDATE_ERR_MOVE_FAILED,       /**< (legacy) file move failed                  */
    UPDATE_ERR_RELOAD_FAILED,     /**< Database reload after update failed        */

    /* New error codes for the Python shell-out path */
    UPDATE_ERR_PYTHON_NOT_FOUND,  /**< python.exe not found on PATH or known locs */
    UPDATE_ERR_SCRIPT_NOT_FOUND,  /**< hash_aggregator.py not found               */
    UPDATE_ERR_PYTHON_FAILED,     /**< Python script exited non-zero              */
    UPDATE_ERR_PYTHON_TIMEOUT,    /**< Python script exceeded timeout             */
    UPDATE_ERR_HMAC_WRITE         /**< DB integrity file could not be written     */
} UpdateErrorCode;

int signature_db_validate_file(const char *sigdb_path);
const char *update_error_code_to_message(int code);

/**
 * @brief Build a full error message including the captured log path and any
 *        error message emitted by the Python aggregator.
 *
 * This is more helpful than update_error_code_to_message() alone because it
 * tells the user WHERE the log file is (e.g. %APPDATA%\FOS-Antivirus\updater.log)
 * and includes any specific error the Python script reported.
 *
 * @param out_buf Buffer to write the message into.
 * @param buf_sz  Size of out_buf.
 * @return Pointer to out_buf (always non-NULL).
 */
char *update_get_full_error_message(char *out_buf, size_t buf_sz);

/* ============================================================================
 * UI Synchronization
 * ========================================================================== */

/** @brief Current progress percentage of the signature update (0-100, 101=Done) */
extern volatile int update_progress;
extern volatile int update_error_code;

#ifdef __cplusplus
}
#endif

#endif /* SIGNATURE_SCAN_H */
