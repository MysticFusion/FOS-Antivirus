/**
 * @file signature_scan.h
 * @brief Signature Detection Engine Interface
 *
 * This module provides the interface for loading malware signature databases
 * and performing high-speed hash lookups to identify known threats.
 *
 */

#ifndef SIGNATURE_SCAN_H
#define SIGNATURE_SCAN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
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
 * @param sigdb_path Path to the signature list file.
 * @return 0 on success, -1 on failure.
 */
int signature_db_load(const char *sigdb_path);

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
 * @param db_path Local path where the updated database should be saved.
 * @return 0 on success, non-zero error code on failure.
 */
int update_signature_db(const char *db_path);

/* ============================================================================
 * UI Synchronization
 * ========================================================================== */

/** @brief Current progress percentage of the signature update (0-100, 101=Done) */
extern volatile int update_progress;

#ifdef __cplusplus
}
#endif

#endif /* SIGNATURE_SCAN_H */
