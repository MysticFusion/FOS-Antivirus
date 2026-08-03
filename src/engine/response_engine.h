/**
 * @file response_engine.h
 * @brief Threat Response & Remediation Interface
 *
 * This module handles the mitigation of detected threats, including
 * file quarantine (authenticated encryption + isolation) and restoration.
 *
 * v2 (MAP I-01/I-02/I-11/I-18):
 *   - Quarantine files are encrypted with AES-256-GCM (Windows CNG).
 *   - A machine-bound master key is protected with Windows DPAPI and
 *     stored in the vault as `vault.key`.
 *   - A per-file key is derived with HKDF-SHA256(master_key, file_uuid).
 *   - Original files are securely deleted (3-pass overwrite).
 *   - Legacy XOR `.vir` files (magic 0xDEADCAFE) can still be restored,
 *     with a security warning logged.
 */

#ifndef RESPONSE_ENGINE_H
#define RESPONSE_ENGINE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/* ============================================================================
 * Error Codes
 * ========================================================================== */

#define RESP_ERR_OK           0   /**< Operation succeeded */
#define RESP_ERR_INVALID_ARGS -1  /**< NULL/invalid input arguments */
#define RESP_ERR_IO           -2  /**< File I/O failure */
#define RESP_ERR_FORMAT       -3  /**< Bad quarantine file format */
#define RESP_ERR_TAMPERED     -4  /**< Authentication failed (tampered data) */
#define RESP_ERR_KEY          -5  /**< Vault key unavailable or mismatched */
#define RESP_ERR_DENIED       -6  /**< Operation refused (e.g. bad destination) */

/* ============================================================================
 * Public Functions
 * ========================================================================== */

/**
 * @brief Isolate and encrypt a malicious file in the quarantine vault.
 *
 * The file body is encrypted with AES-256-GCM under a per-file key derived
 * from the DPAPI-protected vault master key. The original file is then
 * securely deleted (random/zero/random overwrite).
 *
 * @param[in] src_path     Absolute path of the file to quarantine.
 * @param[in] threat_label Name of the detected threat (e.g., "Trojan.Agent").
 *
 * @return 0 on success, non-zero (RESP_ERR_*) on failure.
 */
int response_quarantine_file(
    const char *src_path,
    const char *threat_label
);

/**
 * @brief Restore a file from the quarantine vault to its original location.
 *
 * Handles both the current AES-256-GCM format (magic 0xFEEDFACE) and the
 * legacy XOR format (magic 0xDEADCAFE, with a security warning logged).
 *
 * @param[in] q_path        Path to the encrypted file in the quarantine folder.
 * @param[in] dest_override Optional path to restore to (if NULL, uses the
 *                          original path stored in the quarantine file).
 *
 * @return 0 on success, non-zero (RESP_ERR_*) on error.
 */
int response_restore_file(
    const char *q_path,
    const char *dest_override
);

/**
 * @brief Legacy compatibility wrapper for restoring files.
 *
 * @see response_restore_file
 */
int restore_file_from_quarantine(
    const char *q_path,
    const char *dest_override
);

#ifdef __cplusplus
}
#endif

#endif /* RESPONSE_ENGINE_H */
