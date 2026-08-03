/**
 * @file response_engine.h
 * @brief Threat Response & Remediation Interface
 *
 * This module handles the mitigation of detected threats, including
 * file quarantine (encryption and isolation) and restoration.
 *
 */

#ifndef RESPONSE_ENGINE_H
#define RESPONSE_ENGINE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/* ============================================================================
 * Public Functions
 * ========================================================================== */

/**
 * @brief Isolate and encrypt a malicious file in the quarantine vault.
 *
 * Moving a file to quarantine renders it inert by encrypting its contents
 * and stripping its original filename/extension to prevent accidental execution.
 *
 * @param[in] src_path     Absolute path of the file to quarantine.
 * @param[in] threat_label Name of the detected threat (e.g., "Trojan.Agent").
 *
 * @return 0 on success, non-zero on failure.
 */
int response_quarantine_file(
    const char *src_path,
    const char *threat_label
);

/**
 * @brief Restore a file from the quarantine vault to its original location.
 *
 * @param[in] q_path        Path to the encrypted file in the quarantine folder.
 * @param[in] dest_override Optional paths to restore to (if NULL, uses original path).
 *
 * @return 0 on success, non-zero on error.
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
