/**
 * @file trust.h
 * @brief File Trust Evaluation Interface
 *
 * This module provides logic for determining the trust level of files based on
 * their location, digital signatures, and known system status.
 *
 * v1.2: Added quick_mode parameter to trust_evaluate_path(). In quick mode,
 * WinVerifyTrust uses WTD_REVOCATION_CHECK_NONE (no CRL/OCSP checks) instead
 * of WTD_REVOKE_WHOLECHAIN, which is much faster at the cost of not detecting
 * revoked certificates. Full mode (quick_mode=false) retains the original
 * cache-only revocation check behavior.
 */

#ifndef TRUST_H
#define TRUST_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

/* ============================================================================
 * Trust Level Enumeration
 * ========================================================================== */

/**
 * @brief Classification of how much the system trusts a specific file.
 */
typedef enum {
    TRUST_NONE = 0, /**< Unknown or untrusted file (standard scanning applies) */
    TRUST_PARTIAL,  /**< Signed by a known entity or in a standard app directory */
    TRUST_HIGH      /**< Digitally signed by Microsoft or core system component */
} TrustLevel;

/* ============================================================================
 * Public Functions
 * ========================================================================== */

/**
 * @brief Evaluate the trust level for a given file path.
 *
 * Checks digital signatures, install locations, and system attributes.
 *
 * @param[in] path       Absolute path to the file.
 * @param[in] quick_mode If true, skip revocation checking (faster but less
 *                       thorough). Used by quick scan to avoid slow CRL/OCSP
 *                       network checks. If false, use full revocation checking
 *                       with cache-only URL retrieval (original behavior).
 * @return The calculated TrustLevel.
 */
TrustLevel trust_evaluate_path(const char *path, bool quick_mode);

/**
 * @brief Check if a trust level meets or exceeds a requirement.
 * @return Non-zero if actual >= required.
 */
int trust_is_at_least(TrustLevel actual, TrustLevel required);

#ifdef __cplusplus
}
#endif

#endif /* TRUST_H */
