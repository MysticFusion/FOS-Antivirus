/**
 * @file trust.h
 * @brief File Trust Evaluation Interface
 *
 * This module provides logic for determining the trust level of files based on 
 * their location, digital signatures, and known system status.
 *
 */

#ifndef TRUST_H
#define TRUST_H

#ifdef __cplusplus
extern "C" {
#endif

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
 * @param[in] path Absolute path to the file.
 * @return The calculated TrustLevel.
 */
TrustLevel trust_evaluate_path(const char *path);

/**
 * @brief Check if a trust level meets or exceeds a requirement.
 * @return Non-zero if actual >= required.
 */
int trust_is_at_least(TrustLevel actual, TrustLevel required);

#ifdef __cplusplus
}
#endif

#endif /* TRUST_H */
