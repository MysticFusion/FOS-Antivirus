/**
 * @file scan_executor.h
 * @brief Scan Decision Engine Interface
 *
 * The scan executor is responsible for making the final decision on how
 * to handle a scanned file based on results from all detection layers:
 *   - Layer 1: Signature-based detection
 *   - Layer 2: Heuristic behavioral analysis
 *   - Layer 3: ML-based behavioral analysis
 *
 */

#ifndef SCAN_EXECUTOR_H
#define SCAN_EXECUTOR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include "signature_scan.h"
#include "heuristic_engine.h"
#include "trust.h"

/* ============================================================================
 * Response Action Enumeration
 * ========================================================================== */

/**
 * @brief Final response action for a scanned file.
 *
 * Defines what action the antivirus should take based on scan results.
 */
typedef enum {
    ACTION_NONE = 0,    /**< No action (internal use) */
    ACTION_ALLOW,       /**< File is safe, allow execution */
    ACTION_MONITOR,     /**< File is suspicious, log and monitor */
    ACTION_QUARANTINE   /**< File is malicious, quarantine immediately */
} ResponseAction;

/* ============================================================================
 * Scan Decision Structure
 * ========================================================================== */

/** @brief Maximum length of decision reason string */
#define SCAN_REASON_MAX_LEN 128

/**
 * @brief Final decision produced by the scan executor.
 *
 * Contains the recommended action and a human-readable explanation
 * of why that decision was made.
 */
typedef struct {
    ResponseAction action;                  /**< Recommended action */
    char           reason[SCAN_REASON_MAX_LEN]; /**< Human-readable reason */
} ScanDecision;

/* ============================================================================
 * Public Functions
 * ========================================================================== */

/**
 * @brief Execute the 3-layer scan decision logic.
 *
 * Analyzes results from signature, heuristic, and ML layers to determine
 * the appropriate response action for a file.
 *
 * Decision Priority:
 *   1. Signature match    -> QUARANTINE (100% confidence)
 *   2. High heuristic     -> QUARANTINE (unsigned) / MONITOR (signed)
 *   3. High ML score      -> MONITOR (until model is properly trained)
 *   4. Medium heuristic   -> MONITOR (unsigned only)
 *   5. Default            -> ALLOW
 *
 * @param[in]  file_path    Path to the scanned file (for logging)
 * @param[in]  sig          Signature scan result (may be NULL)
 * @param[in]  heur         Heuristic scan result (may be NULL)
 * @param[in]  ml_score     ML analysis score [0.0-1.0], or -1.0 if not run
 * @param[in]  trust        Trust level of the file (from digital signature)
 * @param[out] out_decision Output decision structure
 */
void execute_scan_decision(
    const char            *file_path,
    const SignatureResult *sig,
    const HeuristicResult *heur,
    double                 ml_score,
    TrustLevel             trust,
    ScanDecision          *out_decision
);

#ifdef __cplusplus
}
#endif

#endif /* SCAN_EXECUTOR_H */
