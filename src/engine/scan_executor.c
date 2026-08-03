/**
 * @file scan_executor.c
 * @brief Scan Decision Engine Implementation
 *
 * Implements the 3-layer threat detection decision logic:
 *   - Layer 1: Signature-based detection (deterministic, highest priority)
 *   - Layer 2: Heuristic behavioral filter (rule-based scoring)
 *   - Layer 3: ML-based behavioral analysis (probabilistic)
 *
 * This module aggregates results from all layers and produces a final
 * decision on how to handle the scanned file.
 *
 */

#include "scan_executor.h"

#include <string.h>

/* ============================================================================
 * Configuration Constants
 * ========================================================================== */

/**
 * @brief Heuristic score thresholds.
 *
 * These thresholds determine how heuristic scores are interpreted:
 *   - HEURISTIC_HIGH_RISK (90+): Very suspicious, potential malware
 *   - HEURISTIC_MED_RISK (50-89): Suspicious, warrants monitoring
 *   - Below 50: Likely benign
 *
 * @note High threshold (90) is conservative to reduce false positives.
 */
#define HEURISTIC_HIGH_RISK     90
#define HEURISTIC_MED_RISK      50

/**
 * @brief ML score threshold for triggering a response.
 *
 * Files with ML score above this threshold are considered suspicious.
 * Currently set conservatively since model is not trained on real data.
 */
#define ML_SCORE_THRESHOLD      0.8

/* ============================================================================
 * Private Helper Functions
 * ========================================================================== */

/**
 * @brief Set the decision output with action and reason.
 *
 * @param[out] out     Decision structure to populate
 * @param[in]  action  Response action to take
 * @param[in]  reason  Human-readable explanation
 */
static void set_decision(ScanDecision *out, ResponseAction action, const char *reason)
{
    out->action = action;
    strncpy(out->reason, reason, sizeof(out->reason) - 1);
    out->reason[sizeof(out->reason) - 1] = '\0';
}

/* ============================================================================
 * Public Functions
 * ========================================================================== */

void execute_scan_decision(
    const char            *file_path,
    const SignatureResult *sig,
    const HeuristicResult *heur,
    double                 ml_score,
    TrustLevel             trust,
    ScanDecision          *out
)
{
    /* Suppress unused parameter warning */
    (void)file_path;

    /* Initialize output */
    memset(out, 0, sizeof(*out));

    /* ========================================================================
     * Layer 1: Signature-based Detection (Deterministic)
     * ======================================================================== 
     * 
     * Signature matches have 100% confidence - if a file's hash matches
     * our malware database, it is definitely malware. This is the only
     * layer that guarantees no false positives.
     */
    if (sig != NULL && sig->matched) {
        set_decision(out, ACTION_QUARANTINE, "Signature-based detection");
        return;
    }

    /* ========================================================================
     * Layer 2: Heuristic Behavioral Filter
     * ======================================================================== 
     *
     * Heuristics examine file properties and behaviors. High scores on
     * unsigned files trigger quarantine; signed files are only monitored
     * to prevent breaking legitimate software.
     */
    if (heur != NULL && heur->score >= HEURISTIC_HIGH_RISK) {
        if (trust == TRUST_NONE) {
            /* Unsigned file with very high risk score -> Quarantine */
            set_decision(out, ACTION_QUARANTINE, "High-risk heuristic (unsigned file)");
            return;
        } else {
            /* Signed file with high score -> Monitor only */
            set_decision(out, ACTION_MONITOR, "Suspicious signed file (monitoring)");
            return;
        }
    }

    /* ========================================================================
     * Layer 3: ML-based Behavioral Analysis
     * ======================================================================== 
     *
     * IMPORTANT: Until the model is trained with real malware samples,
     * ML should ONLY MONITOR, NEVER QUARANTINE. This prevents false
     * positives on legitimate software.
     *
     * When a properly trained model is available, this can be changed to
     * ACTION_QUARANTINE for high-confidence detections.
     */
    if (ml_score >= 0.0 && ml_score > ML_SCORE_THRESHOLD) {
        set_decision(out, ACTION_MONITOR, "AI/ML behavioral analysis (monitoring)");
        return;
    }

    /* ========================================================================
     * Medium Risk Heuristic (Monitoring)
     * ======================================================================== 
     *
     * Files with medium heuristic scores on unsigned files are monitored
     * for potential suspicious activity.
     */
    if (heur != NULL && heur->score >= HEURISTIC_MED_RISK && trust == TRUST_NONE) {
        set_decision(out, ACTION_MONITOR, "Medium-risk heuristic (monitoring)");
        return;
    }

    /* ========================================================================
     * Default: Clean File
     * ======================================================================== */
    set_decision(out, ACTION_ALLOW, "No threat detected");
}
