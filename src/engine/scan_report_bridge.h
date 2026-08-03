/**
 * @file scan_report_bridge.h
 * @brief Scan Result Accumulation & Bridge Interface
 *
 * Provides the bridge between low-level detection workers and the high-level
 * decision engine. It manages the lifecycle of scan reports and ensures
 * all tiered detection results are consolidated before a final decision.
 *
 */

#ifndef SCAN_REPORT_BRIDGE_H
#define SCAN_REPORT_BRIDGE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include "scan_core.h"
#include "signature_scan.h"
#include "heuristic_engine.h"

/* ============================================================================
 * Bridge Management
 * ========================================================================== */

/**
 * @brief Initialize the global reporting bridge state.
 */
int scan_report_bridge_init(void);

/**
 * @brief Clean up and release all bridge resources.
 */
void scan_report_bridge_shutdown(void);

/**
 * @brief Check if the bridge is currently idle (no active scan records).
 */
bool scan_report_is_idle(void);

/* ============================================================================
 * Result Submission (Tiered Pipeline Support)
 * ========================================================================== */

/**
 * @brief Submit a signature-based detection result.
 */
void scan_report_submit_signature(
    ScanInput             *input,
    const SignatureResult *sig
);

/**
 * @brief Submit a heuristic-based detection result.
 */
void scan_report_submit_heuristic(
    ScanInput              *input,
    const HeuristicResult *heur
);

/**
 * @brief Complete a tiered scan session and trigger the final decision.
 *
 * This function processes the final aggregated results (Signature + Heuristic + ML)
 * and executes the remediation plan (quarantine/monitor).
 *
 * @param[in,out] input    The processed scan input (will be freed upon return).
 * @param[in]     sig      Aggregated signature result.
 * @param[in]     heur     Aggregated heuristic result.
 * @param[in]     ml_score Final AI/ML confidence score.
 */
void scan_report_submit_complete(
    ScanInput             *input,
    const SignatureResult *sig,
    const HeuristicResult *heur,
    double                 ml_score
);

#ifdef __cplusplus
}
#endif

#endif /* SCAN_REPORT_BRIDGE_H */
