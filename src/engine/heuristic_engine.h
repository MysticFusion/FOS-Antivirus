/**
 * @file heuristic_engine.h
 * @brief Heuristic Analysis Engine Interface
 *
 * This module provides rule-based behavioral analysis to detect suspicious
 * patterns in files that may not yet have a known signature.
 *
 */

#ifndef HEURISTIC_ENGINE_H
#define HEURISTIC_ENGINE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "feature_extract.h"
#include "trust.h"

/* ============================================================================
 * Decision Thresholds (single source of truth)
 *
 * heuristic_engine.c (verdict classification), scan_executor.c (response
 * action) and scan_core.c (double-extension re-derivation) must all agree.
 * They previously drifted (45 vs 50 for the "suspicious / monitor" gate),
 * which made files scored 45-49 log VERDICT_SUSPICIOUS while being
 * ACTION_ALLOW-ed.
 * ========================================================================== */

#define HEURISTIC_SCORE_MALICIOUS  90  /**< Quarantine-grade heuristic score */
#define HEURISTIC_SCORE_SUSPICIOUS 45  /**< Monitor-grade heuristic score  */

/* ============================================================================
 * Threat Verdict Enumeration
 * ========================================================================== */

/**
 * @brief Categorization of a file based on heuristic analysis.
 */
typedef enum {
    VERDICT_BENIGN = 0, /**< File appears safe */
    VERDICT_SUSPICIOUS, /**< File has unusual properties; monitoring recommended */
    VERDICT_MALICIOUS   /**< File exhibits strong indicators of malware */
} ThreatVerdict;

/* ============================================================================
 * Heuristic Result Structure
 * ========================================================================== */

/**
 * @brief Detailed result from a heuristic evaluation.
 */
typedef struct {
    int           score;           /**< Aggregated risk score (0-100+) */
    ThreatVerdict verdict;         /**< Categorized threat level */
    char          explanation[256];/**< Summary of triggered indicators */
} HeuristicResult;

/* ============================================================================
 * Public Functions
 * ========================================================================== */

/**
 * @brief Evaluates file features against heuristic rules.
 *
 * Analyzes static features, trust levels, and scan context to calculate
 * a risk score and verdict.
 *
 * @param[in]  features Pointer to extracted file features.
 * @param[out] out      Pointer to heuristic result structure to be populated.
 * @param[in]  trust    Digital signature trust level of the file.
 * @param[in]  reason   The reason/context for why the scan was triggered.
 */
void evaluate_heuristics(
    const FileFeatures *features,
    HeuristicResult    *out,
    TrustLevel          trust,
    ScanReason          reason
);

#ifdef __cplusplus
}
#endif

#endif /* HEURISTIC_ENGINE_H */
