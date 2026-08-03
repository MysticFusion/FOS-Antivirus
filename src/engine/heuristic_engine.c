/**
 * @file heuristic_engine.c
 * @brief Heuristic Analysis Engine Implementation
 *
 * Implements a weighted scoring system based on file metadata, location,
 * content entropy, and behavioral context (e.g., rapid file events).
 *
 */

#include "heuristic_engine.h"
#include "trust.h"

#include <string.h>

/* ============================================================================
 * Configuration Constants
 * ========================================================================== */

/** @brief Minimum score for a file to be considered malicious */
#define THRESHOLD_MALICIOUS   90

/** @brief Minimum score for a file to be considered suspicious */
#define THRESHOLD_SUSPICIOUS  45

/* ============================================================================
 * Internal Helpers
 * ========================================================================== */

/**
 * @brief Safely append an indicator string to the reasoning list.
 */
static void append_reason(char *reasons, size_t max_len, const char *msg)
{
    if (reasons[0] != '\0') {
        strncat(reasons, " ", max_len - strlen(reasons) - 1);
    }
    strncat(reasons, msg, max_len - strlen(reasons) - 1);
}

/* ============================================================================
 * Public Functions
 * ========================================================================== */

void evaluate_heuristics(
    const FileFeatures *f,
    HeuristicResult    *out,
    TrustLevel          trust,
    ScanReason          reason
)
{
    if (f == NULL || out == NULL) {
        return;
    }

    /* Initialize result */
    memset(out, 0, sizeof(*out));

    int  score = 0;
    char reasons[256] = {0};

    /* ========================================================================
     * Base Heuristic Signals (Static Analysis)
     * ======================================================================== */

    if (f->is_executable) {
        score += 20;
        append_reason(reasons, sizeof(reasons), "Executable;");
    }

    if (f->in_temp_dir) {
        score += 25;
        append_reason(reasons, sizeof(reasons), "Temp-dir;");
    }

    if (f->in_startup_dir) {
        score += 35;
        append_reason(reasons, sizeof(reasons), "Startup-loc;");
    }

    if (f->high_entropy) {
        score += 20;
        append_reason(reasons, sizeof(reasons), "High-entropy;");
    }

    /* ========================================================================
     * Strong Signals (Reputation & Behavior)
     * ======================================================================== */

    if (f->known_bad_hash) {
        score = 100; /* Override: Instant high risk */
        append_reason(reasons, sizeof(reasons), "Known-malicious-hash;");
    }

    if (reason == SCAN_REASON_RANSOMWARE_BURST) {
        score += 80;
        append_reason(reasons, sizeof(reasons), "Rapid-file-burst;");
    }

    /* ========================================================================
     * Trust-based Dampening
     * ======================================================================== 
     * 
     * We reduce the risk score for files that have valid digital signatures.
     * System-signed files get the highest dampening.
     */
    switch (trust) {
        case TRUST_HIGH:
            score /= 5;   /* Signed by Microsoft or highly trusted identity */
            break;

        case TRUST_PARTIAL:
            score /= 2;   /* Signed, but not system-level identity */
            break;

        case TRUST_NONE:
        default:
            /* No reduction for unsigned/unknown files */
            break;
    }

    /* ========================================================================
     * Final Classification
     * ======================================================================== */

    if (score >= THRESHOLD_MALICIOUS) {
        out->verdict = VERDICT_MALICIOUS;
    } else if (score >= THRESHOLD_SUSPICIOUS) {
        out->verdict = VERDICT_SUSPICIOUS;
    } else {
        out->verdict = VERDICT_BENIGN;
    }

    out->score = score;

    /* Populate explanation string */
    if (reasons[0] == '\0') {
        strncpy(out->explanation, "Neutral/Benign profile", sizeof(out->explanation) - 1);
    } else {
        strncpy(out->explanation, reasons, sizeof(out->explanation) - 1);
    }
}
