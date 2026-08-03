/**
 * @file ml_engine.h
 * @brief Machine Learning Engine Interface (Decision Forest)
 *
 * Provides the interface for AI-based malware detection using the custom FORE
 * format.
 *
 */

#ifndef ML_ENGINE_H
#define ML_ENGINE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "feature_extract.h"
#include <stdbool.h>

/* ============================================================================
 * Constants
 * ========================================================================== */

#define ML_SCORE_ERROR (-1.0)
#define ML_THRESHOLD_LOW (0.5)
#define ML_THRESHOLD_HIGH (0.8)

/* ============================================================================
 * Public Functions
 * ========================================================================== */

/**
 * @brief Initialize the ML engine.
 *
 * Loads the malware detection model from disk and prepares the inference
 * session. This must be called before ml_engine_scan().
 *
 * @param[in] model_path Path to the .bin model file.
 * @return 0 on success, non-zero on failure.
 */
/**
 * @brief Pre-initialization for synchronization primitives.
 * Call this on the main thread before spawning the init thread.
 */
void ml_engine_pre_init(void);

int ml_engine_init(const char *model_path);

/**
 * @brief Cleanup Machine Learning resources.
 */
void ml_engine_cleanup(void);

/**
 * @brief Perform ML-based behavioral analysis on a file.
 *
 * Runs the Decision Forest model inference on the extracted features.
 *
 * @param[in] features  Pointer to extracted file features structure.
 *
 * @return Probability score [0.0 - 1.0] or ML_SCORE_ERROR.
 */
double ml_engine_scan(const FileFeatures *features);

#ifdef __cplusplus
}
#endif

#endif /* ML_ENGINE_H */
