/**
 * @file scan_progress.h
 * @brief Thread-safe Scan Progress Tracking Interface
 *
 * Provides a global mechanism for tracking and retrieving the progress
 * of active scan operations for UI display.
 *
 */

#ifndef SCAN_PROGRESS_H
#define SCAN_PROGRESS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

/* ============================================================================
 * State Management Functions
 * ========================================================================== */

/**
 * @brief Reset and start progress tracking for a new scan.
 * @param total_files Estimated total number of files to scan.
 */
void scan_progress_start(int total_files);

/**
 * @brief Update progress with the current file being processed.
 * @param path Absolute path of the file.
 */
void scan_progress_file_start(const char *path);

/**
 * @brief Update progress counters when a file scan is finished.
 * @param threat_found True if the file was detected as a threat.
 */
void scan_progress_file_done(bool threat_found);

/**
 * @brief Mark the scan operation as finished.
 */
void scan_progress_finish(void);

/* ============================================================================
 * UI Polling Helpers
 * ========================================================================== */

/** @return True if a scan is currently running. */
bool scan_progress_is_running(void);

/** @return Number of files scanned in the current session. */
int scan_progress_files_scanned(void);

/** @return Number of threats detected in the current session. */
int scan_progress_threats_found(void);

/** @return Path of the file currently being processed. */
const char *scan_progress_current_file(void);

#ifdef __cplusplus
}
#endif

#endif /* SCAN_PROGRESS_H */
