/**
 * @file ui_scan.h
 * @brief Scanner UI Subsystem Interface
 *
 * Defines the views and logic for manual scanning, including progress 
 * tracking, results display, and tiered detection coordination.
 *
 */

#ifndef UI_SCAN_H
#define UI_SCAN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <gtk/gtk.h>
#include "app.h"

/* ============================================================================
 * View Creation Functions
 * ========================================================================== */

/**
 * @brief Create the advanced/custom scan setup view.
 */
GtkWidget *create_advanced_scan_view(AppState *app);

/**
 * @brief Create the active scan progress view (spinner and progress bar).
 */
GtkWidget *create_scanner_progress_view(AppState *app);

/**
 * @brief Create the post-scan summary and results view.
 */
GtkWidget *create_scan_complete_view(AppState *app);

/* ============================================================================
 * Scan Logic
 * ========================================================================== */

/**
 * @brief Trigger the scanning pipeline (includes update-checks and background thread).
 * 
 * @param app          The global application state.
 * @param path_or_mode Either an absolute directory path or a mode string 
 *                      (e.g., "QUICK_SCAN", "FULL_SYSTEM").
 */
void start_scan_logic(AppState *app, char *path_or_mode);

#ifdef __cplusplus
}
#endif

#endif /* UI_SCAN_H */