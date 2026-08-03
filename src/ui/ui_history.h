/**
 * @file ui_history.h
 * @brief Detection History View Interface
 *
 * Provides the user interface for viewing and managing (restoring/removing)
 * detected and quarantined threats.
 *
 */

#ifndef UI_HISTORY_H
#define UI_HISTORY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <gtk/gtk.h>
#include "app.h"

/* ============================================================================
 * Public Functions
 * ========================================================================== */

/**
 * @brief Create the detection history view widget.
 * 
 * @param[in,out] app Pointer to the global application state.
 * @return A GTK box containing the history list and controls.
 */
GtkWidget *create_history_view(AppState *app);

/**
 * @brief Force a refresh of the history items from the log file.
 * 
 * @param[in,out] app Pointer to the global application state.
 */
void reload_history_view(AppState *app);

#ifdef __cplusplus
}
#endif

#endif /* UI_HISTORY_H */