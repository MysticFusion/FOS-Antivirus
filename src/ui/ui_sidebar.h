/**
 * @file ui_sidebar.h
 * @brief Sidebar Navigation UI Interface
 *
 * Defines the persistent navigation sidebar used for switching between
 * core application views (Dashboard, History, Settings).
 *
 */

#ifndef UI_SIDEBAR_H
#define UI_SIDEBAR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <gtk/gtk.h>
#include "app.h"

/* ============================================================================
 * Public Functions
 * ========================================================================== */

/**
 * @brief Create the sidebar widget and initialize navigation signals.
 * 
 * @param[in,out] app Pointer to the global application state.
 * @return A constructed GTK box acting as the sidebar.
 */
GtkWidget *create_sidebar(AppState *app);

#ifdef __cplusplus
}
#endif

#endif /* UI_SIDEBAR_H */