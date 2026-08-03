/**
 * @file ui_views.h
 * @brief Main View Management Interface
 *
 * Defines the primary dashboards and settings views for the application.
 *
 */

#ifndef UI_VIEWS_H
#define UI_VIEWS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <gtk/gtk.h>
#include "app.h"

/* ============================================================================
 * Public View Creators
 * ========================================================================== */

/**
 * @brief Initialize the main dashboard view (Status monitoring & Quick operations).
 * @param app Pointer to global application state.
 */
GtkWidget *create_dashboard_view(AppState *app);

/**
 * @brief Initialize the settings view (Theming & Auto-update control).
 * @param app Pointer to global application state.
 */
GtkWidget *create_settings_view(AppState *app);

#ifdef __cplusplus
}
#endif

#endif /* UI_VIEWS_H */