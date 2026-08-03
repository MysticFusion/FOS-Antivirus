/**
 * @file ui_update.h
 * @brief Virus Definition Update UI Interface
 *
 * Provides functions for checking, triggering, and monitoring malware
 * database updates both automatically and manually.
 *
 */

#ifndef UI_UPDATE_H
#define UI_UPDATE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <gtk/gtk.h>
#include "app.h"

/* ============================================================================
 * Public API
 * ========================================================================== */

/**
 * @brief Check if the database was already updated today.
 * @return TRUE if an update is recommended.
 */
gboolean needs_update_today(void);

/**
 * @brief Refresh the "Last Updated" timestamp label in the UI.
 * @param data Pointer to AppState.
 */
gboolean refresh_last_update_label(gpointer data);

/**
 * @brief GLib timer function for periodic silent updates.
 */
gboolean auto_update_timer(gpointer user_data);

/**
 * @brief Callback for manual update button (opens progress dialog).
 */
void on_update_clicked(GtkButton *btn, gpointer user_data);

/**
 * @brief Callback for the auto-update toggle switch.
 */
gboolean on_auto_update_toggled(GtkSwitch *widget, gboolean state, gpointer user_data);

/**
 * @brief Callback for the theme toggle switch.
 */
gboolean on_theme_toggled(GtkSwitch* widget, gboolean state, gpointer user_data);

/**
 * @brief Background thread entry for non-blocking updates.
 */
gpointer silent_update_worker_thread(gpointer data);

#ifdef __cplusplus
}
#endif

#endif /* UI_UPDATE_H */