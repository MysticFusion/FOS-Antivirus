/**
 * @file ui_update.h
 * @brief Virus Definition Update UI Interface
 *
 * Provides functions for checking, triggering, and monitoring malware
 * database updates both automatically and manually.
 *
 * v1.2.1: Added db_is_older_than() to gate silent background updates on
 * actual DB staleness, preventing python.exe from spawning on every app
 * launch when the DB is already fresh.
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
 * @brief Check if the last successful DB update is older than the given
 *        number of hours.
 *
 * Parses the global `last_update_time` string (format "YYYY-MM-DD HH:MM")
 * and compares it to the current time. Returns TRUE if:
 *   - last_update_time is "Never" (never updated), OR
 *   - the parsed timestamp is older than `hours` hours ago, OR
 *   - the timestamp can't be parsed (treat as stale — safer to update).
 *
 * Used to gate silent background updates so python.exe doesn't spawn on
 * every app launch when the DB is already fresh.
 *
 * @param hours  Threshold in hours (e.g., 168 = 7 days, 24 = 1 day).
 * @return TRUE if the DB is stale (older than `hours` or never updated).
 */
gboolean db_is_older_than(int hours);

/**
 * @brief Refresh the "Last Updated" timestamp label in the UI.
 * @param data Pointer to AppState.
 */
gboolean refresh_last_update_label(gpointer data);

/**
 * @brief GLib timer function for periodic silent updates.
 *
 * v1.2.1: Only fires the background updater if the DB is older than 24
 * hours (checked via db_is_older_than(24)). This prevents redundant
 * python.exe spawns when the DB is already fresh.
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
