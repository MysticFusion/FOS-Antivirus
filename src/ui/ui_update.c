/**
 * @file ui_update.c
 * @brief Virus Definition Update UI Implementation
 *
 * Handles the logic and dialogs for malware signature updates. Includes
 * automated daily checks and a manual update dialog with real-time progress.
 *
 * v1.1.1 changes:
 *   - The error display now uses update_get_full_error_message() which includes
 *     the resolved log file path and any specific error from the Python script,
 *     instead of just the bare error-code message.
 *   - The manual update dialog is larger (500x200) to fit the longer error
 *     message with the log path.
 *   - The auto-update toggle callback (on_auto_update_toggled) is KEPT for ABI
 *     compatibility but the toggle UI element has been REMOVED from the Settings
 *     view (see ui_views.c) since it was redundant with the "Update Now" button.
 *     The auto_update_enabled global still controls the 6-hour background timer.
 */

#include "ui_update.h"
#include "app_paths.h"
#include "signature_scan.h"

#include <gtk/gtk.h>
#include <stdio.h>
#include <time.h>
#include <windows.h>
#include <string.h>

/* ============================================================================
 * Internal State
 * ========================================================================== */

static GtkWidget* g_update_dialog = NULL;
static GtkWidget* g_update_progress_bar = NULL;
static GtkWidget* g_update_status_label = NULL;

/* ============================================================================
 * Helper Functions
 * ========================================================================== */

gboolean needs_update_today(void)
{
    if (strcmp(last_update_time, "Never") == 0) {
        return TRUE;
    }

    char today[16];
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    strftime(today, sizeof(today), "%Y-%m-%d", tm_info);

    /* Compare current date to the prefix of the last_update_time string */
    return (strncmp(last_update_time, today, 10) != 0);
}

gboolean db_is_older_than(int hours)
{
    /* Never updated = definitely stale */
    if (strcmp(last_update_time, "Never") == 0) {
        return TRUE;
    }

    /* Parse last_update_time ("YYYY-MM-DD HH:MM") using sscanf (portable,
     * doesn't require strptime which may not be available on all MinGW). */
    int year, month, day, hour, min;
    if (sscanf(last_update_time, "%d-%d-%d %d:%d",
               &year, &month, &day, &hour, &min) != 5) {
        return TRUE;  /* Can't parse = treat as stale (safer to update) */
    }

    struct tm tm_last = {0};
    tm_last.tm_year = year - 1900;
    tm_last.tm_mon = month - 1;
    tm_last.tm_mday = day;
    tm_last.tm_hour = hour;
    tm_last.tm_min = min;
    tm_last.tm_sec = 0;
    tm_last.tm_isdst = -1;  /* Let mktime determine DST */

    time_t last_time = mktime(&tm_last);
    if (last_time == (time_t)-1) {
        return TRUE;  /* mktime failed = treat as stale */
    }

    time_t now = time(NULL);
    double diff_seconds = difftime(now, last_time);
    double diff_hours = diff_seconds / 3600.0;

    return diff_hours > (double)hours;
}

gboolean refresh_last_update_label(gpointer data)
{
    AppState* app = (AppState*)data;
    if (app == NULL || app->last_update_label == NULL) {
        return G_SOURCE_REMOVE;
    }

    char markup[256];
    snprintf(markup, sizeof(markup), "Last Updated: <span weight='bold'>%s</span>", last_update_time);
    gtk_label_set_markup(GTK_LABEL(app->last_update_label), markup);

    return G_SOURCE_REMOVE;
}

/* ============================================================================
 * Background Threading
 * ========================================================================== */

gpointer silent_update_worker_thread(gpointer data)
{
    AppState* app = (AppState*)data;

    int result = update_signature_db(app_path_signature_db());
    if (result == 0) {
        time_t now = time(NULL);
        struct tm* tm_info = localtime(&now);
        strftime(last_update_time, sizeof(last_update_time), "%Y-%m-%d %H:%M", tm_info);

        save_settings();

        if (app != NULL) {
            g_idle_add((GSourceFunc)refresh_last_update_label, app);
        }
    }
    return NULL;
}

gboolean auto_update_timer(gpointer data)
{
    AppState* app = (AppState*)data;
    /* v1.2.1: Only spawn the silent updater if the DB is actually stale
     * (> 24 hours since last successful update). This prevents python.exe
     * from spawning every 6 hours when the DB is already fresh. */
    if (app != NULL && auto_update_enabled && db_is_older_than(24)) {
        g_thread_new("SilentUpdater", silent_update_worker_thread, app);
    }
    return G_SOURCE_CONTINUE;
}

/* ============================================================================
 * Manual Update UI (Dialog)
 * ========================================================================== */

static gboolean destroy_dialog_cb(gpointer data)
{
    if (data != NULL) {
        gtk_window_destroy(GTK_WINDOW(data));
    }
    return G_SOURCE_REMOVE;
}

static gboolean check_manual_update_progress(gpointer user_data)
{
    (void)user_data;  /* not used; we read global update_progress */

    if (g_update_dialog == NULL) {
        return G_SOURCE_REMOVE;
    }

    double fraction = (double)update_progress / 100.0;
    if (fraction > 1.0) fraction = 1.0;
    if (fraction < 0.0) fraction = 0.0;

    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(g_update_progress_bar), fraction);

    char status_text[64];
    if (update_progress < 100 && update_progress >= 0) {
        snprintf(status_text, sizeof(status_text), "Updating... %d%%", update_progress);
        gtk_label_set_text(GTK_LABEL(g_update_status_label), status_text);
    }

    /* 101 status means completed successfully */
    if (update_progress == 101) {
        gtk_label_set_text(GTK_LABEL(g_update_status_label), "Update Complete!");

        time_t now = time(NULL);
        struct tm* tm_info = localtime(&now);
        strftime(last_update_time, sizeof(last_update_time), "%Y-%m-%d %H:%M", tm_info);
        save_settings();

        /* Refresh dashboard label */
        AppState* app = (AppState*)g_object_get_data(G_OBJECT(g_update_dialog), "app_ptr");
        if (app != NULL) {
            refresh_last_update_label(app);
        }

        g_timeout_add_seconds(1, destroy_dialog_cb, g_update_dialog);
        g_update_dialog = NULL;
        return G_SOURCE_REMOVE;
    }

    if (update_progress == -1) {
        /* v1.1.1: Use the full error message that includes the log path and
         * any specific error captured from the Python aggregator's JSONL output.
         * Enable line wrapping so the longer message is readable. */
        char full_msg[1024];
        update_get_full_error_message(full_msg, sizeof(full_msg));
        gtk_label_set_text(GTK_LABEL(g_update_status_label), full_msg);
        gtk_label_set_wrap(GTK_LABEL(g_update_status_label), TRUE);
        gtk_label_set_max_width_chars(GTK_LABEL(g_update_status_label), 60);
        /* Release the singleton so the user can click "Update Now" again.
         * The error window itself stays open (owned by GTK) until the user
         * closes it, so the message remains readable. */
        g_update_dialog = NULL;
        return G_SOURCE_REMOVE;
    }

    return G_SOURCE_CONTINUE;
}

static gpointer manual_update_thread(gpointer data)
{
    (void)data;
    update_signature_db(app_path_signature_db());
    return NULL;
}

void on_update_clicked(GtkButton* btn, gpointer user_data)
{
    (void)btn;
    AppState* app = (AppState*)user_data;

    /* One manual update at a time: the dialog and its widgets are static
     * singletons, and update_signature_db() serialises in the engine —
     * a second click would orphan the first dialog's progress polling. */
    if (g_update_dialog != NULL) {
        gtk_window_present(GTK_WINDOW(g_update_dialog));
        return;
    }

    g_update_dialog = gtk_window_new();
    gtk_window_set_title(GTK_WINDOW(g_update_dialog), "Database Update");
    gtk_window_set_modal(GTK_WINDOW(g_update_dialog), TRUE);
    gtk_window_set_transient_for(GTK_WINDOW(g_update_dialog), GTK_WINDOW(app->window));
    /* v1.1.1: enlarged from 320x160 to 520x220 to fit longer error messages
     * that include the log file path. */
    gtk_window_set_default_size(GTK_WINDOW(g_update_dialog), 520, 220);

    g_object_set_data(G_OBJECT(g_update_dialog), "app_ptr", app);

    GtkWidget* box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 20);
    gtk_widget_set_margin_start(box, 20);
    gtk_widget_set_margin_end(box, 20);
    gtk_widget_set_margin_top(box, 20);
    gtk_widget_set_margin_bottom(box, 20);
    gtk_window_set_child(GTK_WINDOW(g_update_dialog), box);

    g_update_status_label = gtk_label_new("Initializing...");
    /* Enable wrapping so error messages with log paths don't get cut off */
    gtk_label_set_wrap(GTK_LABEL(g_update_status_label), TRUE);
    gtk_label_set_max_width_chars(GTK_LABEL(g_update_status_label), 60);
    gtk_widget_set_halign(g_update_status_label, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(box), g_update_status_label);

    g_update_progress_bar = gtk_progress_bar_new();
    gtk_box_append(GTK_BOX(box), g_update_progress_bar);

    gtk_window_present(GTK_WINDOW(g_update_dialog));

    update_progress = 0;
    g_thread_new("ManualUpdater", manual_update_thread, NULL);
    g_timeout_add(100, (GSourceFunc)check_manual_update_progress, NULL);
}

gboolean on_auto_update_toggled(GtkSwitch* widget, gboolean state, gpointer user_data)
{
    /* v1.1.1: This callback is KEPT for ABI compatibility but the toggle UI
     * element has been REMOVED from the Settings view (see ui_views.c) since
     * it was redundant with the "Update Now" button. The auto_update_enabled
     * global still controls the 6-hour background timer; if you want to
     * re-enable the toggle, re-add it in create_settings_view() in ui_views.c. */
    (void)widget;
    (void)user_data;
    auto_update_enabled = state;
    save_settings();
    return FALSE; /* Default propagation */
}

gboolean on_theme_toggled(GtkSwitch* widget, gboolean state, gpointer user_data)
{
    (void)widget;
    AppState* app = (AppState*)user_data;
    app_set_theme(app, state);
    return FALSE;
}
