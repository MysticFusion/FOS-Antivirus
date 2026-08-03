/**
 * @file ui_update.c
 * @brief Virus Definition Update UI Implementation
 *
 * Handles the logic and dialogs for malware signature updates. Includes
 * automated daily checks and a manual update dialog with real-time progress.
 *
 */

#include "ui_update.h"
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

    int result = update_signature_db("signatures.db");
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
    if (app != NULL && auto_update_enabled) {
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
    if (g_update_dialog == NULL) {
        return G_SOURCE_REMOVE;
    }

    double fraction = (double)update_progress / 100.0;
    if (fraction > 1.0) fraction = 1.0;
    if (fraction < 0.0) fraction = 0.0;

    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(g_update_progress_bar), fraction);
    
    char status_text[64];
    if (update_progress < 100 && update_progress >= 0) {
        snprintf(status_text, sizeof(status_text), "Downloading... %d%%", update_progress);
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
        gtk_label_set_text(GTK_LABEL(g_update_status_label), "Update Failed. Check connection.");
        return G_SOURCE_REMOVE;
    }

    return G_SOURCE_CONTINUE;
}

static gpointer manual_update_thread(gpointer data)
{
    (void)data;
    update_signature_db("signatures.db");
    return NULL;
}

void on_update_clicked(GtkButton* btn, gpointer user_data)
{
    (void)btn;
    AppState* app = (AppState*)user_data;
    
    g_update_dialog = gtk_window_new();
    gtk_window_set_title(GTK_WINDOW(g_update_dialog), "Database Update");
    gtk_window_set_modal(GTK_WINDOW(g_update_dialog), TRUE);
    gtk_window_set_transient_for(GTK_WINDOW(g_update_dialog), GTK_WINDOW(app->window));
    gtk_window_set_default_size(GTK_WINDOW(g_update_dialog), 320, 160);
    
    g_object_set_data(G_OBJECT(g_update_dialog), "app_ptr", app);

    GtkWidget* box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 20);
    gtk_widget_set_margin_start(box, 20);
    gtk_widget_set_margin_end(box, 20);
    gtk_widget_set_margin_top(box, 20);
    gtk_widget_set_margin_bottom(box, 20);
    gtk_window_set_child(GTK_WINDOW(g_update_dialog), box);

    g_update_status_label = gtk_label_new("Initializing...");
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