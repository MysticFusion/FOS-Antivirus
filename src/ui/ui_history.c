/**
 * @file ui_history.c
 * @brief Detection History View Implementation
 *
 * Implements the history tab, which parses the history log and displays
 * quarantined files with options to restore or permanently remove them.
 * Includes auto-refresh logic to capture real-time detections.
 *
 */

#include "ui_history.h"
#include <gtk/gtk.h>
#include <windows.h> 
#include <stdio.h>
#include <string.h>
#include <stdlib.h> 
#include <stdbool.h>

/* ============================================================================
 * External Declarations
 * ========================================================================== */

extern int restore_file_from_quarantine(const char *q_path, const char *dest_path);

/* ============================================================================
 * Data Structures
 * ========================================================================== */

/**
 * @brief Context data for history item action callbacks.
 */
typedef struct {
    char       *orig_path;   /**< Original location of the file */
    char       *q_path;      /**< Current location in quarantine */
    GtkWidget  *lbl_status;  /**< Label showing the item status */
    GtkWidget  *btn_restore; /**< Reference to restore button */
    GtkWidget  *btn_remove;  /**< Reference to remove button */
    AppState   *app;         /**< Global app state pointer */
} HistoryActionData;

/* ============================================================================
 * Internal Helpers
 * ========================================================================== */

static gboolean reload_history_timer_cb(gpointer user_data);

/**
 * @brief Destroyer for HistoryActionData.
 */
static void free_history_action_data(gpointer data)
{
    HistoryActionData *d = (HistoryActionData *)data;
    if (d != NULL) {
        g_free(d->orig_path);
        g_free(d->q_path);
        g_free(d);
    }
}

/* ============================================================================
 * Callbacks
 * ========================================================================== */

/**
 * @brief Permanently delete a quarantined file.
 */
static void on_remove_clicked(GtkButton *btn, gpointer user_data)
{
    (void)btn;
    HistoryActionData *data = (HistoryActionData *)user_data;
    
    if (remove(data->q_path) == 0) {
        gtk_label_set_text(GTK_LABEL(data->lbl_status), "Removed");
        gtk_widget_set_sensitive(data->btn_restore, FALSE);
        gtk_widget_set_sensitive(data->btn_remove, FALSE);

        GtkAlertDialog *alert = gtk_alert_dialog_new("File Permanently Removed");
        gtk_alert_dialog_show(alert, GTK_WINDOW(data->app->window));
        g_object_unref(alert);
        
        reload_history_view(data->app);
    }
}

/**
 * @brief Restore a file from the quarantine vault.
 */
static void on_restore_clicked(GtkButton *btn, gpointer user_data)
{
    (void)btn;
    HistoryActionData *data = (HistoryActionData *)user_data;
    
    if (restore_file_from_quarantine(data->q_path, data->orig_path) == 0) {
        gtk_label_set_text(GTK_LABEL(data->lbl_status), "Restored");
        gtk_widget_set_sensitive(data->btn_restore, FALSE);
        gtk_widget_set_sensitive(data->btn_remove, FALSE);
        
        GtkAlertDialog *alert = gtk_alert_dialog_new("File Restored Successfully");
        gtk_alert_dialog_show(alert, GTK_WINDOW(data->app->window));
        g_object_unref(alert);
        
        reload_history_view(data->app);
    } else {
        GtkAlertDialog *alert = gtk_alert_dialog_new("Failed to Restore. Check permissions or disk space.");
        gtk_alert_dialog_show(alert, GTK_WINDOW(data->app->window));
        g_object_unref(alert);
    }
}

/* ============================================================================
 * Implementation Logic
 * ========================================================================== */

/**
 * @brief Rebuild the list of history items from the log file.
 */
void load_history_items(AppState *app)
{
    /* 1. Clear existing list children */
    GtkWidget *child = gtk_widget_get_first_child(app->history_list_box);
    while (child != NULL) {
        GtkWidget *next = gtk_widget_get_next_sibling(child);
        gtk_list_box_remove(GTK_LIST_BOX(app->history_list_box), child);
        child = next;
    }

    /* 2. Read history log */
    FILE *f = fopen("history.log", "r");
    if (f == NULL) {
        return;
    }

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';

        char *token_date   = strtok(line, "|");
        char *token_threat = strtok(NULL, "|");
        char *token_orig   = strtok(NULL, "|");
        char *token_qpath  = strtok(NULL, "|");

        if (token_date == NULL || token_orig == NULL || token_qpath == NULL) {
            continue;
        }

        /* Check if the physical file still exists in the vault */
        bool quarantine_exists = (GetFileAttributesA(token_qpath) != INVALID_FILE_ATTRIBUTES);

        const char *filename = strrchr(token_orig, '\\');
        if (filename == NULL) {
            filename = strrchr(token_orig, '/');
        }
        filename = (filename != NULL) ? filename + 1 : token_orig;

        /* Create UI Row (Horizontal Box) */
        GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 15);
        gtk_widget_set_margin_start(row, 10);
        gtk_widget_set_margin_end(row, 10);
        gtk_widget_set_margin_top(row, 8);
        gtk_widget_set_margin_top(row, 8);
        gtk_widget_set_margin_bottom(row, 8);
        gtk_widget_add_css_class(row, "history-row");

        /* Col 1: File Name */
        GtkWidget *lbl_name = gtk_label_new(filename);
        gtk_widget_set_size_request(lbl_name, 120, -1);
        gtk_widget_set_halign(lbl_name, GTK_ALIGN_START);
        gtk_label_set_ellipsize(GTK_LABEL(lbl_name), PANGO_ELLIPSIZE_END);
        gtk_box_append(GTK_BOX(row), lbl_name);

        /* Col 2: Original Path */
        GtkWidget *lbl_path = gtk_label_new(token_orig);
        gtk_widget_set_hexpand(lbl_path, TRUE);
        gtk_widget_set_halign(lbl_path, GTK_ALIGN_START);
        gtk_label_set_ellipsize(GTK_LABEL(lbl_path), PANGO_ELLIPSIZE_START);
        gtk_box_append(GTK_BOX(row), lbl_path);

        /* Col 3: Detection Date */
        GtkWidget *lbl_date = gtk_label_new(token_date);
        gtk_widget_set_size_request(lbl_date, 140, -1);
        gtk_box_append(GTK_BOX(row), lbl_date);

        /* Col 4: Status Indicator */
        GtkWidget *lbl_status = gtk_label_new(quarantine_exists ? "Quarantined" : "Inert");
        gtk_widget_set_size_request(lbl_status, 100, -1);
        gtk_widget_set_halign(lbl_status, GTK_ALIGN_START);
        gtk_box_append(GTK_BOX(row), lbl_status);

        /* Col 5: Functional Actions */
        GtkWidget *actions_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
        GtkWidget *btn_restore = gtk_button_new_from_icon_name("system-reboot-symbolic");
        GtkWidget *btn_remove  = gtk_button_new_from_icon_name("user-trash-symbolic");

        if (!quarantine_exists) {
            gtk_widget_set_sensitive(btn_restore, FALSE);
            gtk_widget_set_sensitive(btn_remove, FALSE);
        }

        /* Bind metadata and signals */
        HistoryActionData *data = g_new0(HistoryActionData, 1);
        data->orig_path   = g_strdup(token_orig);
        data->q_path      = g_strdup(token_qpath);
        data->lbl_status  = lbl_status;
        data->btn_restore = btn_restore;
        data->btn_remove  = btn_remove;
        data->app         = app;

        g_signal_connect_data(btn_restore, "clicked", G_CALLBACK(on_restore_clicked), data, NULL, 0);
        g_signal_connect_data(btn_remove, "clicked", G_CALLBACK(on_remove_clicked), data, NULL, 0);
        
        g_object_set_data_full(G_OBJECT(row), "action_data", data, free_history_action_data);

        gtk_box_append(GTK_BOX(actions_box), btn_restore);
        gtk_box_append(GTK_BOX(actions_box), btn_remove);
        gtk_box_append(GTK_BOX(row), actions_box);

        gtk_list_box_append(GTK_LIST_BOX(app->history_list_box), row);
    }

    fclose(f);
}

GtkWidget *create_history_view(AppState *app)
{
    GtkWidget *view = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_widget_set_margin_top(view, 30);
    gtk_widget_set_margin_start(view, 30);
    gtk_widget_set_margin_end(view, 30);

    /* Header Title */
    GtkWidget *title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title), "<span font='28px' weight='bold'>Detection History</span>");
    gtk_widget_set_halign(title, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(view), title);

    /* Column Headers Box */
    GtkWidget *header_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 15);
    gtk_widget_set_margin_start(header_box, 10);
    gtk_widget_set_margin_end(header_box, 20);

    const char *headers[] = { "File Name", "Original Path", "Date/Time", "Result", "Action" };
    int widths[] = { 120, -1, 140, 100, -1 };

    for (int i = 0; i < 5; i++) {
        GtkWidget *lbl = gtk_label_new(headers[i]);
        gtk_widget_add_css_class(lbl, "bold-text");
        gtk_widget_set_halign(lbl, GTK_ALIGN_START);
        if (widths[i] == -1) {
            gtk_widget_set_hexpand(lbl, TRUE);
        } else {
            gtk_widget_set_size_request(lbl, widths[i], -1);
        }
        gtk_box_append(GTK_BOX(header_box), lbl);
    }

    /* Manual Refresh Button */
    GtkWidget *btn_refresh = gtk_button_new_from_icon_name("view-refresh-symbolic");
    gtk_widget_set_halign(btn_refresh, GTK_ALIGN_END);
    g_signal_connect_swapped(btn_refresh, "clicked", G_CALLBACK(load_history_items), app);
    gtk_box_append(GTK_BOX(header_box), btn_refresh);

    gtk_box_append(GTK_BOX(view), header_box);
    gtk_box_append(GTK_BOX(view), gtk_separator_new(GTK_ORIENTATION_HORIZONTAL));
    
    /* Scrollable List Area */
    app->history_list_box = gtk_list_box_new();
    gtk_widget_add_css_class(app->history_list_box, "dashboard-card-bg");
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(app->history_list_box), GTK_SELECTION_NONE);

    GtkWidget *scroll = gtk_scrolled_window_new();
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), app->history_list_box);
    gtk_widget_set_vexpand(scroll, TRUE);
    gtk_box_append(GTK_BOX(view), scroll);

    /* Initial Load */
    load_history_items(app);

    /* Auto-refresh timer to catch real-time monitor events (every 3s) */
    g_timeout_add_seconds(3, (GSourceFunc)reload_history_timer_cb, app);

    return view;
}

static gboolean reload_history_timer_cb(gpointer user_data)
{
    AppState *app = (AppState *)user_data;
    load_history_items(app);
    return TRUE; /* Keep timer active */
}

void reload_history_view(AppState *app)
{
    load_history_items(app);
}
