/**
 * @file ui_scan.c
 * @brief Scanner UI Subsystem Implementation
 *
 * Coordinates the scanning workflow, including update-before-scan checks,
 * worker thread management, and UI progress synchronization using GLib loops.
 *
 */

#include "ui_scan.h"
#include "signature_scan.h"

#include "scan_core.h" 
#include "ui_update.h" 
#include "ui_history.h"
#include "ui_scan_paths.h"
#include "scan_progress.h"

#include <gtk/gtk.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* ============================================================================
 * Internal Data Structures
 * ========================================================================== */

/** @brief Context for sequential update-and-scan operations */
typedef struct {
    AppState *app;
    char     *scan_arg;
} ScanSequenceContext;

/* ============================================================================
 * Internal Prototypes
 * ========================================================================== */

static gpointer scan_worker_thread(gpointer user_data);
static gpointer update_then_scan_worker(gpointer data);
static gboolean start_scan_from_idle_cb(gpointer data);
static gboolean on_scan_progress_tick(gpointer user_data);
static void     on_folder_selected(GObject *source_object, GAsyncResult *res, gpointer user_data);
static void     on_stop_scan(GtkButton *btn, gpointer user_data);

/* ============================================================================
 * Scanning Workflow Logic
 * ========================================================================== */

/**
 * @brief GLib timeout callback: Syncs backend scan progress to the UI.
 */
static gboolean on_scan_progress_tick(gpointer user_data)
{
    AppState *app = (AppState *)user_data;
    bool still_running = scan_progress_is_running();
    int  scanned_count = scan_progress_files_scanned();
    int  threat_count  = scan_progress_threats_found();
    const char *current_file = scan_progress_current_file();

    char label_buffer[512] = "Scanning...";

    if (current_file != NULL && current_file[0] != '\0') {
        GError *error = NULL;
        char   *utf8_path = g_locale_to_utf8(current_file, -1, NULL, NULL, &error);

        if (utf8_path != NULL) {
            size_t len = strlen(utf8_path);
            if (len > 50) {
                snprintf(label_buffer, sizeof(label_buffer), "Scanning: ...%s", utf8_path + len - 50);
            } else {
                snprintf(label_buffer, sizeof(label_buffer), "Scanning: %s", utf8_path);
            }
            g_free(utf8_path);
        } else {
            snprintf(label_buffer, sizeof(label_buffer), "Scanning file...");
            if (error != NULL) g_error_free(error);
        }
    }

    gtk_label_set_text(GTK_LABEL(app->progress_label), label_buffer);
    gtk_progress_bar_pulse(GTK_PROGRESS_BAR(app->progress_bar));

    /* Check for completion */
    if (!still_running && scanned_count > 0) {
        gchar *f_txt = g_strdup_printf("Files Scanned: %d", scanned_count);
        gchar *t_txt = g_strdup_printf("Threats Found: %d", threat_count);

        gtk_label_set_text(GTK_LABEL(app->result_files_label), f_txt);
        gtk_label_set_text(GTK_LABEL(app->result_threats_label), t_txt);

        g_free(f_txt);
        g_free(t_txt);

        reload_history_view(app);
        gtk_stack_set_visible_child_name(GTK_STACK(app->stack), "complete");
        return G_SOURCE_REMOVE;
    }

    return G_SOURCE_CONTINUE; 
}

/**
 * @brief Background thread: Orchestrates the scan core logic.
 */
static gpointer scan_worker_thread(gpointer user_data)
{
    char *mode = (char *)user_data; 
    const char *db_path = "signatures.db"; 

    /* Reset global synchronization context */
    g_mutex_lock(&global_scan_ctx.mutex);
    global_scan_ctx.is_running = true;
    global_scan_ctx.stop_requested = false;
    global_scan_ctx.files_scanned = 0;
    global_scan_ctx.threats_found = 0;
    memset(global_scan_ctx.current_file, 0, 256);
    g_mutex_unlock(&global_scan_ctx.mutex);

    /* Disptach to appropriate scan type */
    if (strcmp(mode, "QUICK_SCAN") == 0) {
        GList *paths = get_quick_scan_paths();
        for (GList *iter = paths; iter != NULL; iter = iter->next) {
            char *folder = (char *)iter->data;
            
            /* Stop check */
            g_mutex_lock(&global_scan_ctx.mutex);
            bool aborted = global_scan_ctx.stop_requested;
            g_mutex_unlock(&global_scan_ctx.mutex);
            
            if (aborted) break;

            scan_core_start_scan(db_path, folder, false);
        }
        g_list_free_full(paths, g_free);
    } else if (strcmp(mode, "FULL_SYSTEM") == 0) {
        scan_core_start_scan(db_path, "C:\\Users", false);
    } else {
        /* Custom directory scan */
        scan_core_start_scan(db_path, mode, false);
    }

    /* Finalize tracking */
    scan_progress_finish(); 
    
    g_mutex_lock(&global_scan_ctx.mutex);
    global_scan_ctx.is_running = false;
    g_mutex_unlock(&global_scan_ctx.mutex);

    g_free(mode); 
    return NULL;
}

static gboolean start_scan_from_idle_cb(gpointer data)
{
    ScanSequenceContext *ctx = (ScanSequenceContext *)data;
    gtk_label_set_text(GTK_LABEL(ctx->app->progress_label), "Initializing...");
    g_thread_new("Scanner", scan_worker_thread, ctx->scan_arg); 
    g_free(ctx);
    return G_SOURCE_REMOVE;
}

static gpointer update_then_scan_worker(gpointer data)
{
    ScanSequenceContext *ctx = (ScanSequenceContext *)data;
    int res = update_signature_db("signatures.db");
    
    if (res == 0) {
        time_t now = time(NULL);
        struct tm *tm_info = localtime(&now);
        strftime(last_update_time, sizeof(last_update_time), "%Y-%m-%d %H:%M", tm_info);
        save_settings();
        g_idle_add((GSourceFunc)refresh_last_update_label, ctx->app);
    }
    
    g_idle_add(start_scan_from_idle_cb, ctx);
    return NULL;
}

void start_scan_logic(AppState *app, char *path_or_mode)
{
    char *thread_safe_arg = g_strdup(path_or_mode);

    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(app->progress_bar), 0.0);
    gtk_stack_set_visible_child_name(GTK_STACK(app->stack), "progress");

    if (auto_update_enabled && needs_update_today()) {
        gtk_label_set_text(GTK_LABEL(app->progress_label), "Checking for updates...");
        
        ScanSequenceContext *ctx = g_new0(ScanSequenceContext, 1);
        ctx->app = app;
        ctx->scan_arg = thread_safe_arg;

        g_thread_new("UpdateThenScan", update_then_scan_worker, ctx);
    } else {
        gtk_label_set_text(GTK_LABEL(app->progress_label), "Initializing...");
        g_thread_new("Scanner", scan_worker_thread, thread_safe_arg);
    }

    /* Start UI polling timer */
    g_timeout_add(100, on_scan_progress_tick, app);
}

/* ============================================================================
 * View Creation Helpers
 * ========================================================================== */

static void on_folder_selected(GObject *source_object, GAsyncResult *res, gpointer user_data)
{
    GtkFileDialog *dialog = GTK_FILE_DIALOG(source_object);
    AppState *app = (AppState *)user_data;
    GError *error = NULL;

    GFile *folder = gtk_file_dialog_select_folder_finish(dialog, res, &error);

    if (folder != NULL) {
        char *path = g_file_get_path(folder);
        if (path) start_scan_logic(app, path); 
        g_object_unref(folder);
    } else {
        if (error) g_error_free(error);
    }
}

static void on_browse_clicked(GtkButton *btn, gpointer user_data)
{
    (void)btn;
    AppState *app = (AppState *)user_data;
    GtkFileDialog *dialog = gtk_file_dialog_new();
    gtk_file_dialog_set_title(dialog, "Select Folder to Scan");
    gtk_file_dialog_select_folder(dialog, GTK_WINDOW(app->window), NULL, on_folder_selected, app);
    g_object_unref(dialog);
}

static void on_back_home(GtkButton *btn, gpointer user_data)
{
    (void)btn;
    gtk_stack_set_visible_child_name(GTK_STACK(((AppState*)user_data)->stack), "dashboard");
}

static void on_stop_scan(GtkButton *btn, gpointer user_data)
{
    (void)btn;
    (void)user_data;
    g_mutex_lock(&global_scan_ctx.mutex);
    global_scan_ctx.stop_requested = true;
    g_mutex_unlock(&global_scan_ctx.mutex);
}

GtkWidget *create_advanced_scan_view(AppState *app)
{
    GtkWidget *view = gtk_box_new(GTK_ORIENTATION_VERTICAL, 20);
    gtk_widget_set_margin_start(view, 30); 
    gtk_widget_set_margin_top(view, 30); 
    gtk_widget_set_margin_end(view, 30);
    
    GtkWidget *title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title), "<span font='28px' weight='bold'>Advanced Scan</span>");
    gtk_widget_set_halign(title, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(view), title);

    /* Custom Scan Card */
    GtkWidget *card = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 20);
    gtk_widget_add_css_class(card, "dashboard-card-bg");
    gtk_widget_set_size_request(card, -1, 80);
    
    gtk_box_append(GTK_BOX(card), gtk_label_new("  Custom Scan (Select Directory)"));
    GtkWidget *spacer = gtk_label_new("");
    gtk_widget_set_hexpand(spacer, TRUE);
    gtk_box_append(GTK_BOX(card), spacer);
    
    GtkWidget *browse_btn = gtk_button_new_with_label("Browse Folders...");
    gtk_widget_add_css_class(browse_btn, "scan-btn");
    gtk_widget_set_margin_end(browse_btn, 20);
    g_signal_connect(browse_btn, "clicked", G_CALLBACK(on_browse_clicked), app);
    gtk_box_append(GTK_BOX(card), browse_btn);

    gtk_box_append(GTK_BOX(view), card);

    /* Back Button */
    GtkWidget *back_btn = gtk_button_new_with_label("Back");
    gtk_widget_set_halign(back_btn, GTK_ALIGN_START);
    gtk_widget_add_css_class(back_btn, "flat-button");
    g_signal_connect(back_btn, "clicked", G_CALLBACK(on_back_home), app);
    gtk_box_append(GTK_BOX(view), back_btn);

    return view;
}

GtkWidget *create_scanner_progress_view(AppState *app)
{
    GtkWidget *view = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_halign(view, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(view, GTK_ALIGN_CENTER);

    /* Progress Card */
    GtkWidget *card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 20);
    gtk_widget_add_css_class(card, "dashboard-card-bg");
    gtk_widget_set_size_request(card, 500, 320);
    gtk_widget_set_valign(card, GTK_ALIGN_CENTER); 

    GtkWidget *inner = gtk_box_new(GTK_ORIENTATION_VERTICAL, 25);
    gtk_widget_set_margin_start(inner, 40);
    gtk_widget_set_margin_end(inner, 40);
    gtk_widget_set_margin_top(inner, 40);
    gtk_widget_set_margin_bottom(inner, 40);

    /* UI Elements */
    GtkWidget *spinner = gtk_spinner_new();
    gtk_widget_set_size_request(spinner, 48, 48);
    gtk_widget_set_halign(spinner, GTK_ALIGN_CENTER);
    gtk_spinner_start(GTK_SPINNER(spinner));
    gtk_box_append(GTK_BOX(inner), spinner);

    app->progress_label = gtk_label_new("Initializing...");
    gtk_widget_set_halign(app->progress_label, GTK_ALIGN_CENTER);
    gtk_label_set_ellipsize(GTK_LABEL(app->progress_label), PANGO_ELLIPSIZE_END);
    gtk_label_set_max_width_chars(GTK_LABEL(app->progress_label), 45); 
    gtk_widget_set_size_request(app->progress_label, 420, -1);
    gtk_box_append(GTK_BOX(inner), app->progress_label);

    app->progress_bar = gtk_progress_bar_new();
    gtk_widget_set_size_request(app->progress_bar, 350, 10);
    gtk_widget_set_halign(app->progress_bar, GTK_ALIGN_CENTER);
    gtk_box_append(GTK_BOX(inner), app->progress_bar);

    GtkWidget *stop_btn = gtk_button_new_with_label("Cancel Scan");
    gtk_widget_add_css_class(stop_btn, "destructive-action");
    gtk_widget_set_halign(stop_btn, GTK_ALIGN_CENTER);
    gtk_widget_set_size_request(stop_btn, 140, 38);
    g_signal_connect(stop_btn, "clicked", G_CALLBACK(on_stop_scan), app);
    gtk_box_append(GTK_BOX(inner), stop_btn);

    gtk_box_append(GTK_BOX(card), inner);
    gtk_box_append(GTK_BOX(view), card);
    return view;
}

GtkWidget *create_scan_complete_view(AppState *app)
{
    GtkWidget *view = gtk_box_new(GTK_ORIENTATION_VERTICAL, 20);
    gtk_widget_set_valign(view, GTK_ALIGN_CENTER);
    gtk_widget_set_halign(view, GTK_ALIGN_CENTER);

    GtkWidget *card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 25);
    gtk_widget_add_css_class(card, "dashboard-card-bg");
    gtk_widget_set_size_request(card, 400, 260);
    gtk_widget_set_margin_start(card, 20);
    gtk_widget_set_margin_end(card, 20);
    gtk_widget_set_margin_top(card, 20);
    gtk_widget_set_margin_bottom(card, 20);

    /* Results Summary */
    GtkWidget *title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title), "<span font='18px' weight='bold'>Scan Completed</span>");
    gtk_box_append(GTK_BOX(card), title);

    app->result_files_label = gtk_label_new("Files Scanned: 0");
    app->result_threats_label = gtk_label_new("Threats Found: 0");
    gtk_box_append(GTK_BOX(card), app->result_files_label);
    gtk_box_append(GTK_BOX(card), app->result_threats_label);

    GtkWidget *home_btn = gtk_button_new_with_label("Back to Dashboard");
    gtk_widget_add_css_class(home_btn, "scan-btn");
    gtk_widget_set_margin_top(home_btn, 10);
    g_signal_connect(home_btn, "clicked", G_CALLBACK(on_back_home), app);
    gtk_box_append(GTK_BOX(card), home_btn);

    gtk_box_append(GTK_BOX(view), card);
    return view;
}