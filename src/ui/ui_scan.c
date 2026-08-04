
/**
 * @file ui_scan.c
 * @brief Scanner UI Subsystem Implementation
 *
 * Coordinates the scanning workflow, including update-before-scan checks,
 * worker thread management, and UI progress synchronization using GLib loops.
 *
 */

#define _CRT_SECURE_NO_WARNINGS

#include "ui_scan.h"
#include "app_paths.h"
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

/** @brief Context for posting scan errors to the GTK main thread */
typedef struct {
    AppState *app;
    char     *error_message;
} ScanErrorData;

/* ============================================================================
 * MAP-01: Single authoritative terminal-state signal (SCAN STATE MACHINE)
 *
 * The old design let the 100 ms progress-tick poll the backend and GUESS
 * whether the scan finished with results, zero files, or an error. Because
 * the deferred error callback (g_idle_add) runs on the same main loop after
 * the tick, the tick could win the race, render "Files Scanned: 0", and
 * swallow the real error. The fix: the worker thread posts exactly ONE
 * terminal message via g_idle_add(scan_terminal_cb) after all work is
 * finalized; the tick only ever updates live telemetry and never decides
 * terminal state.
 * ========================================================================== */

/** @brief Final outcome of a scan session (posted by the worker thread). */
typedef enum {
    SCAN_TERM_OK,          /**< Completed with >= 1 file scanned            */
    SCAN_TERM_EMPTY,       /**< Completed, but no scannable files in target */
    SCAN_TERM_ABORTED,     /**< User requested stop before completion       */
    SCAN_TERM_ERR_NO_DB,   /**< Completed heuristic-only; DB unavailable    */
    SCAN_TERM_ERR_GENERIC  /**< Fatal scan-core failure                     */
} ScanTermStatus;

/** @brief Payload for the authoritative terminal callback. */
typedef struct {
    AppState      *app;
    ScanTermStatus status;
    int            files;
    int            threats;
    char          *err;   /**< optional message, g_free'd by the callback */
} ScanTermMsg;

/* ============================================================================
 * Internal Prototypes
 * ========================================================================== */

static gpointer scan_worker_thread(gpointer user_data);
static gpointer update_then_scan_worker(gpointer data);
static gboolean start_scan_from_idle_cb(gpointer data);
static gboolean on_scan_progress_tick(gpointer user_data);
static gboolean scan_terminal_cb(gpointer user_data);
static void     on_folder_selected(GObject *source_object, GAsyncResult *res, gpointer user_data);
static void     on_stop_or_back_clicked(GtkButton *btn, gpointer user_data);
static void     on_back_home(GtkButton *btn, gpointer user_data);
static void     post_scan_error(AppState *app, const char *msg);
static gboolean show_scan_error_cb(gpointer user_data);

/* ============================================================================
 * Scanning Workflow Logic
 * ========================================================================== */

/**
 * @brief GLib timeout callback: Syncs backend scan progress to the UI.
 *
 * MAP-01: this tick is LIVE-TELEMETRY ONLY. It updates the current-file
 * label and pulses the bar while the scan runs. It NEVER decides terminal
 * state (results / zero-files / error) — that is the exclusive job of
 * scan_terminal_cb(), which the worker thread posts exactly once via
 * g_idle_add() after all work is finalized. This eliminates the
 * tick-vs-error-callback race that produced the "instant 0 files" bug.
 */
static gboolean on_scan_progress_tick(gpointer user_data)
{
    AppState *app = (AppState *)user_data;
    bool still_running = scan_progress_is_running();

    /* If an error was posted (e.g. the update-before-scan path failed),
     * freeze the UI and stop this timer. This path does not post a
     * ScanTermMsg, so the tick must handle it. */
    if (app->scan_error) {
        if (app->progress_bar)
            gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(app->progress_bar), 0.0);
        app->scan_view_active = FALSE;
        return G_SOURCE_REMOVE; /* stop this timer */
    }

    /* Scan finished: the authoritative terminal callback (scan_terminal_cb)
     * is already queued on the main loop and will render the final view.
     * Stop the live telemetry timer. */
    if (!still_running) {
        return G_SOURCE_REMOVE;
    }

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

    return G_SOURCE_CONTINUE;
}

/**
 * @brief MAP-01: the single authoritative scan terminal callback.
 *
 * Runs on the GTK main loop and renders the FINAL scan view exactly once.
 * Because it is posted by the worker thread after scan_progress_finish()
 * (and after the error string is finalized), there is no race with the
 * progress tick: the tick cannot declare "0 files complete" before this
 * callback runs.
 */
static gboolean scan_terminal_cb(gpointer user_data)
{
    ScanTermMsg *m = (ScanTermMsg *)user_data;
    AppState    *app = m->app;

    /* Advisory warning / fatal error: surface on the progress view (the
     * visible "banner"), exactly like the legacy error path. The user
     * dismisses via Cancel/Back. */
    if (m->status == SCAN_TERM_ERR_NO_DB || m->status == SCAN_TERM_ERR_GENERIC) {
        if (app->progress_label) {
            gtk_label_set_text(GTK_LABEL(app->progress_label),
                m->status == SCAN_TERM_ERR_NO_DB
                    ? "Signature database not available - scan ran in "
                      "heuristic-only mode. Run Update in Settings to enable "
                      "signature detection."
                    : (m->err ? m->err : "Scan failed unexpectedly."));
        }
        if (app->progress_bar)
            gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(app->progress_bar), 0.0);
        app->scan_error = TRUE;
        app->scan_view_active = FALSE;
        g_free(m->err);
        g_free(m);
        return G_SOURCE_REMOVE;
    }

    /* Success path (OK / EMPTY / ABORTED): render the complete view with
     * the final, truthful counts. "0 files" is only shown when enumeration
     * actually ran and found nothing — never because an error was pending. */
    gchar *f_txt = g_strdup_printf("Files Scanned: %d", m->files);
    gchar *t_txt = g_strdup_printf("Threats Found: %d", m->threats);
    gtk_label_set_text(GTK_LABEL(app->result_files_label), f_txt);
    gtk_label_set_text(GTK_LABEL(app->result_threats_label), t_txt);
    g_free(f_txt);
    g_free(t_txt);

    if (m->status == SCAN_TERM_ABORTED && app->progress_label) {
        gtk_label_set_text(GTK_LABEL(app->progress_label),
            "Scan stopped by user.");
    } else if (m->status == SCAN_TERM_EMPTY && app->progress_label) {
        gtk_label_set_text(GTK_LABEL(app->progress_label),
            "No scannable files were found in the target.");
    }

    reload_history_view(app);
    app->scan_view_active = FALSE;
    gtk_stack_set_visible_child_name(GTK_STACK(app->stack), "complete");

    g_free(m->err);
    g_free(m);
    return G_SOURCE_REMOVE;
}

/**
 * @brief Helper: Post a scan error to the main thread.
 */
static gboolean show_scan_error_cb(gpointer user_data)
{
    ScanErrorData *ed = (ScanErrorData *)user_data;
    if (ed->app->progress_label)
        gtk_label_set_text(GTK_LABEL(ed->app->progress_label), ed->error_message);
    if (ed->app->progress_bar)
        gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(ed->app->progress_bar), 0.0);
    ed->app->scan_error = TRUE;
    ed->app->scan_view_active = FALSE;
    g_free(ed->error_message);
    g_free(ed);
    return G_SOURCE_REMOVE;
}

static void post_scan_error(AppState *app, const char *msg)
{
    ScanErrorData *ed = g_new(ScanErrorData, 1);
    ed->app = app;
    ed->error_message = g_strdup(msg);
    g_idle_add(show_scan_error_cb, ed);
}

/**
 * @brief Background thread: Orchestrates the scan core logic with error handling.
 *
 * MAP-01/MAP-09: signature-DB loading is DECOUPLED from scan dispatch.
 * The worker no longer pre-loads the DB or aborts when it is missing;
 * the scan core treats the load as advisory (heuristic-only mode) and
 * enumeration always runs. The terminal state is reported through a
 * single authoritative g_idle_add(scan_terminal_cb) posted here, AFTER
 * scan_progress_finish(), so no main-loop race can swallow the result.
 */
static gpointer scan_worker_thread(gpointer user_data)
{
    char *mode = (char *)user_data;
    const char *db_path = app_path_signature_db();

    /* Reset global synchronization context */
    g_mutex_lock(&global_scan_ctx.mutex);
    global_scan_ctx.is_running = true;
    global_scan_ctx.stop_requested = false;
    global_scan_ctx.files_scanned = 0;
    global_scan_ctx.threats_found = 0;
    memset(global_scan_ctx.current_file, 0, 256);
    g_mutex_unlock(&global_scan_ctx.mutex);

    int result = SCANCORE_OK;

    /* Dispatch to appropriate scan type. No signature_db_load() gate here:
     * the scan core performs an advisory load and always enumerates. */
    if (strcmp(mode, "QUICK_SCAN") == 0) {
        /* v1.2: Quick scan uses scan_core_quick_scan() which performs:
         *   1. Running process image scan (Phase B1)
         *   2. Registry persistence target scan (Phase B2)
         *   3. Targeted filesystem walk with extension + mtime filters (Phase A)
         * This replaces the old approach of iterating get_quick_scan_paths()
         * and calling scan_core_start_scan() for each. */
        result = scan_core_quick_scan(db_path);
    } else if (strcmp(mode, "FULL_SYSTEM") == 0) {
        result = scan_core_start_scan(db_path, "C:\\Users", false, false);
    } else {
        /* Custom directory scan */
        result = scan_core_start_scan(db_path, mode, false, false);
    }

    scan_progress_finish();

    g_mutex_lock(&global_scan_ctx.mutex);
    global_scan_ctx.is_running = false;
    AppState *app = global_scan_ctx.app_state;
    g_mutex_unlock(&global_scan_ctx.mutex);

    /* --- Single authoritative terminal message (MAP-01) --- */
    ScanTermMsg *m = g_new0(ScanTermMsg, 1);
    m->app     = app;
    m->files   = scan_progress_files_scanned();
    m->threats = scan_progress_threats_found();

    if (result != SCANCORE_OK) {
        m->status = SCAN_TERM_ERR_GENERIC;
        m->err = g_strdup("Scan failed: the scan core returned an error.");
    } else if (!scan_core_db_available()) {
        /* Advisory warning, NOT an abort: heuristics/ML still ran. */
        m->status = SCAN_TERM_ERR_NO_DB;
    } else if (scan_progress_files_scanned() == 0) {
        m->status = SCAN_TERM_EMPTY;
    } else {
        m->status = SCAN_TERM_OK;
    }

    g_idle_add(scan_terminal_cb, m);

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
    int res = update_signature_db(app_path_signature_db());
    if (res == 0) {
        time_t now = time(NULL);
        struct tm *tm_info = localtime(&now);
        strftime(last_update_time, sizeof(last_update_time), "%Y-%m-%d %H:%M", tm_info);
        save_settings();
        g_idle_add((GSourceFunc)refresh_last_update_label, ctx->app);
        g_idle_add(start_scan_from_idle_cb, ctx);
    } else {
        /* v1.1.1: Use the full error message that includes the log path and
         * any specific error from the Python aggregator. */
        char full_err[1024];
        update_get_full_error_message(full_err, sizeof(full_err));
        post_scan_error(ctx->app, full_err);
        g_free(ctx->scan_arg);
        g_free(ctx);
    }
    return NULL;
}

void start_scan_logic(AppState *app, char *path_or_mode)
{
    char *thread_safe_arg = g_strdup(path_or_mode);

    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(app->progress_bar), 0.0);
    gtk_stack_set_visible_child_name(GTK_STACK(app->stack), "progress");

    app->scan_error = FALSE;      /* reset error state */
    app->scan_view_active = TRUE; /* mark scan view as active */

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
    AppState *app = (AppState *)user_data;
    app->scan_view_active = FALSE;   /* scan results acknowledged */
    app->scan_error = FALSE;        /* clear any error */
    gtk_stack_set_visible_child_name(GTK_STACK(app->stack), "dashboard");
}

/**
 * @brief Handler for the "Cancel Scan" / "Back to Dashboard" button.
 */
static void on_stop_or_back_clicked(GtkButton *btn, gpointer user_data)
{
    (void)btn;
    AppState *app = (AppState *)user_data;
    g_mutex_lock(&global_scan_ctx.mutex);
    bool running = global_scan_ctx.is_running;
    g_mutex_unlock(&global_scan_ctx.mutex);
    if (running) {
        /* Request stop */
        g_mutex_lock(&global_scan_ctx.mutex);
        global_scan_ctx.stop_requested = true;
        g_mutex_unlock(&global_scan_ctx.mutex);
    } else {
        /* Not running, so user can return to dashboard and dismiss error/result */
        app->scan_view_active = FALSE;
        app->scan_error = FALSE;
        gtk_stack_set_visible_child_name(GTK_STACK(app->stack), "dashboard");
    }
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
    g_signal_connect(stop_btn, "clicked", G_CALLBACK(on_stop_or_back_clicked), app);
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
    gtk_box_append(GTK_BOX(view), home_btn);

    gtk_box_append(GTK_BOX(view), card);
    return view;
}
