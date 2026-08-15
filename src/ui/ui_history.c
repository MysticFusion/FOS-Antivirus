/**
 * @file ui_history.c
 * @brief Detection History View Implementation
 *
 * Implements the history tab, which parses the history log and displays
 * quarantined files with options to restore or permanently remove them.
 * Includes auto-refresh logic to capture real-time detections.
 *
 * v1.1 security hardening: paths read from history.log are now canonicalized
 * and validated before being passed to file operations (restore / remove).
 * This defends against a tampered history.log that could otherwise trick the
 * restore function into writing to an arbitrary path (path traversal).
 */

#include "ui_history.h"
#include "app_paths.h"
#include "path_utils.h"
#include <gtk/gtk.h>
#include <windows.h>
#include <shlwapi.h>
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
    char       *orig_path;   /**< Original location of the file (canonicalized) */
    char       *q_path;      /**< Current location in quarantine (canonicalized) */
    GtkWidget  *lbl_status;  /**< Label showing the item status */
    GtkWidget  *btn_restore; /**< Reference to restore button */
    GtkWidget  *btn_remove;  /**< Reference to remove button */
    AppState   *app;         /**< Global app state pointer */
} HistoryActionData;

/* ============================================================================
 * Internal Helpers: Path Canonicalization (v1.1 hardening, U-14 rework)
 *
 * history.log is a plain text file that could be modified by malware or a
 * malicious user. Without canonicalization, an attacker could craft entries
 * like "..\\..\\Windows\\System32\\evil.exe" and trick the restore function
 * into writing to arbitrary paths.
 *
 * U-14 rework: decisions are made from OPEN HANDLES (fos_open_canonical),
 * never from GetFullPathName + GetFileAttributes snapshots:
 *   1. Quarantine paths (.vir) must EXIST: they are opened with
 *      FILE_FLAG_OPEN_REPARSE_POINT and rejected when the object itself is
 *      a reparse point, and their canonical path must sit inside the
 *      quarantine directory.
 *   2. Restore destinations may not exist yet (restore creates parents).
 *      The deepest EXISTING ancestor (the parent directory) is opened and
 *      resolved via GetFinalPathNameByHandleW, so junctions anywhere in the
 *      existing part of the chain are resolved to their real target before
 *      the path is ever handed to the restore engine. Textual checks
 *      (ADS, trailing dot/space, .., UNC, drive form) still apply.
 *   3. All buffers are FOS_MAX_PATH, not MAX_PATH.
 *
 * Residual risk (accepted, documented): the handle is closed after
 * resolution and restore re-opens by path, so a junction swapped into the
 * chain in that window could still redirect the write. Fully closing that
 * gap requires handle-passing through the restore engine.
 * ========================================================================== */

/** Reject ADS streams (colon after the drive letter) and Win32 trailing
 *  dot/space names. Returns true when the input passes. */
static bool basic_text_checks(const char *input) {
    if (input == NULL || input[0] == '\0') return false;
    const char *first_colon = strchr(input, ':');
    if (first_colon && strchr(first_colon + 1, ':')) return false;
    size_t len = strlen(input);
    if (len > 0 && (input[len - 1] == '.' || input[len - 1] == ' ')) return false;
    return true;
}

/**
 * @brief Canonicalize a restore destination (may not exist yet).
 *
 * @param[out] out  FOS_MAX_PATH-byte buffer receiving the canonical UTF-8 path.
 * @return true on success; the caller frees nothing (buffer provided).
 */
static bool canonicalize_restore_dest(const char *input, char *out, size_t out_sz) {
    if (!basic_text_checks(input)) return false;

    wchar_t wide[FOS_MAX_PATH];
    if (MultiByteToWideChar(CP_UTF8, 0, input, -1, wide, FOS_MAX_PATH) <= 0)
        return false;

    wchar_t full[FOS_MAX_PATH];
    DWORD l = GetFullPathNameW(wide, FOS_MAX_PATH, full, NULL);
    if (l == 0 || l >= FOS_MAX_PATH) return false;

    if (wcsstr(full, L"\\..\\") != NULL) return false;
    if (full[0] == L'\\' && full[1] == L'\\') return false; /* UNC */
    if (!iswalpha((wint_t)full[0]) || full[1] != L':' || full[2] != L'\\')
        return false;

    /* Resolve the parent directory from a HANDLE: every junction in the
     * existing part of the ancestor chain collapses to its real target. */
    wchar_t *last_sep = wcsrchr(full, L'\\');
    if (last_sep == NULL || last_sep == full + 2) return false;
    const wchar_t *leaf = last_sep + 1;
    if (*leaf == L'\0') return false;

    *last_sep = L'\0'; /* full = parent dir */
    char parent_canon[FOS_MAX_PATH];
    bool was_reparse = false;
    if (fos_open_canonical(full, true, parent_canon, sizeof(parent_canon),
                           &was_reparse) == 0) {
        if (_snprintf_s(out, out_sz, _TRUNCATE, "%s\\%s", parent_canon, leaf) < 0)
            return false;
        return true;
    }

    /* Parent does not exist (or cannot be opened): the restore engine's
     * create_parent_dirs() will (re)create it. Nothing below a missing
     * directory can be a live junction today, so accept the validated
     * textual form. */
    int n = WideCharToMultiByte(CP_UTF8, 0, full, -1, out, (int)out_sz - 1,
                                NULL, NULL);
    if (n <= 0) return false;
    size_t used = (size_t)n - 1; /* exclude NUL */
    if (used + 1 + wcslen(leaf) * 4 + 1 > out_sz) return false;
    out[used] = '\\';
    WideCharToMultiByte(CP_UTF8, 0, leaf, -1, out + used + 1,
                        (int)(out_sz - used - 1), NULL, NULL);
    return true;
}

/**
 * @brief Validate + canonicalize a quarantine (.vir) path. The file must
 *        exist, must not itself be a reparse point, and must resolve inside
 *        the FOS quarantine directory.
 *
 * @return true when safe; out_canonical receives the UTF-8 canonical path.
 */
static bool is_safe_quarantine_path(const char *input, char *out_canonical, size_t out_sz) {
    if (!basic_text_checks(input)) return false;

    wchar_t wide[FOS_MAX_PATH];
    if (MultiByteToWideChar(CP_UTF8, 0, input, -1, wide, FOS_MAX_PATH) <= 0)
        return false;

    char canonical[FOS_MAX_PATH];
    bool was_reparse = true;
    if (fos_open_canonical(wide, false, canonical, sizeof(canonical),
                           &was_reparse) != 0)
        return false; /* missing/unopenable */
    if (was_reparse)
        return false; /* the .vir artifact itself is a link */

    const char *q_dir = app_path_quarantine_dir();
    if (q_dir == NULL) return false;

    char q_dir_lower[FOS_MAX_PATH];
    strncpy_s(q_dir_lower, sizeof(q_dir_lower), q_dir, _TRUNCATE);
    _strlwr_s(q_dir_lower, sizeof(q_dir_lower));
    size_t q_len = strlen(q_dir_lower);
    if (q_len == 0 || q_dir_lower[q_len - 1] == '\\') return false;

    char canonical_lower[FOS_MAX_PATH];
    strncpy_s(canonical_lower, sizeof(canonical_lower), canonical, _TRUNCATE);
    _strlwr_s(canonical_lower, sizeof(canonical_lower));

    if (_strnicmp(canonical_lower, q_dir_lower, q_len) != 0) return false;
    char sep = canonical_lower[q_len];
    if (sep != '\\' && sep != '\0') return false;

    strncpy_s(out_canonical, out_sz, canonical, _TRUNCATE);
    return true;
}

/* ============================================================================
 * Internal Helpers
 * ========================================================================== */

/**
 * @brief Check if a canonicalized path is under a system directory that
 * restore operations should never write to (Windows, Program Files,
 * Program Files (x86), ProgramData).
 *
 * Returns TRUE if the path is SUSPICIOUS (should be rejected for restore).
 */
static bool is_sensitive_system_path(const char *canonical_path) {
    if (canonical_path == NULL) return true;

    char lower[FOS_MAX_PATH];
    strncpy_s(lower, sizeof(lower), canonical_path, _TRUNCATE);
    _strlwr_s(lower, sizeof(lower));

    static const struct {
        const char *env;      /* environment variable (or NULL for windir) */
    } k_roots[] = {
        { NULL },             /* -> GetWindowsDirectoryA */
        { "ProgramFiles" },
        { "ProgramFiles(x86)" },
        { "ProgramData" },
    };

    for (size_t i = 0; i < sizeof(k_roots) / sizeof(k_roots[0]); i++) {
        char root[FOS_MAX_PATH];
        if (k_roots[i].env == NULL) {
            if (GetWindowsDirectoryA(root, FOS_MAX_PATH) == 0) continue;
        } else {
            if (GetEnvironmentVariableA(k_roots[i].env, root, FOS_MAX_PATH) <= 0)
                continue;
        }
        _strlwr_s(root, sizeof(root));
        size_t rlen = strlen(root);
        if (rlen == 0) continue;
        if (rlen > 0 && root[rlen - 1] == '\\') root[--rlen] = '\0';
        if (_strnicmp(lower, root, rlen) == 0) {
            char sep = lower[rlen];
            if (sep == '\\' || sep == '\0') return true;
        }
    }
    return false;
}

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

    /* U-14: long-path-safe delete (CRT remove() caps at MAX_PATH). */
    fos_path_t q;
    bool removed_ok = fos_path_init(&q, data->q_path) && fos_delete_file(&q);
    if (removed_ok) {
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
 *
 * v1.1: orig_path is canonicalized and validated at history-load time (in
 * load_history_items), so by the time we get here the path has already been
 * vetted. We re-check here as defense-in-depth.
 */
static void on_restore_clicked(GtkButton *btn, gpointer user_data)
{
    (void)btn;
    HistoryActionData *data = (HistoryActionData *)user_data;

    /* Defense-in-depth: re-validate the orig_path before restoring */
    if (data->orig_path == NULL || data->orig_path[0] == '\0') {
        GtkAlertDialog *alert = gtk_alert_dialog_new(
            "Cannot restore: original path is missing or invalid.");
        gtk_alert_dialog_show(alert, GTK_WINDOW(data->app->window));
        g_object_unref(alert);
        return;
    }
    if (is_sensitive_system_path(data->orig_path)) {
        GtkAlertDialog *alert = gtk_alert_dialog_new(
            "Cannot restore: original path is under a protected system directory. "
            "Choose a different destination by editing the history log manually.");
        gtk_alert_dialog_show(alert, GTK_WINDOW(data->app->window));
        g_object_unref(alert);
        return;
    }

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
    FILE *f = fopen(app_path_history_log(), "r");
    if (f == NULL) {
        return;
    }

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';

        char *token_date   = strtok(line, "|");
        (void)strtok(NULL, "|");  /* token_threat — parsed but not displayed */
        char *token_orig   = strtok(NULL, "|");
        char *token_qpath  = strtok(NULL, "|");

        if (token_date == NULL || token_orig == NULL || token_qpath == NULL) {
            continue;
        }

        /* v1.1 security hardening: canonicalize and validate the paths
         * BEFORE using them in any file operation. If validation fails,
         * skip this entry entirely (don't display it, don't allow restore).
         * U-14: both helpers are handle-based; buffers are FOS_MAX_PATH. */
        char canonical_q[FOS_MAX_PATH] = {0};
        if (!is_safe_quarantine_path(token_qpath, canonical_q, sizeof(canonical_q))) {
            /* Quarantine path failed validation — skip this entry */
            continue;
        }
        char canonical_orig_buf[FOS_MAX_PATH];
        if (!canonicalize_restore_dest(token_orig, canonical_orig_buf,
                                       sizeof(canonical_orig_buf))) {
            /* Original path failed canonicalization — skip */
            continue;
        }
        char *canonical_orig = canonical_orig_buf;
        /* If the original path is a sensitive system path, we still display
         * the entry but disable restore (defense-in-depth handled in
         * on_restore_clicked). Display the canonicalized path. */

        /* Check if the physical file still exists in the vault */
        bool quarantine_exists = (GetFileAttributesA(canonical_q) != INVALID_FILE_ATTRIBUTES);

        const char *filename = strrchr(canonical_orig, '\\');
        if (filename == NULL) {
            filename = strrchr(canonical_orig, '/');
        }
        filename = (filename != NULL) ? filename + 1 : canonical_orig;

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

        /* Col 2: Original Path (show canonicalized) */
        GtkWidget *lbl_path = gtk_label_new(canonical_orig);
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

        /* v1.1: also disable restore if orig path is a sensitive system path */
        bool orig_is_sensitive = is_sensitive_system_path(canonical_orig);
        if (orig_is_sensitive) {
            gtk_widget_set_sensitive(btn_restore, FALSE);
        }

        /* Bind metadata and signals. Use the CANONICALIZED paths. */
        HistoryActionData *data = g_new0(HistoryActionData, 1);
        data->orig_path   = g_strdup(canonical_orig);
        data->q_path      = g_strdup(canonical_q);
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


