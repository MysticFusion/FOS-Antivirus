#include <gtk/gtk.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

// Include your backend headers
#include "scan_bridge.h"
#include "signature_scan.h"
#include "scan_core.h"

// --- CSS THEMES ---
// REMOVED: "text-align: left" to fix GTK Warnings
static const char *CSS_LIGHT =
    "window { background-color: #FFFFFF; color: #1A202C; }"
    ".sidebar { background-color: #F7FAFC; border-right: 1px solid #E2E8F0; transition: min-width 200ms ease; }"
    ".dashboard-card-bg { background-color: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 12px; }"
    ".protection-card-bg { background-color: #F7FAFC; border-radius: 12px; }"
    
    /* Nav Items */
    ".nav-item { background: transparent; border: none; border-radius: 6px; padding: 10px 12px; color: #4A5568; }"
    ".nav-item:hover { background: #EDF2F7; color: #2D3748; }"
    
    /* Burger Button */
    ".burger-btn { background: transparent; border: none; color: #4A5568; border-radius: 4px; padding: 8px; }"
    ".burger-btn:hover { background: #E2E8F0; color: #1A202C; }"

    /* Action Buttons */
    ".scan-btn { background: #3182CE; color: white; border-radius: 8px; padding: 6px 16px; border: none; }"
    ".scan-btn:hover { background: #2B6CB0; }"
    ".flat-button { background: transparent; border: none; color: #4A5568; border-radius: 4px; padding: 4px; }"
    ".flat-button:hover { background: #EDF2F7; color: #1A202C; }"
    
    /* Text & Icons */
    ".bold-text { font-weight: bold; font-size: 16px; }"
    ".scanner-icon { background: #EBF8FF; color: #3182CE; border-radius: 10px; padding: 8px; }"
    ".history-icon { background: #EDF2F7; color: #718096; border-radius: 50%; padding: 5px; }"
    "label { color: inherit; }";

static const char *CSS_DARK =
    "window { background-color: #171923; color: #F7FAFC; }"
    ".sidebar { background-color: #1A202C; border-right: 1px solid #2D3748; transition: min-width 200ms ease; }"
    ".dashboard-card-bg { background-color: #2D3748; border: 1px solid #4A5568; border-radius: 12px; }"
    ".protection-card-bg { background-color: #2D3748; border-radius: 12px; }"
    ".nav-item { background: transparent; border: none; border-radius: 6px; padding: 10px 12px; color: #A0AEC0; }"
    ".nav-item:hover { background: #2D3748; color: #FFFFFF; }"
    ".burger-btn { background: transparent; border: none; color: #A0AEC0; border-radius: 4px; padding: 8px; }"
    ".burger-btn:hover { background: #4A5568; color: #FFFFFF; }"
    ".scan-btn { background: #3182CE; color: white; border-radius: 8px; padding: 6px 16px; border: none; }"
    ".scan-btn:hover { background: #2B6CB0; }"
    ".flat-button { background: transparent; border: none; color: #E2E8F0; border-radius: 4px; padding: 4px; }"
    ".flat-button:hover { background: #4A5568; color: #FFFFFF; }"
    ".bold-text { font-weight: bold; font-size: 16px; }"
    ".scanner-icon { background: #2A4365; color: #63B3ED; border-radius: 10px; padding: 8px; }"
    ".history-icon { background: #2D3748; color: #A0AEC0; border-radius: 50%; padding: 5px; }"
    "label { color: inherit; }";

// --- Global Context ---
ScanContext global_scan_ctx;

// --- App State ---
typedef struct {
    GtkWidget *window;
    GtkWidget *sidebar;
    GtkWidget *stack;       
    GtkWidget *progress_bar;
    GtkWidget *progress_label;
    GtkWidget *result_files_label;
    GtkWidget *result_threats_label;
    GtkWidget *history_list_box; 

    GtkCssProvider *css_provider;
    gboolean is_dark_mode;
    gboolean is_sidebar_collapsed; 
    
    GList *sidebar_labels; 
} AppState;

extern int restore_file_from_quarantine(const char *q_path, const char *dest_path);

// --- Forward Declarations ---
GtkWidget *create_dashboard_view(AppState *app);
GtkWidget *create_scanner_progress_view(AppState *app);
GtkWidget *create_scan_complete_view(AppState *app);
GtkWidget *create_advanced_scan_view(AppState *app);
GtkWidget *create_history_view(AppState *app);
GtkWidget *create_settings_view(AppState *app);

static void go_to_dashboard(GtkButton *btn, gpointer user_data);
static void go_to_advanced(GtkButton *btn, gpointer user_data);
static void go_to_history(GtkButton *btn, gpointer user_data);
static void go_to_settings(GtkButton *btn, gpointer user_data);
static void start_quick_scan(GtkButton *btn, gpointer user_data);
static void update_theme(AppState *app);

// --- Backend Logic ---
gpointer scan_worker_thread(gpointer user_data) {
    char *mode = (char *)user_data; 
    const char *db_path = "signatures.db"; 

    g_mutex_lock(&global_scan_ctx.mutex);
    global_scan_ctx.is_running = true;
    global_scan_ctx.stop_requested = false;
    global_scan_ctx.files_scanned = 0;
    global_scan_ctx.threats_found = 0;
    memset(global_scan_ctx.current_file, 0, 256);
    memset(global_scan_ctx.last_threat, 0, 256);
    g_mutex_unlock(&global_scan_ctx.mutex);

    if (strcmp(mode, "QUICK_SCAN") == 0) {
        const char *dirs_to_scan[] = {
            g_get_user_special_dir(G_USER_DIRECTORY_DOWNLOAD),
            g_get_user_special_dir(G_USER_DIRECTORY_DESKTOP),
            NULL
        };
        for (int i = 0; dirs_to_scan[i] != NULL; i++) {
            if (dirs_to_scan[i] == NULL) continue;
            g_mutex_lock(&global_scan_ctx.mutex);
            if (global_scan_ctx.stop_requested) { g_mutex_unlock(&global_scan_ctx.mutex); break; }
            g_mutex_unlock(&global_scan_ctx.mutex);
            signature_scan(db_path, dirs_to_scan[i]);
        }
    } else if (strcmp(mode, "FULL_SYSTEM") == 0) {
        signature_scan(db_path, "C:\\Users"); 
    } else {
        signature_scan(db_path, mode);
    }

    g_mutex_lock(&global_scan_ctx.mutex);
    global_scan_ctx.is_running = false;
    g_mutex_unlock(&global_scan_ctx.mutex);
    g_free(mode); 
    return NULL;
}

static gboolean on_scan_progress_tick(gpointer user_data) {
    AppState *app = (AppState *)user_data;
    g_mutex_lock(&global_scan_ctx.mutex);
    
    // Copy to local buffer to minimize mutex hold time
    char raw_file[256];
    strncpy(raw_file, global_scan_ctx.current_file, 255);
    raw_file[255] = '\0';

    bool still_running = global_scan_ctx.is_running;
    int final_files = global_scan_ctx.files_scanned;
    int final_threats = global_scan_ctx.threats_found;
    g_mutex_unlock(&global_scan_ctx.mutex);

    // FIX: Convert Windows ANSI path to UTF-8 for GTK
    GError *conv_err = NULL;
    char *utf8_file = g_locale_to_utf8(raw_file, -1, NULL, NULL, &conv_err);
    
    char file_label[512];
    if (utf8_file) {
        size_t len = strlen(utf8_file);
        // Smart truncation for long paths
        if (len > 40) 
            snprintf(file_label, sizeof(file_label), "Scanning: ...%s", &utf8_file[len - 40]);
        else 
            snprintf(file_label, sizeof(file_label), "Scanning: %s", utf8_file);
        g_free(utf8_file);
    } else {
        // Fallback if conversion fails (e.g. invalid chars)
        snprintf(file_label, sizeof(file_label), "Scanning: [System File]");
        if (conv_err) g_error_free(conv_err);
    }
    
    gtk_label_set_text(GTK_LABEL(app->progress_label), file_label);
    gtk_progress_bar_pulse(GTK_PROGRESS_BAR(app->progress_bar));

    if (!still_running) {
        gchar *f_txt = g_strdup_printf("Files Scanned: %d", final_files);
        gchar *t_txt = g_strdup_printf("Threats Found: %d", final_threats);
        gtk_label_set_text(GTK_LABEL(app->result_files_label), f_txt);
        gtk_label_set_text(GTK_LABEL(app->result_threats_label), t_txt);
        g_free(f_txt); g_free(t_txt);
        gtk_stack_set_visible_child_name(GTK_STACK(app->stack), "complete");
        return FALSE; 
    }
    return TRUE; 
}

static void start_scan_logic(AppState *app, char *path_or_mode) {
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(app->progress_bar), 0.0);
    gtk_label_set_text(GTK_LABEL(app->progress_label), "Initializing...");
    gtk_stack_set_visible_child_name(GTK_STACK(app->stack), "progress");
    g_thread_new("Scanner", scan_worker_thread, path_or_mode);
    g_timeout_add(100, on_scan_progress_tick, app);
}

static void start_quick_scan(GtkButton *btn, gpointer user_data) {
    start_scan_logic((AppState *)user_data, g_strdup("QUICK_SCAN"));
}

// --- MODERN FILE CHOOSER (Replacements for Deprecated Warnings) ---

static void on_folder_selected(GObject *source_object, GAsyncResult *res, gpointer user_data) {
    GtkFileDialog *dialog = GTK_FILE_DIALOG(source_object);
    AppState *app = (AppState *)user_data;
    GError *error = NULL;

    GFile *folder = gtk_file_dialog_select_folder_finish(dialog, res, &error);

    if (folder != NULL) {
        char *path = g_file_get_path(folder);
        if (path) {
            // FIX: DO NOT free 'path' here! 
            // We pass ownership to start_scan_logic -> scan_worker_thread.
            // The worker thread will g_free() it when finished.
            start_scan_logic(app, path); 
        }
        g_object_unref(folder);
    } else {
        if (error) g_error_free(error);
    }
}

static void on_browse_clicked(GtkButton *btn, gpointer user_data) {
    AppState *app = (AppState *)user_data;
    GtkFileDialog *dialog = gtk_file_dialog_new();
    gtk_file_dialog_set_title(dialog, "Select Folder to Scan");
    gtk_file_dialog_select_folder(dialog, GTK_WINDOW(app->window), NULL, on_folder_selected, app);
    g_object_unref(dialog);
}

static void update_theme(AppState *app) {
    if (app->is_dark_mode) gtk_css_provider_load_from_string(app->css_provider, CSS_DARK);
    else gtk_css_provider_load_from_string(app->css_provider, CSS_LIGHT);
}

static void on_dark_mode_toggled(GtkSwitch *widget, gboolean state, gpointer user_data) {
    AppState *app = (AppState *)user_data;
    app->is_dark_mode = state;
    update_theme(app);
}

typedef struct { char *orig_path; char *q_path; GtkWidget *row_widget; AppState *app; } RestoreData;

// --- MODERN ALERT DIALOG (Replacements for Deprecated Warnings) ---

static void on_restore_clicked(GtkButton *btn, gpointer user_data) {
    RestoreData *data = (RestoreData *)user_data;
    if (restore_file_from_quarantine(data->q_path, data->orig_path) == 0) {
        gtk_list_box_remove(GTK_LIST_BOX(data->app->history_list_box), data->row_widget);
        
        GtkAlertDialog *alert = gtk_alert_dialog_new("File Restored Successfully");
        gtk_alert_dialog_show(alert, GTK_WINDOW(data->app->window));
        g_object_unref(alert);
    }
}

// --- Navigation ---
static void set_active_view(AppState *app, const char *view_name) {
    gtk_stack_set_visible_child_name(GTK_STACK(app->stack), view_name);
}
static void go_to_dashboard(GtkButton *btn, gpointer user_data) { set_active_view((AppState *)user_data, "dashboard"); }
static void go_to_advanced(GtkButton *btn, gpointer user_data) { set_active_view((AppState *)user_data, "advanced_scan"); }
static void go_to_history(GtkButton *btn, gpointer user_data) { set_active_view((AppState *)user_data, "history"); }
static void go_to_settings(GtkButton *btn, gpointer user_data) { set_active_view((AppState *)user_data, "settings"); }

// --- SIDEBAR LOGIC (Toggle functionality) ---

static void toggle_sidebar_collapse(GtkButton *btn, gpointer user_data) {
    AppState *app = (AppState *)user_data;
    app->is_sidebar_collapsed = !app->is_sidebar_collapsed;

    // 1. Hide/Show Labels
    GList *iter = app->sidebar_labels;
    while (iter != NULL) {
        GtkWidget *label = GTK_WIDGET(iter->data);
        gtk_widget_set_visible(label, !app->is_sidebar_collapsed);
        iter = iter->next;
    }

    // 2. Change width request aggressively
    if (app->is_sidebar_collapsed) {
        // Collapsed: 60px (Icon 16 + Padding 12 + 12 + Margins)
        gtk_widget_set_size_request(app->sidebar, 60, -1);
    } else {
        // Expanded: 200px
        gtk_widget_set_size_request(app->sidebar, 200, -1);
    }
}

GtkWidget *create_nav_item(AppState *app, const char *icon_name, const char *label_text) {
    GtkWidget *btn = gtk_button_new();
    gtk_widget_set_hexpand(btn, TRUE); // Ensure button fills width
    gtk_widget_add_css_class(btn, "nav-item");
    
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    // Align content to start, but icon remains visible when shrunk
    gtk_widget_set_halign(box, GTK_ALIGN_START); 
    
    GtkWidget *icon = gtk_image_new_from_icon_name(icon_name);
    // Important: Don't let icon shrink to 0
    gtk_widget_set_size_request(icon, 16, 16); 
    gtk_box_append(GTK_BOX(box), icon);

    GtkWidget *label = gtk_label_new(label_text);
    gtk_box_append(GTK_BOX(box), label);

    // Track label for collapsing
    app->sidebar_labels = g_list_append(app->sidebar_labels, label);

    gtk_button_set_child(GTK_BUTTON(btn), box);
    return btn;
}

GtkWidget *create_sidebar(AppState *app) {
    GtkWidget *sidebar = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0); 
    app->sidebar = sidebar; 
    
    // Initial Width: 200px
    gtk_widget_set_size_request(sidebar, 200, -1); 
    gtk_widget_set_hexpand(sidebar, FALSE); // CRITICAL: Don't let it auto-expand
    gtk_widget_add_css_class(sidebar, "sidebar");

    // --- BURGER BUTTON (Top Left) ---
    GtkWidget *header_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_widget_set_margin_top(header_box, 15);
    // Align margin with the Nav Items (12px padding inside button + 10px margin = ~22px indent)
    gtk_widget_set_margin_start(header_box, 15); 
    gtk_widget_set_margin_bottom(header_box, 20);

    GtkWidget *burger_btn = gtk_button_new();
    gtk_widget_add_css_class(burger_btn, "burger-btn");
    GtkWidget *burger_icon = gtk_image_new_from_icon_name("open-menu-symbolic");
    gtk_button_set_child(GTK_BUTTON(burger_btn), burger_icon);
    
    g_signal_connect(burger_btn, "clicked", G_CALLBACK(toggle_sidebar_collapse), app);
    gtk_box_append(GTK_BOX(header_box), burger_btn);

    gtk_box_append(GTK_BOX(sidebar), header_box);
    
    // --- Navigation Items ---
    GtkWidget *nav_group = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_widget_set_margin_start(nav_group, 10);
    gtk_widget_set_margin_end(nav_group, 10);

    GtkWidget *dash_btn = create_nav_item(app, "view-grid-symbolic", "Dashboard"); 
    g_signal_connect(dash_btn, "clicked", G_CALLBACK(go_to_dashboard), app);
    gtk_box_append(GTK_BOX(nav_group), dash_btn);

    GtkWidget *hist_btn = create_nav_item(app, "document-open-recent-symbolic", "History");
    g_signal_connect(hist_btn, "clicked", G_CALLBACK(go_to_history), app);
    gtk_box_append(GTK_BOX(nav_group), hist_btn);

    gtk_box_append(GTK_BOX(sidebar), nav_group);

    // Spacer
    GtkWidget *spacer = gtk_label_new(""); 
    gtk_widget_set_vexpand(spacer, TRUE);
    gtk_box_append(GTK_BOX(sidebar), spacer);

    // Settings at Bottom
    GtkWidget *sett_group = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_widget_set_margin_start(sett_group, 10);
    gtk_widget_set_margin_end(sett_group, 10);
    gtk_widget_set_margin_bottom(sett_group, 20);

    GtkWidget *sett_btn = create_nav_item(app, "preferences-system-symbolic", "Settings");
    g_signal_connect(sett_btn, "clicked", G_CALLBACK(go_to_settings), app);
    gtk_box_append(GTK_BOX(sett_group), sett_btn);

    gtk_box_append(GTK_BOX(sidebar), sett_group);

    return sidebar;
}

GtkWidget *create_topbar(AppState *app) {
    GtkWidget *topbar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 15);
    gtk_widget_set_margin_top(topbar, 10);
    gtk_widget_set_margin_start(topbar, 15); gtk_widget_set_margin_end(topbar, 15);

    // Sidebar toggle is now inside Sidebar, so we just have logo here
    GtkWidget *logo = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(logo), "<span font='22px' weight='bold' foreground='#3182CE'>🛡️FOS-ANTIVIRUS</span>");
    gtk_box_append(GTK_BOX(topbar), logo);

    return topbar;
}

// --- Views ---

GtkWidget *create_dashboard_view(AppState *app) {
    GtkWidget *col = gtk_box_new(GTK_ORIENTATION_VERTICAL, 20);
    gtk_widget_set_margin_start(col, 30); gtk_widget_set_margin_top(col, 30);
    gtk_widget_set_margin_end(col, 30);
    
    GtkWidget *title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title), "<span font='28px' weight='bold'>Overview</span>");
    gtk_widget_set_halign(title, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(col), title);

    // Scanner Card
    GtkWidget *card = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 20);
    gtk_widget_add_css_class(card, "dashboard-card-bg");
    gtk_widget_set_size_request(card, -1, 100);
    
    GtkWidget *icon = gtk_image_new_from_icon_name("media-record-symbolic");
    gtk_widget_set_size_request(icon, 40, 40); gtk_widget_set_valign(icon, GTK_ALIGN_CENTER); gtk_widget_set_margin_start(icon, 20);
    gtk_widget_add_css_class(icon, "scanner-icon");
    gtk_box_append(GTK_BOX(card), icon);
    
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_widget_set_valign(vbox, GTK_ALIGN_CENTER);
    GtkWidget *l1 = gtk_label_new("Quick Scan"); gtk_widget_set_halign(l1, GTK_ALIGN_START); gtk_widget_add_css_class(l1, "bold-text");
    GtkWidget *l2 = gtk_label_new("Scans critical system areas"); gtk_widget_set_halign(l2, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(vbox), l1); gtk_box_append(GTK_BOX(vbox), l2);
    gtk_box_append(GTK_BOX(card), vbox);
    
    GtkWidget *spacer = gtk_label_new(""); gtk_widget_set_hexpand(spacer, TRUE); gtk_box_append(GTK_BOX(card), spacer);

    GtkWidget *scan_btn = gtk_button_new_with_label("Start Scan");
    gtk_widget_add_css_class(scan_btn, "scan-btn"); gtk_widget_set_margin_end(scan_btn, 20); gtk_widget_set_valign(scan_btn, GTK_ALIGN_CENTER);
    g_signal_connect(scan_btn, "clicked", G_CALLBACK(start_quick_scan), app);
    gtk_box_append(GTK_BOX(card), scan_btn);
    
    GtkWidget *adv_btn = gtk_button_new();
    gtk_widget_add_css_class(adv_btn, "flat-button");
    gtk_button_set_child(GTK_BUTTON(adv_btn), gtk_image_new_from_icon_name("view-more-horizontal-symbolic"));
    g_signal_connect(adv_btn, "clicked", G_CALLBACK(go_to_advanced), app);
    gtk_box_append(GTK_BOX(card), adv_btn);

    gtk_box_append(GTK_BOX(col), card);
    return col;
}

GtkWidget *create_advanced_scan_view(AppState *app) {
    GtkWidget *view = gtk_box_new(GTK_ORIENTATION_VERTICAL, 20);
    gtk_widget_set_margin_start(view, 30); gtk_widget_set_margin_top(view, 30); gtk_widget_set_margin_end(view, 30);
    gtk_box_append(GTK_BOX(view), gtk_label_new("Advanced Scan"));
    GtkWidget *custom_card = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 20);
    gtk_widget_add_css_class(custom_card, "dashboard-card-bg");
    gtk_widget_set_size_request(custom_card, -1, 80);
    gtk_box_append(GTK_BOX(custom_card), gtk_label_new("  Custom Scan (Select Directory)"));
    GtkWidget *sp1 = gtk_label_new(""); gtk_widget_set_hexpand(sp1, TRUE); gtk_box_append(GTK_BOX(custom_card), sp1);
    GtkWidget *sel_btn = gtk_button_new_with_label("Browse Files...");
    gtk_widget_add_css_class(sel_btn, "scan-btn"); gtk_widget_set_margin_end(sel_btn, 20);
    g_signal_connect(sel_btn, "clicked", G_CALLBACK(on_browse_clicked), app);
    gtk_box_append(GTK_BOX(custom_card), sel_btn);
    gtk_box_append(GTK_BOX(view), custom_card);
    GtkWidget *back_btn = gtk_button_new_with_label("Back");
    gtk_widget_set_halign(back_btn, GTK_ALIGN_START);
    gtk_widget_add_css_class(back_btn, "flat-button");
    g_signal_connect(back_btn, "clicked", G_CALLBACK(go_to_dashboard), app);
    gtk_box_append(GTK_BOX(view), back_btn);
    return view;
}

GtkWidget *create_settings_view(AppState *app) {
    GtkWidget *view = gtk_box_new(GTK_ORIENTATION_VERTICAL, 20);
    gtk_widget_set_margin_start(view, 30); gtk_widget_set_margin_top(view, 30); gtk_widget_set_margin_end(view, 30);
    GtkWidget *title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title), "<span font='28px' weight='bold'>Settings</span>");
    gtk_widget_set_halign(title, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(view), title);
    GtkWidget *card = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 20);
    gtk_widget_add_css_class(card, "dashboard-card-bg");
    gtk_widget_set_size_request(card, -1, 80);
    GtkWidget *lbl = gtk_label_new("  Dark Mode");
    gtk_widget_add_css_class(lbl, "bold-text");
    gtk_box_append(GTK_BOX(card), lbl);
    GtkWidget *spacer = gtk_label_new(""); gtk_widget_set_hexpand(spacer, TRUE);
    gtk_box_append(GTK_BOX(card), spacer);
    GtkSwitch *sw = GTK_SWITCH(gtk_switch_new());
    gtk_switch_set_active(sw, app->is_dark_mode);
    g_signal_connect(sw, "state-set", G_CALLBACK(on_dark_mode_toggled), app);
    gtk_widget_set_margin_end(GTK_WIDGET(sw), 20);
    gtk_widget_set_valign(GTK_WIDGET(sw), GTK_ALIGN_CENTER);
    gtk_box_append(GTK_BOX(card), GTK_WIDGET(sw));
    gtk_box_append(GTK_BOX(view), card);
    return view;
}

static void load_history_items(AppState *app) {
    GtkWidget *child = gtk_widget_get_first_child(app->history_list_box);
    while (child != NULL) {
        GtkWidget *next = gtk_widget_get_next_sibling(child);
        gtk_list_box_remove(GTK_LIST_BOX(app->history_list_box), child);
        child = next;
    }
    FILE *f = fopen("history.log", "r");
    if (!f) return;
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        char *date = strtok(line, "|");
        char *name = strtok(NULL, "|");
        char *orig = strtok(NULL, "|");
        char *qpath = strtok(NULL, "|");
        if (date && name && orig && qpath) {
            GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
            gtk_widget_set_margin_top(row, 10); gtk_widget_set_margin_bottom(row, 10);
            char *display_text = g_strdup_printf("<b>%s</b>\n%s\n<small>%s</small>", name, date, orig);
            GtkWidget *lbl = gtk_label_new(NULL);
            gtk_label_set_markup(GTK_LABEL(lbl), display_text);
            g_free(display_text);
            gtk_box_append(GTK_BOX(row), lbl);
            GtkWidget *spacer = gtk_label_new(""); gtk_widget_set_hexpand(spacer, TRUE);
            gtk_box_append(GTK_BOX(row), spacer);
            GtkWidget *rest_btn = gtk_button_new_with_label("Restore");
            gtk_widget_add_css_class(rest_btn, "scan-btn");
            RestoreData *data = g_new0(RestoreData, 1);
            data->orig_path = g_strdup(orig); data->q_path = g_strdup(qpath);
            data->row_widget = row; data->app = app;
            g_signal_connect_data(rest_btn, "clicked", G_CALLBACK(on_restore_clicked), data, (GClosureNotify)g_free, 0);
            gtk_box_append(GTK_BOX(row), rest_btn);
            gtk_list_box_append(GTK_LIST_BOX(app->history_list_box), row);
        }
    }
    fclose(f);
}

GtkWidget *create_history_view(AppState *app) {
    GtkWidget *view = gtk_box_new(GTK_ORIENTATION_VERTICAL, 20);
    gtk_widget_set_margin_top(view, 30); gtk_widget_set_margin_start(view, 30); gtk_widget_set_margin_end(view, 30);
    GtkWidget *title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title), "<span font='28px' weight='bold'>Detection History</span>");
    gtk_widget_set_halign(title, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(view), title);
    app->history_list_box = gtk_list_box_new();
    gtk_widget_add_css_class(app->history_list_box, "dashboard-card-bg");
    GtkWidget *scroll = gtk_scrolled_window_new();
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), app->history_list_box);
    gtk_widget_set_vexpand(scroll, TRUE);
    gtk_box_append(GTK_BOX(view), scroll);
    load_history_items(app);
    return view;
}

GtkWidget *create_scanner_progress_view(AppState *app) {
    GtkWidget *view = gtk_box_new(GTK_ORIENTATION_VERTICAL, 20);
    gtk_widget_set_halign(view, GTK_ALIGN_CENTER); gtk_widget_set_valign(view, GTK_ALIGN_CENTER);
    GtkWidget *card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 30);
    gtk_widget_add_css_class(card, "dashboard-card-bg");
    gtk_widget_set_size_request(card, 500, 250);
    gtk_box_append(GTK_BOX(card), gtk_label_new("Scan in Progress..."));
    app->progress_label = gtk_label_new("Initializing...");
    gtk_box_append(GTK_BOX(card), app->progress_label);
    app->progress_bar = gtk_progress_bar_new();
    gtk_widget_set_margin_start(app->progress_bar, 20); gtk_widget_set_margin_end(app->progress_bar, 20);
    gtk_box_append(GTK_BOX(card), app->progress_bar);
    GtkWidget *cancel_btn = gtk_button_new_with_label("Cancel Scan");
    g_signal_connect(cancel_btn, "clicked", G_CALLBACK(go_to_dashboard), app); 
    gtk_box_append(GTK_BOX(card), cancel_btn);
    gtk_box_append(GTK_BOX(view), card);
    return view;
}

GtkWidget *create_scan_complete_view(AppState *app) {
    GtkWidget *view = gtk_box_new(GTK_ORIENTATION_VERTICAL, 20);
    gtk_widget_set_halign(view, GTK_ALIGN_CENTER); gtk_widget_set_valign(view, GTK_ALIGN_CENTER);
    GtkWidget *card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 20);
    gtk_widget_add_css_class(card, "dashboard-card-bg");
    gtk_widget_set_size_request(card, 400, 250);
    GtkWidget *icon = gtk_image_new_from_icon_name("security-high-symbolic");
    gtk_widget_set_size_request(icon, 64, 64); gtk_widget_add_css_class(icon, "scanner-icon"); 
    gtk_box_append(GTK_BOX(card), icon);
    gtk_box_append(GTK_BOX(card), gtk_label_new("Scan Complete"));
    GtkWidget *grid = gtk_grid_new();
    gtk_widget_set_halign(grid, GTK_ALIGN_CENTER); gtk_grid_set_row_spacing(GTK_GRID(grid), 10); gtk_grid_set_column_spacing(GTK_GRID(grid), 20);
    gtk_box_append(GTK_BOX(card), grid);
    app->result_files_label = gtk_label_new("Files Scanned: 0");
    app->result_threats_label = gtk_label_new("Threats Found: 0");
    gtk_grid_attach(GTK_GRID(grid), app->result_files_label, 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), app->result_threats_label, 0, 1, 1, 1);
    GtkWidget *home_btn = gtk_button_new_with_label("Back to Dashboard");
    gtk_widget_add_css_class(home_btn, "scan-btn"); 
    g_signal_connect(home_btn, "clicked", G_CALLBACK(go_to_dashboard), app);
    gtk_box_append(GTK_BOX(card), home_btn);
    gtk_box_append(GTK_BOX(view), card);
    return view;
}

static void activate(GtkApplication *gtk_app, gpointer user_data) {
    AppState *app = g_new0(AppState, 1); 
    app->window = gtk_application_window_new(gtk_app);
    gtk_window_set_default_size(GTK_WINDOW(app->window), 1000, 650);
    gtk_window_set_title(GTK_WINDOW(app->window), "FOS-Antivirus");

    GtkWidget *main_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_window_set_child(GTK_WINDOW(app->window), main_box);
    gtk_box_append(GTK_BOX(main_box), create_sidebar(app));

    GtkWidget *content = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_hexpand(content, TRUE);
    gtk_box_append(GTK_BOX(main_box), content);
    gtk_box_append(GTK_BOX(content), create_topbar(app));

    GtkWidget *body_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 15);
    gtk_widget_set_vexpand(body_box, TRUE);
    gtk_box_append(GTK_BOX(content), body_box);

    app->stack = gtk_stack_new();
    gtk_stack_set_transition_type(GTK_STACK(app->stack), GTK_STACK_TRANSITION_TYPE_CROSSFADE);
    
    gtk_stack_add_titled(GTK_STACK(app->stack), create_dashboard_view(app), "dashboard", "Dashboard");
    gtk_stack_add_titled(GTK_STACK(app->stack), create_advanced_scan_view(app), "advanced_scan", "Advanced");
    gtk_stack_add_titled(GTK_STACK(app->stack), create_history_view(app), "history", "History");
    gtk_stack_add_titled(GTK_STACK(app->stack), create_settings_view(app), "settings", "Settings");
    gtk_stack_add_titled(GTK_STACK(app->stack), create_scanner_progress_view(app), "progress", "Progress");
    gtk_stack_add_titled(GTK_STACK(app->stack), create_scan_complete_view(app), "complete", "Complete"); 
    
    gtk_box_append(GTK_BOX(body_box), app->stack);

    app->css_provider = gtk_css_provider_new();
    app->is_dark_mode = FALSE;
    update_theme(app);
    
    gtk_style_context_add_provider_for_display(gdk_display_get_default(), GTK_STYLE_PROVIDER(app->css_provider), GTK_STYLE_PROVIDER_PRIORITY_USER);

    gtk_window_present(GTK_WINDOW(app->window));
}

int main(int argc, char **argv) {
    GtkApplication *app = gtk_application_new("com.fyp.antivirus", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);
    int status = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);
    return status;
}