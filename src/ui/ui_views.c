/**
 * @file ui_views.c
 * @brief Main View Management Implementation
 *
 * As of v1.1, the first-run UI lock has been removed:
 *   - The "Initial Database Download" card has been deleted.
 *   - The first_run_update_worker() background thread has been deleted.
 *   - The check_first_run_progress_cb() timer has been deleted.
 *   - Scan / Advanced / Real-Time buttons are enabled unconditionally.
 *   - The realtime-protection switch's is_first_run guard has been removed.
 *
 * If no signature DB exists, scan attempts surface the existing
 * "signature database not loaded" error from scan_worker_thread() in
 * ui_scan.c. The user can also click "Update Now" in Settings to fetch
 * the DB via the Python aggregator.
 */

#define _CRT_SECURE_NO_WARNINGS

#include "ui_views.h"
#include "app_paths.h"
#include "rt_monitor.h"
#include "signature_scan.h"
#include "ui_scan.h"
#include "ui_update.h"

#include <gtk/gtk.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static void on_start_quick_scan(GtkButton *btn, gpointer user_data) {
    (void)btn;
    start_scan_logic((AppState *)user_data, "QUICK_SCAN");
}

static void on_go_to_advanced(GtkButton *btn, gpointer user_data) {
    (void)btn;
    AppState *app = (AppState *)user_data;
    gtk_stack_set_visible_child_name(GTK_STACK(app->stack), "advanced_scan");
}

static void on_realtime_toggled(GObject *object, GParamSpec *pspec, gpointer user_data) {
    (void)pspec;
    AppState *app = (AppState *)user_data;
    GtkSwitch *sw = GTK_SWITCH(object);
    gboolean active = gtk_switch_get_active(sw);

    /* v1.1: the is_first_run guard has been removed. The switch is always
     * sensitive. If the user toggles real-time protection on but no DB is
     * loaded, rt_monitor_start() will return non-zero and we revert. */

    if (active) {
        if (rt_monitor_start(app_path_signature_db()) != 0) {
            g_signal_handlers_block_by_func(sw, on_realtime_toggled, app);
            gtk_switch_set_active(sw, FALSE);
            g_signal_handlers_unblock_by_func(sw, on_realtime_toggled, app);
        }
    } else {
        rt_monitor_stop();
    }
}

static GtkWidget *create_realtime_protection_card(AppState *app) {
    GtkWidget *card = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 20);
    gtk_widget_add_css_class(card, "dashboard-card-bg");
    gtk_widget_set_size_request(card, -1, 95);

    GtkWidget *icon = gtk_image_new_from_icon_name("security-high-symbolic");
    gtk_widget_set_size_request(icon, 40, 40);
    gtk_widget_set_valign(icon, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_start(icon, 20);
    gtk_widget_add_css_class(icon, "scanner-icon");
    gtk_box_append(GTK_BOX(card), icon);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_widget_set_valign(vbox, GTK_ALIGN_CENTER);
    GtkWidget *title = gtk_label_new("Real-Time Protection");
    gtk_widget_set_halign(title, GTK_ALIGN_START);
    gtk_widget_add_css_class(title, "bold-text");
    GtkWidget *desc = gtk_label_new("Monitors system for behavioral threats and malware");
    gtk_widget_set_halign(desc, GTK_ALIGN_START);
    gtk_widget_add_css_class(desc, "dim-label");
    gtk_box_append(GTK_BOX(vbox), title);
    gtk_box_append(GTK_BOX(vbox), desc);
    gtk_box_append(GTK_BOX(card), vbox);

    GtkWidget *spacer = gtk_label_new("");
    gtk_widget_set_hexpand(spacer, TRUE);
    gtk_box_append(GTK_BOX(card), spacer);

    GtkWidget *sw = gtk_switch_new();
    gtk_widget_set_valign(sw, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_end(sw, 20);
    g_signal_connect(sw, "notify::active", G_CALLBACK(on_realtime_toggled), app);
    app->dashboard_rt_switch = sw;
    /* v1.1: switch is always sensitive — no is_first_run guard */
    gtk_box_append(GTK_BOX(card), sw);

    return card;
}

/* v1.1: first_run_update_worker() and check_first_run_progress_cb() have been
 * DELETED. The first-run UI lock is gone. Users can scan immediately. */

GtkWidget *create_dashboard_view(AppState *app) {
    GtkWidget *col = gtk_box_new(GTK_ORIENTATION_VERTICAL, 20);
    gtk_widget_set_margin_start(col, 30);
    gtk_widget_set_margin_end(col, 30);
    gtk_widget_set_margin_top(col, 30);
    gtk_widget_set_margin_bottom(col, 30);

    GtkWidget *title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title), "<span font='28px' weight='bold'>Overview</span>");
    gtk_widget_set_halign(title, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(col), title);

    /* v1.1: The entire `if (app->is_first_run)` block that created the
     * "Initial Database Download" card, spawned first_run_update_worker(),
     * and started the check_first_run_progress_cb timer has been DELETED.
     * The dashboard now renders the scan card unconditionally. */

    GtkWidget *scan_card = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 20);
    gtk_widget_add_css_class(scan_card, "dashboard-card-bg");
    gtk_widget_set_size_request(scan_card, -1, 100);

    GtkWidget *scan_icon = gtk_image_new_from_icon_name("media-record-symbolic");
    gtk_widget_set_size_request(scan_icon, 40, 40);
    gtk_widget_set_valign(scan_icon, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_start(scan_icon, 20);
    gtk_widget_add_css_class(scan_icon, "scanner-icon");
    gtk_box_append(GTK_BOX(scan_card), scan_icon);

    GtkWidget *scan_text_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_widget_set_valign(scan_text_vbox, GTK_ALIGN_CENTER);
    GtkWidget *quick_lbl = gtk_label_new("Quick Scan");
    gtk_widget_set_halign(quick_lbl, GTK_ALIGN_START);
    gtk_widget_add_css_class(quick_lbl, "bold-text");
    GtkWidget *quick_desc = gtk_label_new("Check critical system paths and active processes");
    gtk_widget_set_halign(quick_desc, GTK_ALIGN_START);
    gtk_widget_add_css_class(quick_desc, "dim-label");
    gtk_box_append(GTK_BOX(scan_text_vbox), quick_lbl);
    gtk_box_append(GTK_BOX(scan_text_vbox), quick_desc);
    gtk_box_append(GTK_BOX(scan_card), scan_text_vbox);

    GtkWidget *scanner_spacer = gtk_label_new("");
    gtk_widget_set_hexpand(scanner_spacer, TRUE);
    gtk_box_append(GTK_BOX(scan_card), scanner_spacer);

    GtkWidget *scan_btn = gtk_button_new_with_label("Start Scan");
    gtk_widget_add_css_class(scan_btn, "scan-btn");
    gtk_widget_set_margin_end(scan_btn, 10);
    gtk_widget_set_valign(scan_btn, GTK_ALIGN_CENTER);
    g_signal_connect(scan_btn, "clicked", G_CALLBACK(on_start_quick_scan), app);
    app->dashboard_scan_btn = scan_btn;

    GtkWidget *adv_btn = gtk_button_new();
    gtk_widget_set_size_request(adv_btn, 40, 40);
    gtk_widget_set_valign(adv_btn, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_end(adv_btn, 20);
    gtk_widget_add_css_class(adv_btn, "flat-button");
    gtk_button_set_child(GTK_BUTTON(adv_btn),
                         gtk_image_new_from_icon_name("view-more-horizontal-symbolic"));
    g_signal_connect(adv_btn, "clicked", G_CALLBACK(on_go_to_advanced), app);
    app->dashboard_adv_btn = adv_btn;

    /* v1.1: scan/adv buttons are always sensitive — no is_first_run guard */
    gtk_box_append(GTK_BOX(scan_card), scan_btn);
    gtk_box_append(GTK_BOX(scan_card), adv_btn);
    gtk_box_append(GTK_BOX(col), scan_card);

    gtk_box_append(GTK_BOX(col), create_realtime_protection_card(app));
    return col;
}

GtkWidget *create_settings_view(AppState *app) {
    GtkWidget *view = gtk_box_new(GTK_ORIENTATION_VERTICAL, 20);
    gtk_widget_set_margin_start(view, 30);
    gtk_widget_set_margin_end(view, 30);
    gtk_widget_set_margin_top(view, 30);
    gtk_widget_set_margin_bottom(view, 30);

    GtkWidget *title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title), "<span font='28px' weight='bold'>Settings</span>");
    gtk_widget_set_halign(title, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(view), title);

    GtkWidget *theme_card = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 20);
    gtk_widget_add_css_class(theme_card, "dashboard-card-bg");
    gtk_widget_set_size_request(theme_card, -1, 85);
    GtkWidget *theme_lbl = gtk_label_new("  Dark Mode ");
    gtk_widget_set_margin_start(theme_lbl, 10);
    gtk_widget_add_css_class(theme_lbl, "bold-text");
    gtk_box_append(GTK_BOX(theme_card), theme_lbl);
    GtkWidget *theme_spacer = gtk_label_new("");
    gtk_widget_set_hexpand(theme_spacer, TRUE);
    gtk_box_append(GTK_BOX(theme_card), theme_spacer);
    GtkSwitch *theme_sw = GTK_SWITCH(gtk_switch_new());
    gtk_switch_set_active(theme_sw, app->is_dark_mode);
    g_signal_connect(theme_sw, "state-set", G_CALLBACK(on_theme_toggled), app);
    gtk_widget_set_margin_end(GTK_WIDGET(theme_sw), 20);
    gtk_widget_set_valign(GTK_WIDGET(theme_sw), GTK_ALIGN_CENTER);
    gtk_box_append(GTK_BOX(theme_card), GTK_WIDGET(theme_sw));
    gtk_box_append(GTK_BOX(view), theme_card);

    GtkWidget *upd_card = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 20);
    gtk_widget_add_css_class(upd_card, "dashboard-card-bg");
    gtk_widget_set_size_request(upd_card, -1, 85);

    GtkWidget *upd_text_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_widget_set_valign(upd_text_vbox, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_start(upd_text_vbox, 20);
    GtkWidget *upd_title_lbl = gtk_label_new("Threat Detection Database");
    gtk_widget_add_css_class(upd_title_lbl, "bold-text");
    gtk_widget_set_halign(upd_title_lbl, GTK_ALIGN_START);

    char upd_ts_buf[128];
    snprintf(upd_ts_buf, sizeof(upd_ts_buf), "Last Updated: %s", last_update_time);
    GtkWidget *upd_ts_lbl = gtk_label_new(upd_ts_buf);
    gtk_widget_add_css_class(upd_ts_lbl, "dim-label");
    gtk_widget_set_halign(upd_ts_lbl, GTK_ALIGN_START);
    app->last_update_label = upd_ts_lbl;

    gtk_box_append(GTK_BOX(upd_text_vbox), upd_title_lbl);
    gtk_box_append(GTK_BOX(upd_text_vbox), upd_ts_lbl);
    gtk_box_append(GTK_BOX(upd_card), upd_text_vbox);

    GtkWidget *upd_spacer = gtk_label_new("");
    gtk_widget_set_hexpand(upd_spacer, TRUE);
    gtk_box_append(GTK_BOX(upd_card), upd_spacer);

    /* v1.1.1: The auto-update toggle has been REMOVED from this card.
     * It was redundant with the "Update Now" button — the toggle only
     * controlled the 6-hour background timer, which the user can effectively
     * manage by clicking "Update Now" when they want a refresh. The
     * auto_update_enabled global still defaults to TRUE and the timer still
     * runs; if you want to re-expose the toggle, re-add it here and wire it
     * to on_auto_update_toggled() in ui_update.c. */

    GtkWidget *upd_btn = gtk_button_new_with_label("Update Now");
    gtk_widget_add_css_class(upd_btn, "scan-btn");
    gtk_widget_set_margin_end(upd_btn, 20);
    gtk_widget_set_valign(upd_btn, GTK_ALIGN_CENTER);
    g_signal_connect(upd_btn, "clicked", G_CALLBACK(on_update_clicked), app);
    gtk_box_append(GTK_BOX(upd_card), upd_btn);

    gtk_box_append(GTK_BOX(view), upd_card);
    return view;
}
