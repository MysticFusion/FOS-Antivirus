/**
 * @file ui_views.c
 * @brief Main View Management Implementation
 *
 * Implements the dashboard and settings screens. Handles the coordination
 * of real-time protection toggles, first-run initialization flows, and
 * dashboard quick-actions.
 *
 */

#include "ui_views.h"
#include "ui_scan.h"   
#include "ui_update.h"
#include "rt_monitor.h"
#include "signature_scan.h"

#include <gtk/gtk.h>
#include <time.h>
#include <string.h>
#include <stdio.h>

/* ============================================================================
 * Dashboard Logic
 * ========================================================================== */

static void on_start_quick_scan(GtkButton* btn, gpointer user_data)
{
    (void)btn;
    start_scan_logic((AppState*)user_data, "QUICK_SCAN");
}

static void on_go_to_advanced(GtkButton* btn, gpointer user_data)
{
    (void)btn;
    AppState* app = (AppState*)user_data;
    gtk_stack_set_visible_child_name(GTK_STACK(app->stack), "advanced_scan");
}

/* ============================================================================
 * Real-Time Protection Coordination
 * ========================================================================== */

/**
 * @brief Handle user toggling of the real-time protection switch.
 */
static void on_realtime_toggled(GObject* object, GParamSpec* pspec, gpointer user_data)
{
    (void)pspec;
    AppState* app  = (AppState*)user_data;
    GtkSwitch* sw  = GTK_SWITCH(object);
    gboolean active = gtk_switch_get_active(sw);

    /* Protection level: If first run (no DB), force active=FALSE */
    if (app->is_first_run && active) {
        g_signal_handlers_block_by_func(sw, on_realtime_toggled, app);
        gtk_switch_set_active(sw, FALSE);
        g_signal_handlers_unblock_by_func(sw, on_realtime_toggled, app);
        return; 
    }

    if (active) {
        if (rt_monitor_start("signatures.db") != 0) {
            /* Fallback: revert if engine fails to start */
            g_signal_handlers_block_by_func(sw, on_realtime_toggled, app);
            gtk_switch_set_active(sw, FALSE);
            g_signal_handlers_unblock_by_func(sw, on_realtime_toggled, app);
        }
    } else {
        rt_monitor_stop();
    }
}

/**
 * @brief Factory for the Real-Time protection UI card.
 */
static GtkWidget* create_realtime_protection_card(AppState* app)
{
    GtkWidget* card = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 20);
    gtk_widget_add_css_class(card, "dashboard-card-bg");
    gtk_widget_set_size_request(card, -1, 95);

    /* 1. Icon */
    GtkWidget* icon = gtk_image_new_from_icon_name("security-high-symbolic");
    gtk_widget_set_size_request(icon, 40, 40); 
    gtk_widget_set_valign(icon, GTK_ALIGN_CENTER); 
    gtk_widget_set_margin_start(icon, 20);
    gtk_widget_add_css_class(icon, "scanner-icon");
    gtk_box_append(GTK_BOX(card), icon);

    /* 2. Description Text */
    GtkWidget* vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_widget_set_valign(vbox, GTK_ALIGN_CENTER);
    
    GtkWidget* title = gtk_label_new("Real-Time Protection");
    gtk_widget_set_halign(title, GTK_ALIGN_START);
    gtk_widget_add_css_class(title, "bold-text");
    
    GtkWidget* desc = gtk_label_new("Monitors system for behavioral threats and malware");
    gtk_widget_set_halign(desc, GTK_ALIGN_START);
    gtk_widget_add_css_class(desc, "dim-label");

    gtk_box_append(GTK_BOX(vbox), title);
    gtk_box_append(GTK_BOX(vbox), desc);
    gtk_box_append(GTK_BOX(card), vbox);

    /* 3. Global Action Spacer */
    GtkWidget* spacer = gtk_label_new("");
    gtk_widget_set_hexpand(spacer, TRUE);
    gtk_box_append(GTK_BOX(card), spacer);

    /* 4. Persistence Switch */
    GtkWidget* sw = gtk_switch_new();
    gtk_widget_set_valign(sw, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_end(sw, 20);
    g_signal_connect(sw, "notify::active", G_CALLBACK(on_realtime_toggled), app);
    
    app->dashboard_rt_switch = sw;
    if (app->is_first_run) {
        gtk_widget_set_sensitive(sw, FALSE);
    }
    
    gtk_box_append(GTK_BOX(card), sw);

    return card;
}

/* ============================================================================
 * First Run Initialization Flow
 * ========================================================================== */

static gpointer first_run_update_worker(gpointer data)
{
    (void)data;
    update_progress = 0;
    update_signature_db("signatures.db");
    return NULL;
}

static gboolean check_first_run_progress_cb(gpointer user_data)
{
    AppState* app = (AppState*)user_data;

    double fraction = (double)update_progress / 100.0;
    if (fraction > 1.0) fraction = 1.0;
    if (fraction < 0.0) fraction = 0.0;

    if (app->first_run_bar) {
        gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(app->first_run_bar), fraction);
    }

    char status_text[64];
    if (update_progress < 100 && update_progress >= 0) {
        snprintf(status_text, sizeof(status_text), "Setting up database... %d%%", update_progress);
        if (app->first_run_label) gtk_label_set_text(GTK_LABEL(app->first_run_label), status_text);
    } 
    else if (update_progress == 101) {
        /* PROCEED: Setup finished */
        app->is_first_run = FALSE; 

        if (app->first_run_card)   gtk_widget_set_visible(app->first_run_card, FALSE);
        if (app->dashboard_scan_btn) gtk_widget_set_sensitive(app->dashboard_scan_btn, TRUE);
        if (app->dashboard_adv_btn)  gtk_widget_set_sensitive(app->dashboard_adv_btn, TRUE);
        if (app->dashboard_rt_switch) gtk_widget_set_sensitive(app->dashboard_rt_switch, TRUE);

        /* Timestamp finalization */
        time_t now = time(NULL);
        struct tm* tm_info = localtime(&now);
        strftime(last_update_time, sizeof(last_update_time), "%Y-%m-%d %H:%M", tm_info);
        save_settings();
        
        return G_SOURCE_REMOVE;
    }
    else if (update_progress == -1) {
        if (app->first_run_label) gtk_label_set_text(GTK_LABEL(app->first_run_label), "Setup Failed. Check Internet.");
        
        app->is_first_run = FALSE;
        /* Unlock anyway to allow manual checks */
        if (app->dashboard_scan_btn) gtk_widget_set_sensitive(app->dashboard_scan_btn, TRUE);
        if (app->dashboard_adv_btn)  gtk_widget_set_sensitive(app->dashboard_adv_btn, TRUE);
        if (app->dashboard_rt_switch) gtk_widget_set_sensitive(app->dashboard_rt_switch, TRUE);

        return G_SOURCE_REMOVE;
    }

    return G_SOURCE_CONTINUE;
}

/* ============================================================================
 * Public View Implementation
 * ========================================================================== */

GtkWidget* create_dashboard_view(AppState* app)
{
    GtkWidget* col = gtk_box_new(GTK_ORIENTATION_VERTICAL, 20);
    gtk_widget_set_margin_start(col, 30);
    gtk_widget_set_margin_end(col, 30);
    gtk_widget_set_margin_top(col, 30);
    gtk_widget_set_margin_bottom(col, 30);
    
    GtkWidget* title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title), "<span font='28px' weight='bold'>Overview</span>");
    gtk_widget_set_halign(title, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(col), title);

    /* 1. First Run Setup Overlay (Conditional) */
    if (app->is_first_run) {
        app->first_run_card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 15);
        gtk_widget_add_css_class(app->first_run_card, "dashboard-card-bg");
        
        GtkWidget* inner = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
        gtk_widget_set_margin_start(inner, 20);
        gtk_widget_set_margin_end(inner, 20);
        gtk_widget_set_margin_top(inner, 20);
        gtk_widget_set_margin_bottom(inner, 20);

        GtkWidget* fr_title = gtk_label_new(NULL);
        gtk_label_set_markup(GTK_LABEL(fr_title), "<span size='large' weight='bold'>Initial Database Download</span>");
        gtk_widget_set_halign(fr_title, GTK_ALIGN_START);
        gtk_box_append(GTK_BOX(inner), fr_title);

        app->first_run_label = gtk_label_new("Initializing setup...");
        gtk_widget_set_halign(app->first_run_label, GTK_ALIGN_START);
        gtk_box_append(GTK_BOX(inner), app->first_run_label);

        app->first_run_bar = gtk_progress_bar_new();
        gtk_widget_set_hexpand(app->first_run_bar, TRUE);
        gtk_box_append(GTK_BOX(inner), app->first_run_bar);
        
        gtk_box_append(GTK_BOX(app->first_run_card), inner);
        gtk_box_append(GTK_BOX(col), app->first_run_card);

        g_thread_new("FirstRunUpdater", first_run_update_worker, NULL);
        g_timeout_add(100, check_first_run_progress_cb, app);
    }

    /* 2. Main Quick-Scan Card */
    GtkWidget* scan_card = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 20);
    gtk_widget_add_css_class(scan_card, "dashboard-card-bg");
    gtk_widget_set_size_request(scan_card, -1, 100);
    
    GtkWidget* scan_icon = gtk_image_new_from_icon_name("media-record-symbolic");
    gtk_widget_set_size_request(scan_icon, 40, 40); 
    gtk_widget_set_valign(scan_icon, GTK_ALIGN_CENTER); 
    gtk_widget_set_margin_start(scan_icon, 20);
    gtk_widget_add_css_class(scan_icon, "scanner-icon");
    gtk_box_append(GTK_BOX(scan_card), scan_icon);
    
    GtkWidget* scan_text_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_widget_set_valign(scan_text_vbox, GTK_ALIGN_CENTER);
    
    GtkWidget* quick_lbl = gtk_label_new("Quick Scan"); 
    gtk_widget_set_halign(quick_lbl, GTK_ALIGN_START);
    gtk_widget_add_css_class(quick_lbl, "bold-text");
    
    GtkWidget* quick_desc = gtk_label_new("Check critical system paths and active processes"); 
    gtk_widget_set_halign(quick_desc, GTK_ALIGN_START);
    gtk_widget_add_css_class(quick_desc, "dim-label");

    gtk_box_append(GTK_BOX(scan_text_vbox), quick_lbl); 
    gtk_box_append(GTK_BOX(scan_text_vbox), quick_desc);
    gtk_box_append(GTK_BOX(scan_card), scan_text_vbox);
    
    GtkWidget* scanner_spacer = gtk_label_new(""); 
    gtk_widget_set_hexpand(scanner_spacer, TRUE); 
    gtk_box_append(GTK_BOX(scan_card), scanner_spacer);

    GtkWidget* scan_btn = gtk_button_new_with_label("Start Scan");
    gtk_widget_add_css_class(scan_btn, "scan-btn"); 
    gtk_widget_set_margin_end(scan_btn, 10); 
    gtk_widget_set_valign(scan_btn, GTK_ALIGN_CENTER);
    g_signal_connect(scan_btn, "clicked", G_CALLBACK(on_start_quick_scan), app);
    app->dashboard_scan_btn = scan_btn;

    GtkWidget* adv_btn = gtk_button_new();
    gtk_widget_set_size_request(adv_btn, 40, 40);
    gtk_widget_set_valign(adv_btn, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_end(adv_btn, 20);
    gtk_widget_add_css_class(adv_btn, "flat-button");
    gtk_button_set_child(GTK_BUTTON(adv_btn), gtk_image_new_from_icon_name("view-more-horizontal-symbolic"));
    g_signal_connect(adv_btn, "clicked", G_CALLBACK(on_go_to_advanced), app);
    app->dashboard_adv_btn = adv_btn;

    if (app->is_first_run) {
        gtk_widget_set_sensitive(scan_btn, FALSE);
        gtk_widget_set_sensitive(adv_btn, FALSE);
    }

    gtk_box_append(GTK_BOX(scan_card), scan_btn);
    gtk_box_append(GTK_BOX(scan_card), adv_btn);
    
    gtk_box_append(GTK_BOX(col), scan_card);

    /* 3. Real-Time Protection Card */
    gtk_box_append(GTK_BOX(col), create_realtime_protection_card(app));

    return col;
}

GtkWidget* create_settings_view(AppState* app)
{
    GtkWidget* view = gtk_box_new(GTK_ORIENTATION_VERTICAL, 20);
    gtk_widget_set_margin_start(view, 30);
    gtk_widget_set_margin_end(view, 30);
    gtk_widget_set_margin_top(view, 30);
    gtk_widget_set_margin_bottom(view, 30);
    
    GtkWidget* title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title), "<span font='28px' weight='bold'>Settings</span>");
    gtk_widget_set_halign(title, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(view), title);   

    /* A. Theme Card */
    GtkWidget* theme_card = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 20);
    gtk_widget_add_css_class(theme_card, "dashboard-card-bg");
    gtk_widget_set_size_request(theme_card, -1, 85);
    
    GtkWidget* theme_lbl = gtk_label_new("  Dark Mode ");
    gtk_widget_set_margin_start(theme_lbl, 10);
    gtk_widget_add_css_class(theme_lbl, "bold-text");
    gtk_box_append(GTK_BOX(theme_card), theme_lbl);
    
    GtkWidget* theme_spacer = gtk_label_new(""); 
    gtk_widget_set_hexpand(theme_spacer, TRUE);
    gtk_box_append(GTK_BOX(theme_card), theme_spacer);
    
    GtkSwitch* theme_sw = GTK_SWITCH(gtk_switch_new());
    gtk_switch_set_active(theme_sw, app->is_dark_mode);
    g_signal_connect(theme_sw, "state-set", G_CALLBACK(on_theme_toggled), app);
    gtk_widget_set_margin_end(GTK_WIDGET(theme_sw), 20);
    gtk_widget_set_valign(GTK_WIDGET(theme_sw), GTK_ALIGN_CENTER);
    gtk_box_append(GTK_BOX(theme_card), GTK_WIDGET(theme_sw));
    gtk_box_append(GTK_BOX(view), theme_card);

    /* B. Signature Update Card */
    GtkWidget* upd_card = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 20);
    gtk_widget_add_css_class(upd_card, "dashboard-card-bg");
    gtk_widget_set_size_request(upd_card, -1, 85);

    GtkWidget* upd_text_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_widget_set_valign(upd_text_vbox, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_start(upd_text_vbox, 20);

    GtkWidget* upd_title_lbl = gtk_label_new("Threat Detection Database");
    gtk_widget_add_css_class(upd_title_lbl, "bold-text");
    gtk_widget_set_halign(upd_title_lbl, GTK_ALIGN_START);
    
    char upd_ts_buf[128];
    snprintf(upd_ts_buf, sizeof(upd_ts_buf), "Last Updated: %s", last_update_time);
    GtkWidget* upd_ts_lbl = gtk_label_new(upd_ts_buf);
    gtk_widget_add_css_class(upd_ts_lbl, "dim-label");
    gtk_widget_set_halign(upd_ts_lbl, GTK_ALIGN_START);
    app->last_update_label = upd_ts_lbl;

    gtk_box_append(GTK_BOX(upd_text_vbox), upd_title_lbl);
    gtk_box_append(GTK_BOX(upd_text_vbox), upd_ts_lbl);
    gtk_box_append(GTK_BOX(upd_card), upd_text_vbox);

    GtkWidget* upd_spacer = gtk_label_new("");
    gtk_widget_set_hexpand(upd_spacer, TRUE);
    gtk_box_append(GTK_BOX(upd_card), upd_spacer);

    /* Auto-update switch container */
    GtkWidget* auto_upd_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_widget_set_valign(auto_upd_vbox, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_end(auto_upd_vbox, 20);

    GtkSwitch* auto_upd_sw = GTK_SWITCH(gtk_switch_new());
    gtk_switch_set_active(auto_upd_sw, auto_update_enabled);
    g_signal_connect(auto_upd_sw, "state-set", G_CALLBACK(on_auto_update_toggled), app);
    gtk_box_append(GTK_BOX(auto_upd_vbox), GTK_WIDGET(auto_upd_sw));

    gtk_box_append(GTK_BOX(upd_card), auto_upd_vbox);
    gtk_box_append(GTK_BOX(view), upd_card);

    return view;
}