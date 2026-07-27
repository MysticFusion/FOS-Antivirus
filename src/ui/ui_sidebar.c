/**
 * @file ui_sidebar.c
 * @brief Sidebar Navigation UI Implementation
 */

#include "ui_sidebar.h"
#include "app.h"
#include "scan_core.h"

#include <gtk/gtk.h>
#include <string.h>

/* ============================================================================
 * Internal Helpers
 * ========================================================================== */

/**
 * @brief Safely switch the main view stack, respecting operational locks.
 */
static void set_active_view(AppState *app, const char *view_name) {
    /* 1. Prevent navigation during initial database setup */
    if (app->is_first_run) {
        return;
    }

    /* 2. If a scan view is still active, force to progress
          unless the user explicitly chose "Scan" */
    if (app->scan_view_active && strcmp(view_name, "progress") != 0) {
        gtk_stack_set_visible_child_name(GTK_STACK(app->stack), "progress");
        return;
    }

    /* 3. Normal navigation */
    gtk_stack_set_visible_child_name(GTK_STACK(app->stack), view_name);
}

/* ============================================================================
 * Signal Callbacks
 * ========================================================================== */

static void on_dash_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn;
    set_active_view((AppState *)user_data, "dashboard");
}

static void on_hist_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn;
    set_active_view((AppState *)user_data, "history");
}

static void on_sett_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn;
    set_active_view((AppState *)user_data, "settings");
}

static void on_scan_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn;
    AppState *app = (AppState *)user_data;
    if (app->scan_view_active) {
        gtk_stack_set_visible_child_name(GTK_STACK(app->stack), "progress");
    } else {
        gtk_stack_set_visible_child_name(GTK_STACK(app->stack), "advanced_scan");
    }
}

static void on_toggle_collapse(GtkButton *btn, gpointer user_data) {
    (void)btn;
    AppState *app = (AppState *)user_data;
    app->is_sidebar_collapsed = !app->is_sidebar_collapsed;

    for (GList *iter = app->sidebar_labels; iter != NULL; iter = iter->next) {
        gtk_widget_set_visible(GTK_WIDGET(iter->data), !app->is_sidebar_collapsed);
    }

    if (app->is_sidebar_collapsed) {
        gtk_widget_set_size_request(app->sidebar, 60, -1);
    } else {
        gtk_widget_set_size_request(app->sidebar, 200, -1);
    }
}

/* ============================================================================
 * Constructor Helpers
 * ========================================================================== */

static GtkWidget *create_nav_item(AppState *app, const char *icon_name,
                                  const char *text) {
    GtkWidget *btn = gtk_button_new();
    gtk_widget_set_hexpand(btn, TRUE);
    gtk_widget_add_css_class(btn, "nav-item");

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_widget_set_halign(box, GTK_ALIGN_START);

    GtkWidget *icon = gtk_image_new_from_icon_name(icon_name);
    gtk_widget_set_size_request(icon, 16, 16);
    gtk_box_append(GTK_BOX(box), icon);

    GtkWidget *label = gtk_label_new(text);
    gtk_box_append(GTK_BOX(box), label);

    app->sidebar_labels = g_list_append(app->sidebar_labels, label);

    gtk_button_set_child(GTK_BUTTON(btn), box);
    return btn;
}

/* ============================================================================
 * Public Implementation
 * ========================================================================== */

GtkWidget *create_sidebar(AppState *app) {
    app->sidebar = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_size_request(app->sidebar, 200, -1);
    gtk_widget_set_hexpand(app->sidebar, FALSE);
    gtk_widget_add_css_class(app->sidebar, "sidebar");

    /* 1. Header (Burger Menu) */
    GtkWidget *header_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_widget_set_margin_top(header_box, 15);
    gtk_widget_set_margin_start(header_box, 15);
    gtk_widget_set_margin_bottom(header_box, 20);

    GtkWidget *burger_btn = gtk_button_new();
    gtk_widget_add_css_class(burger_btn, "burger-btn");
    gtk_button_set_child(GTK_BUTTON(burger_btn),
                         gtk_image_new_from_icon_name("open-menu-symbolic"));
    g_signal_connect(burger_btn, "clicked", G_CALLBACK(on_toggle_collapse), app);
    gtk_box_append(GTK_BOX(header_box), burger_btn);
    gtk_box_append(GTK_BOX(app->sidebar), header_box);

    /* 2. Main Navigation Group */
    GtkWidget *nav_group = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_widget_set_margin_start(nav_group, 10);
    gtk_widget_set_margin_end(nav_group, 10);

    GtkWidget *btn_dash = create_nav_item(app, "view-grid-symbolic", "Dashboard");
    g_signal_connect(btn_dash, "clicked", G_CALLBACK(on_dash_clicked), app);
    gtk_box_append(GTK_BOX(nav_group), btn_dash);

    GtkWidget *btn_hist = create_nav_item(app, "document-open-recent-symbolic", "History");
    g_signal_connect(btn_hist, "clicked", G_CALLBACK(on_hist_clicked), app);
    gtk_box_append(GTK_BOX(nav_group), btn_hist);

    GtkWidget *btn_scan = create_nav_item(app, "system-search-symbolic", "Scan");
    g_signal_connect(btn_scan, "clicked", G_CALLBACK(on_scan_clicked), app);
    gtk_box_append(GTK_BOX(nav_group), btn_scan);

    gtk_box_append(GTK_BOX(app->sidebar), nav_group);

    /* 3. Spacer */
    GtkWidget *spacer = gtk_label_new("");
    gtk_widget_set_vexpand(spacer, TRUE);
    gtk_box_append(GTK_BOX(app->sidebar), spacer);

    /* 4. Footer (Settings) */
    GtkWidget *footer_group = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_widget_set_margin_start(footer_group, 10);
    gtk_widget_set_margin_end(footer_group, 10);
    gtk_widget_set_margin_bottom(footer_group, 20);

    GtkWidget *btn_sett = create_nav_item(app, "preferences-system-symbolic", "Settings");
    g_signal_connect(btn_sett, "clicked", G_CALLBACK(on_sett_clicked), app);
    gtk_box_append(GTK_BOX(footer_group), btn_sett);

    gtk_box_append(GTK_BOX(app->sidebar), footer_group);

    return app->sidebar;
}