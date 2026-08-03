/**
 * @file app.h
 * @brief Global Application State and Lifecycle Interface
 *
 * Defines the main AppState structure which holds references to all core
 * UI components, application logic flags, and thread-synchronization objects.
 *
 */

#ifndef APP_H
#define APP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <gtk/gtk.h>
#include <stdbool.h>

/* ============================================================================
 * Application State Structure
 * ========================================================================== */

/**
 * @brief Primary container for the application's runtime state and UI handles.
 */
typedef struct {
    /* Main Window & Containers */
    GtkWidget      *window;
    GtkWidget      *sidebar;
    GtkWidget      *stack;       
    GtkCssProvider *css_provider;
    
    /* Persistent UI Labels & Controls */
    GtkWidget      *progress_bar;
    GtkWidget      *progress_label;
    GtkWidget      *result_files_label;
    GtkWidget      *result_threats_label;
    GtkWidget      *history_list_box; 
    GtkWidget      *last_update_label; 
    GList          *sidebar_labels; 
    
    /* Display States */
    gboolean        is_dark_mode;
    gboolean        is_sidebar_collapsed; 
    
    /* First Run Setup State */
    gboolean        is_first_run;
    GtkWidget      *first_run_card;
    GtkWidget      *first_run_label;
    GtkWidget      *first_run_bar;

    /* Operational Controls (State Lock Management) */
    GtkWidget      *dashboard_scan_btn;
    GtkWidget      *dashboard_adv_btn;
    GtkWidget      *dashboard_rt_switch;
} AppState;

/* ============================================================================
 * Global configuration (Externs)
 * ========================================================================== */

extern gboolean auto_update_enabled;
extern char     last_update_time[64];

/* ============================================================================
 * Public Lifecycle Functions
 * ========================================================================== */

/**
 * @brief Entry point for the GTK application activation signal.
 */
void app_activate(GtkApplication *app);

/**
 * @brief Re-apply CSS theme strings to the global display.
 */
void update_theme(AppState *app);

/**
 * @brief Update application theme preference and persist it.
 */
void app_set_theme(AppState *app, gboolean is_dark);

/**
 * @brief Serialize application settings to local disk.
 */
void save_settings(void);

/**
 * @brief Load application settings from local disk.
 */
void load_settings(void);

#ifdef __cplusplus
}
#endif

#endif /* APP_H */