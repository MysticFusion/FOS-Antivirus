/**
 * @file app.h
 * @brief Global Application State and Lifecycle Interface
 *
 * Defines the main AppState structure which holds references to all core
 * UI components, application logic flags, and thread-synchronization objects.
 *
 * As of v1.1, the `is_first_run` UI lock has been removed. The app no longer
 * blocks scan/realtime buttons when no signature DB exists. Users can scan
 * immediately and will see the existing "signature database not loaded"
 * error if they try to scan with no DB present.
 *
 * The `is_first_run` field is kept in AppState for ABI compatibility but is
 * always FALSE and the associated first-run UI code has been deleted.
 */

#ifndef APP_H
#define APP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <gtk/gtk.h>
#include <stdbool.h>

/* ============================================================================
 * Settings State (loaded from disk before AppState is created)
 * ========================================================================== */

/**
 * @brief Persistent settings loaded from settings.conf.
 *
 * Introduced in v1.1 to replace the `extern gboolean initial_dark_mode;`
 * hack. load_settings() populates this struct, then app_activate() uses it
 * to initialize AppState.
 */
typedef struct {
    gboolean auto_update_enabled;  /**< TRUE if automatic updates are on    */
    char     last_update_time[64]; /**< Human-readable last-update stamp     */
    gboolean is_dark_mode;         /**< TRUE if dark theme should be applied */
} SettingsState;

/* ============================================================================
 * Application State Structure
 * ========================================================================== */

/**
 * @brief Primary container for the application's runtime state and UI handles.
 */
typedef struct _AppState {
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
    gboolean scan_view_active;   /* TRUE from scan start until dismissed */
    gboolean scan_error;         /* TRUE if scan failed, shows error message */

    /* First Run Setup State — DEPRECATED as of v1.1.
     * Always FALSE. Field retained for ABI compatibility; do not set to TRUE.
     * The first-run card UI and the forced-download-on-first-launch behavior
     * have been removed. Users can use the app immediately; if no signature DB
     * exists, scan attempts will surface the normal "database not loaded" error. */
    gboolean        is_first_run;
    GtkWidget      *first_run_card;   /* DEPRECATED — always NULL */
    GtkWidget      *first_run_label;  /* DEPRECATED — always NULL */
    GtkWidget      *first_run_bar;    /* DEPRECATED — always NULL */

    /* Operational Controls (State Lock Management) */
    GtkWidget      *dashboard_scan_btn;
    GtkWidget      *dashboard_adv_btn;
    GtkWidget      *dashboard_rt_switch;
} AppState;

/* ============================================================================
 * Global configuration (Externs)
 *
 * These remain as globals for now because ui_update.c reads them directly.
 * A future refactor could move them into AppState, but that would touch many
 * UI files for limited benefit.
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
 *
 * Reads current values from the AppState via app_get_dark_mode() so that
 * callers don't need to pass state in.
 */
void save_settings(void);

/**
 * @brief Load application settings from local disk into a SettingsState.
 *
 * As of v1.1, this populates the caller-provided SettingsState struct
 * instead of relying on `extern gboolean initial_dark_mode;` globals.
 *
 * @param out SettingsState to populate. Must not be NULL.
 */
void load_settings(SettingsState *out);

/**
 * @brief Get the current dark-mode flag for save_settings().
 *
 * Helper used by save_settings() to read the current theme state from
 * AppState without requiring AppState to be passed in. The current AppState
 * registers its dark mode here via app_set_theme().
 *
 * @return TRUE if dark mode is currently active.
 */
gboolean app_get_dark_mode(void);

#ifdef __cplusplus
}
#endif

#endif /* APP_H */
