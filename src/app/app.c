/**
 * @file app.c
 * @brief Application Main Logic and Configuration Management
 *
 * Implements the core application initialization, setting management, theme
 * handling, and view orchestration.
 *
 * As of v1.1:
 *   - The `extern gboolean initial_dark_mode;` global hack has been removed.
 *     Settings are now loaded into a SettingsState struct and passed into
 *     app_activate() to initialize AppState.
 *   - The is_first_run UI lock has been removed. The app no longer blocks
 *     scan/realtime buttons on first launch. Users can use the app
 *     immediately; if no signature DB exists, scan attempts surface the
 *     normal "database not loaded" error.
 *   - The auto_update subsystem (inert stub) is initialized at startup.
 */

#include "app.h"
#include "app_paths.h"
#include "auto_update.h"

/* UI Views & Components */
#include "ui_history.h"
#include "ui_scan.h"
#include "ui_sidebar.h"
#include "ui_update.h"
#include "ui_views.h"
#include "scan_core.h"
#include "signature_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <shlobj.h>

#ifdef _WIN32
#include <io.h>
#define F_OK 0
#define access _access
#else
#include <unistd.h>
#endif

/* ============================================================================
 * Internal State & Configuration
 * ========================================================================== */

/* Global configuration state for settings persistence.
 * These remain as globals because ui_update.c reads them directly. */
gboolean auto_update_enabled = TRUE;
char last_update_time[64] = "Never";

/* Current dark-mode flag, set by app_set_theme() and read by save_settings().
 * Replaces the old `extern gboolean initial_dark_mode;` hack. */
static gboolean g_current_dark_mode = FALSE;

static void get_settings_path(char *path_out, size_t max_len) {
    PWSTR appdata = NULL;
    if (SUCCEEDED(SHGetKnownFolderPath(&FOLDERID_RoamingAppData, 0, NULL, &appdata))) {
        char appdata_utf8[MAX_PATH];
        WideCharToMultiByte(CP_UTF8, 0, appdata, -1, appdata_utf8, MAX_PATH, NULL, NULL);
        CoTaskMemFree(appdata);

        snprintf(path_out, max_len, "%s\\FOS-Antivirus", appdata_utf8);
        CreateDirectoryA(path_out, NULL);
        snprintf(path_out, max_len, "%s\\FOS-Antivirus\\settings.conf", appdata_utf8);
    } else {
        strncpy(path_out, "settings.conf", max_len);
    }
}


/* ============================================================================
 * Design System: CSS Tokens
 * ========================================================================== */

static const char *CSS_LIGHT =
    "window { background-color: #FFFFFF; color: #1A202C; }"
    ".sidebar { background-color: #F7FAFC; border-right: 1px solid #E2E8F0; }"
    ".dashboard-card-bg { background-color: #FFFFFF; border: 1px solid "
    "#E2E8F0; border-radius: 12px; }"
    ".nav-item { background: transparent; border: none; border-radius: 6px; "
    "padding: 10px 12px; color: #4A5568; }"
    ".nav-item:hover { background: #EDF2F7; color: #2D3748; }"
    ".scan-btn { background: #3182CE; color: white; border-radius: 8px; "
    "padding: 6px 16px; border: none; font-weight: bold; }"
    ".scan-btn:hover { background: #2B6CB0; }"
    ".flat-button { background: transparent; border: none; color: #4A5568; "
    "border-radius: 4px; padding: 8px; }"
    ".flat-button:hover { background: #EDF2F7; color: #1A202C; }"
    ".bold-text { font-weight: bold; font-size: 16px; }"
    ".scanner-icon { background: #EBF8FF; color: #3182CE; border-radius: 10px; "
    "padding: 8px; }"
    ".burger-btn { color: #4A5568; background: transparent; border: none; "
    "padding: 4px; border-radius: 4px; }"
    ".burger-btn:hover { background: #EDF2F7; color: #1A202C; }"
    ".dim-label { color: #2D3748; font-size: 13px; font-weight: 600; }";

static const char *CSS_DARK =
    "window { background-color: #171923; color: #F7FAFC; }"
    ".sidebar { background-color: #1A202C; border-right: 1px solid #2D3748; }"
    ".dashboard-card-bg { background-color: #2D3748; border: 1px solid "
    "#4A5568; border-radius: 12px; }"
    ".nav-item { background: transparent; border: none; border-radius: 6px; "
    "padding: 10px 12px; color: #A0AEC0; }"
    ".nav-item:hover { background: #2D3748; color: #FFFFFF; }"
    ".scan-btn { background: #3182CE; color: white; border-radius: 8px; "
    "padding: 6px 16px; border: none; font-weight: bold; }"
    ".scan-btn:hover { background: #2B6CB0; }"
    ".flat-button { background: transparent; border: none; color: #E2E8F0; "
    "border-radius: 4px; padding: 8px; }"
    ".flat-button:hover { background: #4A5568; color: #FFFFFF; }"
    ".bold-text { font-weight: bold; font-size: 16px; }"
    ".scanner-icon { background: #2A4365; color: #63B3ED; border-radius: 10px; "
    "padding: 8px; }"
    ".burger-btn { color: #A0AEC0; background: transparent; border: none; "
    "padding: 4px; border-radius: 4px; }"
    ".burger-btn:hover { background: #2D3748; color: #FFFFFF; }"
    ".dim-label { color: #E2E8F0; font-size: 13px; font-weight: 600; }"
    ".history-row label { color: #FFFFFF; font-weight: 500; }";

/* ============================================================================
 * Implementation: Settings Persistence
 * ========================================================================== */

void load_settings(SettingsState *out) {
    /* Initialize with defaults */
    if (out == NULL) return;
    out->auto_update_enabled = TRUE;
    strncpy(out->last_update_time, "Never", sizeof(out->last_update_time) - 1);
    out->last_update_time[sizeof(out->last_update_time) - 1] = '\0';
    out->is_dark_mode = FALSE;

    char settings_file[MAX_PATH];
    get_settings_path(settings_file, sizeof(settings_file));
    FILE *f = fopen(settings_file, "r");
    if (f == NULL) return;

    char line[128];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "auto_update=", 12) == 0) {
            out->auto_update_enabled = atoi(line + 12);
        } else if (strncmp(line, "last_update=", 12) == 0) {
            strncpy(out->last_update_time, line + 12,
                    sizeof(out->last_update_time) - 1);
            out->last_update_time[sizeof(out->last_update_time) - 1] = '\0';
            out->last_update_time[strcspn(out->last_update_time, "\r\n")] = '\0';
        } else if (strncmp(line, "dark_mode=", 10) == 0) {
            out->is_dark_mode = atoi(line + 10);
        }
    }
    fclose(f);

    /* Sync to the legacy globals (read by ui_update.c) */
    auto_update_enabled = out->auto_update_enabled;
    strncpy(last_update_time, out->last_update_time,
            sizeof(last_update_time) - 1);
    last_update_time[sizeof(last_update_time) - 1] = '\0';
    /* And to the current-dark-mode tracker used by save_settings() */
    g_current_dark_mode = out->is_dark_mode;
}

void save_settings(void) {
    char settings_file[MAX_PATH];
    get_settings_path(settings_file, sizeof(settings_file));
    FILE *f = fopen(settings_file, "w");
    if (f == NULL) return;
    fprintf(f, "auto_update=%d\n", auto_update_enabled ? 1 : 0);
    fprintf(f, "last_update=%s\n", last_update_time);
    fprintf(f, "dark_mode=%d\n", g_current_dark_mode ? 1 : 0);
    fclose(f);
}

gboolean app_get_dark_mode(void) {
    return g_current_dark_mode;
}

/* ============================================================================
 * Implementation: Theming
 * ========================================================================== */

void update_theme(AppState *app) {
  if (app->is_dark_mode) {
    gtk_css_provider_load_from_string(app->css_provider, CSS_DARK);
  } else {
    gtk_css_provider_load_from_string(app->css_provider, CSS_LIGHT);
  }
}

/* ============================================================================
 * Implementation: Main Entry Flow
 * ========================================================================== */

void app_activate(GtkApplication *gtk_app) {
  /* 1. Load settings into a temporary struct (replaces extern global hack) */
  SettingsState settings;
  load_settings(&settings);

  /* 2. Initialize the auto-update subsystem (inert stub for now) */
  auto_update_init();
  auto_update_check();

  /* 3. State Hub Initialization */
  AppState *app = g_new0(AppState, 1);
  g_mutex_lock(&global_scan_ctx.mutex);
  global_scan_ctx.app_state = app;
  g_mutex_unlock(&global_scan_ctx.mutex);
  app->window = gtk_application_window_new(gtk_app);
  gtk_window_set_default_size(GTK_WINDOW(app->window), 1024, 700);
  gtk_window_set_title(GTK_WINDOW(app->window),
                       "FOS Antivirus - Elite Endpoint Security");

  GtkWidget *main_layout = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
  gtk_window_set_child(GTK_WINDOW(app->window), main_layout);

  /* is_first_run is DEPRECATED as of v1.1 — always FALSE.
   * The first-run UI lock has been removed. The app no longer blocks scan
   * buttons when no signature DB exists; users can scan immediately and
   * will see the existing "database not loaded" error if they try. */
  app->is_first_run = FALSE;
  app->first_run_card = NULL;
  app->first_run_label = NULL;
  app->first_run_bar = NULL;

  /* 4. UI Component Setup */
  gtk_box_append(GTK_BOX(main_layout), create_sidebar(app));

  GtkWidget *content_stack_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
  gtk_widget_set_hexpand(content_stack_box, TRUE);
  gtk_box_append(GTK_BOX(main_layout), content_stack_box);

  app->stack = gtk_stack_new();
  gtk_stack_set_transition_type(GTK_STACK(app->stack),
                                GTK_STACK_TRANSITION_TYPE_CROSSFADE);

  /* Register Sub-views */
  gtk_stack_add_titled(GTK_STACK(app->stack), create_dashboard_view(app),
                       "dashboard", "Status");
  gtk_stack_add_titled(GTK_STACK(app->stack), create_advanced_scan_view(app),
                       "advanced_scan", "Scan");
  gtk_stack_add_titled(GTK_STACK(app->stack), create_history_view(app),
                       "history", "History");
  gtk_stack_add_titled(GTK_STACK(app->stack), create_settings_view(app),
                       "settings", "Settings");
  gtk_stack_add_titled(GTK_STACK(app->stack), create_scanner_progress_view(app),
                       "progress", "Progress");
  gtk_stack_add_titled(GTK_STACK(app->stack), create_scan_complete_view(app),
                       "complete", "Done");

  gtk_box_append(GTK_BOX(content_stack_box), app->stack);

  /* 5. Aesthetic System Initialization (uses settings from SettingsState) */
  app->css_provider = gtk_css_provider_new();
  app->is_dark_mode = settings.is_dark_mode;
  g_current_dark_mode = settings.is_dark_mode;
  update_theme(app);

  gtk_style_context_add_provider_for_display(
      gdk_display_get_default(), GTK_STYLE_PROVIDER(app->css_provider),
      GTK_STYLE_PROVIDER_PRIORITY_USER);

  /* 6. Background Services Initiation */

  /* Periodic update check timer (Every 6 hours).
   * The timer itself checks DB staleness (> 24h) before spawning python.exe,
   * so this just sets up the recurring tick — it won't fire redundantly if
   * the DB is already fresh. */
  g_timeout_add_seconds(6 * 60 * 60, (GSourceFunc)auto_update_timer, app);

  /* v1.2.1: Silent startup update — ONLY if the DB is genuinely stale
   * (> 7 days since last successful update, or never updated).
   *
   * Previous behavior: spawned python.exe on EVERY app launch, which was
   * surprising (user saw python.exe in Task Manager + network bandwidth
   * consumed with no UI indication). Now: if you just updated recently,
   * relaunching the app will NOT spawn a background update. The user can
   * always click "Update Now" in Settings for a manual refresh.
   *
   * The 7-day threshold matches Windows Defender's "skip scheduled quick
   * scan if a qualified scan ran in last 7 days" optimization. */
  if (auto_update_enabled && db_is_older_than(168)) {
    g_thread_new("InitialSilentUpdate",
                 (GThreadFunc)silent_update_worker_thread, app);
  }

  gtk_window_present(GTK_WINDOW(app->window));
}

void app_set_theme(AppState *app, gboolean is_dark) {
  app->is_dark_mode = is_dark;
  g_current_dark_mode = is_dark;  /* Sync for persistence via save_settings() */
  update_theme(app);
  save_settings();
}
