/**
 * @file app.c
 * @brief Application Main Logic and Configuration Management
 *
 * Implements the core application initialization, setting management, theme
 * handling, and view orchestration.
 *
 */

#include "app.h"

/* UI Views & Components */
#include "ui_history.h"
#include "ui_scan.h"
#include "ui_sidebar.h"
#include "ui_update.h"
#include "ui_views.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

#define SETTINGS_FILE "settings.conf"

gboolean auto_update_enabled = TRUE;
char last_update_time[64] = "Never";

/* Global configuration state for settings persistence */
gboolean initial_dark_mode = FALSE; /* Default: Light Mode */

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
    ".burger-btn:hover { background: #2D3748; color: #FFFFFF; }"
    ".dim-label { color: #E2E8F0; font-size: 13px; font-weight: 600; }"
    ".history-row label { color: #FFFFFF; font-weight: 500; }";

/* ============================================================================
 * Implementation: Settings Persistence
 * ========================================================================== */

void load_settings(void) {
  FILE *f = fopen(SETTINGS_FILE, "r");
  if (f == NULL)
    return;

  char line[128];
  while (fgets(line, sizeof(line), f)) {
    if (strncmp(line, "auto_update=", 12) == 0) {
      auto_update_enabled = atoi(line + 12);
    } else if (strncmp(line, "last_update=", 12) == 0) {
      strncpy(last_update_time, line + 12, sizeof(last_update_time) - 1);
      last_update_time[strcspn(last_update_time, "\r\n")] = '\0';
    } else if (strncmp(line, "dark_mode=", 10) == 0) {
      /* We will store this in a static temporary or global if app isn't passed
       * here. However, app struct is created AFTER load_settings. Let's use a
       * global fallback for initialization since we can't easily change
       * function signature traversing the whole codebase right now. But wait,
       * `app_activate` calls `load_settings` BEFORE creating `app`. We need a
       * way to pass this state. Let's verify if `app.c` has a global variable
       * for this? It doesn't. `auto_update_enabled` is global. We should make
       * `is_dark_mode` a global static in app.c or similar, OR just let
       * `app_activate` set it.
       *
       * For now, I will introduce a static global `initial_dark_mode` in this
       * file to hold the value until `app` is created.
       */
      extern gboolean initial_dark_mode; /* Define this outside */
      initial_dark_mode = atoi(line + 10);
    }
  }
  fclose(f);
}

void save_settings(void) {
  FILE *f = fopen(SETTINGS_FILE, "w");
  if (f == NULL)
    return;
  fprintf(f, "auto_update=%d\n", auto_update_enabled ? 1 : 0);
  fprintf(f, "last_update=%s\n", last_update_time);

  /* We need access to the current state.
   * Since this function is void(void), it relies on globals.
   * We need to expose the current dark mode state globally or change the
   * architecture. Given the constraints, let's look at `initial_dark_mode`
   * again. We should update `initial_dark_mode` whenever `app->is_dark_mode`
   * changes, so we can save it here.
   */
  extern gboolean initial_dark_mode;
  fprintf(f, "dark_mode=%d\n", initial_dark_mode ? 1 : 0);

  fclose(f);
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
  load_settings();

  /* 1. State Hub Initialization */
  AppState *app = g_new0(AppState, 1);
  app->window = gtk_application_window_new(gtk_app);
  gtk_window_set_default_size(GTK_WINDOW(app->window), 1024, 700);
  gtk_window_set_title(GTK_WINDOW(app->window),
                       "FOS Antivirus - Elite Endpoint Security");

  GtkWidget *main_layout = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
  gtk_window_set_child(GTK_WINDOW(app->window), main_layout);

  /* Check Deployment State (First run detection) */
  app->is_first_run = (access("signatures.db", F_OK) != 0);

  /* 2. UI Component Setup */
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

  /* 3. Aesthetic System Initialization */
  app->css_provider = gtk_css_provider_new();
  app->is_dark_mode = initial_dark_mode;
  update_theme(app);

  gtk_style_context_add_provider_for_display(
      gdk_display_get_default(), GTK_STYLE_PROVIDER(app->css_provider),
      GTK_STYLE_PROVIDER_PRIORITY_USER);

  /* 4. Background Services Initiation */

  /* Daily update check timer (Every 6 hours) */
  g_timeout_add_seconds(6 * 60 * 60, (GSourceFunc)auto_update_timer, app);

  /* Immediate silent check if enabled */
  if (auto_update_enabled) {
    g_thread_new("InitialSilentUpdate",
                 (GThreadFunc)silent_update_worker_thread, app);
  }

  gtk_window_present(GTK_WINDOW(app->window));
}

void app_set_theme(AppState *app, gboolean is_dark) {
  app->is_dark_mode = is_dark;
  initial_dark_mode = is_dark; /* Sync for persistence */
  update_theme(app);
  save_settings();
}