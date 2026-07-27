/**
 * @file main.c
 * @brief Application Entry Point
 *
 * Initializes the global synchronization objects, third-party library bridges,
 * and launches the GTK application loop.
 *
 */

#include "app.h"
#include <gtk/gtk.h>
#include <windows.h>

#include "app_paths.h"
#include "ml_engine.h"
#include "scan_core.h"
#include "scan_report_bridge.h"

/* ============================================================================
 * Global State Definitions
 * ========================================================================== */

/** @brief Persistent synchronization context for scanning operations */
ScanContext global_scan_ctx;

/* ============================================================================
 * Entry Point
 * ========================================================================== */

static void *ml_init_worker(const char *model_path) {
  ml_engine_init(model_path);
  return NULL;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow) {
  (void)hInstance;
  (void)hPrevInstance;
  (void)lpCmdLine;
  (void)nCmdShow;

  /* 1. Low-level Subsystem Initialization */
  app_paths_init();
  g_mutex_init(&global_scan_ctx.mutex);

  /* Initialize the result reporting pipeline */
  scan_report_bridge_init();

  /* Initialize AI Engine (Background Thread) */
  /* We move this off the main thread to ensure UI appears immediately */
  ml_engine_pre_init();
  g_thread_new("ML_Init_Thread", (GThreadFunc)ml_init_worker,
               (gpointer)app_path_model());

  /* 2. UI Framework Initialization */
  GtkApplication *app = gtk_application_new("com.fos.antivirus.elite",
                                            G_APPLICATION_DEFAULT_FLAGS);

  /* Map the activation signal to the core app logic */
  g_signal_connect(app, "activate", G_CALLBACK(app_activate), NULL);

  /* 3. Execute Main Event Loop */
  int status = g_application_run(G_APPLICATION(app), __argc, __argv);

  /* 4. Graceful Shutdown & Cleanup */
  g_object_unref(app);

  /* Close persistence and reporting subsystems */
  scan_report_bridge_shutdown();
  ml_engine_cleanup();
  g_mutex_clear(&global_scan_ctx.mutex);

  return status;
}
