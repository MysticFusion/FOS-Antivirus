#define _CRT_SECURE_NO_WARNINGS

#include "scan_core.h"
#include "fs_enumerator.h"
#include "hash_util.h"
#include "heuristic_engine.h"
#include "ml_engine.h"
#include "scan_progress.h"
#include "scan_report_bridge.h"
#include "scan_processes.h"
#include "scan_persistence.h"
#include "signature_scan.h"
#include "trust.h"
#include "ui_scan_paths.h"

#include "app.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

/* ============================================================================
 * Configuration & Concurrency
 * ========================================================================== */

#define MAX_CONCURRENT_TASKS 8
#define QUEUE_BACKPRESSURE_LMT 64
#define LOW_PRIORITY_SLEEP_MS 50

/* Phase A3: Files older than this (in days) are skipped in quick scan
 * for non-persistence locations. Most System32/Program Files executables
 * are untouched since OS install — if real-time protection has been
 * running, RTP already scanned them on first access. */
#define QUICK_SCAN_MAX_FILE_AGE_DAYS 30

static GThreadPool *g_scan_pool = NULL;
static GMutex g_scan_pool_mutex;
static gsize g_scan_pool_once = 0;
volatile LONG g_pending_tasks = 0;

/* ============================================================================
 * Phase A1: File Extension Whitelist
 *
 * Only files with these extensions are scanned. The signature DB contains
 * SHA-256 hashes of PE files, and the ML model only works on PE files —
 * scanning .txt, .jpg, .log, .json etc. is wasted work. This filter is
 * ALWAYS active (all scan modes including real-time).
 * ========================================================================== */

static const char *SCANNABLE_EXTENSIONS[] = {
    /* PE executables */
    ".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".drv",
    /* Legacy executables */
    ".com", ".bat", ".cmd",
    /* Scripts */
    ".ps1", ".vbs", ".vbe", ".js", ".jse", ".hta", ".wsf", ".wsh",
    /* Installers */
    ".msi", ".msp",
    /* Macro-bearing Office documents */
    ".docm", ".xlsm", ".pptm",
    NULL
};

static bool is_scannable_extension(const char *path) {
    if (!path) return false;
    const char *dot = strrchr(path, '.');
    if (!dot || dot == path) return false;
    for (int i = 0; SCANNABLE_EXTENSIONS[i] != NULL; i++) {
        if (_stricmp(dot, SCANNABLE_EXTENSIONS[i]) == 0)
            return true;
    }
    return false;
}

/* ============================================================================
 * Phase A3: mtime Filter
 *
 * Skip files older than N days in quick scan mode. Only applies to
 * non-persistence locations (System32, Program Files, Temp) — persistence
 * locations (Startup, Downloads) are always scanned regardless of age.
 * ========================================================================== */

static bool is_file_older_than_days(const char *path, int max_age_days) {
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExA(path, GetFileExInfoStandard, &fad))
        return false;  /* Can't get attributes — don't skip (safer) */

    ULARGE_INTEGER file_time;
    file_time.LowPart = fad.ftLastWriteTime.dwLowDateTime;
    file_time.HighPart = fad.ftLastWriteTime.dwHighDateTime;

    FILETIME now_ft;
    GetSystemTimeAsFileTime(&now_ft);
    ULARGE_INTEGER now_time;
    now_time.LowPart = now_ft.dwLowDateTime;
    now_time.HighPart = now_ft.dwHighDateTime;

    /* FILETIME is in 100-nanosecond intervals since 1601-01-01.
     * Convert to days: 1 day = 24 * 60 * 60 * 10000000 intervals */
    const ULONGLONG INTERVALS_PER_DAY = 24ULL * 60 * 60 * 10000000;
    if (now_time.QuadPart < file_time.QuadPart)
        return false;  /* File time is in the future — don't skip */
    ULONGLONG age_days = (now_time.QuadPart - file_time.QuadPart) / INTERVALS_PER_DAY;
    return age_days > (ULONGLONG)max_age_days;
}

/**
 * @brief Check if a path is a persistence location (exempt from mtime filter).
 *
 * Persistence locations: Startup folder, Downloads folder. These are always
 * scanned regardless of file age because they're common malware drop points.
 */
static bool is_persistence_path(const char *path) {
    if (!path) return false;
    char lower[MAX_PATH];
    strncpy(lower, path, MAX_PATH - 1);
    lower[MAX_PATH - 1] = '\0';
    _strlwr(lower);

    return strstr(lower, "\\startup\\") != NULL ||
           strstr(lower, "\\downloads\\") != NULL ||
           strstr(lower, "\\start menu\\programs\\startup") != NULL;
}

/* ============================================================================
 * Internal Helpers
 * ========================================================================== */

typedef struct {
  char *path;
  ScanReason reason;
  bool quick_mode;
} ScanTask;

static void scan_task_free(ScanTask *task) {
  if (!task)
    return;
  free(task->path);
  free(task);
}

static void scan_task_worker(gpointer data, gpointer user_data);

static void init_scan_pool_once(void) { g_mutex_init(&g_scan_pool_mutex); }

static int ensure_scan_pool(void) {
  if (g_once_init_enter(&g_scan_pool_once)) {
    init_scan_pool_once();
    g_once_init_leave(&g_scan_pool_once, 1);
  }

  g_mutex_lock(&g_scan_pool_mutex);
  if (g_scan_pool == NULL) {
    GError *error = NULL;
    g_scan_pool =
        g_thread_pool_new(scan_task_worker, NULL, MAX_CONCURRENT_TASKS, FALSE,
                          &error);
    if (error != NULL) {
      g_error_free(error);
      g_mutex_unlock(&g_scan_pool_mutex);
      return -1;
    }
  }
  g_mutex_unlock(&g_scan_pool_mutex);
  return 0;
}

/**
 * @brief Optimized scan pipeline.
 */
static void scan_single_file_internal(const char *path, ScanReason reason,
                                      bool quick_mode) {
  if (global_scan_ctx.stop_requested) {
    return;
  }

  /* Phase A1: Extension whitelist — always active. Skip non-executable
   * files (.txt, .jpg, .log, etc.) — the signature DB only contains PE
   * hashes and the ML model only works on PE files. */
  if (!is_scannable_extension(path)) {
    scan_progress_file_done(false);
    return;
  }

  // 1. FAST PASS: Trust & Extension Check
  TrustLevel trust = trust_evaluate_path(path, quick_mode);
  if (trust == TRUST_HIGH) {
    // High trust (e.g. MS signed in System32) -> Skip deep scan
    scan_progress_file_done(false);
    return;
  }

  // Allocate Input
  ScanInput *in = calloc(1, sizeof(*in));
  if (!in) {
    scan_progress_file_done(false);
    return;
  }
  in->path = _strdup(path);
  in->reason = reason;
  in->trust = trust;

  if (global_scan_ctx.stop_requested) {
    free(in->path);
    free(in);
    scan_progress_file_done(false);
    return;
  }

  // 2. HASH CALCULATION (Required for Signatures)
  if (compute_file_sha256(path, in->hash) != 0) {
    free(in->path);
    free(in);
    scan_progress_file_done(false);
    return;
  }

  SignatureResult sig = {0};
  HeuristicResult heur = {0};
  double ml_score = -1.0;

  // 3. SIGNATURE SCAN (O(1))
  signature_scan_hash(in->hash, &sig);
  if (sig.matched) {
    // Atomic threat counter update
    InterlockedIncrement((LONG *)&global_scan_ctx.threats_found);
    scan_report_submit_complete(in, &sig, &heur, ml_score);
    return;
  }

  if (global_scan_ctx.stop_requested) {
    free(in->path);
    free(in);
    scan_progress_file_done(false);
    return;
  }

  // 4. DEEP PASS: Heuristics & ML
  // Extract features only if signatures didn't match
  if (extract_file_features(path, &in->features) == 0) {

    if (global_scan_ctx.stop_requested) {
      free(in->path);
      free(in);
      scan_progress_file_done(false);
      return;
    }

    // Heuristic analysis
    evaluate_heuristics(&in->features, &heur, in->trust, in->reason);

    // ML behavioral analysis (Skip for non-executables)
    if (in->features.is_executable && in->trust != TRUST_HIGH) {
      ml_score = ml_engine_scan(&in->features);
    }
  }

  // Update scanned file counter
  InterlockedIncrement((LONG *)&global_scan_ctx.files_scanned);

  scan_report_submit_complete(in, &sig, &heur, ml_score);
}

/* ============================================================================
 * Public Functions
 * ========================================================================== */

typedef struct {
    bool low_priority;
    bool quick_mode;
    bool skip_old_files;  /**< true = apply mtime filter (non-persistence paths) */
} ScanWalkContext;

static int enqueue_scan_task(const char *path, ScanReason reason,
                             bool quick_mode) {
  if (ensure_scan_pool() != 0 || path == NULL)
    return -1;

  ScanTask *task = calloc(1, sizeof(*task));
  if (!task)
    return -1;

  task->path = _strdup(path);
  task->reason = reason;
  task->quick_mode = quick_mode;
  if (!task->path) {
    scan_task_free(task);
    return -1;
  }

  InterlockedIncrement(&g_pending_tasks);

  GError *error = NULL;
  g_thread_pool_push(g_scan_pool, task, &error);
  if (error != NULL) {
    g_error_free(error);
    InterlockedDecrement(&g_pending_tasks);
    scan_task_free(task);
    return -1;
  }

  return 0;
}

static void scan_task_worker(gpointer data, gpointer user_data) {
  (void)user_data;
  ScanTask *task = (ScanTask *)data;

  if (!global_scan_ctx.stop_requested) {
    scan_progress_file_start(task->path);
    scan_single_file_internal(task->path, task->reason, task->quick_mode);
  }

  InterlockedDecrement(&g_pending_tasks);
  scan_task_free(task);
}

static void scan_walk_callback(const char *path, void *user_data) {
    if (global_scan_ctx.stop_requested)
        return;

    ScanWalkContext *ctx = (ScanWalkContext *)user_data;

    /* Phase A1: Extension whitelist — always active.
     * Skip non-scannable files before enqueueing (saves thread pool overhead). */
    if (!is_scannable_extension(path))
        return;

    /* Phase A3: mtime filter — quick_mode only, skip persistence paths.
     * Files older than 30 days in System32/Program Files/Temp are skipped
     * because RTP already scanned them on first access. Persistence locations
     * (Startup, Downloads) are always scanned regardless of age. */
    if (ctx->quick_mode && ctx->skip_old_files) {
        if (is_file_older_than_days(path, QUICK_SCAN_MAX_FILE_AGE_DAYS))
            return;
    }

    while (g_pending_tasks > QUEUE_BACKPRESSURE_LMT)
        Sleep(10);
    if (ctx->low_priority)
        Sleep(LOW_PRIORITY_SLEEP_MS);

    enqueue_scan_task(path, SCAN_REASON_MANUAL, ctx->quick_mode);
}

int scan_core_start_scan(const char *sigdb_path, const char *path_to_scan,
                         bool low_priority, bool quick_mode) {
  if (!sigdb_path || !path_to_scan)
    return SCANCORE_FILE_ERR;

  if (ensure_scan_pool() != 0)
    return SCANCORE_FATAL_ERR;

  global_scan_ctx.stop_requested = false;

  // Load latest signatures
  if (signature_db_load(sigdb_path) != 0)
    return SCANCORE_FILE_ERR;

  scan_report_bridge_init();
  scan_progress_start(0);

  ScanWalkContext ctx = {
      .low_priority = low_priority,
      .quick_mode = quick_mode,
      .skip_old_files = quick_mode  /* apply mtime filter in quick mode */
  };
  if (list_files_recursive(path_to_scan, scan_walk_callback, &ctx) != 0)
    return SCANCORE_FILE_ERR;

  while (g_pending_tasks > 0)
    Sleep(20);

  return SCANCORE_OK;
}

int scan_core_quick_scan(const char *sigdb_path) {
  if (!sigdb_path)
    return SCANCORE_FILE_ERR;

  if (ensure_scan_pool() != 0)
    return SCANCORE_FATAL_ERR;

  global_scan_ctx.stop_requested = false;

  // Load latest signatures
  if (signature_db_load(sigdb_path) != 0)
    return SCANCORE_FILE_ERR;

  scan_report_bridge_init();
  scan_progress_start(0);

  /* ---- Phase B1: Scan all running process images ----
   * This catches ALL active malware — if malware is running, its process
   * image is in memory and its on-disk file path will be enumerated here.
   * Typically 200-500 unique executable/DLL images across all processes. */
  if (!global_scan_ctx.stop_requested) {
    GList *process_images = scan_processes_get_loaded_images();
    for (GList *iter = process_images;
         iter != NULL && !global_scan_ctx.stop_requested;
         iter = iter->next) {
      const char *img_path = (const char *)iter->data;
      if (is_scannable_extension(img_path)) {
        while (g_pending_tasks > QUEUE_BACKPRESSURE_LMT)
          Sleep(10);
        enqueue_scan_task(img_path, SCAN_REASON_MANUAL, true);
      }
    }
    g_list_free_full(process_images, g_free);
  }

  /* ---- Phase B2: Scan registry persistence target files ----
   * Enumerates Run/RunOnce/Winlogon/IFEO/AppInit_DLLs registry values and
   * scans each referenced file. Catches threats that will activate on next
   * boot but may not be currently running. */
  if (!global_scan_ctx.stop_requested) {
    GList *persistence_files = scan_persistence_get_target_files();
    for (GList *iter = persistence_files;
         iter != NULL && !global_scan_ctx.stop_requested;
         iter = iter->next) {
      const char *file_path = (const char *)iter->data;
      if (is_scannable_extension(file_path)) {
        while (g_pending_tasks > QUEUE_BACKPRESSURE_LMT)
          Sleep(10);
        enqueue_scan_task(file_path, SCAN_REASON_MANUAL, true);
      }
    }
    g_list_free_full(persistence_files, g_free);
  }

  /* ---- Phase A: Walk targeted filesystem paths ----
   * Extension whitelist + mtime filter are applied in scan_walk_callback.
   * Persistence paths (Startup, Downloads) are exempt from mtime filter. */
  if (!global_scan_ctx.stop_requested) {
    GList *paths = get_quick_scan_paths();
    ScanWalkContext ctx = {
        .low_priority = false,
        .quick_mode = true,
        .skip_old_files = false  /* set per-path below */
    };
    for (GList *iter = paths;
         iter != NULL && !global_scan_ctx.stop_requested;
         iter = iter->next) {
      const char *dir_path = (const char *)iter->data;
      /* Persistence paths don't get mtime filter — always scan all files */
      ctx.skip_old_files = !is_persistence_path(dir_path);
      list_files_recursive(dir_path, scan_walk_callback, &ctx);
    }
    g_list_free_full(paths, g_free);
  }

  // Wait for all tasks to complete
  while (g_pending_tasks > 0)
    Sleep(20);

  return SCANCORE_OK;
}

int scan_core_scan_file(const char *sigdb_path, const char *path,
                        ScanReason reason) {
  if (!sigdb_path || !path)
    return -1;
  if (signature_db_load(sigdb_path) != 0)
    return -1;

  scan_progress_start(1);
  /* Real-time scans use quick_mode=false (full trust evaluation).
   * The extension whitelist still applies (in scan_single_file_internal). */
  return enqueue_scan_task(path, reason, false);
}

long scan_core_get_pending_tasks(void) { return g_pending_tasks; }

bool scan_core_is_complete(void) {
  return (g_pending_tasks == 0 && scan_report_is_idle());
}
