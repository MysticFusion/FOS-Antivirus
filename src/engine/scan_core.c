#define _CRT_SECURE_NO_WARNINGS

#include "scan_core.h"
#include "fs_enumerator.h"
#include "hash_util.h"
#include "heuristic_engine.h"
#include "ml_engine.h"
#include "scan_progress.h"
#include "scan_report_bridge.h"
#include "signature_scan.h"
#include "trust.h"

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

static HANDLE g_scan_semaphore = NULL;
volatile LONG g_pending_tasks = 0;

/* ============================================================================
 * Internal Helpers
 * ========================================================================== */

static int ensure_semaphore(void) {
  if (g_scan_semaphore == NULL) {
    g_scan_semaphore = CreateSemaphoreA(NULL, MAX_CONCURRENT_TASKS,
                                        MAX_CONCURRENT_TASKS, NULL);
    if (g_scan_semaphore == NULL)
      return -1;
  }
  return 0;
}

/**
 * @brief Optimized scan pipeline.
 */
static void scan_single_file_internal(const char *path, ScanReason reason) {
  // 1. FAST PASS: Trust & Extension Check
  TrustLevel trust = trust_evaluate_path(path);
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

  // 4. DEEP PASS: Heuristics & ML
  // Extract features only if signatures didn't match
  if (extract_file_features(path, &in->features) == 0) {

    // Heuristic analysis
    evaluate_heuristics(&in->features, &heur, in->trust, in->reason);

    // ML behavioral analysis (Skip for non-executables)
    if (in->features.is_executable && in->trust != TRUST_HIGH) {
      ml_score = ml_engine_scan(&in->features);
      if (ml_score > 0.8) {
        InterlockedIncrement((LONG *)&global_scan_ctx.threats_found);
      }
    }
  }

  // Update scanned file counter
  InterlockedIncrement((LONG *)&global_scan_ctx.files_scanned);

  scan_report_submit_complete(in, &sig, &heur, ml_score);
}

/* ============================================================================
 * Public Functions
 * ========================================================================== */

int scan_core_start_scan(const char *sigdb_path, const char *path_to_scan,
                         bool low_priority) {
  if (!sigdb_path || !path_to_scan)
    return SCANCORE_FATAL_ERR;
  if (ensure_semaphore() != 0)
    return SCANCORE_FATAL_ERR;
  if (signature_db_load(sigdb_path) != 0)
    return SCANCORE_FATAL_ERR;

  scan_report_bridge_init();

  FilePathList list = {0};
  if (list_files_recursive(path_to_scan, &list) != 0)
    return SCANCORE_FILE_ERR;

  scan_progress_start(list.count);

  for (int i = 0; i < list.count; ++i) {
    if (global_scan_ctx.stop_requested)
      break;

    while (g_pending_tasks > QUEUE_BACKPRESSURE_LMT)
      Sleep(10);
    if (low_priority)
      Sleep(LOW_PRIORITY_SLEEP_MS);

    scan_progress_file_start(list.paths[i]);

    // Atomic increment of pending tasks
    InterlockedIncrement(&g_pending_tasks);

    // Launch in background/serial thread pool can be added here,
    // for now we follow the existing pattern of internal execution but with
    // atomic tracking
    scan_single_file_internal(list.paths[i], SCAN_REASON_MANUAL);

    InterlockedDecrement(&g_pending_tasks);
  }

  free_filepath_list(&list);
  return SCANCORE_OK;
}

int scan_core_scan_file(const char *sigdb_path, const char *path,
                        ScanReason reason) {
  if (!sigdb_path || !path)
    return -1;
  if (signature_db_load(sigdb_path) != 0)
    return -1;

  InterlockedIncrement(&g_pending_tasks);
  scan_progress_start(1);
  scan_progress_file_start(path);
  scan_single_file_internal(path, reason);
  InterlockedDecrement(&g_pending_tasks);

  return 0;
}

long scan_core_get_pending_tasks(void) { return g_pending_tasks; }

bool scan_core_is_complete(void) {
  return (g_pending_tasks == 0 && scan_report_is_idle());
}
