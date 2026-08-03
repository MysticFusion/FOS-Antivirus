/**
 * @file scan_report_bridge.c
 * @brief Scan Result Accumulation & Bridge Implementation
 *
 * Implements the logic for consolidating results from the serial pipeline
 * (main). Handles final remediation triggering and UI progress updates.
 *
 * I-13: the legacy parallel accumulation path (scan_record list,
 * find_or_create_record, dispatch_and_cleanup, and the split
 * submit_signature/submit_heuristic API) was removed; the serial pipeline
 * submits fully-aggregated results via scan_report_submit_complete().
 *
 */

#define _CRT_SECURE_NO_WARNINGS

#include "scan_report_bridge.h"
#include "app_paths.h"
#include "response_engine.h"
#include "scan_executor.h"
#include "scan_progress.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <windows.h>

/* ============================================================================
 * Global State
 * ========================================================================== */

static CRITICAL_SECTION g_bridge_lock;

/* External from scan_core */
extern volatile LONG g_pending_tasks;

/* ============================================================================
 * Internal Helpers: Logging
 * ========================================================================== */

/**
 * @brief Log a suspicious heuristic event for later analysis.
 */
static void log_heuristic_event(const char *path, const HeuristicResult *heur) {
  FILE *f = fopen(app_path_heuristics_log(), "a");
  if (f == NULL) {
    return;
  }

  time_t now = time(NULL);
  char ts[64];
  strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));

  fprintf(f, "[%s] FILE=%s SCORE=%d VERDICT=%d REASON=%s\n", ts, path,
          heur->score, heur->verdict, heur->explanation);

  fclose(f);
}

/* ============================================================================
 * Public Functions
 * ========================================================================== */

int scan_report_bridge_init(void) {
  static bool initialized = false;
  if (!initialized) {
    InitializeCriticalSection(&g_bridge_lock);
    initialized = true;
  }
  return 0;
}

void scan_report_bridge_shutdown(void) {
  /* I-13: the parallel record list was removed; nothing to free here.
   * The critical section stays initialized for the app's lifetime. */
}

bool scan_report_is_idle(void) {
  return (g_pending_tasks == 0);
}

void scan_report_submit_complete(ScanInput *input, const SignatureResult *sig,
                                 const HeuristicResult *heur, double ml_score) {
  EnterCriticalSection(&g_bridge_lock);

  if (heur != NULL && heur->verdict != VERDICT_BENIGN) {
    log_heuristic_event(input->path, heur);
  }

  /* Direct execution path for Serial Pipeline */
  ScanDecision decision;

  execute_scan_decision(input->path, sig, heur, ml_score, input->trust,
                        &decision);

  bool threat_found = false;

  if (decision.action == ACTION_QUARANTINE &&
      !global_scan_ctx.stop_requested) {
    threat_found = true;

    /* Select most relevant label */
    const char *label = "Unknown.Threat";
    if (sig != NULL && sig->matched && sig->label != NULL) {
      label = sig->label;
    } else if (ml_score > 0.8) {
      label = "ML.Behavioral.Malware";
    } else if (heur != NULL && heur->score >= 80) {
      label = "Heuristic.HighRisk";
    } else if (heur != NULL &&
               strstr(heur->explanation, "Ransomware") != NULL) {
      label = "Behavioral.Ransomware";
    }

    response_quarantine_file(input->path, label);
  }

  if (threat_found) {
    printf("[SCAN-COMPLETED] File: %s | Verdict: THREAT DETECTED", input->path);
  } else {
    printf("[SCAN-COMPLETED] File: %s | Verdict: CLEAN", input->path);
  }

  if (ml_score >= 0.0) {
    printf(" (ML Score: %.4f)\n", ml_score);
  } else {
    printf("\n");
  }

  scan_progress_file_done(threat_found);

  /* Input object lifecycle ends here */
  free(input->path);
  free(input);

  LeaveCriticalSection(&g_bridge_lock);
}
