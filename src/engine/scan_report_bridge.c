/**
 * @file scan_report_bridge.c
 * @brief Scan Result Accumulation & Bridge Implementation
 *
 * Implements the logic for consolidating results from parallel scan workers
 * (legacy) and the serial pipeline (main). Handles final remediation
 * triggering and UI progress updates.
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
 * Internal Data Structures
 * ========================================================================== */

/**
 * @brief Accumulator for parallel (Layered) scan results.
 */
typedef struct scan_record {
  ScanInput *input; /**< Originating scan input */

  bool has_sig;  /**< True if signature results arrived */
  bool has_heur; /**< True if heuristic results arrived */

  SignatureResult sig; /**< Saved signature result */
  char *sig_label;     /**< Heap-allocated signature label */

  HeuristicResult heur; /**< Saved heuristic result */

  struct scan_record *next; /**< Linked list continuation */
} scan_record;

/* ============================================================================
 * Global State
 * ========================================================================== */

static scan_record *g_records = NULL;
static CRITICAL_SECTION g_bridge_lock;
static volatile LONG g_active_records = 0;

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

/**
 * @brief Log generic detected threats to the central history log.
 */
static void log_to_history(const char *path, const char *label) {
  FILE *f = fopen(app_path_history_log(), "a");
  if (f == NULL) {
    return;
  }

  time_t now = time(NULL);
  char ts[64];
  strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));

  fprintf(f, "[%s] %s | %s\n", ts, label, path);
  fclose(f);
}

/* ============================================================================
 * Internal Helpers: Record Management
 * ========================================================================== */

/**
 * @brief Locate or allocate a record for parallel result accumulation.
 */
static scan_record *find_or_create_record(ScanInput *input) {
  for (scan_record *r = g_records; r != NULL; r = r->next) {
    if (input->path != NULL && r->input->path != NULL &&
        strcmp(r->input->path, input->path) == 0) {
      return r;
    }
  }

  scan_record *r = calloc(1, sizeof(*r));
  if (r == NULL) {
    return NULL;
  }

  r->input = input;
  r->next = g_records;
  g_records = r;

  InterlockedIncrement(&g_active_records);
  return r;
}

/**
 * @brief Finalize and free a scan record after both results arrive.
 */
static void dispatch_and_cleanup(scan_record *r) {
  ScanDecision decision;

  /* Legacy Parallel Path (No ML support) */
  execute_scan_decision(r->input->path, &r->sig, &r->heur, -1.0,
                        r->input->trust, &decision);

  bool threat_found = false;

  if (decision.action == ACTION_QUARANTINE &&
      !global_scan_ctx.stop_requested) {
    threat_found = true;

    const char *label = "Heuristic.Suspicious";
    if (r->sig.label != NULL) {
      label = r->sig.label;
    } else if (r->heur.verdict == VERDICT_MALICIOUS) {
      label = "Heuristic.AI.Malware";
    } else if (strstr(r->heur.explanation, "Ransomware") != NULL) {
      label = "Behavioral.Ransomware";
    }

    response_quarantine_file(r->input->path, label);
  }

  if (threat_found) {
    printf("[SCAN-COMPLETED] File: %s | Verdict: THREAT DETECTED\n",
           r->input->path);
  }

  scan_progress_file_done(threat_found);

  /* Unlink from list */
  scan_record **pp = &g_records;
  while (*pp != NULL) {
    if (*pp == r) {
      *pp = r->next;
      break;
    }
    pp = &(*pp)->next;
  }

  free(r->sig_label);
  free(r->input->path);
  free(r->input);
  free(r);

  InterlockedDecrement(&g_active_records);
}

/**
 * @brief Attempt to execute decision if all results are ready.
 */
static void try_dispatch(scan_record *r) {
  if (r->has_sig && r->has_heur) {
    dispatch_and_cleanup(r);
  }
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
  EnterCriticalSection(&g_bridge_lock);

  scan_record *r = g_records;
  while (r != NULL) {
    scan_record *next = r->next;
    free(r->sig_label);
    free(r->input->path);
    free(r->input);
    free(r);
    r = next;
  }
  g_records = NULL;

  LeaveCriticalSection(&g_bridge_lock);
  /* Note: Critical section should stay initialized if app still running */
}

bool scan_report_is_idle(void) {
  return (g_active_records == 0 && g_pending_tasks == 0);
}

void scan_report_submit_signature(ScanInput *input,
                                  const SignatureResult *sig) {
  EnterCriticalSection(&g_bridge_lock);

  scan_record *r = find_or_create_record(input);
  if (r != NULL) {
    r->sig.matched = sig->matched;
    if (sig->label != NULL) {
      free(r->sig_label);
      r->sig_label = _strdup(sig->label);
      r->sig.label = r->sig_label;
    }
    r->has_sig = true;
    try_dispatch(r);
  }

  LeaveCriticalSection(&g_bridge_lock);
}

void scan_report_submit_heuristic(ScanInput *input,
                                  const HeuristicResult *heur) {
  EnterCriticalSection(&g_bridge_lock);

  scan_record *r = find_or_create_record(input);
  if (r != NULL) {
    r->heur = *heur;
    r->has_heur = true;

    if (heur->verdict != VERDICT_BENIGN) {
      log_heuristic_event(input->path, heur);
    }
    try_dispatch(r);
  }

  LeaveCriticalSection(&g_bridge_lock);
}

void scan_report_submit_complete(ScanInput *input, const SignatureResult *sig,
                                 const HeuristicResult *heur, double ml_score) {
  EnterCriticalSection(&g_bridge_lock);

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
