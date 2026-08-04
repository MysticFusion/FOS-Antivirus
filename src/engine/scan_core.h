/**
 * @file scan_core.h
 * @brief Multithreaded Scan Core Interface
 *
 * This module coordinates the signature, heuristic, and ML detection layers.
 * It provides high-level APIs for scanning individual files or recursive
 * directory trees.
 *
 * v1.2 changes:
 *   - scan_core_start_scan() now takes a quick_mode parameter.
 *   - New scan_core_quick_scan() function that performs the full quick-scan
 *     workflow: (1) scan all running process images, (2) scan registry
 *     persistence target files, (3) walk targeted filesystem paths with
 *     extension whitelist + mtime filtering.
 *   - Extension whitelist filter is ALWAYS active (all scan modes) — non-
 *     executable files (.txt, .jpg, .log, etc.) are never scanned.
 *   - mtime filter is active only in quick_mode — files older than 30 days
 *     in non-persistence locations are skipped.
 */

#ifndef SCAN_CORE_H
#define SCAN_CORE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <windows.h>
#include <glib.h>
#include "feature_extract.h"
#include "trust.h"

typedef struct _AppState AppState;

/* ============================================================================
 * Return Codes
 * ========================================================================== */

#define SCANCORE_OK          0
#define SCANCORE_MATCH       1
#define SCANCORE_HANDLED     2
#define SCANCORE_FATAL_ERR  -1
#define SCANCORE_FILE_ERR   -2

/* ============================================================================
 * Scan Input Structure
 * ========================================================================== */

/**
 * @brief Metadata and features for a file being processed by the scan pipeline.
 */
typedef struct {
    char          *path;       /**< Heap-allocated absolute path */
    unsigned char  hash[32];   /**< SHA-256 file hash */
    FileFeatures   features;   /**< Extracted static features */
    TrustLevel     trust;      /**< Digital signature trust level */
    ScanReason     reason;     /**< Trigger context for this scan */
} ScanInput;

/* ============================================================================
 * Global Synchronization Context
 * ========================================================================== */

/**
 * @brief Thread-safe context for managing scan state and UI synchronization.
 */
typedef struct {
    /* Synchronization */
    GMutex mutex;

    /* Control Flags */
    bool is_running;
    bool stop_requested;

    /* MAP-01/MAP-09: signature-DB availability is ADVISORY, not fatal.
     * Enumeration and per-file analysis always run; when false, the
     * signature layer is bypassed and the UI surfaces a heuristic-only
     * warning instead of aborting the scan. */
    bool db_available;

    /* Progress Tracking */
    int  files_scanned;
    int  threats_found;
    char current_file[256];
    AppState *app_state;
} ScanContext;

extern ScanContext global_scan_ctx;

/* ============================================================================
 * Advisory Signature-DB Availability (MAP-01 / MAP-09)
 * ========================================================================== */

/**
 * @brief Record whether the signature database could be loaded for the
 *        current scan session. Never fatal: a missing/invalid DB only
 *        disables the signature layer, not enumeration/heuristics/ML.
 */
void scan_core_set_db_available(bool ok);

/**
 * @brief Read the advisory DB-availability flag for the current scan.
 * @return true if the signature database is loaded and usable.
 */
bool scan_core_db_available(void);

/* ============================================================================
 * Public Functions
 * ========================================================================== */

/**
 * @brief Initialize and start a recursive directory scan.
 *
 * @param[in] sigdb_path    Path to the signature database.
 * @param[in] path_to_scan  Directory or file path to scan.
 * @param[in] low_priority  If true, throttles resource usage to minimize system impact.
 * @param[in] quick_mode    If true, applies mtime filtering and uses fast trust
 *                          evaluation (no revocation checks). If false, uses
 *                          full trust evaluation and no mtime filtering.
 *
 * @return 0 on success, negative error code on failure.
 */
int scan_core_start_scan(
    const char *sigdb_path,
    const char *path_to_scan,
    bool        low_priority,
    bool        quick_mode
);

/**
 * @brief Perform a full quick scan (Phase A + Phase B).
 *
 * This is the recommended entry point for quick scan. It performs:
 *   1. Scan all running process images (Phase B1 — EnumProcesses + EnumProcessModulesEx)
 *   2. Scan registry persistence target files (Phase B2 — Run/RunOnce/Winlogon/IFEO)
 *   3. Walk targeted filesystem paths with extension whitelist + mtime filtering
 *      (Phase A — System32, Program Files, Startup, Downloads, Temp, etc.)
 *
 * All three steps use the same scan pipeline (signature DB + heuristics + ML)
 * and share a single progress tracking session.
 *
 * @param[in] sigdb_path Path to the signature database.
 * @return 0 on success, negative error code on failure.
 */
int scan_core_quick_scan(const char *sigdb_path);

/**
 * @brief Scan a single file immediately (typically used for real-time events).
 *
 * @param[in] sigdb_path Path to the signature database.
 * @param[in] file_path  Path to the file to scan.
 * @param[in] reason     Context/Reason for the scan.
 *
 * @return 0 on success, non-zero on failure.
 */
int scan_core_scan_file(
    const char *sigdb_path,
    const char *file_path,
    ScanReason  reason
);

/**
 * @brief Scan a single file addressed by a wide-character path (no W->A
 *        round-trip through the caller). Long-path safe.
 */
int scan_core_scan_file_wide(
    const char *sigdb_path,
    const wchar_t *file_path,
    ScanReason  reason
);

/**
 * @brief Get the number of pending tasks in the scan queue.
 */
long scan_core_get_pending_tasks(void);

/**
 * @brief Check if all active and pending scan tasks are finished.
 */
bool scan_core_is_complete(void);

#ifdef __cplusplus
}
#endif

#endif /* SCAN_CORE_H */
