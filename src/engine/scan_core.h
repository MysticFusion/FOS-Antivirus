/**
 * @file scan_core.h
 * @brief Multithreaded Scan Core Interface
 *
 * This module coordinates the signature, heuristic, and ML detection layers.
 * It provides high-level APIs for scanning individual files or recursive
 * directory trees.
 *
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

    /* Progress Tracking */
    int  files_scanned;
    int  threats_found;
    char current_file[256];
} ScanContext;

extern ScanContext global_scan_ctx;

/* ============================================================================
 * Public Functions
 * ========================================================================== */

/**
 * @brief Initialize and start a recursive directory scan.
 *
 * @param[in] sigdb_path    Path to the signature database.
 * @param[in] path_to_scan  Directory or file path to scan.
 * @param[in] low_priority  If true, throttles resource usage to minimize system impact.
 *
 * @return 0 on success, negative error code on failure.
 */
int scan_core_start_scan(
    const char *sigdb_path,
    const char *path_to_scan,
    bool        low_priority
);

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
