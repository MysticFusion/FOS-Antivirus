/**
 * @file rt_monitor.h
 * @brief Real-Time File System Monitor Interface
 *
 * This module provides the interface for the background real-time monitoring
 * system, which watches for file system events (creation, modification)
 * and triggers immediate virus scans.
 *
 */

#ifndef RT_MONITOR_H
#define RT_MONITOR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

/* ============================================================================
 * Public Functions
 * ========================================================================== */

/**
 * @brief Start the real-time monitoring service.
 *
 * Initializes the filesystem watcher on the user's home directory and starts
 * a background thread to process events. Also triggers a background scan
 * of existing files.
 *
 * @param[in] sigdb_path  Path to the signature database file.
 * @return 0 on success, -1 on failure.
 */
int rt_monitor_start(const char *sigdb_path);

/**
 * @brief Stop the real-time monitoring service.
 *
 * Signals the background thread to stop, closes directory handles, and
 * waits for the thread to terminate.
 */
void rt_monitor_stop(void);

#ifdef __cplusplus
}
#endif

#endif /* RT_MONITOR_H */