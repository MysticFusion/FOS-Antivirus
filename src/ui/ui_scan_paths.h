/**
 * @file ui_scan_paths.h
 * @brief Scan Target Policy Definition
 *
 * Defines the system paths included in standard scan modes (e.g., Quick Scan).
 *
 */

#ifndef UI_SCAN_PATHS_H
#define UI_SCAN_PATHS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <glib.h>

/**
 * @brief Retrieve a list of high-priority system paths for scanning.
 * 
 * Includes System32, Program Files, Startup, and Downloads.
 * 
 * @return GList of allocated strings (paths). Caller must free.
 */
GList *get_quick_scan_paths(void);

#ifdef __cplusplus
}
#endif

#endif /* UI_SCAN_PATHS_H */
