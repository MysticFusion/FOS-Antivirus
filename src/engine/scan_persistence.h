/**
 * @file scan_persistence.h
 * @brief Registry Persistence Enumeration Interface
 *
 * Enumerates Windows registry persistence locations (Run/RunOnce/Winlogon/
 * IFEO/AppInit_DLLs) and extracts the file paths referenced by each entry.
 * Returns a deduplicated list for scanning.
 *
 * This is the SECOND step of quick scan (Phase B2). Catches threats that
 * will activate on next boot or on login but may not be currently running.
 *
 * Registry keys scanned:
 *   HKLM\Software\Microsoft\Windows\CurrentVersion\Run
 *   HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
 *   HKCU\Software\Microsoft\Windows\CurrentVersion\Run
 *   HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
 *   HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon (Shell, Userinit)
 *   HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*\Debugger
 *   HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs
 */

#ifndef SCAN_PERSISTENCE_H
#define SCAN_PERSISTENCE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <glib.h>

/**
 * @brief Enumerate file paths referenced by registry persistence entries.
 *
 * Walks Run/RunOnce/Winlogon/IFEO/AppInit_DLLs registry keys, parses each
 * value's command line to extract the referenced file path(s), verifies
 * the file exists, and returns the deduplicated set.
 *
 * @return GList of allocated strings (full file paths). Caller must free
 *         with g_list_free_full(list, g_free). Returns NULL on error or
 *         if no persistence entries were found.
 */
GList *scan_persistence_get_target_files(void);

#ifdef __cplusplus
}
#endif

#endif /* SCAN_PERSISTENCE_H */
