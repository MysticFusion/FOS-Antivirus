/**
 * @file scan_processes.h
 * @brief Running Process Image Enumeration Interface
 *
 * Enumerates all running processes and their loaded modules (executables +
 * DLLs) to produce a deduplicated list of on-disk file paths for scanning.
 *
 * This is the FIRST step of quick scan (Phase B1). If malware is currently
 * active, its process image is loaded in memory and its on-disk file path
 * will be enumerated here. This catches ALL active file-based malware with
 * only ~200-500 file scans (vs. ~750K-1M for a full filesystem walk).
 *
 * Limitations (userland, no kernel driver):
 *   - Does NOT scan process memory directly (would need ReadProcessMemory)
 *   - Does NOT detect process hollowing / reflective DLL injection
 *   - Does NOT detect fileless malware living only in PowerShell memory
 *   For these, AMSI integration would be needed (future enhancement).
 */

#ifndef SCAN_PROCESSES_H
#define SCAN_PROCESSES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <glib.h>

/**
 * @brief Enumerate all running process images (executables + DLLs).
 *
 * Walks every running process via EnumProcesses + EnumProcessModulesEx +
 * GetModuleFileNameEx, collects the on-disk file path of every loaded
 * module, deduplicates, and returns the unique set.
 *
 * @return GList of allocated strings (full file paths). Caller must free
 *         with g_list_free_full(list, g_free). Returns NULL on error or
 *         if no processes were found.
 */
GList *scan_processes_get_loaded_images(void);

#ifdef __cplusplus
}
#endif

#endif /* SCAN_PROCESSES_H */
