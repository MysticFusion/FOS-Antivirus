/**
 * @file scan_processes.c
 * @brief Running Process Image Enumeration Implementation
 *
 * Uses EnumProcesses + EnumProcessModulesEx + GetModuleFileNameEx to
 * enumerate every loaded executable and DLL across all running processes.
 * Returns a deduplicated GList of on-disk file paths.
 *
 * Requires linking with psapi.lib (added to CMakeLists.txt).
 */

#define _CRT_SECURE_NO_WARNINGS

#include "scan_processes.h"

#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * Configuration
 * ========================================================================== */

#define MAX_PROCESSES       2048
#define INITIAL_MODULE_COUNT 512

/* ============================================================================
 * Internal Helpers
 * ========================================================================== */

/**
 * @brief Add a path to the list if it's not already present (deduplication).
 *
 * Uses a simple linear search since the list is typically 200-500 entries.
 * A hash set would be faster but adds complexity for minimal gain.
 */
static void add_path_if_unique(GList **list, const char *path) {
    if (!path || !*path)
        return;

    /* Verify the file actually exists on disk */
    if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES)
        return;

    /* Linear search for deduplication */
    for (GList *iter = *list; iter != NULL; iter = iter->next) {
        if (_stricmp((const char *)iter->data, path) == 0)
            return;  /* Already in list */
    }

    *list = g_list_append(*list, _strdup(path));
}

/**
 * @brief Enumerate all modules loaded in a single process.
 */
static void enumerate_process_modules(HANDLE hProcess, GList **list) {
    HMODULE *modules = NULL;
    DWORD needed = 0;
    DWORD count = 0;

    /* First call to get the buffer size */
    if (!EnumProcessModulesEx(hProcess, NULL, 0, &needed,
                              LIST_MODULES_ALL)) {
        return;
    }

    if (needed == 0)
        return;

    modules = (HMODULE *)malloc(needed);
    if (!modules)
        return;

    /* Second call to get the actual modules */
    if (EnumProcessModulesEx(hProcess, modules, needed, &needed,
                             LIST_MODULES_ALL)) {
        count = needed / sizeof(HMODULE);

        for (DWORD i = 0; i < count; i++) {
            char module_path[MAX_PATH] = {0};

            /* Get the full file path of this module */
            if (GetModuleFileNameExA(hProcess, modules[i],
                                     module_path, MAX_PATH) > 0) {
                add_path_if_unique(list, module_path);
            }
        }
    }

    free(modules);
}

/* ============================================================================
 * Public Functions
 * ========================================================================== */

GList *scan_processes_get_loaded_images(void) {
    GList *list = NULL;
    DWORD *pids = NULL;
    DWORD pid_size = MAX_PROCESSES * sizeof(DWORD);
    DWORD bytes_returned = 0;

    pids = (DWORD *)malloc(pid_size);
    if (!pids)
        return NULL;

    /* Enumerate all process IDs */
    if (!EnumProcesses(pids, pid_size, &bytes_returned)) {
        free(pids);
        return NULL;
    }

    /* If the buffer was too small, retry with a larger buffer */
    if (bytes_returned >= pid_size) {
        free(pids);
        pid_size = bytes_returned * 2;
        pids = (DWORD *)malloc(pid_size);
        if (!pids)
            return NULL;
        if (!EnumProcesses(pids, pid_size, &bytes_returned)) {
            free(pids);
            return NULL;
        }
    }

    DWORD pid_count = bytes_returned / sizeof(DWORD);

    for (DWORD i = 0; i < pid_count; i++) {
        DWORD pid = pids[i];

        /* Skip the System Idle Process (PID 0) and System process (PID 4) */
        if (pid == 0 || pid == 4)
            continue;

        /* Open the process with query + vm_read permissions.
         * PROCESS_VM_READ is needed for EnumProcessModulesEx.
         * If we can't open a process (e.g. protected process), skip it. */
        HANDLE hProcess = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE,
            pid);

        if (!hProcess) {
            /* Try with limited query rights (no VM_READ) — this lets us
             * at least get the main executable path via QueryFullProcessImageName */
            hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (hProcess) {
                char exe_path[MAX_PATH] = {0};
                DWORD len = MAX_PATH;
                if (QueryFullProcessImageNameA(hProcess, 0, exe_path, &len)) {
                    add_path_if_unique(&list, exe_path);
                }
                CloseHandle(hProcess);
            }
            continue;
        }

        /* Enumerate all modules (exe + all loaded DLLs) */
        enumerate_process_modules(hProcess, &list);

        CloseHandle(hProcess);
    }

    free(pids);
    return list;
}
