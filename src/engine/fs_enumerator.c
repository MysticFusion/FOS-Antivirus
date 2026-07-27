/**
 * @file fs_enumerator.c
 * @brief Filesystem Enumerator Utility Implementation
 *
 * Uses Win32 FindFirstFile/FindNextFile APIs for recursive file enumeration.
 *
 */

#include "fs_enumerator.h"

#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ============================================================================
 * Internal Helpers
 * ========================================================================== */

/**
 * @brief Recursive internal walker function.
 */
static void walk_recursive(const char *dir, fs_enum_callback_t callback, void *user_data)
{
    char pattern[MAX_PATH];
    snprintf(pattern, MAX_PATH, "%s\\*", dir);

    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        /* Skip self and parent directory references */
        if (strcmp(fd.cFileName, ".") == 0 ||
            strcmp(fd.cFileName, "..") == 0) {
            continue;
        }

        char full_path[MAX_PATH];
        snprintf(full_path, MAX_PATH, "%s\\%s", dir, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            /* Recursively enter directories */
            walk_recursive(full_path, callback, user_data);
        } else {
            /* Report standard files */
            callback(full_path, user_data);
        }
    } while (FindNextFileA(h, &fd));

    FindClose(h);
}

/* ============================================================================
 * Public Functions
 * ========================================================================== */

int list_files_recursive(const char *root, fs_enum_callback_t callback, void *user_data)
{
    if (root == NULL || callback == NULL) {
        return -1;
    }

    /* Start recursive search */
    walk_recursive(root, callback, user_data);

    return 0;
}
