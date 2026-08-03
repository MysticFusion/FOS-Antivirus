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
 * @brief Safely add a path to the dynamically growing FilePathList.
 */
static void add_path(FilePathList *list, const char *p)
{
    char **new_paths = realloc(list->paths, sizeof(char *) * (list->count + 1));
    if (new_paths != NULL) {
        list->paths = new_paths;
        list->paths[list->count++] = _strdup(p);
    }
}

/**
 * @brief Recursive internal walker function.
 */
static void walk_recursive(const char *dir, FilePathList *list)
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
            walk_recursive(full_path, list);
        } else {
            /* Log standard files */
            add_path(list, full_path);
        }
    } while (FindNextFileA(h, &fd));

    FindClose(h);
}

/* ============================================================================
 * Public Functions
 * ========================================================================== */

int list_files_recursive(const char *root, FilePathList *out)
{
    if (root == NULL || out == NULL) {
        return -1;
    }

    /* Initialize list */
    out->paths = NULL;
    out->count = 0;

    /* Start recursive search */
    walk_recursive(root, out);

    return 0;
}

void free_filepath_list(FilePathList *list)
{
    if (list == NULL || list->paths == NULL) {
        return;
    }

    for (int i = 0; i < list->count; i++) {
        if (list->paths[i] != NULL) {
            free(list->paths[i]);
        }
    }

    free(list->paths);
    list->paths = NULL;
    list->count = 0;
}
