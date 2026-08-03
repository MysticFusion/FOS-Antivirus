/**
 * @file ui_scan_paths.c
 * @brief Scan Target Policy Implementation
 *
 * Implements OS-specific path discovery for targeted scanning modes.
 *
 */

#include "ui_scan_paths.h"
#include <windows.h>
#include <shlobj.h>
#include <string.h>

GList *get_quick_scan_paths(void)
{
    GList *paths = NULL;
    char   buffer[MAX_PATH];

    /* 1. System Core Directory (System32) */
    if (GetSystemDirectoryA(buffer, MAX_PATH) > 0) {
        paths = g_list_append(paths, g_strdup(buffer));
    }

    /* 2. Platform-specific Program Files */
    if (SHGetFolderPathA(NULL, CSIDL_PROGRAM_FILES, NULL, 0, buffer) == S_OK) {
        paths = g_list_append(paths, g_strdup(buffer));
    }

    /* 3. Global/User Startup Locations */
    if (SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, buffer) == S_OK) {
        paths = g_list_append(paths, g_strdup(buffer));
    }

    /* 4. Common Downloads Directory */
    if (SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, buffer) == S_OK) {
        strncat(buffer, "\\Downloads", MAX_PATH - strlen(buffer) - 1);
        paths = g_list_append(paths, g_strdup(buffer));
    }

    /* 5. Temp Directory */
    if (GetTempPathA(MAX_PATH, buffer) > 0) {
        /* Remove trailing backslash if present for consistency */
        size_t len = strlen(buffer);
        if (len > 0 && buffer[len-1] == '\\') {
            buffer[len-1] = '\0';
        }
        paths = g_list_append(paths, g_strdup(buffer));
    }

    /* 6. AppData Roaming (Common Persistence) */
    if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, buffer) == S_OK) {
        paths = g_list_append(paths, g_strdup(buffer));
    }

    /* 7. AppData Local (Staging Areas) */
    if (SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, buffer) == S_OK) {
        paths = g_list_append(paths, g_strdup(buffer));
    }

    return paths;
}
