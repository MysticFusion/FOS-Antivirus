/**
 * @file ui_scan_paths.c
 * @brief Scan Target Policy Implementation
 *
 * Implements OS-specific path discovery for targeted scanning modes.
 *
 * v1.2: Quick scan paths have been redesigned based on research into what
 * real AVs (Windows Defender, Kaspersky, Bitdefender, etc.) actually scan.
 * The old implementation recursively walked all of %APPDATA% and %LOCALAPPDATA%
 * (500K+ files of browser caches, Electron app data, etc.). The new
 * implementation uses targeted subpaths that focus on:
 *   - System core (System32, Program Files) — with mtime filter
 *   - Persistence (Startup folder) — no mtime filter
 *   - User drop points (Downloads) — no mtime filter
 *   - Staging areas (Temp) — with mtime filter
 *   - Per-user installs (LocalAppData\Programs) — with mtime filter
 *
 * Combined with the extension whitelist and mtime filter in scan_core.c,
 * this reduces quick scan from ~750K-1M files to ~5K-20K files.
 */

#include "ui_scan_paths.h"
#include <windows.h>
#include <shlobj.h>
#include <string.h>

GList *get_quick_scan_paths(void)
{
    GList *paths = NULL;
    char   buffer[MAX_PATH];

    /* 1. System Core Directory (System32)
     *    mtime filter: YES (most files untouched since OS install) */
    if (GetSystemDirectoryA(buffer, MAX_PATH) > 0) {
        paths = g_list_append(paths, g_strdup(buffer));
    }

    /* 2. Program Files
     *    mtime filter: YES (most files untouched since install) */
    if (SHGetFolderPathA(NULL, CSIDL_PROGRAM_FILES, NULL, 0, buffer) == S_OK) {
        paths = g_list_append(paths, g_strdup(buffer));
    }

    /* 3. User Startup Folder (persistence — no mtime filter)
     *    CSIDL_STARTUP = %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
     *    This is the #1 persistence location for user-mode malware. */
    if (SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, buffer) == S_OK) {
        paths = g_list_append(paths, g_strdup(buffer));
    }

    /* 4. Common Startup Folder (all users — persistence)
     *    CSIDL_COMMON_STARTUP = C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup */
    if (SHGetFolderPathA(NULL, CSIDL_COMMON_STARTUP, NULL, 0, buffer) == S_OK) {
        paths = g_list_append(paths, g_strdup(buffer));
    }

    /* 5. Downloads Directory (user drop point — no mtime filter)
     *    Newly downloaded files are the most likely source of fresh malware. */
    if (SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, buffer) == S_OK) {
        strncat(buffer, "\\Downloads", MAX_PATH - strlen(buffer) - 1);
        paths = g_list_append(paths, g_strdup(buffer));
    }

    /* 6. Temp Directory (staging area — mtime filter: YES)
     *    Malware often drops payloads in Temp before moving them elsewhere. */
    if (GetTempPathA(MAX_PATH, buffer) > 0) {
        /* Remove trailing backslash if present for consistency */
        size_t len = strlen(buffer);
        if (len > 0 && buffer[len-1] == '\\') {
            buffer[len-1] = '\0';
        }
        paths = g_list_append(paths, g_strdup(buffer));
    }

    /* 7. Per-user installed programs (LocalAppData\Programs — mtime filter: YES)
     *    Many modern apps install here (Chrome, Discord, VS Code, etc.)
     *    rather than Program Files. Malware can also install here without
     *    admin privileges. */
    if (SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, buffer) == S_OK) {
        strncat(buffer, "\\Programs", MAX_PATH - strlen(buffer) - 1);
        paths = g_list_append(paths, g_strdup(buffer));
    }

    /* NOTE: We deliberately do NOT scan all of %APPDATA% or %LOCALAPPDATA%
     * recursively. These directories contain hundreds of thousands of files
     * (browser caches, Electron app resources, package manager caches, etc.)
     * that are overwhelmingly non-executable. The extension whitelist filter
     * in scan_core.c would eliminate most of them, but even the directory
     * enumeration itself is slow. Instead, we rely on:
     *   - Phase B1 (scan_processes.c): scans all loaded DLL/exe images
     *   - Phase B2 (scan_persistence.c): scans registry Run/RunOnce/IFEO entries
     *   - The targeted paths above (Startup, Temp, Programs)
     * to cover the actual threat surface. */

    return paths;
}
