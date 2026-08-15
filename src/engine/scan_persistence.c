/**
 * @file scan_persistence.c
 * @brief Registry Persistence Enumeration Implementation
 *
 * Walks Windows registry persistence locations and extracts referenced
 * file paths. Handles command-line parsing for entries like:
 *   "C:\Program Files\app\app.exe" --flag
 *   C:\Windows\system32\rundll32.exe "C:\path\to\dll.dll",EntryPoint
 *   C:\path\to\exe.exe
 */

#define _CRT_SECURE_NO_WARNINGS

#include "scan_persistence.h"
#include "path_utils.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strsafe.h>

/* ============================================================================
 * Internal Helpers
 * ========================================================================== */

/**
 * @brief Add a path to the list if it's not already present and the file exists.
 *
 * MAPv3 U-03: closes the check-then-open TOCTOU (CWE-367). The old code
 * verified existence with GetFileAttributesA and deferred the real open to
 * the scanner, leaving a window where the path could be swapped for a
 * junction. Now the file is opened IMMEDIATELY (CreateFileW via
 * fos_open_canonical) and the recorded path is the handle-derived canonical
 * path (GetFinalPathNameByHandleW), so the scanner's later re-open targets
 * the same object.
 */
static void add_path_if_unique(GList **list, const char *path) {
    if (!path || !*path)
        return;

    wchar_t wide[FOS_MAX_PATH];
    if (MultiByteToWideChar(CP_UTF8, 0, path, -1, wide, FOS_MAX_PATH) <= 0)
        return;

    char canonical[FOS_MAX_PATH];
    if (fos_open_canonical(wide, true, canonical, sizeof(canonical), NULL) != 0)
        return;

    /* Linear search for deduplication */
    for (GList *iter = *list; iter != NULL; iter = iter->next) {
        if (_stricmp((const char *)iter->data, canonical) == 0)
            return;
    }

    *list = g_list_append(*list, _strdup(canonical));
}

/**
 * @brief Extract file path(s) from a command-line string.
 *
 * Handles:
 *   - Quoted paths: "C:\Program Files\app\app.exe" --flag
 *   - Unquoted paths: C:\Windows\notepad.exe
 *   - rundll32/regsvr32: also extracts the DLL path from arguments
 *
 * The first token is always the executable path. If it's rundll32.exe or
 * regsvr32.exe, the next token is treated as a DLL path.
 */
static void extract_paths_from_cmdline(const char *cmdline, GList **list) {
    if (!cmdline || !*cmdline)
        return;

    const char *p = cmdline;
    /* Skip leading whitespace */
    while (*p == ' ' || *p == '\t')
        p++;

    if (!*p)
        return;

    char exe_path[MAX_PATH] = {0};

    if (*p == '"') {
        /* Quoted path */
        p++;
        int i = 0;
        while (*p && *p != '"' && i < MAX_PATH - 1) {
            exe_path[i++] = *p++;
        }
        exe_path[i] = '\0';
        if (*p == '"')
            p++;
    } else {
        /* Unquoted path — take up to first space or tab */
        int i = 0;
        while (*p && *p != ' ' && *p != '\t' && i < MAX_PATH - 1) {
            exe_path[i++] = *p++;
        }
        exe_path[i] = '\0';
    }

    if (exe_path[0]) {
        add_path_if_unique(list, exe_path);
    }

    /* Check if this is rundll32 or regsvr32 — if so, extract the DLL path */
    const char *basename = strrchr(exe_path, '\\');
    basename = basename ? basename + 1 : exe_path;

    if (_stricmp(basename, "rundll32.exe") == 0 ||
        _stricmp(basename, "regsvr32.exe") == 0) {
        /* Skip whitespace after the executable */
        while (*p == ' ' || *p == '\t')
            p++;
        if (!*p)
            return;

        char dll_path[MAX_PATH] = {0};

        if (*p == '"') {
            p++;
            int i = 0;
            while (*p && *p != '"' && i < MAX_PATH - 1) {
                dll_path[i++] = *p++;
            }
            dll_path[i] = '\0';
        } else {
            /* Take up to comma, space, or end */
            int i = 0;
            while (*p && *p != ',' && *p != ' ' && *p != '\t' && i < MAX_PATH - 1) {
                dll_path[i++] = *p++;
            }
            dll_path[i] = '\0';
        }

        if (dll_path[0]) {
            add_path_if_unique(list, dll_path);
        }
    }
}

/**
 * @brief Enumerate all string values under a registry key and extract
 *        file paths from each value's data.
 *
 * @param root     Root key (HKEY_LOCAL_MACHINE or HKEY_CURRENT_USER)
 * @param subkey   Registry subkey path
 * @param value_filter If non-NULL, only process values whose name matches
 *                     this filter (case-insensitive). If NULL, process all.
 * @param list     Output list to append paths to.
 */
static void scan_registry_key(HKEY root, const char *subkey,
                              const char *value_filter, GList **list) {
    HKEY hKey;
    LONG result = RegOpenKeyExA(root, subkey, 0, KEY_READ, &hKey);
    if (result != ERROR_SUCCESS)
        return;

    DWORD index = 0;
    for (;;) {
        char value_name[MAX_PATH] = {0};
        DWORD name_len = MAX_PATH;
        DWORD value_type = 0;
        char value_data[2048] = {0};
        DWORD data_len = sizeof(value_data);

        LONG rc = RegEnumValueA(hKey, index, value_name, &name_len, NULL,
                                &value_type, (LPBYTE)value_data, &data_len);
        if (rc == ERROR_NO_MORE_ITEMS)
            break;
        if (rc != ERROR_SUCCESS)
            break;

        /* Only process string-type values (REG_SZ, REG_EXPAND_SZ) */
        if (value_type == REG_SZ || value_type == REG_EXPAND_SZ) {
            /* If a value filter is specified, only process matching values */
            if (value_filter != NULL) {
                if (_stricmp(value_name, value_filter) != 0) {
                    index++;
                    continue;
                }
            }

            /* Expand environment variables if REG_EXPAND_SZ */
            if (value_type == REG_EXPAND_SZ) {
                char expanded[2048] = {0};
                DWORD expanded_len = ExpandEnvironmentStringsA(
                    value_data, expanded, sizeof(expanded));
                if (expanded_len > 0 && expanded_len <= sizeof(expanded)) {
                    extract_paths_from_cmdline(expanded, list);
                }
            } else {
                extract_paths_from_cmdline(value_data, list);
            }
        }

        index++;
    }

    RegCloseKey(hKey);
}

/**
 * @brief Scan the Image File Execution Options (IFEO) Debugger key.
 *
 * IFEO allows setting a "Debugger" value for any executable name. When that
 * executable is launched, Windows actually launches the debugger program
 * with the original executable as an argument. Malware abuses this to
 * hijack legitimate executables.
 *
 * Structure: HKLM\...\Image File Execution Options\<exe_name>\Debugger = "path"
 */
static void scan_ifeo_debugger(GList **list) {
    const char *ifeo_base =
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
        "Image File Execution Options";

    HKEY hIfeo;
    LONG result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, ifeo_base, 0,
                                KEY_READ, &hIfeo);
    if (result != ERROR_SUCCESS)
        return;

    DWORD subkey_index = 0;
    for (;;) {
        char subkey_name[MAX_PATH] = {0};
        DWORD name_len = MAX_PATH;
        FILETIME ft;

        LONG rc = RegEnumKeyExA(hIfeo, subkey_index, subkey_name,
                                &name_len, NULL, NULL, NULL, &ft);
        if (rc == ERROR_NO_MORE_ITEMS)
            break;
        if (rc != ERROR_SUCCESS)
            break;

        /* Open the subkey and look for a "Debugger" value */
        char full_path[MAX_PATH * 2];
        snprintf(full_path, sizeof(full_path), "%s\\%s", ifeo_base, subkey_name);

        HKEY hSubkey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, full_path, 0,
                          KEY_READ, &hSubkey) == ERROR_SUCCESS) {
            char debugger_data[2048] = {0};
            DWORD data_len = sizeof(debugger_data);
            DWORD value_type = 0;

            if (RegQueryValueExA(hSubkey, "Debugger", NULL, &value_type,
                                 (LPBYTE)debugger_data, &data_len) == ERROR_SUCCESS) {
                if (value_type == REG_SZ || value_type == REG_EXPAND_SZ) {
                    if (value_type == REG_EXPAND_SZ) {
                        char expanded[2048] = {0};
                        ExpandEnvironmentStringsA(debugger_data, expanded,
                                                  sizeof(expanded));
                        extract_paths_from_cmdline(expanded, list);
                    } else {
                        extract_paths_from_cmdline(debugger_data, list);
                    }
                }
            }
            RegCloseKey(hSubkey);
        }

        subkey_index++;
    }

    RegCloseKey(hIfeo);
}

/* ============================================================================
 * Public Functions
 * ========================================================================== */

GList *scan_persistence_get_target_files(void) {
    GList *list = NULL;

    /* ---- Run / RunOnce keys ----
     * These are the most common persistence mechanisms. Values are command
     * lines that execute at startup (HKLM) or login (HKCU). */
    scan_registry_key(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        NULL, &list);
    scan_registry_key(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        NULL, &list);
    scan_registry_key(HKEY_CURRENT_USER,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        NULL, &list);
    scan_registry_key(HKEY_CURRENT_USER,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        NULL, &list);

    /* ---- Winlogon keys ----
     * Shell: replaces explorer.exe (rare, high-impact malware)
     * Userinit: runs at every login (common persistence) */
    scan_registry_key(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        "Shell", &list);
    scan_registry_key(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        "Userinit", &list);

    /* ---- AppInit_DLLs ----
     * DLLs loaded into every process that loads user32.dll. Classic
     * persistence/injection mechanism. The value is a semicolon or
     * comma-separated list of DLL paths. */
    scan_registry_key(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
        "AppInit_DLLs", &list);

    /* ---- Image File Execution Options Debugger ----
     * Allows hijacking any executable by setting a "Debugger" value. */
    scan_ifeo_debugger(&list);

    return list;
}


