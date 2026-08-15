#define _CRT_SECURE_NO_WARNINGS
#include "scan_processes.h"
#include "path_utils.h"
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strsafe.h>

#define MAX_PROCESSES 2048

static GHashTable *g_dedup_table = NULL;

/* MAPv3 U-03: the check-then-open TOCTOU (CWE-367) is closed by opening the
 * path IMMEDIATELY and deriving the recorded path from the opened handle
 * (fos_open_canonical -> GetFinalPathNameByHandleW). The scanner's later
 * re-open by path now targets the same object that was validated here; a
 * file swapped for a junction in the old GetFileAttributesA window can no
 * longer redirect the hash to an unrelated target.
 *
 * MAPv3 U-05: the caller supplies the WIDE path (GetModuleFileNameExW), so
 * no ANSI truncation can silently shorten a >260-char module path. */
static void add_path_if_unique(GList **list, const wchar_t *path) {
    if (!path || !*path) return;
    char canonical[FOS_MAX_PATH];
    if (fos_open_canonical(path, true, canonical, sizeof(canonical), NULL) != 0) return;
    if (!g_dedup_table) g_dedup_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    char lower[FOS_MAX_PATH]; StringCchCopyA(lower, sizeof(lower), canonical); _strlwr_s(lower, sizeof(lower));
    if (g_hash_table_contains(g_dedup_table, lower)) return;
    g_hash_table_add(g_dedup_table, _strdup(lower));
    *list = g_list_append(*list, _strdup(canonical));
}

static void enumerate_process_modules(HANDLE hProcess, GList **list) {
    HMODULE *modules=NULL; DWORD needed=0;
    if (!EnumProcessModulesEx(hProcess, NULL, 0, &needed, LIST_MODULES_ALL)) return;
    if (needed==0 || needed> 100*1024) return;
    modules = (HMODULE*)malloc(needed); if (!modules) return;
    if (EnumProcessModulesEx(hProcess, modules, needed, &needed, LIST_MODULES_ALL)) {
        DWORD count = needed / sizeof(HMODULE);
        for (DWORD i=0;i<count;i++) {
            /* MAPv3 U-05: wide API + dynamic buffer. GetModuleFileNameExW
             * returns 0 with ERROR_INSUFFICIENT_BUFFER when the module path
             * exceeds the buffer (long-path support); grow geometrically up
             * to FOS_MAX_PATH instead of truncating into a stack MAX_PATH
             * array (CWE-120: silent truncation / un-terminated reads). */
            size_t cap = 1024;
            wchar_t *buf = NULL;
            while (cap <= FOS_MAX_PATH) {
                wchar_t *nb = (wchar_t*)realloc(buf, cap * sizeof(wchar_t));
                if (!nb) { free(buf); buf = NULL; break; }
                buf = nb;
                DWORD n = GetModuleFileNameExW(hProcess, modules[i], buf, (DWORD)cap);
                if (n == 0) {
                    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) { cap *= 2; continue; }
                    free(buf); buf = NULL; break;
                }
                if (n >= cap) { cap *= 2; continue; } /* possibly truncated */
                break;
            }
            if (buf) {
                add_path_if_unique(list, buf);
                free(buf);
            }
        }
    }
    free(modules);
}

GList *scan_processes_get_loaded_images(void) {
    GList *list=NULL;
    if (g_dedup_table) { g_hash_table_destroy(g_dedup_table); g_dedup_table=NULL; }
    g_dedup_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    DWORD *pids=NULL; DWORD pid_size=MAX_PROCESSES*sizeof(DWORD); DWORD bytes_returned=0;
    pids=(DWORD*)malloc(pid_size); if (!pids) return NULL;
    if (!EnumProcesses(pids, pid_size, &bytes_returned)) { free(pids); g_hash_table_destroy(g_dedup_table); g_dedup_table=NULL; return NULL; }
    if (bytes_returned >= pid_size) {
        free(pids); pid_size=bytes_returned*2; if (pid_size> 100*1024) { g_hash_table_destroy(g_dedup_table); g_dedup_table=NULL; return NULL; }
        pids=(DWORD*)malloc(pid_size); if (!pids) { g_hash_table_destroy(g_dedup_table); g_dedup_table=NULL; return NULL; }
        if (!EnumProcesses(pids, pid_size, &bytes_returned)) { free(pids); g_hash_table_destroy(g_dedup_table); g_dedup_table=NULL; return NULL; }
    }
    DWORD pid_count=bytes_returned/sizeof(DWORD);
    for (DWORD i=0;i<pid_count;i++) {
        DWORD pid=pids[i]; if (pid==0||pid==4) continue;
        HANDLE hProcess=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, FALSE, pid);
        if (!hProcess) {
            hProcess=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (hProcess) {
                wchar_t exe_path[FOS_MAX_PATH]={0}; DWORD len=FOS_MAX_PATH;
                if (QueryFullProcessImageNameW(hProcess, 0, exe_path, &len)) add_path_if_unique(&list, exe_path);
                CloseHandle(hProcess);
            }
            continue;
        }
        enumerate_process_modules(hProcess, &list);
        CloseHandle(hProcess);
    }
    free(pids);
    if (g_dedup_table) { g_hash_table_destroy(g_dedup_table); g_dedup_table=NULL; }
    return list;
}
