#define _CRT_SECURE_NO_WARNINGS
#include "scan_processes.h"
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strsafe.h>

#define MAX_PROCESSES 2048

static GHashTable *g_dedup_table = NULL;

static void add_path_if_unique(GList **list, const char *path) {
    if (!path || !*path) return;
    DWORD attrs = GetFileAttributesA(path);
    if (attrs==INVALID_FILE_ATTRIBUTES) return;
    if (attrs & FILE_ATTRIBUTE_REPARSE_POINT) return;
    if (!g_dedup_table) g_dedup_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    char lower[MAX_PATH]; StringCchCopyA(lower, MAX_PATH, path); _strlwr_s(lower, sizeof(lower));
    if (g_hash_table_contains(g_dedup_table, lower)) return;
    g_hash_table_add(g_dedup_table, _strdup(lower));
    *list = g_list_append(*list, _strdup(path));
}

static void enumerate_process_modules(HANDLE hProcess, GList **list) {
    HMODULE *modules=NULL; DWORD needed=0;
    if (!EnumProcessModulesEx(hProcess, NULL, 0, &needed, LIST_MODULES_ALL)) return;
    if (needed==0 || needed> 100*1024) return;
    modules = (HMODULE*)malloc(needed); if (!modules) return;
    if (EnumProcessModulesEx(hProcess, modules, needed, &needed, LIST_MODULES_ALL)) {
        DWORD count = needed / sizeof(HMODULE);
        for (DWORD i=0;i<count;i++) {
            char module_path[MAX_PATH]={0};
            if (GetModuleFileNameExA(hProcess, modules[i], module_path, MAX_PATH)>0) {
                add_path_if_unique(list, module_path);
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
                char exe_path[MAX_PATH]={0}; DWORD len=MAX_PATH;
                if (QueryFullProcessImageNameA(hProcess, 0, exe_path, &len)) add_path_if_unique(&list, exe_path);
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
