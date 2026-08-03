#define _CRT_SECURE_NO_WARNINGS
#include "app_paths.h"
#include <shlobj.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <strsafe.h>

static INIT_ONCE g_init_once = INIT_ONCE_STATIC_INIT;
static bool g_initialized = false;
static char g_app_dir[MAX_PATH] = {0};
static char g_signature_db[MAX_PATH] = {0};
static char g_history_log[MAX_PATH] = {0};
static char g_heuristics_log[MAX_PATH] = {0};
static char g_quarantine_dir[MAX_PATH] = {0};
static char g_model_path[MAX_PATH] = {0};

static void join_path_safe(char *out, size_t out_sz, const char *base, const char *leaf)
{
    if (!out || !base || !leaf) return;
    StringCchPrintfA(out, out_sz, "%s\\%s", base, leaf);
}

static bool file_exists_safe(const char *path)
{
    if (!path) return false;
    DWORD attrs = GetFileAttributesA(path);
    return attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

static void resolve_model_path(void)
{
    char exe_path[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, exe_path, MAX_PATH);
    char *last_slash = strrchr(exe_path, '\\');
    if (last_slash) *last_slash = '\0';

    char candidate[MAX_PATH] = {0};
    join_path_safe(candidate, sizeof(candidate), exe_path, "ml\\models\\forest.bin");
    if (file_exists_safe(candidate)) { StringCchCopyA(g_model_path, MAX_PATH, candidate); return; }

    join_path_safe(candidate, sizeof(candidate), exe_path, "..\\assets\\models\\forest.bin");
    if (file_exists_safe(candidate)) { StringCchCopyA(g_model_path, MAX_PATH, candidate); return; }

    StringCchCopyA(g_model_path, MAX_PATH, "assets\\models\\forest.bin");
}

static void resolve_signature_db(void)
{
    /* I-22/R-09: prefer the read-only system location
     * C:\ProgramData\FOS-Antivirus\signatures.db. HMAC verification is
     * enforced at load time regardless of which location is used, so a
     * fallback to the legacy user-app-dir database is still tamper-evident. */
    PWSTR progdata = NULL;
    char pd_dir[MAX_PATH] = {0};
    if (SUCCEEDED(SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, NULL, &progdata))) {
        char progdata_utf8[MAX_PATH] = {0};
        WideCharToMultiByte(CP_UTF8, 0, progdata, -1, progdata_utf8, MAX_PATH, NULL, NULL);
        CoTaskMemFree(progdata);
        join_path_safe(pd_dir, sizeof(pd_dir), progdata_utf8, "FOS-Antivirus");
        CreateDirectoryA(pd_dir, NULL); /* ok if it already exists */

        char candidate[MAX_PATH] = {0};
        join_path_safe(candidate, sizeof(candidate), pd_dir, "signatures.db");
        if (file_exists_safe(candidate)) {
            StringCchCopyA(g_signature_db, MAX_PATH, candidate);
            return;
        }
    }

    char candidate_db[MAX_PATH] = {0};
    join_path_safe(candidate_db, sizeof(candidate_db), g_app_dir, "malware_hashes.db");
    if (file_exists_safe(candidate_db)) {
        StringCchCopyA(g_signature_db, MAX_PATH, candidate_db);
        return;
    }
    join_path_safe(candidate_db, sizeof(candidate_db), g_app_dir, "signatures.db");
    if (file_exists_safe(candidate_db)) {
        StringCchCopyA(g_signature_db, MAX_PATH, candidate_db);
        return;
    }

    /* No database anywhere yet: prefer ProgramData if it is usable,
     * otherwise the user app dir (updates need a writable target). */
    if (pd_dir[0] && GetFileAttributesA(pd_dir) != INVALID_FILE_ATTRIBUTES) {
        join_path_safe(g_signature_db, sizeof(g_signature_db), pd_dir, "signatures.db");
    } else {
        join_path_safe(g_signature_db, sizeof(g_signature_db), g_app_dir, "signatures.db");
    }
}

static BOOL CALLBACK init_paths_cb(PINIT_ONCE once, PVOID param, PVOID *ctx)
{
    (void)once; (void)param; (void)ctx;
    PWSTR appdata = NULL;
    if (SUCCEEDED(SHGetKnownFolderPath(&FOLDERID_RoamingAppData, 0, NULL, &appdata))) {
        char appdata_utf8[MAX_PATH] = {0};
        WideCharToMultiByte(CP_UTF8, 0, appdata, -1, appdata_utf8, MAX_PATH, NULL, NULL);
        CoTaskMemFree(appdata);
        join_path_safe(g_app_dir, sizeof(g_app_dir), appdata_utf8, "FOS-Antivirus");
    } else {
        StringCchCopyA(g_app_dir, MAX_PATH, "FOS-Antivirus");
    }
    CreateDirectoryA(g_app_dir, NULL);

    resolve_signature_db();

    join_path_safe(g_history_log, sizeof(g_history_log), g_app_dir, "history.log");
    join_path_safe(g_heuristics_log, sizeof(g_heuristics_log), g_app_dir, "heuristics.log");
    join_path_safe(g_quarantine_dir, sizeof(g_quarantine_dir), g_app_dir, "Quarantine");
    CreateDirectoryA(g_quarantine_dir, NULL);
    resolve_model_path();
    g_initialized = true;
    return TRUE;
}

int app_paths_init(void)
{
    InitOnceExecuteOnce(&g_init_once, init_paths_cb, NULL, NULL);
    return g_initialized ? 0 : -1;
}

const char *app_path_signature_db(void) { app_paths_init(); return g_signature_db; }
const char *app_path_history_log(void) { app_paths_init(); return g_history_log; }
const char *app_path_heuristics_log(void) { app_paths_init(); return g_heuristics_log; }
const char *app_path_quarantine_dir(void) { app_paths_init(); return g_quarantine_dir; }
const char *app_path_model(void) { app_paths_init(); return g_model_path; }
