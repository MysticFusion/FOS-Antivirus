/**
 * @file scan_progress.c
 * @brief Thread-safe progress - hardened with snapshot helper for FFI
 */
#include "scan_progress.h"
#include <string.h>
#include <windows.h>

static CRITICAL_SECTION g_progress_lock;
static INIT_ONCE g_init_once = INIT_ONCE_STATIC_INIT;
static bool g_is_running = false;
static int g_files_scanned = 0;
static int g_threats_found = 0;
static char g_current_file[MAX_PATH] = {0};

static BOOL CALLBACK init_lock(PINIT_ONCE once, PVOID param, PVOID *ctx)
{
    (void)once; (void)param; (void)ctx;
    InitializeCriticalSection(&g_progress_lock);
    return TRUE;
}
static void ensure_initialized(void) { InitOnceExecuteOnce(&g_init_once, init_lock, NULL, NULL); }

void scan_progress_start(int total_files)
{
    (void)total_files;
    ensure_initialized();
    EnterCriticalSection(&g_progress_lock);
    g_is_running = true;
    g_files_scanned = 0;
    g_threats_found = 0;
    g_current_file[0] = '\0';
    LeaveCriticalSection(&g_progress_lock);
}

void scan_progress_file_start(const char *path)
{
    ensure_initialized();
    EnterCriticalSection(&g_progress_lock);
    if (path) {
        strncpy_s(g_current_file, sizeof(g_current_file), path, _TRUNCATE);
    } else {
        g_current_file[0] = '\0';
    }
    LeaveCriticalSection(&g_progress_lock);
}

void scan_progress_file_done(bool threat_found)
{
    ensure_initialized();
    EnterCriticalSection(&g_progress_lock);
    g_files_scanned++;
    if (threat_found) g_threats_found++;
    LeaveCriticalSection(&g_progress_lock);
}

void scan_progress_finish(void)
{
    ensure_initialized();
    EnterCriticalSection(&g_progress_lock);
    g_is_running = false;
    g_current_file[0] = '\0';
    LeaveCriticalSection(&g_progress_lock);
}

bool scan_progress_is_running(void)
{
    ensure_initialized();
    EnterCriticalSection(&g_progress_lock);
    bool r = g_is_running;
    LeaveCriticalSection(&g_progress_lock);
    return r;
}

int scan_progress_files_scanned(void)
{
    ensure_initialized();
    EnterCriticalSection(&g_progress_lock);
    int r = g_files_scanned;
    LeaveCriticalSection(&g_progress_lock);
    return r;
}

int scan_progress_threats_found(void)
{
    ensure_initialized();
    EnterCriticalSection(&g_progress_lock);
    int r = g_threats_found;
    LeaveCriticalSection(&g_progress_lock);
    return r;
}

const char *scan_progress_current_file(void)
{
    // Legacy unsafe accessor - returns pointer to internal buffer
    // For new code use snapshot below
    return g_current_file;
}

/* Atomic snapshot for FFI - copies all fields under single lock.
 * Struct definition lives in scan_progress.h. */
void scan_progress_snapshot(ScanProgressSnapshot *out)
{
    if (!out) return;
    ensure_initialized();
    EnterCriticalSection(&g_progress_lock);
    out->is_running = g_is_running;
    out->files_scanned = g_files_scanned;
    out->threats_found = g_threats_found;
    strncpy_s(out->current_file, sizeof(out->current_file), g_current_file, _TRUNCATE);
    LeaveCriticalSection(&g_progress_lock);
}
