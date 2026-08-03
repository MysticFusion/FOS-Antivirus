/**
 * @file scan_progress.c
 * @brief Thread-safe Scan Progress Tracking Implementation
 *
 * Implements centralized state tracking for foreground scan operations
 * using Win32 Critical Sections for thread-safe access from various
 * scan workers and the UI polling thread.
 *
 */

#include "scan_progress.h"

#include <string.h>
#include <windows.h>

/* ============================================================================
 * Internal State
 * ========================================================================== */

static CRITICAL_SECTION g_progress_lock;
static bool             g_initialized = false;

static bool             g_is_running = false;
static int              g_files_scanned = 0;
static int              g_threats_found = 0;
static char             g_current_file[MAX_PATH] = {0};

/* ============================================================================
 * Internal Helpers
 * ========================================================================== */

/**
 * @brief Ensures the global critical section is initialized.
 */
static void ensure_initialized(void)
{
    if (!g_initialized) {
        InitializeCriticalSection(&g_progress_lock);
        g_initialized = true;
    }
}

/* ============================================================================
 * Public Functions
 * ========================================================================== */

void scan_progress_start(int total_files)
{
    /* Parameter reserved for future progress percentage calculation */
    (void)total_files;
    
    ensure_initialized();

    EnterCriticalSection(&g_progress_lock);
    g_is_running      = true;
    g_files_scanned   = 0;
    g_threats_found   = 0;
    g_current_file[0] = '\0';
    LeaveCriticalSection(&g_progress_lock);
}

void scan_progress_file_start(const char *path)
{
    ensure_initialized();

    EnterCriticalSection(&g_progress_lock);
    if (path != NULL) {
        strncpy(g_current_file, path, sizeof(g_current_file) - 1);
        g_current_file[sizeof(g_current_file) - 1] = '\0';
    }
    LeaveCriticalSection(&g_progress_lock);
}

void scan_progress_file_done(bool threat_found)
{
    ensure_initialized();

    EnterCriticalSection(&g_progress_lock);
    g_files_scanned++;
    if (threat_found) {
        g_threats_found++;
    }
    LeaveCriticalSection(&g_progress_lock);
}

void scan_progress_finish(void)
{
    ensure_initialized();

    EnterCriticalSection(&g_progress_lock);
    g_is_running = false;
    LeaveCriticalSection(&g_progress_lock);
}

/* ============================================================================
 * UI Polling Accessors
 * ========================================================================== */

bool scan_progress_is_running(void)
{
    return g_is_running;
}

int scan_progress_files_scanned(void)
{
    return g_files_scanned;
}

int scan_progress_threats_found(void)
{
    return g_threats_found;
}

const char *scan_progress_current_file(void)
{
    return g_current_file;
}
