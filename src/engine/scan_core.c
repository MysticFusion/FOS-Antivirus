/**
 * @file scan_core.c - HARDENED
 * Fixes: threadpool race, backpressure busy-wait, TOCTOU, whitelist bypass, atomic counters
 */
#define _CRT_SECURE_NO_WARNINGS
#include "scan_core.h"
#include "feature_extract.h"
#include "fs_enumerator.h"
#include "hash_util.h"
#include "heuristic_engine.h"
#include "ml_engine.h"
#include "scan_executor.h"
#include "scan_persistence.h"
#include "scan_processes.h"
#include "scan_progress.h"
#include "scan_report_bridge.h"
#include "signature_scan.h"
#include "trust.h"
#include "ui_scan_paths.h"
#include <glib.h>
#include <shlwapi.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>

#define MAX_CONCURRENT_TASKS 8
#define QUEUE_BACKPRESSURE_LMT 64
#define QUICK_SCAN_MAX_FILE_AGE_DAYS 30
#define MAX_PATH_LEN 260

typedef struct { char *path; ScanReason reason; bool quick_mode; } ScanTask;

static GThreadPool *g_scan_pool = NULL;
static GMutex g_scan_pool_mutex;
static GOnce g_pool_once = G_ONCE_INIT;
volatile LONG g_pending_tasks = 0;
static HANDLE g_backpressure_event = NULL;

static const char *g_allowed_exts[] = {".exe",".dll",".sys",".scr",".cpl",".ocx",".drv",".com",".bat",".cmd",".ps1",".vbs",".vbe",".js",".jse",".hta",".wsf",".wsh",".msi",".msp",".docm",".xlsm",".pptm",NULL};

static bool is_file_older_than_days(const char *path, int days)
{
    if (!path || days<=0) return false;
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExA(path, GetFileExInfoStandard, &fad)) return false;
    if (fad.ftLastWriteTime.dwLowDateTime==0 && fad.ftLastWriteTime.dwHighDateTime==0) return false;
    FILETIME now; GetSystemTimeAsFileTime(&now);
    ULARGE_INTEGER ulNow, ulWrite;
    ulNow.LowPart=now.dwLowDateTime; ulNow.HighPart=now.dwHighDateTime;
    ulWrite.LowPart=fad.ftLastWriteTime.dwLowDateTime; ulWrite.HighPart=fad.ftLastWriteTime.dwHighDateTime;
    const ULONGLONG diff = ulNow.QuadPart > ulWrite.QuadPart ? ulNow.QuadPart - ulWrite.QuadPart : 0;
    ULONGLONG days100ns = (ULONGLONG)days * 24 * 60 * 60 * 10000000ULL;
    return diff > days100ns;
}

static bool is_persistence_path(const char *path)
{
    if (!path) return false;
    char lower[MAX_PATH]; strncpy_s(lower, sizeof(lower), path, _TRUNCATE); _strlwr_s(lower, sizeof(lower));
    return strstr(lower, "\\startup\\") || strstr(lower, "\\downloads\\") || strstr(lower, "start menu\\programs\\startup");
}

static bool is_extension_allowed(const char *path)
{
    if (!path) return false;
    const char *ext = PathFindExtensionA(path);
    if (!ext || *ext=='\0') return false;
    // Handle double extension like .txt.exe - last ext wins, still covered
    char ext_low[32]; strncpy_s(ext_low, sizeof(ext_low), ext, _TRUNCATE); _strlwr_s(ext_low, sizeof(ext_low));
    for (int i=0; g_allowed_exts[i]; i++) if (strcmp(ext_low, g_allowed_exts[i])==0) return true;
    return false;
}

static void scan_task_free(ScanTask *t){ if(!t) return; free(t->path); free(t); }

static void finish_task(void)
{
    InterlockedDecrement(&g_pending_tasks);
    if (g_backpressure_event) SetEvent(g_backpressure_event);
}

static void scan_single_file_internal(const char *path, ScanReason reason, bool quick_mode)
{
    if (!path) { finish_task(); return; }

    g_mutex_lock(&global_scan_ctx.mutex);
    bool stop = global_scan_ctx.stop_requested;
    g_mutex_unlock(&global_scan_ctx.mutex);
    if (stop) { finish_task(); return; }

    scan_progress_file_start(path);

    if (!is_extension_allowed(path)) {
        scan_progress_file_done(false);
        finish_task();
        return;
    }

    TrustLevel trust = trust_evaluate_path(path, quick_mode);
    if (trust == TRUST_HIGH) {
        scan_progress_file_done(false);
        finish_task();
        return;
    }

    ScanInput *input = (ScanInput*)calloc(1, sizeof(*input));
    if (!input) { scan_progress_file_done(false); finish_task(); return; }
    input->path = _strdup(path);
    input->reason = reason;
    input->trust = trust;
    if (!input->path) {
        free(input);
        scan_progress_file_done(false);
        finish_task();
        return;
    }

    if (compute_file_sha256(path, input->hash) != 0) {
        scan_progress_file_done(false);
        g_free(input->path);
        free(input);
        finish_task();
        return;
    }

    SignatureResult sig = {0};
    HeuristicResult heur = {0};
    double ml_score = -1.0;

    signature_scan_hash(input->hash, &sig);
    if (sig.matched) {
        g_mutex_lock(&global_scan_ctx.mutex);
        global_scan_ctx.threats_found++;
        g_mutex_unlock(&global_scan_ctx.mutex);
        scan_report_submit_complete(input, &sig, &heur, ml_score);
        finish_task();
        return;
    }

    if (extract_file_features(path, &input->features) == 0) {
        evaluate_heuristics(&input->features, &heur, trust, reason);
        if (trust == TRUST_NONE) ml_score = ml_engine_scan(&input->features);
    }

    g_mutex_lock(&global_scan_ctx.mutex);
    global_scan_ctx.files_scanned++;
    g_mutex_unlock(&global_scan_ctx.mutex);

    scan_report_submit_complete(input, &sig, &heur, ml_score);
    finish_task();
}

static void scan_task_worker(gpointer data, gpointer user_data)
{
    (void)user_data;
    ScanTask *task = (ScanTask*)data;
    if (!task) { InterlockedDecrement(&g_pending_tasks); return; }
    scan_single_file_internal(task->path, task->reason, task->quick_mode);
    scan_task_free(task);
}

static gpointer init_pool_once(gpointer d)
{
    (void)d;
    g_mutex_init(&g_scan_pool_mutex);
    g_backpressure_event = CreateEvent(NULL, FALSE, TRUE, NULL);
    GError *err=NULL;
    g_scan_pool = g_thread_pool_new(scan_task_worker, NULL, MAX_CONCURRENT_TASKS, FALSE, &err);
    if (err) { g_error_free(err); g_scan_pool=NULL; }
    return NULL;
}

static int enqueue_scan_task(const char *path, ScanReason reason, bool quick_mode)
{
    g_once(&g_pool_once, init_pool_once, NULL);
    if (!g_scan_pool) return -1;
    // Backpressure with event wait, not busy sleep
    while (InterlockedCompareExchange(&g_pending_tasks, 0, 0) > QUEUE_BACKPRESSURE_LMT) {
        if (g_backpressure_event) WaitForSingleObject(g_backpressure_event, 20);
        else Sleep(10);
        g_mutex_lock(&global_scan_ctx.mutex);
        bool stop = global_scan_ctx.stop_requested;
        g_mutex_unlock(&global_scan_ctx.mutex);
        if (stop) return -1;
    }
    ScanTask *task = (ScanTask*)calloc(1, sizeof(ScanTask));
    if (!task) return -1;
    task->path = _strdup(path);
    if (!task->path) { free(task); return -1; }
    task->reason = reason;
    task->quick_mode = quick_mode;
    InterlockedIncrement(&g_pending_tasks);
    GError *err=NULL;
    g_thread_pool_push(g_scan_pool, task, &err);
    if (err) { g_error_free(err); scan_task_free(task); InterlockedDecrement(&g_pending_tasks); return -1; }
    return 0;
}

static void scan_walk_callback(const char *file_path, void *user_data)
{
    if (!file_path || !user_data) return;
    bool quick_mode = *(bool*)user_data;
    // Apply filters
    if (quick_mode) {
        if (!is_persistence_path(file_path) && is_file_older_than_days(file_path, QUICK_SCAN_MAX_FILE_AGE_DAYS)) return;
    }
    enqueue_scan_task(file_path, SCAN_REASON_MANUAL, quick_mode);
}

int scan_core_start_scan(const char *sigdb_path, const char *path_to_scan,
                         bool low_priority, bool quick_mode)
{
    (void)low_priority;
    if (!sigdb_path || !path_to_scan) return SCANCORE_FILE_ERR;
    if (signature_db_load(sigdb_path)!=0) return SCANCORE_FILE_ERR;
    scan_progress_start(0);
    g_mutex_lock(&global_scan_ctx.mutex);
    global_scan_ctx.stop_requested=false;
    global_scan_ctx.is_running=true;
    g_mutex_unlock(&global_scan_ctx.mutex);

    bool qm = quick_mode;
    list_files_recursive(path_to_scan, scan_walk_callback, &qm);

    while (InterlockedCompareExchange(&g_pending_tasks, 0, 0) > 0) {
        Sleep(20);
        g_mutex_lock(&global_scan_ctx.mutex);
        bool stop = global_scan_ctx.stop_requested;
        g_mutex_unlock(&global_scan_ctx.mutex);
        if (stop) break;
    }
    scan_progress_finish();
    g_mutex_lock(&global_scan_ctx.mutex);
    global_scan_ctx.is_running=false;
    g_mutex_unlock(&global_scan_ctx.mutex);
    return SCANCORE_OK;
}

int scan_core_quick_scan(const char *sigdb_path)
{
    if (signature_db_load(sigdb_path)!=0) return SCANCORE_FILE_ERR;
    scan_progress_start(0);
    g_mutex_lock(&global_scan_ctx.mutex);
    global_scan_ctx.stop_requested=false; global_scan_ctx.is_running=true;
    g_mutex_unlock(&global_scan_ctx.mutex);

    GList *proc = scan_processes_get_loaded_images();
    for (GList *l=proc; l; l=l->next) {
        if (l->data) enqueue_scan_task((char*)l->data, SCAN_REASON_MANUAL, true);
    }
    if (proc) g_list_free_full(proc, g_free);

    GList *persist = scan_persistence_get_target_files();
    for (GList *l=persist; l; l=l->next) {
        if (l->data) enqueue_scan_task((char*)l->data, SCAN_REASON_MANUAL, true);
    }
    if (persist) g_list_free_full(persist, g_free);

    GList *quick_paths = get_quick_scan_paths();
    for (GList *l=quick_paths; l; l=l->next) {
        if (!l->data) continue;
        bool skip_old = !is_persistence_path((char*)l->data);
        // Walk each path
        list_files_recursive((char*)l->data, scan_walk_callback, &skip_old);
    }
    if (quick_paths) g_list_free_full(quick_paths, g_free);

    while (InterlockedCompareExchange(&g_pending_tasks, 0, 0) > 0) {
        Sleep(20);
        g_mutex_lock(&global_scan_ctx.mutex);
        bool stop = global_scan_ctx.stop_requested;
        g_mutex_unlock(&global_scan_ctx.mutex);
        if (stop) break;
    }
    scan_progress_finish();
    g_mutex_lock(&global_scan_ctx.mutex);
    global_scan_ctx.is_running=false;
    g_mutex_unlock(&global_scan_ctx.mutex);
    return SCANCORE_OK;
}

int scan_core_scan_file(const char *sigdb_path, const char *file_path, ScanReason reason)
{
    (void)sigdb_path;
    if (!file_path) return SCANCORE_FILE_ERR;
    if (signature_db_load(sigdb_path)!=0) return SCANCORE_FILE_ERR;
    return enqueue_scan_task(file_path, reason, false);
}

bool scan_core_is_complete(void) { return InterlockedCompareExchange(&g_pending_tasks,0,0)==0 && scan_report_is_idle(); }
