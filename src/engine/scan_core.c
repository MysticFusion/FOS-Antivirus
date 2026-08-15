/**
 * @file scan_core.c - HARDENED
 * Fixes: threadpool race, backpressure busy-wait, TOCTOU, whitelist bypass, atomic counters
 */
#define _CRT_SECURE_NO_WARNINGS
#include "scan_core.h"
#include "amsi_scan.h"
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
#include "path_utils.h"
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
#define HEUR_DOUBLE_EXT_SCORE 15 /* MAP-10: invoice.pdf.exe social engineering */

typedef struct { char *path; ScanReason reason; bool quick_mode; } ScanTask;

/* MAP-08: explicit filter options for the directory-walk callback. The old
 * code reused a `bool` named `quick_mode` at the call site and
 * `skip_old` semantics in the callback, which was a latent correctness
 * hazard (any "rename to match" commit would invert the age filter). */
typedef struct {
    bool apply_age_filter; /* true  -> skip files older than max_age_days
                            *         (persistence paths are always exempt) */
    int  max_age_days;     /* age threshold in days, when the filter is on  */
} WalkFilter;

static GThreadPool *g_scan_pool = NULL;
static GMutex g_scan_pool_mutex;
static GOnce g_pool_once = G_ONCE_INIT;
volatile LONG g_pending_tasks = 0;
static HANDLE g_backpressure_event = NULL;

static const char *g_allowed_exts[] = {".exe",".dll",".sys",".scr",".cpl",".ocx",".drv",".com",".bat",".cmd",".ps1",".vbs",".vbe",".js",".jse",".hta",".wsf",".wsh",".msi",".msp",".docm",".xlsm",".pptm",NULL};

static bool is_file_older_than_days_wide(const wchar_t *path, int days)
{
    if (!path || days<=0) return false;
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExW(path, GetFileExInfoStandard, &fad)) return false;
    if (fad.ftLastWriteTime.dwLowDateTime==0 && fad.ftLastWriteTime.dwHighDateTime==0) return false;
    FILETIME now; GetSystemTimeAsFileTime(&now);
    ULARGE_INTEGER ulNow, ulWrite;
    ulNow.LowPart=now.dwLowDateTime; ulNow.HighPart=now.dwHighDateTime;
    ulWrite.LowPart=fad.ftLastWriteTime.dwLowDateTime; ulWrite.HighPart=fad.ftLastWriteTime.dwHighDateTime;
    const ULONGLONG diff = ulNow.QuadPart > ulWrite.QuadPart ? ulNow.QuadPart - ulWrite.QuadPart : 0;
    ULONGLONG days100ns = (ULONGLONG)days * 24 * 60 * 60 * 10000000ULL;
    return diff > days100ns;
}

static bool is_file_older_than_days(const char *path, int days)
{
    if (!path || days<=0) return false;
    fos_path_t fp;
    if (!fos_path_init(&fp, path)) return false;
    return is_file_older_than_days_wide(fp.wide, days);
}

static bool is_persistence_path(const char *path)
{
    if (!path) return false;
    /* MAP-07: wide-char search so paths > MAX_PATH (260) are not truncated
     * away before the persistence markers are located. */
    wchar_t wide[FOS_MAX_PATH];
    if (MultiByteToWideChar(CP_UTF8, 0, path, -1, wide, FOS_MAX_PATH) <= 0) return false;
    return StrStrIW(wide, L"\\startup\\") != NULL ||
           StrStrIW(wide, L"\\downloads\\") != NULL ||
           StrStrIW(wide, L"start menu\\programs\\startup") != NULL;
}

/* MAP-10: detect the classic social-engineering double extension
 * ("invoice.pdf.exe"). Returns true when the terminal extension is preceded
 * by a document-type extension (pdf/docx/xlsx/jpg/txt/...). */
static bool has_suspicious_double_ext(const char *path)
{
    if (!path) return false;
    const char *last = PathFindExtensionA(path);
    if (!last || *last == '\0') return false;

    /* Walk backwards from the terminal extension to the previous '.'. */
    const char *p = last - 1;
    while (p > path && *p != '.') p--;
    if (*p != '.') return false;           /* single extension only */
    if (p == path) return false;

    size_t inner_len = (size_t)(last - p); /* includes the leading '.' */
    if (inner_len >= 16) return false;

    static const char *k_doc_exts[] = {
        ".pdf", ".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt",
        ".jpg", ".jpeg", ".png", ".gif", ".txt", ".rtf", ".csv", NULL
    };
    char inner[16];
    strncpy_s(inner, sizeof(inner), p, _TRUNCATE);
    _strlwr_s(inner, sizeof(inner));
    for (int i = 0; k_doc_exts[i] != NULL; i++) {
        if (strcmp(inner, k_doc_exts[i]) == 0) return true;
    }
    return false;
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

/* U-10: script-type content that registered AMSI providers (Defender's
 * script engine, etc.) can evaluate far better than static heuristics. */
static bool is_script_path(const char *path)
{
    if (!path) return false;
    const char *ext = PathFindExtensionA(path);
    if (!ext || *ext == '\0') return false;
    static const char *k_script_exts[] = {
        ".js", ".jse", ".vbs", ".vbe", ".ps1", ".bat", ".cmd",
        ".hta", ".wsf", ".wsh", ".py", NULL
    };
    char ext_low[16]; strncpy_s(ext_low, sizeof(ext_low), ext, _TRUNCATE); _strlwr_s(ext_low, sizeof(ext_low));
    for (int i = 0; k_script_exts[i]; i++)
        if (strcmp(ext_low, k_script_exts[i]) == 0) return true;
    return false;
}

/* U-10: submit script content to the platform's AMSI providers. A provider
 * DETECTION is treated like the strongest static signal: the file is scored
 * malicious. The decision engine still applies trust dampening, so signed
 * detections are monitored rather than quarantined. */
static void apply_amsi_verdict(const fos_path_t *fp, const char *utf8_path,
                               HeuristicResult *heur)
{
    if (amsi_scan_file_wide(fp, NULL) != AMSI_SCAN_MALWARE) return;

    heur->score = 100;
    heur->verdict = VERDICT_MALICIOUS;
    size_t used = strlen(heur->explanation);
    if (used < sizeof(heur->explanation) - 1) {
        strncat(heur->explanation, " AMSI-malicious;",
                sizeof(heur->explanation) - used - 1);
    }
    (void)utf8_path;
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

    fos_path_t fp;
    if (!fos_path_init(&fp, path)) {
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

    if (compute_file_sha256_wide(&fp, input->hash) != 0) {
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
        global_scan_ctx.files_scanned++;
        g_mutex_unlock(&global_scan_ctx.mutex);
        scan_report_submit_complete(input, &sig, &heur, ml_score);
        finish_task();
        return;
    }

    if (extract_file_features_wide(&fp, &input->features) == 0) {
        evaluate_heuristics(&input->features, &heur, trust, reason);
        if (trust == TRUST_NONE) ml_score = ml_engine_scan(&input->features);
    }

    /* U-10: script files go through the platform's AMSI providers. */
    if (is_script_path(path)) {
        apply_amsi_verdict(&fp, path, &heur);
    }

    /* MAP-10: double-extension files (invoice.pdf.exe) get an additive
     * risk score; re-derive the verdict against the shared thresholds from
     * heuristic_engine.h. */
    if (has_suspicious_double_ext(path)) {
        heur.score += HEUR_DOUBLE_EXT_SCORE;
        if (heur.score >= HEURISTIC_SCORE_MALICIOUS) {
            heur.verdict = VERDICT_MALICIOUS;
        } else if (heur.score >= HEURISTIC_SCORE_SUSPICIOUS) {
            heur.verdict = VERDICT_SUSPICIOUS;
        }
        size_t used = strlen(heur.explanation);
        if (used < sizeof(heur.explanation) - 1) {
            strncat(heur.explanation, " Double-extension;",
                    sizeof(heur.explanation) - used - 1);
        }
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
    /* MAP-08: explicit WalkFilter semantics, no more bool-overloading. */
    WalkFilter *filter = (WalkFilter*)user_data;
    /* Apply filters: the age filter is opt-in per walk root, and
     * persistence paths (Startup/Downloads) are always exempt because
     * persistence is time-independent. */
    if (filter->apply_age_filter) {
        if (!is_persistence_path(file_path) &&
            is_file_older_than_days(file_path, filter->max_age_days)) return;
    }
    enqueue_scan_task(file_path, SCAN_REASON_MANUAL, filter->apply_age_filter);
}

/* MAP-01/MAP-09: advisory signature-DB availability flag. */
void scan_core_set_db_available(bool ok)
{
    g_mutex_lock(&global_scan_ctx.mutex);
    global_scan_ctx.db_available = ok;
    g_mutex_unlock(&global_scan_ctx.mutex);
}

bool scan_core_db_available(void)
{
    g_mutex_lock(&global_scan_ctx.mutex);
    bool ok = global_scan_ctx.db_available;
    g_mutex_unlock(&global_scan_ctx.mutex);
    return ok;
}

int scan_core_start_scan(const char *sigdb_path, const char *path_to_scan,
                         bool low_priority, bool quick_mode)
{
    (void)low_priority;
    if (!sigdb_path || !path_to_scan) return SCANCORE_FILE_ERR;

    /* MAP-01: ALWAYS start progress FIRST, before any DB work, so the
     * progress subsystem can never report "not running" while a scan is
     * actually being dispatched. */
    scan_progress_start(0);

    /* MAP-01/MAP-09: the signature DB load is advisory. A missing or
     * invalid DB disables only the signature layer; enumeration, heuristic
     * and ML analysis still run and the UI surfaces a warning. */
    bool db_ok = (signature_db_load(sigdb_path) == 0);

    g_mutex_lock(&global_scan_ctx.mutex);
    global_scan_ctx.stop_requested=false;
    global_scan_ctx.is_running=true;
    global_scan_ctx.db_available=db_ok;
    g_mutex_unlock(&global_scan_ctx.mutex);

    WalkFilter wf;
    wf.apply_age_filter = quick_mode;
    wf.max_age_days     = QUICK_SCAN_MAX_FILE_AGE_DAYS;
    list_files_recursive(path_to_scan, scan_walk_callback, &wf);

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
    if (!sigdb_path) return SCANCORE_FILE_ERR;

    /* MAP-01: progress first; DB load advisory (see scan_core_start_scan). */
    scan_progress_start(0);
    bool db_ok = (signature_db_load(sigdb_path) == 0);

    g_mutex_lock(&global_scan_ctx.mutex);
    global_scan_ctx.stop_requested=false; global_scan_ctx.is_running=true;
    global_scan_ctx.db_available=db_ok;
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
        /* MAP-08: explicit WalkFilter. Persistence roots (Startup,
         * Downloads) are exempt from the age filter; everything else
         * skips files older than 30 days. */
        WalkFilter wf;
        wf.apply_age_filter = !is_persistence_path((char*)l->data);
        wf.max_age_days     = QUICK_SCAN_MAX_FILE_AGE_DAYS;
        // Walk each path
        list_files_recursive((char*)l->data, scan_walk_callback, &wf);
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
    /* Advisory (MAP-01/09): single-file scans proceed in heuristic-only
     * mode when the DB is absent; the RT monitor never silently drops a
     * file because definitions are missing. */
    scan_core_set_db_available(signature_db_load(sigdb_path) == 0);
    return enqueue_scan_task(file_path, reason, false);
}

int scan_core_scan_file_wide(const char *sigdb_path, const wchar_t *file_path, ScanReason reason)
{
    (void)sigdb_path;
    if (!file_path) return SCANCORE_FILE_ERR;
    scan_core_set_db_available(signature_db_load(sigdb_path) == 0); /* advisory */

    /* Wide -> UTF-8 once (the scan pipeline is char-based up to the per-file
     * fos_path_t conversion). Uses a full FOS_MAX_PATH buffer so deep paths
     * are not truncated like the old MAX_PATH round-trip. */
    char utf8_path[FOS_MAX_PATH * 4];
    fos_path_t fp;
    if (!fos_path_init_w(&fp, file_path)) return SCANCORE_FILE_ERR;
    if (fos_path_to_utf8(&fp, utf8_path, sizeof(utf8_path)) != 0) return SCANCORE_FILE_ERR;
    return enqueue_scan_task(utf8_path, reason, false);
}

bool scan_core_is_complete(void) { return InterlockedCompareExchange(&g_pending_tasks,0,0)==0 && scan_report_is_idle(); }
