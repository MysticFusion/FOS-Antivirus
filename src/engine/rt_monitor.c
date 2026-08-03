#define _CRT_SECURE_NO_WARNINGS
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A000006 /* Win10 RS3: ReadDirectoryChangesExW */
#endif
#include "app_paths.h"
#include "rt_monitor.h"
#include "scan_core.h"
#include "signature_scan.h"
#include "path_utils.h"
#include <shlobj.h>
#include <shlwapi.h>
#include <stdbool.h>
#include <stdio.h>
#include <strsafe.h>
#include <time.h>
#include <wchar.h>
#include <windows.h>

#define RT_BUFFER_SIZE 65536
#define MAX_WATCHES 8
#define RT_WORKER_COUNT 4
#define BURST_WINDOW_SEC 2
#define BURST_THRESHOLD 5
#define LOG_DEDUP_INTERVAL_SEC 1
#define RESCAN_THROTTLE_SEC 10

/* R-04: multi-directory watcher (overlapped I/O + I/O completion port).
 * Watched directories: Profile, Windows, ProgramFiles, ProgramFilesX86,
 * ProgramData. Directories that cannot be opened (e.g. no permission) are
 * skipped with a log entry and monitoring continues on the rest. */
typedef struct {
    HANDLE dir_handle;
    OVERLAPPED overlapped;
    BYTE buffer[RT_BUFFER_SIZE];
    wchar_t root_path[FOS_MAX_PATH];
    volatile LONG active;
    volatile LONG rescan_pending;
} watch_handle_t;

static watch_handle_t g_watches[MAX_WATCHES];
static int g_num_watches = 0;
static HANDLE g_iocp = NULL;
static HANDLE g_worker_threads[RT_WORKER_COUNT] = {0};
static volatile LONG g_rt_running = 0;
static char g_sigdb_path[MAX_PATH] = {0};
static CRITICAL_SECTION g_rt_lock;
static INIT_ONCE g_rt_once = INIT_ONCE_STATIC_INIT;
static BOOL CALLBACK init_rt_lock(PINIT_ONCE o, PVOID p, PVOID *c){ (void)o;(void)p;(void)c; InitializeCriticalSection(&g_rt_lock); return TRUE; }
static void ensure_lock(){ InitOnceExecuteOnce(&g_rt_once, init_rt_lock, NULL, NULL); }

static time_t g_burst_timestamps[BURST_THRESHOLD] = {0};
static int g_burst_head = 0;
static char g_last_log_path[FOS_MAX_PATH * 4] = {0};
static time_t g_last_log_time = 0;

static void rt_log_event(const char *message) {
  if (!message) return;
  const char *log_path = app_path_heuristics_log();
  if (!log_path) return;
  FILE *f = NULL;
  if (fopen_s(&f, log_path, "a")!=0 || !f) return;
  time_t now = time(NULL);
  char ts[64];
  struct tm tm_now; localtime_s(&tm_now, &now);
  strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm_now);
  fprintf(f, "[%s] RT-MONITOR=%s\n", ts, message);
  fclose(f);
}

static bool is_interesting_file(const wchar_t *path) {
  if (!path) return false;
  const wchar_t *ext = PathFindExtensionW(path);
  if (!ext || *ext == L'\0') return false;
  return (_wcsicmp(ext, L".exe") == 0 || _wcsicmp(ext, L".dll") == 0 ||
          _wcsicmp(ext, L".sys") == 0 || _wcsicmp(ext, L".scr") == 0 ||
          _wcsicmp(ext, L".js") == 0 || _wcsicmp(ext, L".vbs") == 0);
}

static bool wide_to_utf8(const wchar_t *w, char *out, size_t out_sz) {
  if (!w || !out || out_sz==0) return false;
  return WideCharToMultiByte(CP_UTF8, 0, w, -1, out, (int)out_sz, NULL, NULL) > 0;
}

/* Full rescan of one watched root (buffer overflow / watch I/O failure). */
static DWORD WINAPI rt_rescan_proc(LPVOID param) {
  watch_handle_t *w = (watch_handle_t *)param;
  char utf8_root[FOS_MAX_PATH * 4];
  if (wide_to_utf8(w->root_path, utf8_root, sizeof(utf8_root))) {
    printf("[RT-MONITOR] Full rescan: %s\n", utf8_root);
    scan_core_start_scan(g_sigdb_path, utf8_root, true, false);
  }
  InterlockedExchange(&w->rescan_pending, 0);
  return 0;
}

static void trigger_rescan(watch_handle_t *w) {
  if (!w || !InterlockedCompareExchange(&g_rt_running, 0, 0)) return;
  if (InterlockedCompareExchange(&w->rescan_pending, 1, 0) != 0) return;
  HANDLE h = CreateThread(NULL, 0, rt_rescan_proc, w, 0, NULL);
  if (h) CloseHandle(h);
  else InterlockedExchange(&w->rescan_pending, 0);
}

static void issue_read(watch_handle_t *w) {
  if (!w || !w->active || !InterlockedCompareExchange(&g_rt_running, 0, 0)) return;
  memset(&w->overlapped, 0, sizeof(w->overlapped));
  if (!ReadDirectoryChangesExW(w->dir_handle, w->buffer, sizeof(w->buffer), TRUE,
                               FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE |
                                   FILE_NOTIFY_CHANGE_LAST_WRITE,
                               NULL, &w->overlapped, NULL,
                               ReadDirectoryNotifyExtendedInformation)) {
    rt_log_event("ReadDirectoryChangesExW failed; scheduling rescan");
    trigger_rescan(w);
  }
}

static void process_events(watch_handle_t *w, DWORD bytes) {
  if (bytes == 0) {
    rt_log_event("directory change buffer overflow; full rescan scheduled");
    trigger_rescan(w);
    return;
  }

  FILE_NOTIFY_EXTENDED_INFORMATION *fni = (FILE_NOTIFY_EXTENDED_INFORMATION *)w->buffer;
  for (;;) {
    wchar_t rel_path[FOS_MAX_PATH];
    wchar_t full_path[FOS_MAX_PATH];
    int char_count = (int)(fni->FileNameLength / sizeof(wchar_t));
    if (char_count >= FOS_MAX_PATH) char_count = FOS_MAX_PATH - 1;
    memcpy(rel_path, fni->FileName, (size_t)char_count * sizeof(wchar_t));
    rel_path[char_count] = L'\0';
    if (PathCombineW(full_path, w->root_path, rel_path) == NULL) goto next_entry;

    if (fni->Action == FILE_ACTION_ADDED || fni->Action == FILE_ACTION_MODIFIED ||
        fni->Action == FILE_ACTION_RENAMED_NEW_NAME) {
      if (is_interesting_file(full_path)) {
        char utf8_path[FOS_MAX_PATH * 4];
        wide_to_utf8(full_path, utf8_path, sizeof(utf8_path));
        if (fni->Action == FILE_ACTION_ADDED) {
          WIN32_FILE_ATTRIBUTE_DATA attrs;
          if (GetFileAttributesExW(full_path, GetFileExInfoStandard, &attrs)) {
            if (attrs.nFileSizeLow == 0 && attrs.nFileSizeHigh == 0) goto next_entry;
            if (attrs.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) goto next_entry;
          }
        }
        ScanReason reason = SCAN_REASON_RT_MODIFY;
        time_t now = time(NULL);
        if (fni->Action == FILE_ACTION_ADDED || fni->Action == FILE_ACTION_RENAMED_NEW_NAME) {
          ensure_lock();
          EnterCriticalSection(&g_rt_lock);
          g_burst_timestamps[g_burst_head] = now;
          g_burst_head = (g_burst_head + 1) % BURST_THRESHOLD;
          time_t oldest = g_burst_timestamps[g_burst_head];
          LeaveCriticalSection(&g_rt_lock);
          if (oldest > 0 && (now - oldest) <= BURST_WINDOW_SEC) {
            reason = SCAN_REASON_RANSOMWARE_BURST;
            printf("[RT-MONITOR] !!! RANSOMWARE BURST DETECTED: %s !!!\n", utf8_path);
          } else {
            reason = SCAN_REASON_RT_CREATE;
          }
        }
        ensure_lock();
        EnterCriticalSection(&g_rt_lock);
        bool should_scan = (strcmp(utf8_path, g_last_log_path) != 0 ||
                            (now - g_last_log_time) > LOG_DEDUP_INTERVAL_SEC);
        if (should_scan) {
          strncpy_s(g_last_log_path, sizeof(g_last_log_path), utf8_path, _TRUNCATE);
          g_last_log_time = now;
        }
        LeaveCriticalSection(&g_rt_lock);
        if (should_scan) {
          scan_core_scan_file_wide(g_sigdb_path, full_path, reason);
        }
      }
    }
next_entry:
    if (fni->NextEntryOffset == 0) break;
    fni = (FILE_NOTIFY_EXTENDED_INFORMATION *)((BYTE *)fni + fni->NextEntryOffset);
  }
}

static DWORD WINAPI rt_worker_proc(LPVOID param) {
  (void)param;
  while (InterlockedCompareExchange(&g_rt_running, 0, 0)) {
    DWORD bytes = 0;
    ULONG_PTR key = 0;
    OVERLAPPED *ov = NULL;
    if (!GetQueuedCompletionStatus(g_iocp, &bytes, &key, &ov, 2000)) {
      if (ov == NULL) continue; /* timeout — loop re-checks running flag */
      /* Failed I/O on a watch (e.g. handle closed during shutdown). */
      if (!InterlockedCompareExchange(&g_rt_running, 0, 0)) break;
      watch_handle_t *w = (watch_handle_t *)key;
      rt_log_event("directory watch I/O failed; scheduling rescan");
      trigger_rescan(w);
      continue;
    }
    if (key == 0 && ov == NULL) break; /* shutdown marker */
    watch_handle_t *w = (watch_handle_t *)key;
    process_events(w, bytes);
    issue_read(w);
  }
  return 0;
}

static DWORD WINAPI rt_startup_scan_proc(LPVOID param) {
  (void)param;
  char utf8_root[FOS_MAX_PATH * 4];
  if (g_num_watches > 0) {
    wide_to_utf8(g_watches[0].root_path, utf8_root, sizeof(utf8_root));
    printf("[RT-MONITOR] Starting background scan: %s\n", utf8_root);
    scan_core_start_scan(g_sigdb_path, utf8_root, true, false);
  }
  return 0;
}

int rt_monitor_start(const char *sigdb_path) {
  ensure_lock();
  if (InterlockedCompareExchange(&g_rt_running, 0, 0)) return 0;
  if (!sigdb_path) return -1;
  StringCchCopyA(g_sigdb_path, MAX_PATH, sigdb_path);

  static const KNOWNFOLDERID *k_watch_folders[] = {
      &FOLDERID_Profile, &FOLDERID_Windows, &FOLDERID_ProgramFiles,
      &FOLDERID_ProgramFilesX86, &FOLDERID_ProgramData,
  };

  g_iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, RT_WORKER_COUNT);
  if (!g_iocp) return -1;

  InterlockedExchange(&g_rt_running, 1);
  g_num_watches = 0;
  for (size_t i = 0; i < sizeof(k_watch_folders) / sizeof(k_watch_folders[0]) && g_num_watches < MAX_WATCHES; i++) {
    PWSTR folder_path = NULL;
    if (FAILED(SHGetKnownFolderPath(k_watch_folders[i], 0, NULL, &folder_path))) continue;
    watch_handle_t *w = &g_watches[g_num_watches];
    memset(w, 0, sizeof(*w));
    wcsncpy_s(w->root_path, FOS_MAX_PATH, folder_path, _TRUNCATE);
    CoTaskMemFree(folder_path);

    w->dir_handle = CreateFileW(w->root_path, FILE_LIST_DIRECTORY,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                NULL, OPEN_EXISTING,
                                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);
    if (w->dir_handle == INVALID_HANDLE_VALUE) {
      rt_log_event("watch setup denied (access denied?) — skipping directory");
      continue;
    }
    if (!CreateIoCompletionPort(w->dir_handle, g_iocp, (ULONG_PTR)w, 0)) {
      CloseHandle(w->dir_handle);
      w->dir_handle = INVALID_HANDLE_VALUE;
      rt_log_event("CreateIoCompletionPort failed — skipping directory");
      continue;
    }
    InterlockedExchange(&w->active, 1);
    g_num_watches++;
    printf("[RT-MONITOR] Watching: %ls\n", w->root_path);
  }

  if (g_num_watches == 0) {
    InterlockedExchange(&g_rt_running, 0);
    CloseHandle(g_iocp);
    g_iocp = NULL;
    return -1;
  }

  for (int i = 0; i < RT_WORKER_COUNT; i++) {
    g_worker_threads[i] = CreateThread(NULL, 0, rt_worker_proc, NULL, 0, NULL);
    if (!g_worker_threads[i]) g_worker_threads[i] = NULL;
  }
  for (int i = 0; i < g_num_watches; i++) issue_read(&g_watches[i]);

  HANDLE h_startup = CreateThread(NULL, 0, rt_startup_scan_proc, NULL, 0, NULL);
  if (h_startup) CloseHandle(h_startup);
  return 0;
}

void rt_monitor_stop(void) {
  ensure_lock();
  if (!InterlockedCompareExchange(&g_rt_running, 0, 0)) return;
  InterlockedExchange(&g_rt_running, 0);

  /* Wake all workers with shutdown markers. */
  for (int i = 0; i < RT_WORKER_COUNT; i++)
    PostQueuedCompletionStatus(g_iocp, 0, 0, NULL);
  for (int i = 0; i < RT_WORKER_COUNT; i++) {
    if (g_worker_threads[i]) {
      WaitForSingleObject(g_worker_threads[i], 2000);
      CloseHandle(g_worker_threads[i]);
      g_worker_threads[i] = NULL;
    }
  }

  for (int i = 0; i < g_num_watches; i++) {
    watch_handle_t *w = &g_watches[i];
    InterlockedExchange(&w->active, 0);
    if (w->dir_handle != INVALID_HANDLE_VALUE) {
      CancelIoEx(w->dir_handle, NULL);
      CloseHandle(w->dir_handle);
      w->dir_handle = INVALID_HANDLE_VALUE;
    }
  }
  g_num_watches = 0;

  if (g_iocp) {
    CloseHandle(g_iocp);
    g_iocp = NULL;
  }
}
