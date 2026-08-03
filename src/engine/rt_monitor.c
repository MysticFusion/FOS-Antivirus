#define _CRT_SECURE_NO_WARNINGS
#include "app_paths.h"
#include "rt_monitor.h"
#include "scan_core.h"
#include "signature_scan.h"
#include <shlobj.h>
#include <shlwapi.h>
#include <stdbool.h>
#include <stdio.h>
#include <strsafe.h>
#include <time.h>
#include <wchar.h>
#include <windows.h>
#pragma comment(lib, "shlwapi.lib")

#define RT_BUFFER_SIZE 65536
#define MAX_PATH_W 1024
#define BURST_WINDOW_SEC 2
#define BURST_THRESHOLD 5
#define LOG_DEDUP_INTERVAL_SEC 1

static HANDLE g_rt_thread = NULL;
static HANDLE g_dir_handle = NULL;
static volatile LONG g_rt_running = 0;
static char g_sigdb_path[MAX_PATH] = {0};
static WCHAR g_watch_root[MAX_PATH] = {0};
static CRITICAL_SECTION g_rt_lock;
static INIT_ONCE g_rt_once = INIT_ONCE_STATIC_INIT;
static BOOL CALLBACK init_rt_lock(PINIT_ONCE o, PVOID p, PVOID *c){ (void)o;(void)p;(void)c; InitializeCriticalSection(&g_rt_lock); return TRUE; }
static void ensure_lock(){ InitOnceExecuteOnce(&g_rt_once, init_rt_lock, NULL, NULL); }

static time_t g_burst_timestamps[BURST_THRESHOLD] = {0};
static int g_burst_head = 0;
static char g_last_log_path[MAX_PATH] = {0};
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

static DWORD WINAPI rt_thread_proc(LPVOID param) {
  (void)param;
  BYTE buffer[RT_BUFFER_SIZE];
  DWORD bytes;
  printf("[RT-MONITOR] Background Monitor Started on root: %ls\n", g_watch_root);

  while (InterlockedCompareExchange(&g_rt_running,0,0)) {
    if (!ReadDirectoryChangesW(g_dir_handle, buffer, sizeof(buffer), TRUE,
                               FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE,
                               &bytes, NULL, NULL)) {
      if (!InterlockedCompareExchange(&g_rt_running,0,0) || GetLastError() == ERROR_OPERATION_ABORTED) break;
      rt_log_event("ReadDirectoryChangesW failed; backing off");
      Sleep(1000);
      continue;
    }
    if (bytes == 0) {
      rt_log_event("directory change buffer overflow or empty event batch");
      Sleep(500);
      continue;
    }
    FILE_NOTIFY_INFORMATION *fni = (FILE_NOTIFY_INFORMATION *)buffer;
    while (fni) {
      wchar_t rel_path[MAX_PATH]; wchar_t full_path[MAX_PATH];
      int char_count = fni->FileNameLength / sizeof(wchar_t);
      if (char_count >= MAX_PATH) char_count = MAX_PATH-1;
      wcsncpy_s(rel_path, MAX_PATH, fni->FileName, char_count);
      rel_path[char_count] = L'\0';
      if (PathCombineW(full_path, g_watch_root, rel_path)==NULL) goto next_entry;

      if (fni->Action == FILE_ACTION_ADDED || fni->Action == FILE_ACTION_MODIFIED || fni->Action == FILE_ACTION_RENAMED_NEW_NAME) {
        if (is_interesting_file(full_path)) {
          char utf8_path[MAX_PATH];
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
          bool should_scan = (strcmp(utf8_path, g_last_log_path) != 0 || (now - g_last_log_time) > LOG_DEDUP_INTERVAL_SEC);
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
      fni = (FILE_NOTIFY_INFORMATION *)((BYTE *)fni + fni->NextEntryOffset);
    }
  }
  return 0;
}

static DWORD WINAPI rt_startup_scan_proc(LPVOID param) {
  (void)param;
  char utf8_root[MAX_PATH];
  wide_to_utf8(g_watch_root, utf8_root, MAX_PATH);
  printf("[RT-MONITOR] Starting background scan: %s\n", utf8_root);
  scan_core_start_scan(g_sigdb_path, utf8_root, true, false);
  return 0;
}

int rt_monitor_start(const char *sigdb_path) {
  ensure_lock();
  if (InterlockedCompareExchange(&g_rt_running,0,0)) return 0;
  if (!sigdb_path) return -1;
  StringCchCopyA(g_sigdb_path, MAX_PATH, sigdb_path);
  PWSTR profile_path = NULL;
  if (FAILED(SHGetKnownFolderPath(&FOLDERID_Profile, 0, NULL, &profile_path))) return -1;
  wcsncpy_s(g_watch_root, MAX_PATH, profile_path, _TRUNCATE);
  CoTaskMemFree(profile_path);
  g_dir_handle = CreateFileW(g_watch_root, FILE_LIST_DIRECTORY, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
  if (g_dir_handle == INVALID_HANDLE_VALUE) return -1;
  InterlockedExchange(&g_rt_running, 1);
  g_rt_thread = CreateThread(NULL, 0, rt_thread_proc, NULL, 0, NULL);
  if (!g_rt_thread) {
    InterlockedExchange(&g_rt_running, 0);
    CloseHandle(g_dir_handle); g_dir_handle=INVALID_HANDLE_VALUE;
    return -1;
  }
  HANDLE h_startup = CreateThread(NULL, 0, rt_startup_scan_proc, NULL, 0, NULL);
  if (h_startup) CloseHandle(h_startup);
  return 0;
}

void rt_monitor_stop(void) {
  if (!InterlockedCompareExchange(&g_rt_running,0,0)) return;
  InterlockedExchange(&g_rt_running, 0);
  if (g_dir_handle != INVALID_HANDLE_VALUE) {
    CancelIoEx(g_dir_handle, NULL);
    CloseHandle(g_dir_handle);
    g_dir_handle = INVALID_HANDLE_VALUE;
  }
  if (g_rt_thread) {
    WaitForSingleObject(g_rt_thread, 2000);
    CloseHandle(g_rt_thread);
    g_rt_thread = NULL;
  }
}
