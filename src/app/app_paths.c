#define _CRT_SECURE_NO_WARNINGS

#include "app_paths.h"

#include <shlobj.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>

#ifdef _WIN32
#include <io.h>
#define F_OK 0
#define access _access
#endif

static bool g_initialized = false;
static char g_app_dir[MAX_PATH] = {0};
static char g_signature_db[MAX_PATH] = {0};
static char g_history_log[MAX_PATH] = {0};
static char g_heuristics_log[MAX_PATH] = {0};
static char g_quarantine_dir[MAX_PATH] = {0};
static char g_model_path[MAX_PATH] = {0};

static void join_path(char *out, size_t out_sz, const char *base,
                      const char *leaf) {
  snprintf(out, out_sz, "%s\\%s", base, leaf);
}

static bool file_exists(const char *path) {
  return path != NULL && access(path, F_OK) == 0;
}

static void resolve_model_path(void) {
  char exe_path[MAX_PATH] = {0};
  GetModuleFileNameA(NULL, exe_path, MAX_PATH);
  char *last_slash = strrchr(exe_path, '\\');
  if (last_slash)
    *last_slash = '\0';

  char candidate[MAX_PATH] = {0};
  join_path(candidate, sizeof(candidate), exe_path, "ml\\models\\forest.bin");
  if (file_exists(candidate)) {
    strncpy(g_model_path, candidate, sizeof(g_model_path) - 1);
    return;
  }

  join_path(candidate, sizeof(candidate), exe_path,
            "..\\assets\\models\\forest.bin");
  if (file_exists(candidate)) {
    strncpy(g_model_path, candidate, sizeof(g_model_path) - 1);
    return;
  }

  strncpy(g_model_path, "assets\\models\\forest.bin", sizeof(g_model_path) - 1);
}

int app_paths_init(void) {
  if (g_initialized)
    return 0;

  PWSTR appdata = NULL;
  if (SUCCEEDED(
          SHGetKnownFolderPath(&FOLDERID_RoamingAppData, 0, NULL, &appdata))) {
    char appdata_utf8[MAX_PATH] = {0};
    WideCharToMultiByte(CP_UTF8, 0, appdata, -1, appdata_utf8, MAX_PATH, NULL,
                        NULL);
    CoTaskMemFree(appdata);
    join_path(g_app_dir, sizeof(g_app_dir), appdata_utf8, "FOS-Antivirus");
  } else {
    strncpy(g_app_dir, "FOS-Antivirus", sizeof(g_app_dir) - 1);
  }

  CreateDirectoryA(g_app_dir, NULL);

  char candidate_db[MAX_PATH] = {0};
  join_path(candidate_db, sizeof(candidate_db), g_app_dir, "malware_hashes.db");
  if (file_exists(candidate_db)) {
    strncpy(g_signature_db, candidate_db, sizeof(g_signature_db) - 1);
  } else {
    join_path(candidate_db, sizeof(candidate_db), g_app_dir, "signatures.db");
    if (file_exists(candidate_db)) {
      strncpy(g_signature_db, candidate_db, sizeof(g_signature_db) - 1);
    } else {
      join_path(candidate_db, sizeof(candidate_db), "signatures", "malware_hashes.db");
      if (file_exists(candidate_db)) {
        strncpy(g_signature_db, candidate_db, sizeof(g_signature_db) - 1);
      } else {
        join_path(g_signature_db, sizeof(g_signature_db), g_app_dir, "signatures.db");
      }
    }
  }

  join_path(g_history_log, sizeof(g_history_log), g_app_dir, "history.log");
  join_path(g_heuristics_log, sizeof(g_heuristics_log), g_app_dir,
            "heuristics.log");
  join_path(g_quarantine_dir, sizeof(g_quarantine_dir), g_app_dir,
            "Quarantine");
  CreateDirectoryA(g_quarantine_dir, NULL);

  resolve_model_path();
  g_initialized = true;
  return 0;
}

const char *app_path_signature_db(void) {
  app_paths_init();
  return g_signature_db;
}

const char *app_path_history_log(void) {
  app_paths_init();
  return g_history_log;
}

const char *app_path_heuristics_log(void) {
  app_paths_init();
  return g_heuristics_log;
}

const char *app_path_quarantine_dir(void) {
  app_paths_init();
  return g_quarantine_dir;
}

const char *app_path_model(void) {
  app_paths_init();
  return g_model_path;
}
