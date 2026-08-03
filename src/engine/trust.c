#define _CRT_SECURE_NO_WARNINGS

#include "trust.h"

#include <ctype.h>
#include <shlobj.h>
#include <softpub.h>
#include <stdbool.h>
#include <string.h>
#include <strsafe.h>
#include <windows.h>
#include <wintrust.h>

/* ============================================================================
 * Internal Helpers: Path Matching
 * ========================================================================== */

static bool path_starts_with_w(const WCHAR *path, const WCHAR *prefix) {
  if (path == NULL || prefix == NULL)
    return false;
  while (*prefix && *path) {
    if (towlower(*path) != towlower(*prefix))
      return false;
    path++;
    prefix++;
  }
  return (*prefix == L'\0');
}

/* ============================================================================
 * Digital Signature Verification
 * ========================================================================== */

static bool verify_digital_signature(const char *path,
                                     bool *is_microsoft_signed) {
  if (is_microsoft_signed)
    *is_microsoft_signed = false;

  WCHAR w_path[MAX_PATH];
  if (!MultiByteToWideChar(CP_UTF8, 0, path, -1, w_path, MAX_PATH))
    return false;

  WINTRUST_FILE_INFO file_info = {sizeof(file_info)};
  file_info.pcwszFilePath = w_path;

  WINTRUST_DATA trust_data = {sizeof(trust_data)};
  trust_data.dwUIChoice = WTD_UI_NONE;
  trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
  trust_data.dwUnionChoice = WTD_CHOICE_FILE;
  trust_data.pFile = &file_info;
  trust_data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

  GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
  LONG status = WinVerifyTrust(NULL, &policy, &trust_data);
  if (status != ERROR_SUCCESS)
    return false;

  /* Additional check for Microsoft Origin */
  if (is_microsoft_signed) {
    PWSTR win_path = NULL;
    if (SUCCEEDED(
            SHGetKnownFolderPath(&FOLDERID_Windows, 0, NULL, &win_path))) {
      if (path_starts_with_w(w_path, win_path)) {
        *is_microsoft_signed = true;
      }
      CoTaskMemFree(win_path);
    }
  }

  return true;
}

/* ============================================================================
 * Public Functions
 * ========================================================================== */

TrustLevel trust_evaluate_path(const char *path) {
  if (path == NULL || *path == '\0')
    return TRUST_NONE;

  WCHAR w_path[MAX_PATH];
  MultiByteToWideChar(CP_UTF8, 0, path, -1, w_path, MAX_PATH);

  PWSTR win_path = NULL, prog_path = NULL, prog86_path = NULL, data_path = NULL;
  TrustLevel result = TRUST_NONE;

  // 1. Core System Locations (High Trust)
  if (SUCCEEDED(SHGetKnownFolderPath(&FOLDERID_Windows, 0, NULL, &win_path))) {
    WCHAR sys32[MAX_PATH], winsxs[MAX_PATH];
    StringCchCopyW(sys32, MAX_PATH, win_path);
    StringCchCatW(sys32, MAX_PATH, L"\\System32\\");
    StringCchCopyW(winsxs, MAX_PATH, win_path);
    StringCchCatW(winsxs, MAX_PATH, L"\\WinSxS\\");

    if (path_starts_with_w(w_path, sys32) ||
        path_starts_with_w(w_path, winsxs)) {
      result = TRUST_HIGH;
    }
    CoTaskMemFree(win_path);
    if (result == TRUST_HIGH)
      return result;
  }

  // 2. Digital Signature Verification
  bool is_microsoft = false;
  if (verify_digital_signature(path, &is_microsoft)) {
    return is_microsoft ? TRUST_HIGH : TRUST_PARTIAL;
  }

  // 3. Application Directories (Partial Trust)
  if (SUCCEEDED(
          SHGetKnownFolderPath(&FOLDERID_ProgramFiles, 0, NULL, &prog_path))) {
    if (path_starts_with_w(w_path, prog_path))
      result = TRUST_PARTIAL;
    CoTaskMemFree(prog_path);
  }
  if (result == TRUST_NONE &&
      SUCCEEDED(SHGetKnownFolderPath(&FOLDERID_ProgramFilesX86, 0, NULL,
                                     &prog86_path))) {
    if (path_starts_with_w(w_path, prog86_path))
      result = TRUST_PARTIAL;
    CoTaskMemFree(prog86_path);
  }
  if (result == TRUST_NONE &&
      SUCCEEDED(
          SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, NULL, &data_path))) {
    if (path_starts_with_w(w_path, data_path))
      result = TRUST_PARTIAL;
    CoTaskMemFree(data_path);
  }

  return result;
}

int trust_is_at_least(TrustLevel actual, TrustLevel required) {
  return (actual >= required);
}
