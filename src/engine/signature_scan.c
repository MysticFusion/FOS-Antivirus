#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#define _CRT_SECURE_NO_WARNINGS

#include "signature_scan.h"
#include "hash_util.h"

#include <errno.h>
#include <objbase.h>
#include <shldisp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <urlmon.h>
#include <windows.h>

/* ============================================================================
 * Configuration Constants
 * ========================================================================== */

#define GENERIC_THREAT_LABEL "MalwareBazaar.Threat"
#define BAZAAR_EXPORT_URL "https://bazaar.abuse.ch/export/txt/sha256/full/"
#define HASH_TABLE_SIZE 65536

/* ============================================================================
 * Global State
 * ========================================================================== */

volatile int update_progress = 0;
static SigHashTable *g_sig_table = NULL;
static SRWLOCK g_db_lock = SRWLOCK_INIT;
static bool g_db_loaded = false;

/* ============================================================================
 * Internal Helpers: Hex Processing
 * ========================================================================== */

static int hex_char_to_nibble(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return 10 + (c - 'a');
  if (c >= 'A' && c <= 'F')
    return 10 + (c - 'A');
  return -1;
}

static int hex_string_to_bytes(const char *hex,
                               unsigned char out[SHA256_SIZE]) {
  for (int i = 0; i < SHA256_SIZE; ++i) {
    int hi = hex_char_to_nibble(hex[i * 2]);
    int lo = hex_char_to_nibble(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0) {
      return -1;
    }
    out[i] = (unsigned char)((hi << 4) | lo);
  }
  return 0;
}

/* ============================================================================
 * Native ZIP Extraction (COM Shell.Application)
 * ========================================================================== */

static HRESULT unzip_db_native(const char *zip_path, const char *dest_folder) {
  HRESULT hr;
  IShellDispatch *pShell = NULL;
  Folder *pZipFile = NULL;
  Folder *pDestFolder = NULL;
  FolderItems *pItems = NULL;
  VARIANT varZip, varDest, varItem, varOptions;

  hr = CoCreateInstance(&CLSID_Shell, NULL, CLSCTX_INPROC_SERVER,
                        &IID_IShellDispatch, (void **)&pShell);
  if (FAILED(hr))
    return hr;

  // Convert paths to BSTR variants
  WCHAR wZip[MAX_PATH], wDest[MAX_PATH];
  MultiByteToWideChar(CP_UTF8, 0, zip_path, -1, wZip, MAX_PATH);
  MultiByteToWideChar(CP_UTF8, 0, dest_folder, -1, wDest, MAX_PATH);

  VariantInit(&varZip);
  varZip.vt = VT_BSTR;
  varZip.bstrVal = SysAllocString(wZip);

  VariantInit(&varDest);
  varDest.vt = VT_BSTR;
  varDest.bstrVal = SysAllocString(wDest);

  hr = pShell->lpVtbl->NameSpace(pShell, varZip, &pZipFile);
  if (SUCCEEDED(hr) && pZipFile) {
    hr = pShell->lpVtbl->NameSpace(pShell, varDest, &pDestFolder);
    if (SUCCEEDED(hr) && pDestFolder) {
      hr = pZipFile->lpVtbl->Items(pZipFile, &pItems);
      if (SUCCEEDED(hr) && pItems) {
        VariantInit(&varItem);
        varItem.vt = VT_DISPATCH;
        varItem.pdispVal = (IDispatch *)pItems;

        VariantInit(&varOptions);
        varOptions.vt = VT_I4;
        varOptions.lVal =
            4 | 16 | 1024; // FOF_SILENT | FOF_NOCONFIRMATION | FOF_NOERRORUI

        hr = pDestFolder->lpVtbl->CopyHere(pDestFolder, varItem, varOptions);
        pItems->lpVtbl->Release(pItems);
      }
      pDestFolder->lpVtbl->Release(pDestFolder);
    }
    pZipFile->lpVtbl->Release(pZipFile);
  }

  VariantClear(&varZip);
  VariantClear(&varDest);
  pShell->lpVtbl->Release(pShell);

  return hr;
}

/* ============================================================================
 * Public Functions: Scan API
 * ========================================================================== */

int signature_db_load(const char *sigdb_path) {
  AcquireSRWLockExclusive(&g_db_lock);
  if (g_db_loaded) {
    ReleaseSRWLockExclusive(&g_db_lock);
    return 0;
  }

  FILE *f = fopen(sigdb_path, "r");
  if (f == NULL) {
    ReleaseSRWLockExclusive(&g_db_lock);
    return -1;
  }

  g_sig_table = sig_hash_table_init(HASH_TABLE_SIZE);
  if (!g_sig_table) {
    fclose(f);
    ReleaseSRWLockExclusive(&g_db_lock);
    return -1;
  }

  char line[512];
  while (fgets(line, sizeof(line), f)) {
    line[strcspn(line, "\r\n")] = '\0';
    if (line[0] == '\0' || line[0] == '#')
      continue;

    unsigned char hash[SHA256_SIZE];
    if (hex_string_to_bytes(line, hash) == 0) {
      sig_hash_table_add(g_sig_table, hash, GENERIC_THREAT_LABEL);
    }
  }

  fclose(f);
  g_db_loaded = true;
  ReleaseSRWLockExclusive(&g_db_lock);
  return 0;
}

void signature_db_unload(void) {
  AcquireSRWLockExclusive(&g_db_lock);
  if (g_db_loaded) {
    sig_hash_table_free(g_sig_table);
    g_sig_table = NULL;
    g_db_loaded = false;
  }
  ReleaseSRWLockExclusive(&g_db_lock);
}

int signature_scan_hash(const unsigned char hash[SHA256_SIZE],
                        SignatureResult *out) {
  AcquireSRWLockShared(&g_db_lock);
  if (!g_db_loaded || out == NULL) {
    ReleaseSRWLockShared(&g_db_lock);
    return -1;
  }

  out->matched = false;
  out->label = NULL;

  const char *label = sig_hash_table_lookup(g_sig_table, hash);
  if (label) {
    out->matched = true;
    out->label = label;
  }

  ReleaseSRWLockShared(&g_db_lock);
  return 0;
}

/* ============================================================================
 * Update Mechanism (Download & Extract)
 * ========================================================================== */

typedef struct {
  IBindStatusCallbackVtbl *lpVtbl;
  LONG ref_count;
} DownloadProgress;

static HRESULT STDMETHODCALLTYPE QueryInterface(IBindStatusCallback *this,
                                                REFIID riid, void **pp) {
  if (IsEqualIID(riid, &IID_IUnknown) ||
      IsEqualIID(riid, &IID_IBindStatusCallback)) {
    *pp = this;
    return S_OK;
  }
  return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE AddRef(IBindStatusCallback *this) { return 1; }
static ULONG STDMETHODCALLTYPE Release(IBindStatusCallback *this) { return 1; }
static HRESULT STDMETHODCALLTYPE OnProgress(IBindStatusCallback *t, ULONG prog,
                                            ULONG max, ULONG code,
                                            LPCWSTR text) {
  if (max > 0)
    update_progress = (int)((double)prog / (double)max * 100.0);
  return S_OK;
}
static HRESULT STDMETHODCALLTYPE OnStartBinding(IBindStatusCallback *t, DWORD r,
                                                IBinding *b) {
  return S_OK;
}
static HRESULT STDMETHODCALLTYPE GetPriority(IBindStatusCallback *t, LONG *p) {
  return S_OK;
}
static HRESULT STDMETHODCALLTYPE OnLowResource(IBindStatusCallback *t,
                                               DWORD r) {
  return S_OK;
}
static HRESULT STDMETHODCALLTYPE OnStopBinding(IBindStatusCallback *t,
                                               HRESULT h, LPCWSTR e) {
  return S_OK;
}
static HRESULT STDMETHODCALLTYPE GetBindInfo(IBindStatusCallback *t, DWORD *g,
                                             BINDINFO *b) {
  return S_OK;
}
static HRESULT STDMETHODCALLTYPE OnDataAvailable(IBindStatusCallback *t,
                                                 DWORD g, DWORD s, FORMATETC *f,
                                                 STGMEDIUM *m) {
  return S_OK;
}
static HRESULT STDMETHODCALLTYPE OnObjectAvailable(IBindStatusCallback *t,
                                                   REFIID r, IUnknown *p) {
  return S_OK;
}

static IBindStatusCallbackVtbl g_progress_vtbl = {
    QueryInterface, AddRef,          Release,          OnStartBinding,
    GetPriority,    OnLowResource,   OnProgress,       OnStopBinding,
    GetBindInfo,    OnDataAvailable, OnObjectAvailable};

int update_signature_db(const char *db_path) {
  CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

  char zip_path[MAX_PATH], extracted_name[] = "full_sha256.txt",
                           temp_db_path[MAX_PATH];
  char current_dir[MAX_PATH];
  GetCurrentDirectoryA(MAX_PATH, current_dir);

  snprintf(zip_path, MAX_PATH, "%s\\signatures.zip", current_dir);
  snprintf(temp_db_path, MAX_PATH, "%s.tmp", db_path);

  DownloadProgress monitor = {&g_progress_vtbl, 1};
  update_progress = 0;

  /* 1. Download ZIP */
  HRESULT hr = URLDownloadToFileA(NULL, BAZAAR_EXPORT_URL, zip_path, 0,
                                  (IBindStatusCallback *)&monitor);
  if (hr != S_OK) {
    update_progress = -1;
    CoUninitialize();
    return -1;
  }

  /* 2. Native Extraction */
  hr = unzip_db_native(zip_path, current_dir);
  DeleteFileA(zip_path);

  if (FAILED(hr)) {
    update_progress = -1;
    CoUninitialize();
    return -1;
  }

  /* 3. Validation & Atomic Swap */
  if (MoveFileExA(extracted_name, temp_db_path, MOVEFILE_REPLACE_EXISTING)) {
    if (MoveFileExA(temp_db_path, db_path, MOVEFILE_REPLACE_EXISTING)) {
      update_progress = 101;
      CoUninitialize();
      return 0;
    }
  }

  update_progress = -1;
  CoUninitialize();
  return -1;
}
