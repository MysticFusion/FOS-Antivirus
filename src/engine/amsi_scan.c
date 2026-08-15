/**
 * @file amsi_scan.c
 * @brief AMSI client integration (U-10) — see amsi_scan.h for the design.
 */

#define _CRT_SECURE_NO_WARNINGS
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include "amsi_scan.h"

#include <windows.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

/* amsi.h is not shipped by all MinGW toolchains; declare the small surface
 * we use directly (signatures per the Windows SDK). */
typedef void *HAMSICONTEXT;
typedef ULONGLONG AMSI_SESSION;
typedef enum AMSI_RESULT {
    AMSI_RESULT_CLEAN = 0,
    AMSI_RESULT_NOT_DETECTED = 1,
    AMSI_RESULT_BLOCKED_BY_ADMIN_START = 0x4000,
    AMSI_RESULT_BLOCKED_BY_ADMIN_END = 0x4FFF,
    AMSI_RESULT_DETECTED = 32768
} AMSI_RESULT;

typedef HRESULT(WINAPI *PFN_AmsiInitialize)(
    LPCWSTR antivirusName, HAMSICONTEXT *amsiContext);
typedef HRESULT(WINAPI *PFN_AmsiUninitialize)(HAMSICONTEXT amsiContext);
typedef HRESULT(WINAPI *PFN_AmsiOpenSession)(
    HAMSICONTEXT amsiContext, AMSI_SESSION *session);
typedef void(WINAPI *PFN_AmsiCloseSession)(
    HAMSICONTEXT amsiContext, AMSI_SESSION session);
typedef HRESULT(WINAPI *PFN_AmsiScanBuffer)(
    HAMSICONTEXT amsiContext, PVOID buffer, ULONG length,
    LPCWSTR contentName, AMSI_SESSION session, AMSI_RESULT *result);

/* Cap the amount of file content submitted per scan. Real script payloads
 * are far smaller; the cap bounds memory + provider work on huge inputs. */
#define AMSI_MAX_CONTENT (8 * 1024 * 1024)

static HMODULE g_amsi_dll = NULL;
static HAMSICONTEXT g_amsi_ctx = NULL;
static PFN_AmsiInitialize g_pAmsiInitialize = NULL;
static PFN_AmsiUninitialize g_pAmsiUninitialize = NULL;
static PFN_AmsiOpenSession g_pAmsiOpenSession = NULL;
static PFN_AmsiCloseSession g_pAmsiCloseSession = NULL;
static PFN_AmsiScanBuffer g_pAmsiScanBuffer = NULL;
static bool g_amsi_ready = false;
static INIT_ONCE g_amsi_once = INIT_ONCE_STATIC_INIT;
static CRITICAL_SECTION g_amsi_lock;

static BOOL CALLBACK amsi_init_once(PINIT_ONCE o, PVOID p, PVOID *c)
{
    (void)o; (void)p; (void)c;
    InitializeCriticalSection(&g_amsi_lock);

    g_amsi_dll = LoadLibraryW(L"amsi.dll");
    if (!g_amsi_dll) return TRUE; /* unavailable -> stay not-ready */

    g_pAmsiInitialize =
        (PFN_AmsiInitialize)GetProcAddress(g_amsi_dll, "AmsiInitialize");
    g_pAmsiUninitialize =
        (PFN_AmsiUninitialize)GetProcAddress(g_amsi_dll, "AmsiUninitialize");
    g_pAmsiOpenSession =
        (PFN_AmsiOpenSession)GetProcAddress(g_amsi_dll, "AmsiOpenSession");
    g_pAmsiCloseSession =
        (PFN_AmsiCloseSession)GetProcAddress(g_amsi_dll, "AmsiCloseSession");
    g_pAmsiScanBuffer =
        (PFN_AmsiScanBuffer)GetProcAddress(g_amsi_dll, "AmsiScanBuffer");

    if (g_pAmsiInitialize && g_pAmsiUninitialize && g_pAmsiOpenSession &&
        g_pAmsiCloseSession && g_pAmsiScanBuffer) {
        HAMSICONTEXT ctx = NULL;
        if (SUCCEEDED(g_pAmsiInitialize(L"FOS-Antivirus", &ctx)) && ctx) {
            g_amsi_ctx = ctx;
            g_amsi_ready = true;
        }
    }
    return TRUE;
}

static void amsi_ensure_init(void)
{
    InitOnceExecuteOnce(&g_amsi_once, amsi_init_once, NULL, NULL);
}

int amsi_scan_available(void)
{
    amsi_ensure_init();
    return g_amsi_ready ? 1 : 0;
}

int amsi_scan_buffer(const void *buf, size_t len, const wchar_t *content_name)
{
    amsi_ensure_init();
    if (!g_amsi_ready || !buf || len == 0)
        return (buf && len) ? AMSI_SCAN_ERROR : AMSI_SCAN_CLEAN;

    /* One session per call: sessions are not thread-safe, the context is. */
    AMSI_SESSION session = 0;
    HRESULT hr = g_pAmsiOpenSession(g_amsi_ctx, &session);
    if (FAILED(hr))
        return AMSI_SCAN_ERROR;

    EnterCriticalSection(&g_amsi_lock);
    AMSI_RESULT result = AMSI_RESULT_CLEAN;
    hr = g_pAmsiScanBuffer(g_amsi_ctx, (PVOID)buf, (ULONG)len,
                           content_name ? content_name : L"FOS-Antivirus:buffer",
                           session, &result);
    LeaveCriticalSection(&g_amsi_lock);

    g_pAmsiCloseSession(g_amsi_ctx, session);

    if (FAILED(hr))
        return AMSI_SCAN_ERROR;
    /* Only a provider DETECTION counts as malware; "blocked by admin
     * policy" is a policy verdict, not a detection. */
    return (result >= AMSI_RESULT_DETECTED) ? AMSI_SCAN_MALWARE
                                            : AMSI_SCAN_CLEAN;
}

int amsi_scan_file_wide(const fos_path_t *path, const wchar_t *content_name)
{
    if (!path)
        return AMSI_SCAN_ERROR;

    amsi_ensure_init();
    if (!g_amsi_ready)
        return AMSI_SCAN_CLEAN; /* unavailable is not suspicious */

    HANDLE h = CreateFileW(path->wide, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return AMSI_SCAN_ERROR;

    LARGE_INTEGER size;
    if (!GetFileSizeEx(h, &size) || size.QuadPart < 0) {
        CloseHandle(h);
        return AMSI_SCAN_ERROR;
    }
    size_t to_read = (size.QuadPart > (LONGLONG)AMSI_MAX_CONTENT)
                         ? (size_t)AMSI_MAX_CONTENT
                         : (size_t)size.QuadPart;
    if (to_read == 0) {
        CloseHandle(h);
        return AMSI_SCAN_CLEAN; /* empty file: nothing to evaluate */
    }

    void *buf = malloc(to_read);
    if (!buf) {
        CloseHandle(h);
        return AMSI_SCAN_ERROR;
    }

    size_t got_total = 0;
    while (got_total < to_read) {
        DWORD want = (DWORD)(to_read - got_total);
        DWORD got = 0;
        if (!ReadFile(h, (char *)buf + got_total, want, &got, NULL) ||
            got == 0) {
            free(buf);
            CloseHandle(h);
            return AMSI_SCAN_ERROR;
        }
        got_total += got;
    }
    CloseHandle(h);

    int rc = amsi_scan_buffer(buf, got_total,
                              content_name ? content_name : path->wide);
    free(buf);
    return rc;
}
