/**
 * @file path_utils.c
 * @brief Long-path-aware path utilities (I-06 remediation)
 */

#define _CRT_SECURE_NO_WARNINGS

#include "path_utils.h"

#include <stdio.h>
#include <string.h>

bool fos_path_init(fos_path_t *p, const char *utf8_input)
{
    if (!p || !utf8_input) {
        return false;
    }

    int n = MultiByteToWideChar(CP_UTF8, 0, utf8_input, -1, p->wide, FOS_MAX_PATH);
    if (n <= 0) {
        p->wide[0] = L'\0';
        p->is_long = false;
        return false;
    }

    return fos_path_init_w(p, p->wide);
}

bool fos_path_init_w(fos_path_t *p, const wchar_t *wide_input)
{
    if (!p || !wide_input) {
        return false;
    }

    size_t len = wcslen(wide_input);
    if (len >= FOS_MAX_PATH) {
        p->wide[0] = L'\0';
        p->is_long = false;
        return false;
    }

    wcscpy_s(p->wide, FOS_MAX_PATH, wide_input);
    p->is_long = false;

    if (len >= 248) {
        wchar_t tmp[FOS_MAX_PATH];
        wcscpy_s(tmp, FOS_MAX_PATH, p->wide);

        if (wcsncmp(tmp, L"\\\\?\\", 4) == 0) {
            /* Already long-path prefixed — leave as-is. */
        } else if (tmp[0] == L'\\' && tmp[1] == L'\\') {
            /* UNC path → "\\?\UNC\server\share" form */
            const wchar_t unc_prefix[] = L"\\\\?\\UNC\\";
            wcscpy_s(p->wide, FOS_MAX_PATH, unc_prefix);
            wcscat_s(p->wide, FOS_MAX_PATH, tmp + 2);
            p->is_long = true;
        } else {
            const wchar_t prefix[] = L"\\\\?\\";
            wcscpy_s(p->wide, FOS_MAX_PATH, prefix);
            wcscat_s(p->wide, FOS_MAX_PATH, tmp);
            p->is_long = true;
        }
    }

    return true;
}

const wchar_t *fos_path_w(const fos_path_t *p)
{
    return (p != NULL) ? p->wide : NULL;
}

int fos_path_to_utf8(const fos_path_t *p, char *out, size_t out_sz)
{
    if (!p || !out || out_sz == 0) {
        return -1;
    }
    return WideCharToMultiByte(CP_UTF8, 0, p->wide, -1, out, (int)out_sz,
                               NULL, NULL) > 0 ? 0 : -1;
}

HANDLE fos_create_file(const fos_path_t *p, DWORD access, DWORD share,
                       DWORD disposition, DWORD flags)
{
    if (!p) {
        return INVALID_HANDLE_VALUE;
    }
    return CreateFileW(p->wide, access, share, NULL, disposition, flags, NULL);
}

bool fos_get_file_attributes(const fos_path_t *p, WIN32_FILE_ATTRIBUTE_DATA *fad)
{
    if (!p || !fad) {
        return false;
    }
    return GetFileAttributesExW(p->wide, GetFileExInfoStandard, fad) != 0;
}

bool fos_file_exists(const fos_path_t *p)
{
    WIN32_FILE_ATTRIBUTE_DATA fad;
    return fos_get_file_attributes(p, &fad) &&
           !(fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
}

bool fos_delete_file(const fos_path_t *p)
{
    return (p != NULL) && (DeleteFileW(p->wide) != 0);
}

FILE *fos_fopen(const fos_path_t *p, const char *mode)
{
    if (!p || !mode) {
        return NULL;
    }

    wchar_t wmode[8];
    size_t i = 0;
    while (mode[i] != '\0' && i < (sizeof(wmode) / sizeof(wmode[0])) - 1) {
        wmode[i] = (wchar_t)(unsigned char)mode[i];
        i++;
    }
    wmode[i] = L'\0';

    return _wfopen(p->wide, wmode);
}
