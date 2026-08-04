/**
 * @file fs_enumerator.c
 * @brief Secure Filesystem Enumerator - hardened
 *
 * MAP-07: enumeration is wide-char (UTF-16) with the "\\?\" long-path
 * prefix. The old narrow-char MAX_PATH (260) buffers silently truncated
 * deep paths (node_modules, deep Java package trees, Electron resources)
 * and the old code skipped them with `continue`, leaving a coverage gap
 * an attacker could exploit by nesting a payload deep enough to escape
 * enumeration. Long paths are now enumerated and hashed correctly.
 */
#include "fs_enumerator.h"
#include "path_utils.h"
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MAX_RECURSION_DEPTH 32

typedef struct {
    fs_enum_callback_t cb;
    void *user_data;
    int depth;
} walk_ctx_t;

/**
 * @brief Convert a (possibly "\\?\" prefixed) wide path to UTF-8 for the
 *        callback, stripping the prefix so downstream consumers (trust
 *        evaluation, known-folder matching) see a conventional path.
 *        fos_path_init re-applies the prefix when it is needed again.
 * @return 0 on success.
 */
static int wide_to_utf8_cb(const wchar_t *wide, char *out, size_t out_sz)
{
    if (!wide || !out || out_sz < 4) return -1;

    const wchar_t *p = wide;
    size_t extra = 0;
    if (wcsncmp(p, L"\\\\?\\UNC\\", 8) == 0) {
        p += 8;          /* restore the leading "\\" of a UNC path */
        extra = 2;
    } else if (wcsncmp(p, L"\\\\?\\", 4) == 0) {
        p += 4;
    }

    int n = WideCharToMultiByte(CP_UTF8, 0, p, -1,
                                out + extra, (int)(out_sz - extra), NULL, NULL);
    if (n <= 0) return -1;
    if (extra == 2) {
        out[0] = '\\';
        out[1] = '\\';
    }
    return 0;
}

static void walk_recursive_wide(const wchar_t *dir, walk_ctx_t *ctx)
{
    if (!dir || !ctx) return;
    if (ctx->depth > MAX_RECURSION_DEPTH) return;

    size_t dir_len = wcslen(dir);
    if (dir_len == 0 || dir_len >= FOS_MAX_PATH - 2) return;

    /* pattern = <dir>\*  (heap-allocated: keeps per-frame stack usage flat
     * across recursion so 64 KB path buffers cannot overflow the stack). */
    wchar_t *pattern = (wchar_t *)malloc((dir_len + 3) * sizeof(wchar_t));
    if (!pattern) return;
    memcpy(pattern, dir, dir_len * sizeof(wchar_t));
    pattern[dir_len] = L'\\';
    pattern[dir_len + 1] = L'*';
    pattern[dir_len + 2] = L'\0';

    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileExW(pattern, FindExInfoBasic, &fd,
                                FindExSearchNameMatch, NULL,
                                FIND_FIRST_EX_LARGE_FETCH);
    free(pattern);
    if (h == INVALID_HANDLE_VALUE) return;

    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;

        size_t name_len = wcslen(fd.cFileName);
        if (dir_len + 1 + name_len + 1 > FOS_MAX_PATH) continue; /* beyond API capacity */

        wchar_t *full = (wchar_t *)malloc((dir_len + name_len + 2) * sizeof(wchar_t));
        if (!full) continue;
        memcpy(full, dir, dir_len * sizeof(wchar_t));
        full[dir_len] = L'\\';
        memcpy(full + dir_len + 1, fd.cFileName, name_len * sizeof(wchar_t));
        full[dir_len + 1 + name_len] = L'\0';

        /* Skip reparse points (junctions, symlinks) to prevent loops */
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
            free(full);
            continue;
        }

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            ctx->depth++;
            walk_recursive_wide(full, ctx);
            ctx->depth--;
        } else {
            /* Skip ADS streams (colon) */
            if (!wcschr(fd.cFileName, L':')) {
                char *utf8 = (char *)malloc(FOS_MAX_PATH * 4);
                if (utf8 && wide_to_utf8_cb(full, utf8, FOS_MAX_PATH * 4) == 0) {
                    ctx->cb(utf8, ctx->user_data);
                }
                free(utf8);
            }
        }
        free(full);
    } while (FindNextFileW(h, &fd));

    FindClose(h);
}

int list_files_recursive(const char *root, fs_enum_callback_t callback, void *user_data)
{
    if (!root || !callback) return -1;

    /* MAP-07: convert the root once to a wide, long-path-prefixed form;
     * every descendant inherits the "\\?\" prefix so deep paths enumerate
     * correctly. Short roots stay unprefixed (conventional paths). */
    fos_path_t fp_root;
    if (!fos_path_init(&fp_root, root)) return -1;
    const wchar_t *wroot = fos_path_w(&fp_root);

    DWORD attrs = GetFileAttributesW(wroot);
    if (attrs == INVALID_FILE_ATTRIBUTES) return -1;
    if (!(attrs & FILE_ATTRIBUTE_DIRECTORY)) return -1;
    if (attrs & FILE_ATTRIBUTE_REPARSE_POINT) return -1;

    walk_ctx_t ctx = {0};
    ctx.cb = callback;
    ctx.user_data = user_data;
    ctx.depth = 0;
    walk_recursive_wide(wroot, &ctx);
    return 0;
}
