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

        /* MAPv3 U-04: OPEN THE CHILD IMMEDIATELY — never defer the open past
         * enumeration. The old code skipped reparse points based on the
         * find-data and opened the path much later; in that window an
         * attacker could convert a normal directory into a junction pointing
         * at C:\Windows\System32 and redirect the scan. Now:
         *   1. CreateFileW + FILE_FLAG_OPEN_REPARSE_POINT pins the object as
         *      it exists right now (the handle never follows a link that was
         *      not there at enumeration time).
         *   2. Reparse-ness is decided atomically from the HANDLE
         *      (GetFileInformationByHandleEx), so a stale find-data decision
         *      is impossible.
         *   3. The canonical path passed to the callback is derived from the
         *      same handle (GetFinalPathNameByHandleW) — the callback and the
         *      hash stage operate on the verified object, not on the name
         *      captured earlier.
         * A reparse-point object is skipped (never followed): following a
         * directory junction could both loop and escape the scan root. */
        char *canonical = (char *)malloc(FOS_MAX_PATH);
        if (!canonical) { free(full); continue; }
        bool was_reparse = false;
        if (fos_open_canonical(full, false, canonical, FOS_MAX_PATH, &was_reparse) != 0 ||
            was_reparse) {
            free(canonical);
            free(full);
            continue;
        }

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            /* Recurse into the canonical path (fos_open_canonical already
             * resolved any junction components above the leaf). The
             * canonical form is unprefixed, so re-apply the long-path
             * "\\?\" / "\\?\UNC\" prefix (mirrors fos_path_init_w) to keep
             * deep paths enumerating (MAP-07). */
            wchar_t *wcanon = (wchar_t *)malloc(FOS_MAX_PATH * sizeof(wchar_t));
            if (wcanon) {
                int n = MultiByteToWideChar(CP_UTF8, 0, canonical, -1, wcanon, FOS_MAX_PATH);
                if (n > 0) {
                    wchar_t *prefixed = (wchar_t *)malloc((n + 8) * sizeof(wchar_t));
                    if (prefixed) {
                        if (wcsncmp(wcanon, L"\\\\?\\", 4) == 0) {
                            wcscpy_s(prefixed, n + 8, wcanon);
                        } else if (wcanon[0] == L'\\' && wcanon[1] == L'\\') {
                            wcscpy_s(prefixed, n + 8, L"\\\\?\\UNC\\");
                            wcscat_s(prefixed, n + 8, wcanon + 2);
                        } else {
                            wcscpy_s(prefixed, n + 8, L"\\\\?\\");
                            wcscat_s(prefixed, n + 8, wcanon);
                        }
                        ctx->depth++;
                        walk_recursive_wide(prefixed, ctx);
                        ctx->depth--;
                        free(prefixed);
                    }
                }
                free(wcanon);
            }
        } else {
            /* Skip ADS streams (colon) */
            if (!wcschr(fd.cFileName, L':')) {
                ctx->cb(canonical, ctx->user_data);
            }
        }
        free(canonical);
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
