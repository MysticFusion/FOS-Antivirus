/**
 * @file fs_enumerator.c
 * @brief Secure Filesystem Enumerator - hardened
 */
#include "fs_enumerator.h"
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

static void walk_recursive_secure(const char *dir, walk_ctx_t *ctx)
{
    if (!dir || !ctx) return;
    if (ctx->depth > MAX_RECURSION_DEPTH) return;

    char pattern[MAX_PATH];
    int n = snprintf(pattern, MAX_PATH, "%s\\*", dir);
    if (n < 0 || n >= MAX_PATH) return;

    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileExA(pattern, FindExInfoBasic, &fd, FindExSearchNameMatch, NULL, FIND_FIRST_EX_LARGE_FETCH);
    if (h == INVALID_HANDLE_VALUE) return;

    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;

        char full_path[MAX_PATH];
        n = snprintf(full_path, MAX_PATH, "%s\\%s", dir, fd.cFileName);
        if (n < 0 || n >= MAX_PATH) continue;

        /* Skip reparse points (junctions, symlinks) to prevent loops */
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
        /* Skip system protected dirs that cause huge enumeration */
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            ctx->depth++;
            walk_recursive_secure(full_path, ctx);
            ctx->depth--;
        } else {
            /* Skip ADS streams (colon) */
            if (strchr(fd.cFileName, ':')) continue;
            ctx->cb(full_path, ctx->user_data);
        }
    } while (FindNextFileA(h, &fd));

    FindClose(h);
}

int list_files_recursive(const char *root, fs_enum_callback_t callback, void *user_data)
{
    if (!root || !callback) return -1;
    DWORD attrs = GetFileAttributesA(root);
    if (attrs == INVALID_FILE_ATTRIBUTES) return -1;
    if (!(attrs & FILE_ATTRIBUTE_DIRECTORY)) return -1;
    if (attrs & FILE_ATTRIBUTE_REPARSE_POINT) return -1;

    walk_ctx_t ctx = {0};
    ctx.cb = callback;
    ctx.user_data = user_data;
    ctx.depth = 0;
    walk_recursive_secure(root, &ctx);
    return 0;
}
