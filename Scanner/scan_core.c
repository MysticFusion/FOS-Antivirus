#define _CRT_SECURE_NO_WARNINGS
#include "scan_core.h"
#include "sha2.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <windows.h>

#define READ_CHUNK (64 * 1024)

// --- Compute SHA-256 of a file ---
int compute_file_sha256(const char *path, unsigned char out_hash[32]) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        // fprintf(stderr, "open '%s' failed: %s\n", path, strerror(errno));
        return -1;
    }

    unsigned char buf[READ_CHUNK];
    sha256_ctx ctx;
    sha256_init(&ctx);

    size_t r;
    while ((r = fread(buf, 1, sizeof(buf), f)) > 0)
        sha256_update(&ctx, buf, r);

    if (ferror(f)) {
        fclose(f);
        return -1;
    }

    sha256_final(&ctx, out_hash);
    fclose(f);
    return 0;
}

// --- Internal Recursive Scanner ---
static int scan_path_recursive(const char *path, file_callback_t cb, void *ctx) {
    WIN32_FIND_DATAA findData;
    char searchPath[MAX_PATH];
    struct stat st = {0}; // Dummy stat struct since we are using Windows API

    // 1. Check if the path itself is a file (not a directory)
    DWORD attr = GetFileAttributesA(path);
    if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
         return cb(path, &st, ctx);
    }

    // 2. Prepare to search inside the directory
    snprintf(searchPath, MAX_PATH, "%s\\*", path);
    HANDLE hFind = FindFirstFileA(searchPath, &findData);
    
    if (hFind == INVALID_HANDLE_VALUE) {
        return SCANCORE_OK; // Directory empty or inaccessible
    }

    int overall_result = SCANCORE_OK;

    do {
        // Skip "." and ".."
        if (strcmp(findData.cFileName, ".") == 0 || strcmp(findData.cFileName, "..") == 0)
            continue;

        char fullPath[MAX_PATH];
        // Construct full path
        _snprintf_s(fullPath, sizeof(fullPath), _TRUNCATE, "%s\\%s", path, findData.cFileName);

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // Recurse into subdirectory
            int r = scan_path_recursive(fullPath, cb, ctx);
            if (r == SCANCORE_FATAL_ERR) { overall_result = SCANCORE_FATAL_ERR; break; }
        } else {
            // It's a file, call the callback
            int r = cb(fullPath, &st, ctx);
            if (r == SCANCORE_FATAL_ERR) { overall_result = SCANCORE_FATAL_ERR; break; }
            // Note: We don't stop on MATCH, we keep scanning other files
        }

    } while (FindNextFileA(hFind, &findData) != 0);

    FindClose(hFind);
    return overall_result;
}

// --- Public Scan Function ---
int scan_path(const char *path_to_scan, file_callback_t cb, void *ctx) {
    return scan_path_recursive(path_to_scan, cb, ctx);
}