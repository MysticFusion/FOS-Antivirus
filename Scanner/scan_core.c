#define _CRT_SECURE_NO_WARNINGS
#include "scan_bridge.h"
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
// --- FILE: scan_core.c (Final corrected list_path_recursive_internal) ---

// --- Internal Recursive Path Lister ---
static int list_path_recursive_internal(const char *path, FilePathList *list) {
    // Check for stop request (for responsive UI during listing)
    g_mutex_lock(&global_scan_ctx.mutex);
    if (global_scan_ctx.stop_requested) {
        g_mutex_unlock(&global_scan_ctx.mutex);
        return SCANCORE_FATAL_ERR;
    }
    g_mutex_unlock(&global_scan_ctx.mutex);

    WIN32_FIND_DATAA findData;
    char searchPath[MAX_PATH];
    
    // 1. Check if the path itself is a directory
    DWORD attr = GetFileAttributesA(path);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        // Path is invalid or inaccessible
        return SCANCORE_OK; 
    }
    
    if (!(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        // If it's a single file, add it directly
        list->paths = g_list_append(list->paths, g_strdup(path));
        list->total_files++;
        return SCANCORE_OK;
    }
    
    // --- Directory Search Logic ---
    
    size_t len = strlen(path);
    // Check if the path already ends with a backslash. 
    // This is often true for root directories like "C:\"
    bool ends_with_slash = (len > 0 && path[len - 1] == '\\'); 

    // 2. Prepare the search path: must be "Path\*" (one separator)
    if (ends_with_slash) {
        // Path is "C:\". Search path is "C:\*"
        // We use %s* (no backslash in the format string)
        snprintf(searchPath, MAX_PATH, "%s*", path); 
    } else {
        // Path is "C:\Users". Search path is "C:\Users\*"
        // We use \\* (literal '\' followed by *)
        snprintf(searchPath, MAX_PATH, "%s\\*", path); 
    }

    HANDLE hFind = FindFirstFileA(searchPath, &findData);
    
    if (hFind == INVALID_HANDLE_VALUE) {
        // Directory empty or inaccessible (or path was fundamentally wrong)
        return SCANCORE_OK; 
    }

    int overall_result = SCANCORE_OK;

    do {
        // Skip "." and ".."
        if (strcmp(findData.cFileName, ".") == 0 || strcmp(findData.cFileName, "..") == 0)
            continue;

        char fullPath[MAX_PATH];
        
        // Construct the full path for recursion/listing.
        // It must always have exactly one separator between path and filename.
        if (ends_with_slash) {
            // Path is "C:\". Full path is "C:\filename"
            // Use %s%s (no separator in format string)
            _snprintf_s(fullPath, sizeof(fullPath), _TRUNCATE, "%s%s", path, findData.cFileName);
        } else {
            // Path is "C:\Users". Full path is "C:\Users\filename"
            // Use %s\%s (literal '\' in format string)
            _snprintf_s(fullPath, sizeof(fullPath), _TRUNCATE, "%s\\%s", path, findData.cFileName);
        }
        
        // Note: The literal '\' in C string literals is written as "\". 
        // We do *not* use "\\\\" here, as that was causing the double-backslash issue.

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // Recurse into subdirectory
            int r = list_path_recursive_internal(fullPath, list);
            if (r == SCANCORE_FATAL_ERR) { overall_result = SCANCORE_FATAL_ERR; break; }
        } else {
            // It's a file, add the path to the list
            list->paths = g_list_append(list->paths, g_strdup(fullPath));
            list->total_files++;
        }

    } while (FindNextFileA(hFind, &findData) && overall_result != SCANCORE_FATAL_ERR);

    FindClose(hFind);
    return overall_result;
}

// --- Public Path Lister (Phase 1) ---
FilePathList* list_files_recursive(const char *path_to_scan) {
    FilePathList *list = malloc(sizeof(FilePathList));
    if (!list) return NULL;
    
    list->paths = NULL;
    list->total_files = 0;
    
    // Start the recursive listing
    list_path_recursive_internal(path_to_scan, list);
    
    return list;
}

// --- List Free Function ---
void free_filepath_list(FilePathList *list) {
    if (list) {
        // g_list_free_full frees the list nodes and the data (char*) contained in them
        g_list_free_full(list->paths, g_free); 
        free(list);
    }
}