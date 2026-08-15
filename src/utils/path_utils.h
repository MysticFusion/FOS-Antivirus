/**
 * @file path_utils.h
 * @brief Long-path-aware path utilities (I-06 remediation)
 *
 * Provides wide-character (UTF-16) path handling with automatic
 * "\\?\" prefixing for paths longer than 248 characters, lifting the
 * MAX_PATH (260) limitation that silently skipped deep paths.
 */

#ifndef PATH_UTILS_H
#define PATH_UTILS_H

#include <stdbool.h>
#include <stdio.h>
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Windows long-path limit in UTF-16 code units (with "\\?\" prefix) */
#define FOS_MAX_PATH 32768

/**
 * @brief A path that is always stored as a wide-character string and is
 *        automatically long-path-prefixed when needed.
 *
 * NOTE: 64 KB of stack per instance. Declare locally, never store in
 * large arrays.
 */
typedef struct {
    wchar_t wide[FOS_MAX_PATH];
    bool    is_long;  /**< true if a "\\?\" (or "\\?\UNC\") prefix was applied */
} fos_path_t;

/**
 * @brief Initialize a fos_path_t from a UTF-8/ANSI path string.
 *
 * Converts to UTF-16 and applies the long-path prefix when the length
 * is >= 248 characters. Paths that are already prefixed are left intact.
 *
 * @return true on success.
 */
bool fos_path_init(fos_path_t *p, const char *utf8_input);

/** @brief Initialize a fos_path_t directly from a UTF-16 string (no
 *         UTF-8 round-trip). Applies the same prefixing rules. */
bool fos_path_init_w(fos_path_t *p, const wchar_t *wide_input);

/** @brief Return the wide string (with prefix applied). */
const wchar_t *fos_path_w(const fos_path_t *p);

/**
 * @brief Convert the (possibly prefixed) wide path back to UTF-8.
 * @return 0 on success.
 */
int fos_path_to_utf8(const fos_path_t *p, char *out, size_t out_sz);

/** @brief CreateFileW wrapper. Returns INVALID_HANDLE_VALUE on failure. */
HANDLE fos_create_file(const fos_path_t *p, DWORD access, DWORD share,
                       DWORD disposition, DWORD flags);

/** @brief GetFileAttributesExW wrapper. */
bool fos_get_file_attributes(const fos_path_t *p, WIN32_FILE_ATTRIBUTE_DATA *fad);

/** @brief Check existence (files only, not directories). */
bool fos_file_exists(const fos_path_t *p);

/** @brief DeleteFileW wrapper. */
bool fos_delete_file(const fos_path_t *p);

/** @brief _wfopen wrapper; mode is a C-style "rb"/"wb"/"ab"/... string. */
FILE *fos_fopen(const fos_path_t *p, const char *mode);

/**
 * @brief MAPv3 U-03/U-04: atomically open a path and resolve its canonical
 *        final path from the opened handle.
 *
 * Closes the check-then-open (TOCTOU, CWE-367) window: the object is opened
 * IMMEDIATELY with CreateFileW and the returned path is derived from that
 * handle via GetFinalPathNameByHandleW — never from a later re-check. The
 * caller passes the canonical path (or the handle) downstream.
 *
 * @param wide_path      UTF-16 path to open (long-path prefix accepted).
 * @param follow_reparse true  -> follow reparse points at open time; the
 *                              returned path is the fully-resolved target
 *                              path (use for leaf files).
 *                       false -> FILE_FLAG_OPEN_REPARSE_POINT; the returned
 *                              path is the link object's own path (use for
 *                              directory walking where following would let
 *                              a junction escape the scan root).
 * @param out_utf8       canonical path as UTF-8 with the "\\?\" /
 *                       "\\?\UNC\" prefix stripped (conventional form).
 * @param out_sz         size of out_utf8 in bytes.
 * @param was_reparse    optional; set to true when the opened object is
 *                       itself a reparse point (decided atomically via the
 *                       handle, not stale find-data).
 * @return 0 on success, -1 on any open/resolve failure.
 */
int fos_open_canonical(const wchar_t *wide_path, bool follow_reparse,
                       char *out_utf8, size_t out_sz, bool *was_reparse);

#ifdef __cplusplus
}
#endif

#endif /* PATH_UTILS_H */
