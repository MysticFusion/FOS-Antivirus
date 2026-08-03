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

#ifdef __cplusplus
}
#endif

#endif /* PATH_UTILS_H */
