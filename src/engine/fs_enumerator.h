/**
 * @file fs_enumerator.h
 * @brief Filesystem Enumerator Utility Interface
 *
 * Provides functions for recursive file discovery on the Windows filesystem.
 *
 */

#ifndef FS_ENUMERATOR_H
#define FS_ENUMERATOR_H

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Data Structures
 * ========================================================================== */

/**
 * @brief Container for a list of discovered file paths.
 */
typedef struct {
    char **paths; /**< Array of heap-allocated strings */
    int    count; /**< Number of paths in the list */
} FilePathList;

/* ============================================================================
 * Public Functions
 * ========================================================================== */

/**
 * @brief Discover all files in a directory and its subdirectories.
 *
 * @param[in]  root     Starting directory path.
 * @param[out] out_list List to populate with found file paths.
 *
 * @return 0 on success, non-zero on error.
 */
int list_files_recursive(
    const char   *root,
    FilePathList *out_list
);

/**
 * @brief Release memory allocated for a FilePathList.
 *
 * @param[in] list List to clean up.
 */
void free_filepath_list(FilePathList *list);

#ifdef __cplusplus
}
#endif

#endif /* FS_ENUMERATOR_H */
