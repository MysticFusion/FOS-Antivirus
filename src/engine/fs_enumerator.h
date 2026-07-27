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

/**
 * @brief Callback function type for file discovery.
 * @param path The absolute path of the discovered file.
 * @param user_data Opaque pointer to user-defined data.
 */
typedef void (*fs_enum_callback_t)(const char *path, void *user_data);

/* ============================================================================
 * Public Functions
 * ========================================================================== */

/**
 * @brief Discover all files in a directory and its subdirectories.
 *
 * @param[in]  root       Starting directory path.
 * @param[in]  callback   Function to call for each discovered file.
 * @param[in]  user_data  User data to pass to the callback.
 *
 * @return 0 on success, non-zero on error.
 */
int list_files_recursive(
    const char         *root,
    fs_enum_callback_t  callback,
    void               *user_data
);

#ifdef __cplusplus
}
#endif

#endif /* FS_ENUMERATOR_H */
