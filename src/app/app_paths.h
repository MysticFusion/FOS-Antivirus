/**
 * @file app_paths.h
 * @brief Centralized runtime path resolution.
 */

#ifndef APP_PATHS_H
#define APP_PATHS_H

#ifdef __cplusplus
extern "C" {
#endif

int app_paths_init(void);

const char *app_path_signature_db(void);
const char *app_path_history_log(void);
const char *app_path_heuristics_log(void);
const char *app_path_quarantine_dir(void);
const char *app_path_model(void);

#ifdef __cplusplus
}
#endif

#endif /* APP_PATHS_H */
