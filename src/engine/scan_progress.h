/**
 * @file scan_progress.h - HARDENED with snapshot
 */
#ifndef SCAN_PROGRESS_H
#define SCAN_PROGRESS_H
#include <stdbool.h>
#include <windows.h>
#ifdef __cplusplus
extern "C" {
#endif
void scan_progress_start(int total_files);
void scan_progress_file_start(const char *path);
void scan_progress_file_done(bool threat_found);
void scan_progress_finish(void);
bool scan_progress_is_running(void);
int scan_progress_files_scanned(void);
int scan_progress_threats_found(void);
const char *scan_progress_current_file(void);

// New atomic snapshot for FFI
typedef struct {
    bool is_running;
    int files_scanned;
    int threats_found;
    char current_file[MAX_PATH];
} ScanProgressSnapshot;
void scan_progress_snapshot(ScanProgressSnapshot *out);

#ifdef __cplusplus
}
#endif
#endif
