#ifndef SCAN_CORE_H
#define SCAN_CORE_H

#include <sys/stat.h>

/* Return codes */
#define SCANCORE_OK          0
#define SCANCORE_MATCH       1
#define SCANCORE_HANDLED     2  // Indicates file was quarantined/removed
#define SCANCORE_FATAL_ERR  -1
#define SCANCORE_FILE_ERR   -2

typedef int (*file_callback_t)(const char *path, const struct stat *st, void *ctx);

/* Recursive scan of a path */
int scan_path(const char *path_to_scan, file_callback_t cb, void *ctx);

/* Compute SHA-256 of a file (returns 0 on success) */
int compute_file_sha256(const char *path, unsigned char out_hash[32]);

#endif