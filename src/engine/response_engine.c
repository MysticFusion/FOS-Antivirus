/**
 * @file response_engine.c
 * @brief Threat Response & Remediation Implementation
 *
 * Implements a secure quarantine vault using XOR encryption and a custom
 * header format to store original file metadata. Tracks history in a local log.
 *
 */

#define _CRT_SECURE_NO_WARNINGS

#include "response_engine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <windows.h>

/* ============================================================================
 * Configuration & Storage Constants
 * ========================================================================== */

#define QUARANTINE_DIR      "Quarantine"
#define HISTORY_LOG         "history.log"
#define XOR_KEY             0x5A
#define Q_MAGIC             0xDEADCAFE
#define READ_BUFFER_SIZE    4096

/* ============================================================================
 * Data Structures
 * ========================================================================== */

#pragma pack(push, 1)
/**
 * @brief Metadata header stored at the beginning of every quarantined file.
 */
typedef struct {
    uint32_t magic;           /**< Q_MAGIC identifier */
    uint64_t timestamp;       /**< Time of quarantine */
    uint32_t path_len;        /**< Length of original absolute path */
    char     threat_name[64]; /**< Label of the detected threat */
} QuarantineHeader;
#pragma pack(pop)

/* ============================================================================
 * Internal Helpers
 * ========================================================================== */

/**
 * @brief Log a quarantine event to the local history database.
 */
static void log_to_history(
    const char *threat_label,
    const char *orig_path,
    const char *q_path
)
{
    FILE *f = fopen(HISTORY_LOG, "a");
    if (f == NULL) {
        return;
    }

    time_t now = time(NULL);
    char   time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));

    /* Entry format: Timestap|Label|OriginalPath|QuarantinePath */
    fprintf(f, "%s|%s|%s|%s\n", time_str, threat_label, orig_path, q_path);
    fclose(f);
}

/* ============================================================================
 * Public Functions
 * ========================================================================== */

int response_quarantine_file(
    const char *src_path,
    const char *threat_label
)
{
    /* Ensure quarantine vault directory exists */
    CreateDirectoryA(QUARANTINE_DIR, NULL);

    /* Generate isolated filename in vault */
    char        dst_filename[MAX_PATH];
    const char *orig_filename = strrchr(src_path, '\\');
    orig_filename = (orig_filename != NULL) ? orig_filename + 1 : src_path;

    snprintf(dst_filename, MAX_PATH, "%s\\%lu_%s.vir", 
             QUARANTINE_DIR, GetTickCount(), orig_filename);

    FILE *fin = fopen(src_path, "rb");
    if (fin == NULL) {
        return -1;
    }

    FILE *fout = fopen(dst_filename, "wb");
    if (fout == NULL) {
        fclose(fin);
        return -1;
    }

    /* Prepare and write metadata header */
    QuarantineHeader header;
    memset(&header, 0, sizeof(header));
    header.magic     = Q_MAGIC;
    header.timestamp = (uint64_t)time(NULL);
    header.path_len  = (uint32_t)strlen(src_path);
    strncpy(header.threat_name, threat_label, sizeof(header.threat_name) - 1);

    fwrite(&header, sizeof(header), 1, fout);
    fwrite(src_path, 1, header.path_len, fout);

    /* Encrypt and copy file data */
    unsigned char buffer[READ_BUFFER_SIZE];
    size_t        bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), fin)) > 0) {
        for (size_t i = 0; i < bytes_read; i++) {
            buffer[i] ^= XOR_KEY;
        }
        fwrite(buffer, 1, bytes_read, fout);
    }

    fclose(fin);
    fclose(fout);

    /* Safely delete the original file */
    if (DeleteFileA(src_path)) {
        log_to_history(threat_label, src_path, dst_filename);
        return 0;
    }

    return -1;
}

int response_restore_file(
    const char *q_path,
    const char *dest_override
)
{
    FILE *fin = fopen(q_path, "rb");
    if (fin == NULL) {
        return -1;
    }

    /* Parse metadata header */
    QuarantineHeader header;
    if (fread(&header, sizeof(header), 1, fin) != 1 || header.magic != Q_MAGIC) {
        fclose(fin);
        return -2;
    }

    char *stored_path = malloc(header.path_len + 1);
    if (stored_path == NULL) {
        fclose(fin);
        return -1;
    }

    fread(stored_path, 1, header.path_len, fin);
    stored_path[header.path_len] = '\0';

    const char *target_dest = (dest_override != NULL) ? dest_override : stored_path;

    FILE *fout = fopen(target_dest, "wb");
    if (fout == NULL) {
        free(stored_path);
        fclose(fin);
        return -3;
    }

    /* Decrypt and restore data */
    unsigned char buffer[READ_BUFFER_SIZE];
    size_t        bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), fin)) > 0) {
        for (size_t i = 0; i < bytes_read; i++) {
            buffer[i] ^= XOR_KEY;
        }
        fwrite(buffer, 1, bytes_read, fout);
    }

    free(stored_path);
    fclose(fin);
    fclose(fout);

    /* Remove the quarantine artifact on success */
    DeleteFileA(q_path);
    return 0;
}

int restore_file_from_quarantine(
    const char *q_path,
    const char *dest_override
)
{
    return response_restore_file(q_path, dest_override);
}
