/**
 * @file response_engine.c
 * @brief Threat Response & Remediation Implementation
 *
 * Implements a secure quarantine vault using XOR encryption and a custom
 * header format to store original file metadata. Tracks history in a local log.
 *
 * v1.1 fix: corrected a typo in response_restore_file() where the line
 *   `stored_patheader.path_len] = '\0';`
 * was a compilation-breaking typo (should have been
 *   `stored_path[header.path_len] = '\0';`
 * ). Fixed.
 */

#define _CRT_SECURE_NO_WARNINGS

#include "response_engine.h"
#include "app_paths.h"

#include <io.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <windows.h>
#include <wincrypt.h>

/* ============================================================================
 * Configuration & Storage Constants
 * ========================================================================== */

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
    uint8_t  key[32];         /**< Random XOR pad */
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
    FILE *f = fopen(app_path_history_log(), "a");
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

static int flush_file(FILE *f)
{
    if (fflush(f) != 0) {
        return -1;
    }

    intptr_t os_handle = _get_osfhandle(_fileno(f));
    if (os_handle == -1) {
        return -1;
    }

    return FlushFileBuffers((HANDLE)os_handle) ? 0 : -1;
}

static void create_parent_dirs(const char *path)
{
    char tmp[MAX_PATH];
    strncpy(tmp, path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    for (char *p = tmp; *p; ++p) {
        if (*p != '\\' && *p != '/') {
            continue;
        }

        if (p == tmp || (p > tmp && p[-1] == ':')) {
            continue;
        }

        char old = *p;
        *p = '\0';
        CreateDirectoryA(tmp, NULL);
        *p = old;
    }
}

/* ============================================================================
 * Public Functions
 * ========================================================================== */

int response_quarantine_file(
    const char *src_path,
    const char *threat_label
)
{
    if (src_path == NULL || threat_label == NULL || src_path[0] == '\0') {
        return -1;
    }

    /* Ensure quarantine vault directory exists */
    const char *quarantine_dir = app_path_quarantine_dir();
    CreateDirectoryA(quarantine_dir, NULL);

    /* Generate isolated filename in vault */
    char        dst_filename[MAX_PATH];
    const char *orig_filename = strrchr(src_path, '\\');
    orig_filename = (orig_filename != NULL) ? orig_filename + 1 : src_path;

    snprintf(dst_filename, MAX_PATH, "%s\\%llu_%s.vir",
             quarantine_dir, GetTickCount64(), orig_filename);

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

    HCRYPTPROV hProv;
    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        CryptGenRandom(hProv, sizeof(header.key), header.key);
        CryptReleaseContext(hProv, 0);
    } else {
        for (int i = 0; i < sizeof(header.key); i++) header.key[i] = rand() % 256;
    }

    strncpy(header.threat_name, threat_label, sizeof(header.threat_name) - 1);

    fwrite(&header, sizeof(header), 1, fout);
    fwrite(src_path, 1, header.path_len, fout);

    /* Encrypt and copy file data */
    unsigned char buffer[READ_BUFFER_SIZE];
    size_t        bytes_read;
    uint64_t      total_read = 0;
    uint64_t      total_written = 0;
    int           copy_ok = 1;

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), fin)) > 0) {
        total_read += (uint64_t)bytes_read;
        for (size_t i = 0; i < bytes_read; i++) {
            buffer[i] ^= header.key[i % 32];
        }
        size_t bytes_written = fwrite(buffer, 1, bytes_read, fout);
        total_written += (uint64_t)bytes_written;
        if (bytes_written != bytes_read) {
            copy_ok = 0;
            break;
        }
    }

    if (ferror(fin) || ferror(fout) || total_read != total_written) {
        copy_ok = 0;
    }

    if (flush_file(fout) != 0) {
        copy_ok = 0;
    }

    int close_in_ok = (fclose(fin) == 0);
    int close_out_ok = (fclose(fout) == 0);

    if (!copy_ok || !close_in_ok || !close_out_ok) {
        DeleteFileA(dst_filename);
        return -1;
    }

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
    if (q_path == NULL || q_path[0] == '\0') {
        return -1;
    }

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

    if (header.path_len == 0 || header.path_len > 32768) {
        fclose(fin);
        return -2;
    }

    char *stored_path = malloc(header.path_len + 1);
    if (stored_path == NULL) {
        fclose(fin);
        return -1;
    }

    if (fread(stored_path, 1, header.path_len, fin) != header.path_len) {
        free(stored_path);
        fclose(fin);
        return -2;
    }
    /* v1.1 FIX: was `stored_patheader.path_len] = '\0';` (typo, would not compile).
     * Now correctly null-terminates the stored_path buffer. */
    stored_path[header.path_len] = '\0';

    const char *target_dest = (dest_override != NULL) ? dest_override : stored_path;
    if (target_dest == NULL || target_dest[0] == '\0') {
        free(stored_path);
        fclose(fin);
        return -3;
    }

    create_parent_dirs(target_dest);

    FILE *fout = fopen(target_dest, "wb");
    if (fout == NULL) {
        free(stored_path);
        fclose(fin);
        return -3;
    }

    /* Decrypt and restore data */
    unsigned char buffer[READ_BUFFER_SIZE];
    size_t        bytes_read;
    int           restore_ok = 1;

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), fin)) > 0) {
        for (size_t i = 0; i < bytes_read; i++) {
            buffer[i] ^= header.key[i % 32];
        }
        if (fwrite(buffer, 1, bytes_read, fout) != bytes_read) {
            restore_ok = 0;
            break;
        }
    }

    if (ferror(fin) || ferror(fout) || flush_file(fout) != 0) {
        restore_ok = 0;
    }

    free(stored_path);
    int close_in_ok = (fclose(fin) == 0);
    int close_out_ok = (fclose(fout) == 0);

    if (!restore_ok || !close_in_ok || !close_out_ok) {
        return -4;
    }

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


