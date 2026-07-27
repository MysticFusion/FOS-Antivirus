/**
 * @file auto_update.c
 * @brief Inert stub implementation for the future server-based auto-update.
 *
 * See auto_update.h for design notes. This file deliberately does nothing
 * useful — it exists so the call-site in app.c is already wired up and a
 * future implementation only needs to replace the bodies of these functions.
 */

#define _CRT_SECURE_NO_WARNINGS

#include "auto_update.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

/* ============================================================================
 * Internal State
 * ========================================================================== */

static bool g_initialized = false;
static bool g_first_check = true;

/* ============================================================================
 * Public Functions
 * ========================================================================== */

void auto_update_init(void) {
    if (g_initialized) {
        return;
    }
    g_initialized = true;
    g_first_check = true;

    /* Future: load cached update metadata, configure server URL, etc. */
}

int auto_update_check(void) {
    /* INERT STUB — does nothing useful.
     *
     * When you implement real server-based auto-update, replace this body
     * with:
     *   1. HTTP GET to your server's version manifest URL.
     *   2. Parse response, compare version against compiled-in APP_VERSION.
     *   3. If newer version available, return non-zero (or trigger download
     *      + verification + apply workflow).
     *
     * Recommended server URL pattern (replace with your own):
     *   https://your-update-server.example.com/fos-antivirus/manifest.json
     *
     * Recommended manifest format:
     *   {
     *     "latest_version": "1.2.0",
     *     "download_url":    "https://.../fos-antivirus-1.2.0.zip",
     *     "signature_url":   "https://.../fos-antivirus-1.2.0.zip.sig",
     *     "release_notes":   "..."
     *   }
     */

    if (g_first_check) {
        g_first_check = false;
        /* Log to a debug file so we can confirm the call-site works.
         * This will be removed once real implementation lands. */
        char appdata[MAX_PATH] = {0};
        if (GetEnvironmentVariableA("APPDATA", appdata,
                                    sizeof(appdata)) > 0) {
            /* Create the parent directory %APPDATA%\FOS-Antivirus (not the
             * log file itself — that was a bug in v1.1 that created a
             * directory named auto_update.log instead of a file). */
            char dir_path[MAX_PATH] = {0};
            snprintf(dir_path, sizeof(dir_path),
                     "%s\\FOS-Antivirus", appdata);
            CreateDirectoryA(dir_path, NULL);

            /* Now open the LOG FILE (not a directory) for append */
            char log_file[MAX_PATH] = {0};
            snprintf(log_file, sizeof(log_file),
                     "%s\\FOS-Antivirus\\auto_update.log", appdata);
            FILE *f = fopen(log_file, "a");
            if (f) {
                fprintf(f, "[auto_update] check called (inert stub, no-op)\n");
                fclose(f);
            }
        }
    }

    /* Return 0 = no update available. Future implementation: return non-zero
     * if an update is available. */
    return 0;
}
