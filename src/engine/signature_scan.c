#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#define _CRT_SECURE_NO_WARNINGS

#include "signature_scan.h"
#include "signature_scan_sqlite.h"
#include "hash_util.h"
#include "db_hmac.h"

#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <windows.h>
#include <shlwapi.h>
#include <shellapi.h>

/* Mutex to serialise update_signature_db() calls across threads */
static SRWLOCK g_update_lock = SRWLOCK_INIT;

/* ============================================================================
 * Configuration Constants
 * ========================================================================== */

#define GENERIC_THREAT_LABEL "MalwareBazaar.Threat"
#define HASH_TABLE_SIZE      65536
#define USER_AGENT           "FOS-Antivirus/1.0"

/* Python script timeout: 30 minutes (large URLhaus download can take a while) */
#define UPDATE_TIMEOUT_MS    (30 * 60 * 1000)

/* Names of the Python executable candidates, in priority order */
static const char *PYTHON_CANDIDATES[] = {
    "python.exe",
    "python3.exe",
    "pythonw.exe",
    /* Common Windows install locations */
    "C:\\Python313\\python.exe",
    "C:\\Python312\\python.exe",
    "C:\\Python311\\python.exe",
    "C:\\Python310\\python.exe",
    "C:\\Python39\\python.exe",
    NULL /* sentinel */
};

/* Environment variable / env-prefix locations to probe for per-user Python */
static const char *PYTHON_USER_PATHS[] = {
    "LocalAppData\\Programs\\Python\\Python313\\python.exe",
    "LocalAppData\\Programs\\Python\\Python312\\python.exe",
    "LocalAppData\\Programs\\Python\\Python311\\python.exe",
    "LocalAppData\\Programs\\Python\\Python310\\python.exe",
    NULL /* sentinel */
};

/* ============================================================================
 * Global State
 * ========================================================================== */

volatile int update_progress = 0;
volatile int update_error_code = UPDATE_ERR_NONE;
static SigHashTable *g_sig_table = NULL;
static SigHashDb *g_sig_db = NULL;
static SRWLOCK g_db_lock = SRWLOCK_INIT;
static bool g_db_loaded = false;
static bool g_use_sqlite = false;

/* ============================================================================
 * Forward Declarations
 * ========================================================================== */

static bool is_sqlite_database(const char *path);

/* ============================================================================
 * Internal Helpers: Hex Processing
 * ========================================================================== */

static int hex_char_to_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static int hex_string_to_bytes(const char *hex,
                               unsigned char out[SHA256_SIZE]) {
    for (int i = 0; i < SHA256_SIZE; ++i) {
        int hi = hex_char_to_nibble(hex[i * 2]);
        int lo = hex_char_to_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 0;
}

static bool is_valid_sha256_line(const char *line) {
    if (line == NULL) return false;
    for (int i = 0; i < SHA256_SIZE * 2; ++i) {
        if (hex_char_to_nibble(line[i]) < 0) return false;
    }
    return line[SHA256_SIZE * 2] == '\0' || line[SHA256_SIZE * 2] == '\r' ||
           line[SHA256_SIZE * 2] == '\n' || line[SHA256_SIZE * 2] == ' ';
}

/* Validate a signature file. Accepts both SQLite databases and legacy
 * one-hash-per-line text files. */
static int validate_signature_file(const char *path) {
    /* First: is it a SQLite database? */
    if (is_sqlite_database(path)) {
        return sig_db_validate(path);
    }

    /* Otherwise: must be a text file with at least one valid sha256 line */
    FILE *f = fopen(path, "r");
    if (f == NULL) return -1;
    int valid = 0;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '\0' || line[0] == '#') continue;
        if (is_valid_sha256_line(line)) valid++;
        if (valid >= 1) break;
    }
    fclose(f);
    return valid > 0 ? 0 : -1;
}

int signature_db_validate_file(const char *sigdb_path) {
    return validate_signature_file(sigdb_path);
}

bool signature_db_is_sqlite(const char *db_path) {
    if (db_path == NULL) return false;
    return is_sqlite_database(db_path);
}

const char *update_error_code_to_message(int code) {
    switch (code) {
        case UPDATE_ERR_NONE:
            return "Update succeeded.";
        case UPDATE_ERR_NET_INIT:
            return "Update failed: network initialization error (legacy).";
        case UPDATE_ERR_NET_OPEN_URL:
            return "Update failed: unable to open update URL (legacy).";
        case UPDATE_ERR_NET_READ:
            return "Update failed: network read error (legacy).";
        case UPDATE_ERR_IO_WRITE:
            return "Update failed: unable to write download file (legacy).";
        case UPDATE_ERR_EMPTY_DOWNLOAD:
            return "Update failed: server returned empty data (legacy).";
        case UPDATE_ERR_TRUNCATED_DOWNLOAD:
            return "Update failed: incomplete download received (legacy).";
        case UPDATE_ERR_INVALID_ARCHIVE:
            return "Update failed: unsupported archive format (legacy).";
        case UPDATE_ERR_INVALID_FORMAT:
            return "Update failed: database file format invalid.";
        case UPDATE_ERR_MOVE_FAILED:
            return "Update failed: cannot replace local database file (legacy).";
        case UPDATE_ERR_RELOAD_FAILED:
            return "Update failed: database reload failed.";
        case UPDATE_ERR_PYTHON_NOT_FOUND:
            return "Update failed: Python not found. Install Python 3.8+ from python.org "
                   "and ensure it's on your PATH.";
        case UPDATE_ERR_SCRIPT_NOT_FOUND:
            return "Update failed: hash_aggregator.py not found next to the application "
                   "executable. Reinstall FOS Antivirus.";
        case UPDATE_ERR_PYTHON_FAILED:
            return "Update failed: the hash aggregator script returned an error.";
        case UPDATE_ERR_PYTHON_TIMEOUT:
            return "Update failed: the hash aggregator script timed out after 30 minutes. "
                   "Check your network connection.";
        case UPDATE_ERR_HMAC_WRITE:
            return "Update failed: the signature database integrity file could not be "
                   "written (insufficient permissions?). The database location requires "
                   "administrator rights to update.";
        default:
            return "Update failed due to an unknown error.";
    }
}

/* Forward-declare the static state used by update_get_full_error_message().
 * These are defined ONCE here (with initializers) and used by both
 * update_get_full_error_message() above and process_jsonl_line() below. */
static char g_log_path[MAX_PATH] = {0};
static char g_error_msg[512] = {0};

char *update_get_full_error_message(char *out_buf, size_t buf_sz) {
    if (out_buf == NULL || buf_sz == 0) return out_buf;

    const char *base_msg = update_error_code_to_message(update_error_code);

    /* Build a richer message that includes:
     *   1. The base error message for the error code
     *   2. Any specific error captured from the Python script's JSONL output
     *   3. The resolved log file path (so the user knows where to look)
     */
    size_t written = 0;
    int n = snprintf(out_buf, buf_sz, "%s", base_msg);
    if (n < 0 || (size_t)n >= buf_sz) {
        return out_buf;  /* truncated; just return what we have */
    }
    written = (size_t)n;

    /* Append the captured Python error message, if any */
    if (g_error_msg[0] != '\0') {
        n = snprintf(out_buf + written, buf_sz - written,
                     "\n\nDetail: %s", g_error_msg);
        if (n > 0 && (size_t)n < buf_sz - written) {
            written += (size_t)n;
        }
    }

    /* Append the log path, if captured */
    if (g_log_path[0] != '\0') {
        n = snprintf(out_buf + written, buf_sz - written,
                     "\n\nSee log file: %s", g_log_path);
        if (n > 0 && (size_t)n < buf_sz - written) {
            written += (size_t)n;
        }
    } else {
        /* No log path captured — try the default AppData location as a hint */
        n = snprintf(out_buf + written, buf_sz - written,
                     "\n\nSee: %%APPDATA%%\\FOS-Antivirus\\updater.log");
        if (n > 0 && (size_t)n < buf_sz - written) {
            written += (size_t)n;
        }
    }

    return out_buf;
}

static void free_signature_table_unlocked(void) {
    if (g_db_loaded) {
        if (g_use_sqlite && g_sig_db) {
            sig_db_close(g_sig_db);
            g_sig_db = NULL;
            g_use_sqlite = false;
        } else if (!g_use_sqlite && g_sig_table) {
            sig_hash_table_free(g_sig_table);
            g_sig_table = NULL;
        }
        g_db_loaded = false;
    }
}

static bool is_sqlite_database(const char *path) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) return false;

    /* SQLite database files start with "SQLite format 3" */
    unsigned char header[16];
    bool is_sqlite = false;

    if (fread(header, 1, 16, f) == 16) {
        if (header[0] == 'S' && header[1] == 'Q' && header[2] == 'L' &&
            header[3] == 'i' && header[4] == 't' && header[5] == 'e' &&
            header[6] == ' ' && header[7] == 'f') {
            is_sqlite = true;
        }
    }

    fclose(f);
    return is_sqlite;
}

static int load_signature_file_unlocked(const char *sigdb_path) {
    /* I-22/R-09: refuse to load databases whose HMAC-SHA256 integrity file
     * is missing or mismatched. */
    if (db_hmac_verify_file(sigdb_path) != 0) {
        return -1;
    }

    /* Check if this is a SQLite database */
    if (is_sqlite_database(sigdb_path)) {
        SigHashDb *db = sig_db_open(sigdb_path);
        if (!db) return -1;

        free_signature_table_unlocked();
        g_sig_db = db;
        g_use_sqlite = true;
        g_db_loaded = true;
        return 0;
    }

    /* Fall back to text file format (one sha256 per line) */
    FILE *f = fopen(sigdb_path, "r");
    if (f == NULL) return -1;
    SigHashTable *new_table = sig_hash_table_init(HASH_TABLE_SIZE);
    if (!new_table) { fclose(f); return -1; }
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '\0' || line[0] == '#') continue;
        unsigned char hash[SHA256_SIZE];
        if (hex_string_to_bytes(line, hash) == 0) {
            sig_hash_table_add(new_table, hash, GENERIC_THREAT_LABEL);
        }
    }
    fclose(f);
    free_signature_table_unlocked();
    g_sig_table = new_table;
    g_use_sqlite = false;
    g_db_loaded = true;
    return 0;
}

/* ============================================================================
 * Python script discovery
 * ========================================================================== */

/**
 * @brief Locate hash_aggregator.py next to the EXE.
 *
 * I-04 hardening: only the staged location <exe_dir>\scripts\hash_aggregator.py
 * is accepted (the CMake build copies the script there from the source tree).
 * The previous fallbacks (<exe_dir>\hash_aggregator.py and
 * <exe_dir>\..\scripts\...) are removed: they allowed executing a planted
 * script from a writable application directory.
 */
static bool find_aggregator_script(char *out_path, size_t out_sz) {
    char exe_dir[MAX_PATH] = {0};
    if (GetModuleFileNameA(NULL, exe_dir, MAX_PATH) <= 0) return false;
    char *slash = strrchr(exe_dir, '\\');
    if (slash) *slash = '\0';

    snprintf(out_path, out_sz, "%s\\scripts\\hash_aggregator.py", exe_dir);
    if (GetFileAttributesA(out_path) != INVALID_FILE_ATTRIBUTES) {
        return true;
    }
    return false;
}

/**
 * @brief Search for python.exe on PATH, then in well-known install locations.
 *
 * Strategy:
 *   1. %PATH% search via SearchPathA
 *   2. C:\PythonNNN\python.exe for NNN = 313, 312, 311, 310, 39
 *   3. %LOCALAPPDATA%\Programs\Python\PythonNNN\python.exe
 *
 * Returns true and fills python_path on success.
 */
static bool find_python(char *python_path, size_t path_sz) {
    /* 1. Try each candidate name on PATH */
    for (int i = 0; PYTHON_CANDIDATES[i] != NULL; i++) {
        DWORD len = SearchPathA(NULL, PYTHON_CANDIDATES[i], NULL,
                                (DWORD)path_sz, python_path, NULL);
        if (len > 0 && len < path_sz) {
            return true;
        }
    }

    /* 2. Try absolute paths from PYTHON_CANDIDATES */
    for (int i = 0; PYTHON_CANDIDATES[i] != NULL; i++) {
        const char *cand = PYTHON_CANDIDATES[i];
        /* Skip the bare names — already tried via SearchPath above */
        if (strchr(cand, '\\') == NULL) continue;
        if (GetFileAttributesA(cand) != INVALID_FILE_ATTRIBUTES) {
            strncpy(python_path, cand, path_sz - 1);
            python_path[path_sz - 1] = '\0';
            return true;
        }
    }

    /* 3. Try %LOCALAPPDATA%\Programs\Python\PythonNNN\python.exe */
    char local_appdata[MAX_PATH] = {0};
    if (GetEnvironmentVariableA("LOCALAPPDATA", local_appdata,
                                sizeof(local_appdata)) > 0) {
        for (int i = 0; PYTHON_USER_PATHS[i] != NULL; i++) {
            snprintf(python_path, path_sz, "%s\\%s",
                     local_appdata, PYTHON_USER_PATHS[i]);
            if (GetFileAttributesA(python_path) != INVALID_FILE_ATTRIBUTES) {
                return true;
            }
        }
    }

    return false;
}

/* ============================================================================
 * JSONL progress parsing
 *
 * The Python aggregator emits one JSON object per line on stdout, e.g.:
 *   {"event":"progress","source":"malwarebazaar","pct":45,"msg":"downloading"}
 *   {"event":"source_done","source":"malwarebazaar","count":1111618,"elapsed_sec":12.3}
 *   {"event":"complete","total_unique":1123456,"duplicates_removed":8765,"elapsed_sec":187.4}
 *
 * We parse these to update the update_progress global (0-100, with 101=done).
 * ========================================================================== */

/**
 * @brief Extract the integer value of a JSON field like "pct":45 from a line.
 *
 * This is a minimal hand-rolled parser; we don't pull in a full JSON library
 * for one field. Returns true if found.
 */
static bool json_extract_int(const char *line, const char *key, int *out) {
    /* Build a search pattern like "key": */
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\":", key);

    const char *p = strstr(line, pattern);
    if (p == NULL) return false;
    p += strlen(pattern);

    /* Skip whitespace */
    while (*p == ' ' || *p == '\t') p++;

    /* Parse integer (handle negative) */
    int sign = 1;
    if (*p == '-') { sign = -1; p++; }
    if (*p < '0' || *p > '9') return false;

    int val = 0;
    while (*p >= '0' && *p <= '9') {
        val = val * 10 + (*p - '0');
        p++;
    }
    *out = val * sign;
    return true;
}

/**
 * @brief Extract the string value of a JSON field like "event":"complete"
 *        into out_buf (null-terminated). Returns true on success.
 */
static bool json_extract_str(const char *line, const char *key,
                             char *out_buf, size_t buf_sz) {
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\":", key);

    const char *p = strstr(line, pattern);
    if (p == NULL) return false;
    p += strlen(pattern);

    while (*p == ' ' || *p == '\t') p++;
    if (*p != '"') return false;
    p++; /* skip opening quote */

    size_t i = 0;
    while (*p && *p != '"' && i < buf_sz - 1) {
        /* Handle escape sequences minimally (just copy the char after backslash) */
        if (*p == '\\' && *(p + 1)) {
            p++;
        }
        out_buf[i++] = *p++;
    }
    out_buf[i] = '\0';
    return true;
}

/**
 * @brief Update update_progress based on a parsed JSONL line.
 *
 * As of v1.1.1, the Python aggregator emits a WEIGHTED GLOBAL progress
 * percentage in every event (`global_pct` field, 0-100). This is computed
 * on the Python side as a weighted average across all sources (weighted
 * by approximate source size), so the bar moves monotonically forward
 * instead of jumping around when a new source starts.
 *
 * The C side simply reads `global_pct` and displays it verbatim — no
 * per-source averaging on the C side anymore.
 *
 * On "complete" event, set update_progress = 101 (signals UI to close).
 * On "log_path" event, capture the path for inclusion in error messages.
 * On "error" / "source_fail" events: don't change progress (the script's
 * non-zero exit will set the final error).
 */

/* Captured log path from the Python script's "log_path" event. Used to
 * build a more helpful error message when the update fails.
 * (Defined earlier in this file, near update_get_full_error_message().) */

/* Captured error message from the Python script's "error" or "source_fail"
 * events, if any. (Defined earlier in this file.) */

static void reset_progress_state(void) {
    g_log_path[0] = '\0';
    g_error_msg[0] = '\0';
}

static void process_jsonl_line(const char *line) {
    char event[32] = {0};
    if (!json_extract_str(line, "event", event, sizeof(event))) {
        /* Also check for the LOG_PATH= prefix that the script writes to stderr
         * (merged into our stdout pipe). This is a fallback in case the JSONL
         * event is missed. */
        if (strncmp(line, "LOG_PATH=", 9) == 0) {
            const char *p = line + 9;
            size_t len = strlen(p);
            /* Strip trailing newline/whitespace */
            while (len > 0 && (p[len-1] == '\n' || p[len-1] == '\r' ||
                               p[len-1] == ' ' || p[len-1] == '\t')) {
                len--;
            }
            if (len >= sizeof(g_log_path)) len = sizeof(g_log_path) - 1;
            memcpy(g_log_path, p, len);
            g_log_path[len] = '\0';
        }
        return;
    }

    if (strcmp(event, "log_path") == 0) {
        /* Capture the resolved log path for error messages */
        char path[MAX_PATH] = {0};
        if (json_extract_str(line, "path", path, sizeof(path))) {
            strncpy(g_log_path, path, sizeof(g_log_path) - 1);
            g_log_path[sizeof(g_log_path) - 1] = '\0';
        }
        return;
    }

    if (strcmp(event, "progress") == 0 ||
        strcmp(event, "source_done") == 0 ||
        strcmp(event, "source_skip") == 0 ||
        strcmp(event, "source_fail") == 0) {
        /* All these events carry a global_pct field — use it verbatim */
        int global_pct = -1;
        if (json_extract_int(line, "global_pct", &global_pct) && global_pct >= 0) {
            update_progress = global_pct;
        }
        /* If this is a source_fail, also capture the error message */
        if (strcmp(event, "source_fail") == 0) {
            char src[32] = {0};
            char err[400] = {0};
            if (json_extract_str(line, "source", src, sizeof(src)) &&
                json_extract_str(line, "error", err, sizeof(err))) {
                snprintf(g_error_msg, sizeof(g_error_msg),
                         "Source '%s' failed: %s", src, err);
            }
        }
    } else if (strcmp(event, "complete") == 0) {
        int global_pct = 100;
        json_extract_int(line, "global_pct", &global_pct);
        update_progress = 100;
    } else if (strcmp(event, "error") == 0) {
        /* Capture the error message */
        char err[400] = {0};
        if (json_extract_str(line, "error", err, sizeof(err))) {
            strncpy(g_error_msg, err, sizeof(g_error_msg) - 1);
            g_error_msg[sizeof(g_error_msg) - 1] = '\0';
        }
    }
}

/* ============================================================================
 * Public Functions: Scan API
 * ========================================================================== */

int signature_db_load(const char *sigdb_path) {
    AcquireSRWLockExclusive(&g_db_lock);
    if (g_db_loaded) {
        ReleaseSRWLockExclusive(&g_db_lock);
        return 0;
    }
    int rc = load_signature_file_unlocked(sigdb_path);
    ReleaseSRWLockExclusive(&g_db_lock);
    return rc;
}

int signature_db_reload(const char *sigdb_path) {
    AcquireSRWLockExclusive(&g_db_lock);
    int rc = load_signature_file_unlocked(sigdb_path);
    ReleaseSRWLockExclusive(&g_db_lock);
    return rc;
}

void signature_db_unload(void) {
    AcquireSRWLockExclusive(&g_db_lock);
    free_signature_table_unlocked();
    ReleaseSRWLockExclusive(&g_db_lock);
}

int signature_scan_hash(const unsigned char hash[SHA256_SIZE],
                        SignatureResult *out) {
    AcquireSRWLockShared(&g_db_lock);
    if (!g_db_loaded || out == NULL) {
        ReleaseSRWLockShared(&g_db_lock);
        return -1;
    }
    out->matched = false;
    out->label = NULL;

    if (g_use_sqlite && g_sig_db) {
        /* SQLite lookup */
        const char *label = NULL;
        int result = sig_db_lookup_hash(g_sig_db, hash, &label);
        if (result == 1) {
            out->matched = true;
            out->label = label;
        }
    } else if (!g_use_sqlite && g_sig_table) {
        /* Hash table lookup (legacy text format) */
        const char *label = sig_hash_table_lookup(g_sig_table, hash);
        if (label) {
            out->matched = true;
            out->label = label;
        }
    }

    ReleaseSRWLockShared(&g_db_lock);
    return 0;
}

/* ============================================================================
 * Update Mechanism (Shell out to scripts/hash_aggregator.py)
 *
 * Replaces the legacy WinINet downloader. The Python aggregator pulls from
 * 5 public no-auth sources (MalwareBazaar, URLhaus, ThreatFox, ESET,
 * TweetFeed) into a single SQLite database with a backward-compat view
 * named `malware_hashes` so the existing C-side lookup query still works.
 * ========================================================================== */

/**
 * @brief Read stdout from the Python process line by line, parse JSONL,
 *        and update update_progress. Runs in a worker thread.
 */
static DWORD WINAPI stdout_reader_thread(LPVOID param) {
    HANDLE hRead = (HANDLE)param;
    char buf[8192];
    char line[2048];
    size_t line_len = 0;

    for (;;) {
        DWORD bytes_read = 0;
        BOOL ok = ReadFile(hRead, buf, sizeof(buf) - 1, &bytes_read, NULL);
        if (!ok || bytes_read == 0) {
            /* Process stdout closed or error */
            break;
        }
        buf[bytes_read] = '\0';

        /* Split into lines and process each */
        for (DWORD i = 0; i < bytes_read; i++) {
            if (buf[i] == '\n' || buf[i] == '\r') {
                if (line_len > 0) {
                    line[line_len] = '\0';
                    process_jsonl_line(line);
                    line_len = 0;
                }
            } else if (line_len < sizeof(line) - 1) {
                line[line_len++] = buf[i];
            }
            /* If line is too long, just drop the overflow chars */
        }
        /* Handle a trailing partial line */
        if (line_len > 0 && line_len < sizeof(line) - 1) {
            /* Don't process yet — wait for newline or EOF */
        }
    }

    /* Process any final partial line */
    if (line_len > 0) {
        line[line_len] = '\0';
        process_jsonl_line(line);
    }

    return 0;
}

int update_signature_db(const char *db_path) {
    /* Serialise: only one update at a time across all threads */
    AcquireSRWLockExclusive(&g_update_lock);

    char python_path[MAX_PATH] = {0};
    char script_path[MAX_PATH] = {0};
    char cmdline[3 * MAX_PATH] = {0};
    int result = -1;

    update_progress = 0;
    update_error_code = UPDATE_ERR_NONE;
    reset_progress_state();

    /* 1. Find Python */
    if (!find_python(python_path, sizeof(python_path))) {
        update_error_code = UPDATE_ERR_PYTHON_NOT_FOUND;
        update_progress = -1;
        ReleaseSRWLockExclusive(&g_update_lock);
        return -1;
    }

    /* 2. Find the aggregator script */
    if (!find_aggregator_script(script_path, sizeof(script_path))) {
        update_error_code = UPDATE_ERR_SCRIPT_NOT_FOUND;
        update_progress = -1;
        ReleaseSRWLockExclusive(&g_update_lock);
        return -1;
    }

    /* 3. Build command line: python.exe "<script>" --db "<db_path>" update.
     *    All paths are quoted in case of spaces (e.g. "C:\Program Files\..."). */
    snprintf(cmdline, sizeof(cmdline),
             "\"%s\" \"%s\" --db \"%s\" update",
             python_path, script_path, db_path);

    /* 4. Set up stdout pipe so we can read JSONL progress */
    SECURITY_ATTRIBUTES sa = {sizeof(SECURITY_ATTRIBUTES), NULL, TRUE};
    HANDLE hChildStdoutRead = NULL, hChildStdoutWrite = NULL;
    if (!CreatePipe(&hChildStdoutRead, &hChildStdoutWrite, &sa, 0)) {
        update_error_code = UPDATE_ERR_PYTHON_FAILED;
        update_progress = -1;
        ReleaseSRWLockExclusive(&g_update_lock);
        return -1;
    }
    /* Ensure the read handle is NOT inherited */
    SetHandleInformation(hChildStdoutRead, HANDLE_FLAG_INHERIT, 0);

    /* 5. Launch the Python process */
    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hChildStdoutWrite;
    si.hStdError = hChildStdoutWrite; /* merge stderr into the same pipe */
    si.hStdInput = NULL;

    PROCESS_INFORMATION pi = {0};

    BOOL launched = CreateProcessA(
        NULL,          /* lpApplicationName (NULL = use cmdline) */
        cmdline,       /* lpcmdline (must be mutable) */
        NULL,          /* lpProcessAttributes */
        NULL,          /* lpThreadAttributes */
        TRUE,          /* bInheritHandles */
        CREATE_NO_WINDOW, /* dwCreationFlags */
        NULL,          /* lpEnvironment */
        NULL,          /* lpCurrentDirectory */
        &si, &pi);

    /* Close the write end of the pipe in the parent — important! */
    CloseHandle(hChildStdoutWrite);
    hChildStdoutWrite = NULL;

    if (!launched) {
        CloseHandle(hChildStdoutRead);
        update_error_code = UPDATE_ERR_PYTHON_FAILED;
        update_progress = -1;
        ReleaseSRWLockExclusive(&g_update_lock);
        return -1;
    }

    /* 6. Start the stdout reader thread (parses JSONL progress) */
    HANDLE hReader = CreateThread(NULL, 0, stdout_reader_thread,
                                  hChildStdoutRead, 0, NULL);

    /* 7. Wait for the Python process to finish (with timeout) */
    DWORD wait_result = WaitForSingleObject(pi.hProcess, UPDATE_TIMEOUT_MS);
    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);

    /* 8. Wait for the reader thread to drain remaining output */
    if (hReader) {
        WaitForSingleObject(hReader, 5000); /* 5s grace */
        CloseHandle(hReader);
    }
    CloseHandle(hChildStdoutRead);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    if (wait_result == WAIT_TIMEOUT) {
        update_error_code = UPDATE_ERR_PYTHON_TIMEOUT;
        update_progress = -1;
        ReleaseSRWLockExclusive(&g_update_lock);
        return -1;
    }

    if (exit_code != 0) {
        /* Python script failed. Check if any sources succeeded —
         * exit_code 0 = at least one source succeeded. */
        update_error_code = UPDATE_ERR_PYTHON_FAILED;
        update_progress = -1;
        ReleaseSRWLockExclusive(&g_update_lock);
        return -1;
    }

    /* 9. Validate the resulting DB file */
    update_progress = 98;  /* Loading into engine */
    if (signature_db_validate_file(db_path) != 0) {
        update_error_code = UPDATE_ERR_INVALID_FORMAT;
        update_progress = -1;
        ReleaseSRWLockExclusive(&g_update_lock);
        return -1;
    }

    /* 9b. Write the HMAC-SHA256 integrity file next to the DB (I-22/R-09).
     * Load will refuse the DB without it. */
    if (db_hmac_write_file(db_path) != 0) {
        update_error_code = UPDATE_ERR_HMAC_WRITE;
        update_progress = -1;
        ReleaseSRWLockExclusive(&g_update_lock);
        return -1;
    }

    /* 10. Reload the database into the engine */
    if (signature_db_reload(db_path) != 0) {
        update_error_code = UPDATE_ERR_RELOAD_FAILED;
        update_progress = -1;
        ReleaseSRWLockExclusive(&g_update_lock);
        return -1;
    }

    update_progress = 101;  /* completed */
    update_error_code = UPDATE_ERR_NONE;
    result = 0;

    ReleaseSRWLockExclusive(&g_update_lock);
    return result;
}


