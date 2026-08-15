#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#define _CRT_SECURE_NO_WARNINGS

#include "signature_scan.h"
#include "signature_scan_sqlite.h"
#include "hash_util.h"
#include "db_hmac.h"
#include "script_verify.h"   /* I-19: SHA-256 pin check for hash_aggregator.py */
#include "path_utils.h"      /* FOS_MAX_PATH (MAP-12: wide command line) */

#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <wchar.h>
#include <windows.h>
#include <shlwapi.h>
#include <shellapi.h>
#include <wintrust.h>
#include <softpub.h>

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

/* ============================================================================
 * Python interpreter verification (MAPv3 U-06)
 *
 * The aggregator script is SHA-256 pinned (I-19), but the interpreter
 * executing it is attacker-controllable via PATH. Before any python.exe runs
 * with the AV's privileges, it must pass Authenticode verification AND its
 * signer certificate must belong to the Python Software Foundation.
 * ========================================================================== */

/**
 * @brief Verify that python_path is Authenticode-signed by the Python
 *        Software Foundation.
 *
 * Uses WinVerifyTrust (WINTRUST_ACTION_GENERIC_VERIFY_V2) on the file and
 * extracts the signer certificate subject from the provider state. The chain
 * is validated against the local cache only (no network revocation fetch) so
 * updates still work offline; the signer-subject check is the decisive gate.
 *
 * @return true when the file is validly signed by the PSF.
 */
static bool verify_python_interpreter(const char *python_path)
{
    if (!python_path || !*python_path) return false;

    wchar_t wide[FOS_MAX_PATH];
    if (MultiByteToWideChar(CP_UTF8, 0, python_path, -1, wide, FOS_MAX_PATH) <= 0)
        return false;

    WINTRUST_FILE_INFO file_info;
    memset(&file_info, 0, sizeof(file_info));
    file_info.cbStruct = sizeof(file_info);
    file_info.pcwszFilePath = wide;

    WINTRUST_DATA wtd;
    memset(&wtd, 0, sizeof(wtd));
    wtd.cbStruct = sizeof(wtd);
    wtd.dwUnionChoice = WTD_CHOICE_FILE;
    wtd.pFile = &file_info;
    wtd.dwStateAction = WTD_STATEACTION_VERIFY;
    wtd.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG rc = WinVerifyTrust(NULL, &action, &wtd);
    if (rc != ERROR_SUCCESS) {
        return false;
    }

    bool trusted = false;
    do {
        CRYPT_PROVIDER_DATA *pdata = WTHelperProvDataFromStateData(wtd.hWVTStateData);
        if (pdata == NULL) break;
        CRYPT_PROVIDER_SGNR *psgnr = WTHelperGetProvSignerFromChain(pdata, 0, FALSE, 0);
        if (psgnr == NULL || psgnr->csCertChain == 0 || psgnr->pasCertChain == NULL) break;

        /* The first certificate in the signer chain is the leaf signer cert. */
        CRYPT_PROVIDER_CERT *signer_cert = &psgnr->pasCertChain[0];
        if (signer_cert == NULL || signer_cert->pCert == NULL) break;

        /* The signer certificate subject must identify the PSF. */
        wchar_t subject[256];
        DWORD n = CertNameToStrW(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                 &signer_cert->pCert->pCertInfo->Subject,
                                 CERT_X500_NAME_STR, subject, 256);
        if (n <= 0) break;
        trusted = (StrStrIW(subject, L"Python Software Foundation") != NULL);
    } while (0);

    /* Close the WinVerifyTrust state so the provider is freed. */
    wtd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &action, &wtd);

    return trusted;
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
        case UPDATE_ERR_SCRIPT_TAMPERED:
            return "Update failed: hash_aggregator.py failed its integrity check. The "
                   "script next to the executable does not match the build-time hash; "
                   "reinstall FOS Antivirus or update the build.";
        case UPDATE_ERR_PYTHON_UNTRUSTED:
            return "Update failed: the Python interpreter is not digitally signed by "
                   "the Python Software Foundation and was refused. Install Python "
                   "3.8+ from python.org and try again.";
        case UPDATE_ERR_SCRIPT_DIR_DIRTY:
            return "Update failed: unexpected Python module (.py) files found next "
                   "to hash_aggregator.py. Remove them (they can hijack the update "
                   "run) and try again.";
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

    /* Fall back to text file format (one sha256 per line, optionally
     * "hash <label>"). MAP-11: labels are preserved per entry instead of
     * collapsing everything to a generic label. */
    FILE *f = fopen(sigdb_path, "r");
    if (f == NULL) return -1;
    SigHashTable *new_table = sig_hash_table_init(HASH_TABLE_SIZE);
    if (!new_table) { fclose(f); return -1; }
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '\0' || line[0] == '#') continue;

        /* Bounded copy of the first 64 chars guarantees hex_string_to_bytes
         * never reads past the end of a short line. */
        char hash_hex[SHA256_SIZE * 2 + 1];
        strncpy_s(hash_hex, sizeof(hash_hex), line, SHA256_SIZE * 2);
        hash_hex[SHA256_SIZE * 2] = '\0';

        unsigned char hash[SHA256_SIZE];
        if (hex_string_to_bytes(hash_hex, hash) != 0) continue;

        /* MAP-11: parse an optional "hash <label>" attribution. Everything
         * after the first space/tab (leading whitespace trimmed) becomes the
         * label, up to the hash-table's 128-char limit. */
        const char *label = GENERIC_THREAT_LABEL;
        char label_buf[129] = {0};
        if (line[SHA256_SIZE * 2] == ' ' || line[SHA256_SIZE * 2] == '\t') {
            const char *rest = line + SHA256_SIZE * 2;
            while (*rest == ' ' || *rest == '\t') rest++;
            if (*rest != '\0' && strlen(rest) <= 128) {
                strncpy_s(label_buf, sizeof(label_buf), rest, _TRUNCATE);
                label = label_buf;
            }
        }
        sig_hash_table_add(new_table, hash, label);
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
 * @brief U-06b: refuse to run when extra .py modules sit beside the script.
 *
 * Python prepends the script's directory to sys.path (before Python 3.11
 * there is no supported way to disable this from the command line). A
 * planted scripts\json.py (or csv.py, sqlite3.py, ...) would be imported
 * INSTEAD of the standard-library module, executing attacker code inside
 * the PSF-signed interpreter. The pinned script itself is covered by the
 * I-19 hash pin, but arbitrary new files are not — so the whole directory
 * must contain no other importable module.
 *
 * @return 0 when the scripts dir is clean, -1 when it is dirty.
 */
static int verify_scripts_dir_clean(const char *script_path) {
    char dir[MAX_PATH];
    strncpy_s(dir, sizeof(dir), script_path, _TRUNCATE);
    char *slash = strrchr(dir, '\\');
    if (!slash) return -1;
    *slash = '\0';

    wchar_t wdir[MAX_PATH];
    if (MultiByteToWideChar(CP_UTF8, 0, dir, -1, wdir, MAX_PATH) <= 0) return -1;
    wchar_t pattern[MAX_PATH];
    _snwprintf_s(pattern, MAX_PATH, _TRUNCATE, L"%s\\*.py", wdir);

    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileExW(pattern, FindExInfoBasic, &fd, FindExSearchNameMatch,
                                NULL, FIND_FIRST_EX_LARGE_FETCH);
    if (h == INVALID_HANDLE_VALUE) return 0; /* no extra modules */

    int dirty = 0;
    do {
        if (_wcsicmp(fd.cFileName, L"hash_aggregator.py") != 0) {
            dirty = -1;
            break;
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return dirty;
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

    /* MAPv3 U-06: the interpreter must be Authenticode-signed by the Python
     * Software Foundation before it is allowed to execute the pinned
     * aggregator script. An attacker who modifies PATH to point at a
     * malicious python.exe is stopped here, before any code runs with the
     * AV's privileges. */
    if (!verify_python_interpreter(python_path)) {
        update_error_code = UPDATE_ERR_PYTHON_UNTRUSTED;
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

    /* 3. I-19: verify the staged script against its build-time SHA-256 pin.
     *    A planted or tampered script (path-planting, drive-by edit) fails
     *    here and is never executed. */
    if (signature_script_verify(script_path) != 0) {
        update_error_code = UPDATE_ERR_SCRIPT_TAMPERED;
        update_progress = -1;
        ReleaseSRWLockExclusive(&g_update_lock);
        return -1;
    }

    /* 3b. U-06b: no extra importable modules beside the script (see
     *     verify_scripts_dir_clean). */
    if (verify_scripts_dir_clean(script_path) != 0) {
        update_error_code = UPDATE_ERR_SCRIPT_DIR_DIRTY;
        update_progress = -1;
        ReleaseSRWLockExclusive(&g_update_lock);
        return -1;
    }

    /* 4. MAP-12: build the command line with CreateProcess quoting rules.
     *    Every path is wrapped in double quotes ("C:\Program Files\..." etc.).
     *    No shell is involved (no system()/ShellExecuteExA — a security
     *    product must never route its update through a shell).
     *
     *    U-06 hardening: -E ignores all PYTHON* environment variables
     *    (PYTHONPATH/PYTHONHOME/...) inherited from the AV process, so a
     *    user-level environment cannot shadow the interpreter's imports.
     *    (-E is available on every Python 3 release; -P/-I would also drop
     *    the script-dir prepend but only exist since 3.11 — the scripts-dir
     *    check above covers that vector for older interpreters.) */
    wchar_t python_w[FOS_MAX_PATH], script_w[FOS_MAX_PATH], db_w[FOS_MAX_PATH];
    wchar_t cmdline_w[FOS_MAX_PATH * 4];
    if (MultiByteToWideChar(CP_UTF8, 0, python_path, -1,
                            python_w, FOS_MAX_PATH) <= 0 ||
        MultiByteToWideChar(CP_UTF8, 0, script_path, -1,
                            script_w, FOS_MAX_PATH) <= 0 ||
        MultiByteToWideChar(CP_UTF8, 0, db_path, -1,
                            db_w, FOS_MAX_PATH) <= 0) {
        update_error_code = UPDATE_ERR_PYTHON_FAILED;
        update_progress = -1;
        ReleaseSRWLockExclusive(&g_update_lock);
        return -1;
    }
    if (_snwprintf_s(cmdline_w, FOS_MAX_PATH * 4, _TRUNCATE,
                     L"\"%s\" -E \"%s\" --db \"%s\" update",
                     python_w, script_w, db_w) < 0) {
        update_error_code = UPDATE_ERR_PYTHON_FAILED;
        update_progress = -1;
        ReleaseSRWLockExclusive(&g_update_lock);
        return -1;
    }

    /* 5. Set up stdout pipe so we can read JSONL progress */
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

    /* 6. Launch the Python process.
     *    MAP-12: CreateProcessW with lpApplicationName set explicitly to the
     *    resolved python.exe absolute path (never NULL-with-cmdline) and the
     *    script path quoted per CreateProcess quoting rules. This closes the
     *    argument-injection surface on paths containing spaces or special
     *    characters. */
    STARTUPINFOW si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hChildStdoutWrite;
    si.hStdError = hChildStdoutWrite; /* merge stderr into the same pipe */
    si.hStdInput = NULL;

    PROCESS_INFORMATION pi = {0};

    BOOL launched = CreateProcessW(
        python_w,      /* lpApplicationName: resolved python.exe absolute path */
        cmdline_w,     /* lpCommandLine: quoted script + args (mutable)       */
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

    /* 7. Start the stdout reader thread (parses JSONL progress) */
    HANDLE hReader = CreateThread(NULL, 0, stdout_reader_thread,
                                  hChildStdoutRead, 0, NULL);

    /* 8. Wait for the Python process to finish (with timeout) */
    DWORD wait_result = WaitForSingleObject(pi.hProcess, UPDATE_TIMEOUT_MS);

    if (wait_result == WAIT_TIMEOUT) {
        /* Kill the orphaned aggregator: leaving it running would keep the
         * aggregator's cross-process FileLock held, so every later update
         * would fail with "another instance is already running" until the
         * orphan happens to exit. */
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 5000);
    }

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


