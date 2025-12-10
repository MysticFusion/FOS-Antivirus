#define _CRT_SECURE_NO_WARNINGS
#include "signature_scan.h"
#include "scan_bridge.h"
#include "scan_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <stdint.h>
#include <windows.h> 

#define SHA256_SIZE 32
#define HEXLEN (SHA256_SIZE * 2)
#define GENERIC_LABEL "MalwareBazaar_Threat"
#define QUARANTINE_DIR "Quarantine"
#define HISTORY_LOG "history.log"
#define XOR_KEY 0x5A 
#define Q_MAGIC 0xDEADCAFE // Magic number to identify our files

// --- The Professional Quarantine Header ---
// Every file in the quarantine folder will start with this struct.
typedef struct {
    uint32_t magic;         // verification bytes
    uint64_t timestamp;     // when it was quarantined
    uint32_t path_len;      // length of original path string
    char threat_name[64];   // name of the virus
} QuarantineHeader;

// --- Signature Structs ---
typedef struct {
    unsigned char hash[SHA256_SIZE];
    char *label;
} sig_entry;

typedef struct {
    sig_entry *items;
    size_t count;
    size_t cap;
} sig_db;

// --- Helpers ---
static void log_to_history(const char *display_name, const char *orig, const char *q_path) {
    FILE *f = fopen(HISTORY_LOG, "a");
    if (!f) return;
    
    // Get Time String
    time_t now = time(NULL);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));

    // Format: TIME|THREAT|ORIGINAL|QUARANTINE
    fprintf(f, "%s|%s|%s|%s\n", time_str, display_name, orig, q_path);
    fclose(f);
}

// --- CORE: Quarantine Function ---
static int quarantine_file(const char *src_path, const char *threat_label) {
    CreateDirectoryA(QUARANTINE_DIR, NULL);

    // 1. Generate Unique Name (Timestamp + Hash-ish)
    // Using current ticks ensures we never overwrite a file, even if names are same
    char dst_filename[MAX_PATH];
    const char *orig_name = strrchr(src_path, '\\');
    orig_name = orig_name ? orig_name + 1 : src_path;
    
    snprintf(dst_filename, MAX_PATH, "%s\\%lu_%s.vir", QUARANTINE_DIR, GetTickCount(), orig_name);

    FILE *fin = fopen(src_path, "rb");
    if (!fin) return -1;

    FILE *fout = fopen(dst_filename, "wb");
    if (!fout) { fclose(fin); return -1; }

    // 2. Prepare and Write Header
    QuarantineHeader header;
    header.magic = Q_MAGIC;
    header.timestamp = (uint64_t)time(NULL);
    header.path_len = (uint32_t)strlen(src_path);
    strncpy(header.threat_name, threat_label, 63);
    
    fwrite(&header, sizeof(QuarantineHeader), 1, fout);
    
    // 3. Write Original Path (So we can restore even if history log is deleted!)
    fwrite(src_path, 1, header.path_len, fout);

    // 4. Encrypt and Write Payload
    unsigned char buffer[4096];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), fin)) > 0) {
        for (size_t i = 0; i < bytes; i++) buffer[i] ^= XOR_KEY;
        fwrite(buffer, 1, bytes, fout);
    }

    fclose(fin);
    fclose(fout);

    // 5. Delete Original and Log
    if (DeleteFileA(src_path)) {
        log_to_history(threat_label, src_path, dst_filename);
        return 0;
    }
    return -1;
}

// --- CORE: Restore Function ---
int restore_file_from_quarantine(const char *q_path, const char *dest_path_override) {
    FILE *fin = fopen(q_path, "rb");
    if (!fin) return -1;

    // 1. Verify Header
    QuarantineHeader header;
    if (fread(&header, sizeof(QuarantineHeader), 1, fin) != 1) { fclose(fin); return -2; }
    
    if (header.magic != Q_MAGIC) {
        // Not a valid quarantine file from this AV
        fclose(fin); 
        return -3; 
    }

    // 2. Read Stored Path (We ignore it if override is provided, but we must skip the bytes)
    char *stored_path = malloc(header.path_len + 1);
    fread(stored_path, 1, header.path_len, fin);
    stored_path[header.path_len] = 0;

    // Use override if provided (from history log), otherwise use stored path
    const char *final_dest = (dest_path_override) ? dest_path_override : stored_path;

    FILE *fout = fopen(final_dest, "wb");
    if (!fout) { 
        free(stored_path); fclose(fin); return -4; // Permission error?
    }

    // 3. Decrypt Payload
    unsigned char buffer[4096];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), fin)) > 0) {
        for (size_t i = 0; i < bytes; i++) buffer[i] ^= XOR_KEY;
        fwrite(buffer, 1, bytes, fout);
    }

    free(stored_path);
    fclose(fin);
    fclose(fout);

    // 4. Delete from Quarantine
    DeleteFileA(q_path);
    return 0;
}

// --- Standard SigDB Functions (Unchanged) ---
static int hexnibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}
static int hex_to_bytes(const char *hex, unsigned char out[SHA256_SIZE]) {
    for (int i = 0; i < SHA256_SIZE; ++i) {
        int hi = hexnibble(hex[2*i]);
        int lo = hexnibble(hex[2*i+1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (hi << 4) | lo;
    }
    return 0;
}
static int hash_equals(const unsigned char h1[SHA256_SIZE], const unsigned char h2[SHA256_SIZE]) {
    return memcmp(h1, h2, SHA256_SIZE) == 0;
}
static int sigdb_add(sig_db *db, const unsigned char hash[SHA256_SIZE], const char *label) {
    if (db->count >= db->cap) {
        size_t new_cap = (db->cap == 0) ? 64 : db->cap * 2;
        sig_entry *new_items = realloc(db->items, new_cap * sizeof(sig_entry));
        if (!new_items) return -1;
        db->items = new_items;
        db->cap = new_cap;
    }
    memcpy(db->items[db->count].hash, hash, SHA256_SIZE);
    db->items[db->count].label = strdup(label);
    db->count++;
    return 0;
}
static int sigdb_load(sig_db *db, const char *sigdb_path) {
    memset(db, 0, sizeof(sig_db));
    FILE *f = fopen(sigdb_path, "r");
    if (!f) return -1;
    char line[128];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        if (line[0] == 0 || line[0] == '#') continue;
        unsigned char hash[SHA256_SIZE];
        if (hex_to_bytes(line, hash) == 0) sigdb_add(db, hash, GENERIC_LABEL);
    }
    fclose(f);
    return 0;
}
static void sigdb_free(sig_db *db) {
    if (db) {
        for (size_t i = 0; i < db->count; ++i) free(db->items[i].label);
        free(db->items);
        memset(db, 0, sizeof(sig_db));
    }
}

// --- Scanning Callback ---
typedef struct { const sig_db *db; } scan_ctx;

static int file_scan_cb(const char *path, const struct stat *st, void *ctxptr) {
    (void)st;
    scan_ctx *ctx = (scan_ctx *)ctxptr;

    g_mutex_lock(&global_scan_ctx.mutex);
    snprintf(global_scan_ctx.current_file, 255, "%s", path);
    global_scan_ctx.files_scanned++;
    if (global_scan_ctx.stop_requested) {
        g_mutex_unlock(&global_scan_ctx.mutex);
        return SCANCORE_FATAL_ERR; 
    }
    g_mutex_unlock(&global_scan_ctx.mutex);

    unsigned char hash[SHA256_SIZE];
    if (compute_file_sha256(path, hash) != 0) return SCANCORE_FILE_ERR;

    for (size_t i = 0; i < ctx->db->count; ++i) {
        if (hash_equals(hash, ctx->db->items[i].hash)) {
            
            g_mutex_lock(&global_scan_ctx.mutex);
            global_scan_ctx.threats_found++;
            snprintf(global_scan_ctx.last_threat, 255, "%s", ctx->db->items[i].label);
            g_mutex_unlock(&global_scan_ctx.mutex);

            printf("\n[ALERT] THREAT FOUND: %s\n", path);

            // New Quarantine Call
            if (quarantine_file(path, ctx->db->items[i].label) == 0) {
                return SCANCORE_HANDLED; 
            } else {
                return SCANCORE_MATCH; 
            }
        }
    }
    return SCANCORE_OK;
}

int signature_scan(const char *sigdb_path, const char *path_to_scan) {
    sig_db db;
    if (sigdb_load(&db, sigdb_path) != 0) return SCANCORE_FATAL_ERR;
    scan_ctx ctx = { .db = &db };
    int result = scan_path(path_to_scan, file_scan_cb, &ctx);
    sigdb_free(&db);
    return result;
}