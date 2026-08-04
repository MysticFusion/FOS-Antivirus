/**
 * test_scan_nodb.c -- MAP-01 / MAP-09 regression test (P0 blocker).
 *
 * Asserts the decoupling fix: a directory scan dispatched with NO signature
 * database must still enumerate and count files (files_scanned > 0), must
 * return SCANCORE_OK (not a fatal DB error), and must expose the advisory
 * `db_available == false` state — which the UI renders as the
 * "heuristic-only mode" banner instead of the bogus "Files Scanned: 0"
 * complete screen.
 *
 * Also covers MAP-11: legacy text signature databases with "hash <label>"
 * lines preserve per-entry attribution instead of collapsing to the generic
 * label.
 */
#include "unity.h"

#include "db_hmac.h"
#include "hash_util.h"
#include "scan_core.h"
#include "scan_progress.h"
#include "signature_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define GENERIC_LABEL "MalwareBazaar.Threat"

/* The production definition lives in src/main.c; this test harness is a
 * standalone binary, so it provides the shared scan context itself. */
ScanContext global_scan_ctx;

static char g_scan_dir[MAX_PATH];
static char g_db_path[MAX_PATH];

static void write_file(const char *path, const char *content)
{
    FILE *f = fopen(path, "wb");
    TEST_ASSERT_NOT_NULL(f);
    fwrite(content, 1, strlen(content), f);
    fclose(f);
}

static void hex_to_bytes(const char *hex, unsigned char out[SHA256_SIZE])
{
    for (int i = 0; i < SHA256_SIZE; i++) {
        unsigned v = 0;
        TEST_ASSERT_EQUAL_INT(1, sscanf(hex + i * 2, "%2x", &v));
        out[i] = (unsigned char)v;
    }
}

/* ============================================================================
 * MAP-01 / MAP-09: scan with no DB present must still enumerate
 * ========================================================================== */

static void test_scan_without_db_still_enumerates(void)
{
    char f1[MAX_PATH], f2[MAX_PATH], no_db[MAX_PATH];
    snprintf(f1, sizeof(f1), "%s\\hello.exe", g_scan_dir);
    snprintf(f2, sizeof(f2), "%s\\payload.scr", g_scan_dir);
    write_file(f1, "not a real PE, but the pipeline hashes any whitelisted file\n");
    write_file(f2, "also not a PE; just needs to be enumerated\n");

    snprintf(no_db, sizeof(no_db), "%s\\nonexistent_signatures.db", g_scan_dir);

    int rc = scan_core_start_scan(no_db, g_scan_dir, false, false);

    /* The scan must complete normally (no fatal DB gate) ... */
    TEST_ASSERT_EQUAL_INT(SCANCORE_OK, rc);
    /* ... the DB availability must be exposed as advisory-false ... */
    TEST_ASSERT_FALSE(scan_core_db_available());
    /* ... and the files must actually be counted (the P0 "instant 0 files"
     * symptom is exactly what this assertion kills). */
    TEST_ASSERT_TRUE(scan_progress_files_scanned() >= 2);
}

/* ============================================================================
 * MAP-11: text DB "hash <label>" lines preserve attribution
 * ========================================================================== */

static void test_text_db_labels_preserved(void)
{
    /* Two entries: one labeled, one unlabeled (falls back to generic). */
    static const char k_db[] =
        "# MAP-11 fixture\n"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa Trojan.Agent\n"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n";
    write_file(g_db_path, k_db);

    /* The loader refuses DBs without a valid HMAC (I-22/R-09), so compute
     * one in-process (same DPAPI-derived key => verifies). */
    TEST_ASSERT_EQUAL_INT(0, db_hmac_write_file(g_db_path));

    TEST_ASSERT_EQUAL_INT(0, signature_db_load(g_db_path));

    unsigned char h[SHA256_SIZE];
    SignatureResult sig = {0};

    hex_to_bytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", h);
    TEST_ASSERT_EQUAL_INT(0, signature_scan_hash(h, &sig));
    TEST_ASSERT_TRUE(sig.matched);
    TEST_ASSERT_TRUE(sig.label != NULL);
    TEST_ASSERT_EQUAL_STRING("Trojan.Agent", sig.label);

    hex_to_bytes("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", h);
    TEST_ASSERT_EQUAL_INT(0, signature_scan_hash(h, &sig));
    TEST_ASSERT_TRUE(sig.matched);
    TEST_ASSERT_EQUAL_STRING(GENERIC_LABEL, sig.label);
}

static void test_malformed_text_db_lines_skipped(void)
{
    static const char k_db[] =
        "not-a-hash\n"
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\n";
    write_file(g_db_path, k_db);
    TEST_ASSERT_EQUAL_INT(0, db_hmac_write_file(g_db_path));
    TEST_ASSERT_EQUAL_INT(0, signature_db_load(g_db_path));

    unsigned char h[SHA256_SIZE];
    SignatureResult sig = {0};
    hex_to_bytes("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", h);
    TEST_ASSERT_EQUAL_INT(0, signature_scan_hash(h, &sig));
    TEST_ASSERT_TRUE(sig.matched);
    TEST_ASSERT_EQUAL_STRING(GENERIC_LABEL, sig.label);
}

void setUp(void) {}
void tearDown(void)
{
    char hmac_path[MAX_PATH];
    snprintf(hmac_path, sizeof(hmac_path), "%s.hmac", g_db_path);
    DeleteFileA(hmac_path);
    DeleteFileA(g_db_path);
    signature_db_unload();
}

int main(void)
{
    const char *tmp = getenv("TEMP");
    if (!tmp) tmp = "C:\\Windows\\Temp";
    snprintf(g_scan_dir, sizeof(g_scan_dir), "%s\\fos_nodb_scan_%lu",
             tmp, GetCurrentProcessId());
    CreateDirectoryA(g_scan_dir, NULL);
    snprintf(g_db_path, sizeof(g_db_path), "%s\\fos_label_test.db", tmp);

    g_mutex_init(&global_scan_ctx.mutex);

    setvbuf(stdout, NULL, _IONBF, 0); /* crash-friendly output */

    UNITY_BEGIN();
    RUN_TEST(test_scan_without_db_still_enumerates);
    RUN_TEST(test_text_db_labels_preserved);
    RUN_TEST(test_malformed_text_db_lines_skipped);
    int rc = UNITY_END();

    g_mutex_clear(&global_scan_ctx.mutex);

    /* Cleanup the temp scan directory */
    {
        WIN32_FIND_DATAA fd;
        char pattern[MAX_PATH];
        snprintf(pattern, sizeof(pattern), "%s\\*", g_scan_dir);
        HANDLE h = FindFirstFileA(pattern, &fd);
        if (h != INVALID_HANDLE_VALUE) {
            do {
                if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
                char p[MAX_PATH];
                snprintf(p, sizeof(p), "%s\\%s", g_scan_dir, fd.cFileName);
                DeleteFileA(p);
            } while (FindNextFileA(h, &fd));
            FindClose(h);
        }
        RemoveDirectoryA(g_scan_dir);
    }
    return rc;
}
