/**
 * test_amsi.c -- U-10 AMSI client integration tests.
 *
 * The environment decides how much can be asserted:
 *   - amsi_scan_available() must be stable (0 or 1),
 *   - benign script content must NEVER be reported malicious,
 *   - a nonexistent file is a local error (-1), never MALWARE,
 *   - the EICAR string wrapped in script syntax is reported when a real
 *     provider (e.g. Defender) is active; that check is informational
 *     because a machine without script providers legitimately says CLEAN.
 */
#include "unity.h"
#include "amsi_scan.h"
#include "path_utils.h"

#include <stdio.h>
#include <string.h>
#include <windows.h>

static char g_dir[MAX_PATH];

static void write_ansi(const char *name, const char *content)
{
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%s\\%s", g_dir, name);
    FILE *f = fopen(path, "wb");
    TEST_ASSERT_NOT_NULL(f);
    fwrite(content, 1, strlen(content), f);
    fclose(f);
}

static void test_availability_is_stable(void)
{
    int a = amsi_scan_available();
    int b = amsi_scan_available();
    TEST_ASSERT_EQUAL_INT(a, b);
    TEST_ASSERT_TRUE(a == 0 || a == 1);
}

static void test_benign_script_is_clean(void)
{
    static const char k_benign[] =
        "// totally boring script\n"
        "var sum = 0;\n"
        "for (var i = 0; i < 10; i++) { sum += i; }\n"
        "console.log(sum);\n";
    int rc = amsi_scan_buffer(k_benign, strlen(k_benign), L"benign.js");
    TEST_ASSERT_EQUAL_INT(AMSI_SCAN_CLEAN, rc);
}

static void test_benign_script_file_is_clean(void)
{
    write_ansi("benign.js", "var x = 1;\n");
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%s\\benign.js", g_dir);

    fos_path_t fp;
    TEST_ASSERT_TRUE(fos_path_init(&fp, path));
    int rc = amsi_scan_file_wide(&fp, NULL);
    TEST_ASSERT_EQUAL_INT(AMSI_SCAN_CLEAN, rc);
}

static void test_empty_buffer_is_clean(void)
{
    TEST_ASSERT_EQUAL_INT(AMSI_SCAN_CLEAN, amsi_scan_buffer("", 0, L"empty"));
}

static void test_missing_file_is_error_not_malware(void)
{
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%s\\does_not_exist.js", g_dir);
    fos_path_t fp;
    TEST_ASSERT_TRUE(fos_path_init(&fp, path));
    int rc = amsi_scan_file_wide(&fp, NULL);
    TEST_ASSERT_EQUAL_INT(AMSI_SCAN_ERROR, rc);
}

static void test_eicar_in_script_reported_or_clean(void)
{
    /* EICAR test string split so this source file itself stays inert. */
    static const char k_part1[] = "var s = \"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-S";
    static const char k_part2[] = "TANDARD-ANTIVIRUS-TEST-FILE!$H+H*\";\n";
    char eicar_js[512];
    snprintf(eicar_js, sizeof(eicar_js), "%s%s", k_part1, k_part2);

    int rc = amsi_scan_buffer(eicar_js, strlen(eicar_js), L"eicar-test.js");
    /* Only assert the safe outcomes: never ERROR, and CLEAN is fine when
     * no script-aware provider is registered. DETECTED machines (Defender
     * with real-time protection) report MALWARE. */
    TEST_ASSERT_TRUE_MESSAGE(rc == AMSI_SCAN_CLEAN || rc == AMSI_SCAN_MALWARE,
                             "AMSI verdict must be CLEAN or MALWARE, never an error");
}

void setUp(void) {}
void tearDown(void) {}

int main(void)
{
    const char *tmp = getenv("TEMP");
    if (!tmp) tmp = "C:\\Windows\\Temp";
    snprintf(g_dir, sizeof(g_dir), "%s\\fos_amsi_test_%lu", tmp,
             (unsigned long)GetCurrentProcessId());
    CreateDirectoryA(g_dir, NULL);

    UNITY_BEGIN();
    RUN_TEST(test_availability_is_stable);
    RUN_TEST(test_benign_script_is_clean);
    RUN_TEST(test_benign_script_file_is_clean);
    RUN_TEST(test_empty_buffer_is_clean);
    RUN_TEST(test_missing_file_is_error_not_malware);
    RUN_TEST(test_eicar_in_script_reported_or_clean);
    int rc = UNITY_END();

    /* cleanup */
    {
        char path[MAX_PATH];
        snprintf(path, sizeof(path), "%s\\benign.js", g_dir);
        DeleteFileA(path);
        RemoveDirectoryA(g_dir);
    }
    return rc;
}
