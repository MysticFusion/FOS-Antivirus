/**
 * @file test_ml_scores.c
 * @brief Score regression on real system binaries through the full C pipeline.
 *
 * Regression pins for the shipped forest.bin (see scripts/validate_model.py
 * for the structural/parity checks). Tests gracefully SKIP when the sample
 * files are not present (e.g., different Windows build), so this never fails
 * on machines without the expected system files.
 */
#include "unity.h"
#include "ml_engine.h"
#include "feature_extract.h"
#include "path_utils.h"
#include <stdio.h>
#include <stdlib.h>

static const char *MODEL_PATH;
static const char *samples[][2] = {
    { "C:\\Windows\\System32\\kernel32.dll", "0.50" }, /* low: DLL, MS-signed, benign */
    { "C:\\Windows\\System32\\user32.dll",   "0.50" },
    { "C:\\Windows\\System32\\msvcp140.dll", "0.50" },
    { "C:\\Windows\\System32\\ntoskrnl.exe", "0.80" }, /* core kernel image */
    { "C:\\Windows\\System32\\cmd.exe",      "0.80" }, /* mid zone, under gate */
    { NULL, NULL }
};
static const size_t N_SAMPLES = 5;

void setUp(void) {}
void tearDown(void) {}

static int all_samples_present(void)
{
    for (size_t i = 0; i < N_SAMPLES; i++) {
        fos_path_t p;
        if (!fos_path_init(&p, samples[i][0])) return 0;
        if (!fos_file_exists(&p)) return 0;
    }
    return 1;
}

static void test_model_scores_real_system_files(void)
{
    if (!all_samples_present()) {
        TEST_IGNORE_MESSAGE("system sample files not present - skipping");
    }

    TEST_ASSERT_EQUAL_INT(0, ml_engine_init(MODEL_PATH));

    for (size_t i = 0; i < N_SAMPLES; i++) {
        double cap = atof(samples[i][1]);
        fos_path_t p;
        TEST_ASSERT(fos_path_init(&p, samples[i][0]));

        FileFeatures f;
        TEST_ASSERT_EQUAL_INT(0, extract_file_features_wide(&p, &f));

        double s = ml_engine_scan(&f);
        char msg[256];
        snprintf(msg, sizeof(msg), "%s score=%.5f must be < %.2f",
                 samples[i][0], s, cap);
        TEST_ASSERT_MESSAGE(s < cap, msg);
    }

    ml_engine_cleanup();
}

int main(int argc, char **argv)
{
    MODEL_PATH = (argc > 1) ? argv[1] : "assets/models/forest.bin";
    UNITY_BEGIN();
    RUN_TEST(test_model_scores_real_system_files);
    return UNITY_END();
}
