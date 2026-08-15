/**
 * @file test_ransomware_signals.c
 * @brief Unit tests for the R-05 corroborated ransomware signal tracker.
 *
 * Covers: sliding-window rate threshold, window expiry, extension-rewrite
 * pairing + dedup, same-extension renames, and the >=2-signals rule.
 */
#include "unity.h"
#include "ransomware_signals.h"
#include <stdlib.h>

static rw_tracker_t *t;

void setUp(void)    { t = rw_tracker_create(); TEST_ASSERT_NOT_NULL(t); }
void tearDown(void) { rw_tracker_free(t); }

/* --- rate window ---------------------------------------------------------- */

static void test_rate_below_threshold_not_set(void)
{
    for (int i = 0; i < RW_RATE_THRESHOLD - 1; i++) {
        rw_tracker_on_exec_event(t, 100);
    }
    TEST_ASSERT_EQUAL_INT(0, rw_tracker_signals(t, 104, false) & RW_SIG_RATE);
}

static void test_rate_threshold_set(void)
{
    for (int i = 0; i < RW_RATE_THRESHOLD; i++) {
        rw_tracker_on_exec_event(t, 100);
    }
    TEST_ASSERT_EQUAL_INT(RW_SIG_RATE, rw_tracker_signals(t, 105, false) & RW_SIG_RATE);
}

static void test_rate_window_expiry_prunes(void)
{
    for (int i = 0; i < RW_RATE_THRESHOLD; i++) {
        rw_tracker_on_exec_event(t, 100);
    }
    TEST_ASSERT_EQUAL_INT(RW_SIG_RATE, rw_tracker_signals(t, 104, false) & RW_SIG_RATE);
    /* All events now older than the 5 s window. */
    TEST_ASSERT_EQUAL_INT(0, rw_tracker_signals(t, 106, false) & RW_SIG_RATE);
}

static void test_rate_sliding_window_stays_set(void)
{
    /* A burst at t=0 stays inside the 5 s window [0,5] until t=6. */
    for (int i = 0; i < 10; i++) rw_tracker_on_exec_event(t, 0);
    TEST_ASSERT_EQUAL_INT(RW_SIG_RATE, rw_tracker_signals(t, 4, false) & RW_SIG_RATE);
    TEST_ASSERT_EQUAL_INT(RW_SIG_RATE, rw_tracker_signals(t, 5, false) & RW_SIG_RATE);
    TEST_ASSERT_EQUAL_INT(0, rw_tracker_signals(t, 6, false) & RW_SIG_RATE);
    /* ...a fresh burst inside the window keeps it set. */
    for (int i = 0; i < 10; i++) rw_tracker_on_exec_event(t, 6);
    TEST_ASSERT_EQUAL_INT(RW_SIG_RATE, rw_tracker_signals(t, 9, false) & RW_SIG_RATE);
    TEST_ASSERT_EQUAL_INT(0, rw_tracker_signals(t, 12, false) & RW_SIG_RATE);
}

/* --- extension rewriting -------------------------------------------------- */

static void test_ext_rewrite_threshold(void)
{
    for (int i = 0; i < RW_EXT_THRESHOLD; i++) {
        rw_tracker_on_rename_old(t, 200, 1000 + i, L".doc");
        rw_tracker_on_rename_new(t, 200, 1000 + i, L".locked");
    }
    TEST_ASSERT_EQUAL_INT(RW_SIG_EXT, rw_tracker_signals(t, 200, false) & RW_SIG_EXT);
}

static void test_ext_rewrite_below_threshold(void)
{
    for (int i = 0; i < RW_EXT_THRESHOLD - 1; i++) {
        rw_tracker_on_rename_old(t, 200, 1000 + i, L".doc");
        rw_tracker_on_rename_new(t, 200, 1000 + i, L".locked");
    }
    TEST_ASSERT_EQUAL_INT(0, rw_tracker_signals(t, 200, false) & RW_SIG_EXT);
}

static void test_same_extension_rename_not_counted(void)
{
    for (int i = 0; i < RW_EXT_THRESHOLD + 5; i++) {
        rw_tracker_on_rename_old(t, 200, 2000 + i, L".txt");
        rw_tracker_on_rename_new(t, 200, 2000 + i, L".txt");
    }
    TEST_ASSERT_EQUAL_INT(0, rw_tracker_signals(t, 200, false) & RW_SIG_EXT);
}

static void test_rename_new_without_old_pair_ignored(void)
{
    for (int i = 0; i < RW_EXT_THRESHOLD + 5; i++) {
        rw_tracker_on_rename_new(t, 200, 3000 + i, L".exe");
    }
    TEST_ASSERT_EQUAL_INT(0, rw_tracker_signals(t, 200, false) & RW_SIG_EXT);
}

static void test_same_file_not_counted_twice(void)
{
    /* One file renamed twice within the window must count once. */
    for (int i = 0; i < RW_EXT_THRESHOLD; i++) {
        rw_tracker_on_rename_old(t, 200, 4000, L".doc");
        rw_tracker_on_rename_new(t, 200, 4000, L".locked");
    }
    TEST_ASSERT_EQUAL_INT(0, rw_tracker_signals(t, 200, false) & RW_SIG_EXT);
}

static void test_ext_window_expiry(void)
{
    for (int i = 0; i < RW_EXT_THRESHOLD; i++) {
        rw_tracker_on_rename_old(t, 300, 5000 + i, L".doc");
        rw_tracker_on_rename_new(t, 300, 5000 + i, L".locked");
    }
    TEST_ASSERT_EQUAL_INT(RW_SIG_EXT, rw_tracker_signals(t, 305, false) & RW_SIG_EXT);
    TEST_ASSERT_EQUAL_INT(0, rw_tracker_signals(t, 311, false) & RW_SIG_EXT);
}

static void test_ext_change_case_insensitive_same(void)
{
    rw_tracker_on_rename_old(t, 200, 6000, L".DOC");
    rw_tracker_on_rename_new(t, 200, 6000, L".doc");
    TEST_ASSERT_EQUAL_INT(0, rw_tracker_signals(t, 200, false) & RW_SIG_EXT);
}

/* --- confirmation rule (>=2 of 3 signals) ---------------------------------- */

static void test_confirmation_requires_two_signals(void)
{
    /* RATE alone -> no context */
    for (int i = 0; i < RW_RATE_THRESHOLD; i++) rw_tracker_on_exec_event(t, 400);
    int sig = rw_tracker_signals(t, 405, false);
    TEST_ASSERT_FALSE(rw_signals_confirmed(sig));
    /* RATE + SCOPE -> context */
    sig = rw_tracker_signals(t, 405, true);
    TEST_ASSERT_TRUE(rw_signals_confirmed(sig));
}

static void test_confirmation_ext_plus_scope(void)
{
    for (int i = 0; i < RW_EXT_THRESHOLD; i++) {
        rw_tracker_on_rename_old(t, 500, 7000 + i, L".doc");
        rw_tracker_on_rename_new(t, 500, 7000 + i, L".locked");
    }
    TEST_ASSERT_TRUE(rw_signals_confirmed(rw_tracker_signals(t, 500, true)));
    TEST_ASSERT_FALSE(rw_signals_confirmed(rw_tracker_signals(t, 500, false)));
}

static void test_confirmation_rate_plus_ext(void)
{
    for (int i = 0; i < RW_RATE_THRESHOLD; i++) rw_tracker_on_exec_event(t, 600);
    for (int i = 0; i < RW_EXT_THRESHOLD; i++) {
        rw_tracker_on_rename_old(t, 600, 8000 + i, L".doc");
        rw_tracker_on_rename_new(t, 600, 8000 + i, L".locked");
    }
    TEST_ASSERT_TRUE(rw_signals_confirmed(rw_tracker_signals(t, 605, false)));
    TEST_ASSERT_TRUE(rw_signals_confirmed(rw_tracker_signals(t, 605, true)));
}

/* --- U-07: bulk rename storms must not blind the tracker ------------------ */

static void test_rename_storm_does_not_exhaust_slots(void)
{
    /* A benign bulk rename (git checkout / compiler output / renormalize)
     * generates far more unmatched rename-old events than the legacy fixed
     * 64-slot table could hold. After the storm, the ACTUAL extension
     * rewrites must still be tracked. */
    for (int i = 0; i < 5000; i++) {
        rw_tracker_on_rename_old(t, 700, 100000 + i, L".tmp");
        /* no rename_new: the pair never completes (unmatched storm) */
    }
    /* The real ransomware-style rewrites arrive after the storm. */
    for (int i = 0; i < RW_EXT_THRESHOLD; i++) {
        rw_tracker_on_rename_old(t, 701, 200000 + i, L".doc");
        rw_tracker_on_rename_new(t, 701, 200000 + i, L".locked");
    }
    TEST_ASSERT_EQUAL_INT(RW_SIG_EXT, rw_tracker_signals(t, 702, false) & RW_SIG_EXT);
}

static void test_storm_growth_bounded(void)
{
    /* Repeated refresh of the SAME file id must not grow the table. */
    for (int i = 0; i < 1000; i++) {
        rw_tracker_on_rename_old(t, 800, 42, L".doc");
    }
    for (int i = 0; i < RW_EXT_THRESHOLD; i++) {
        rw_tracker_on_rename_old(t, 801, 300000 + i, L".doc");
        rw_tracker_on_rename_new(t, 801, 300000 + i, L".crypt");
    }
    TEST_ASSERT_EQUAL_INT(RW_SIG_EXT, rw_tracker_signals(t, 802, false) & RW_SIG_EXT);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_rate_below_threshold_not_set);
    RUN_TEST(test_rate_threshold_set);
    RUN_TEST(test_rate_window_expiry_prunes);
    RUN_TEST(test_rate_sliding_window_stays_set);
    RUN_TEST(test_ext_rewrite_threshold);
    RUN_TEST(test_ext_rewrite_below_threshold);
    RUN_TEST(test_same_extension_rename_not_counted);
    RUN_TEST(test_rename_new_without_old_pair_ignored);
    RUN_TEST(test_same_file_not_counted_twice);
    RUN_TEST(test_ext_window_expiry);
    RUN_TEST(test_ext_change_case_insensitive_same);
    RUN_TEST(test_confirmation_requires_two_signals);
    RUN_TEST(test_confirmation_ext_plus_scope);
    RUN_TEST(test_confirmation_rate_plus_ext);
    RUN_TEST(test_rename_storm_does_not_exhaust_slots);
    RUN_TEST(test_storm_growth_bounded);
    return UNITY_END();
}
