/**
 * test_script_pin.c -- I-19: build-time SHA-256 pin of hash_aggregator.py.
 *
 * Verifies that the staged script next to the built EXE byte-matches the
 * hash embedded in the binary at configure time (aggregator_hash.h). If the
 * script and the pin ever diverge (tampering, partial stage), the updater
 * would refuse to execute it -- and this test fails to say why.
 *
 * Also proves the tamper path: a modified copy of the script must NOT match
 * the pin.
 *
 * The checks call the PRODUCTION function signature_script_verify() -- the
 * exact gate used by update_signature_db() at runtime -- so the test cannot
 * drift from the shipped code (it previously re-implemented the check and
 * missed a call-order bug that made the runtime check fail unconditionally).
 */
#include "unity.h"

#include <stdio.h>
#include <windows.h>

#include "script_verify.h"

static char g_staged_path[MAX_PATH];

static void test_staged_script_matches_pin(void) {
  TEST_ASSERT_EQUAL_INT(0, signature_script_verify(g_staged_path));
}

static void test_tampered_script_does_not_match_pin(void) {
  /* Append a byte and expect the verify gate to reject it. */
  char tmp[MAX_PATH];
  snprintf(tmp, sizeof(tmp), "%s_tampered.py", g_staged_path);
  FILE *f = fopen(g_staged_path, "rb");
  TEST_ASSERT_NOT_NULL(f);
  FILE *g = fopen(tmp, "wb");
  TEST_ASSERT_NOT_NULL(g);
  char buf[8192];
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), f)) > 0) fwrite(buf, 1, n, g);
  fwrite("x", 1, 1, g); /* tamper */
  fclose(f);
  fclose(g);

  TEST_ASSERT_NOT_EQUAL(0, signature_script_verify(tmp));
  remove(tmp);
}

void setUp(void) {}
void tearDown(void) {}

int main(int argc, char **argv) {
  if (argc < 2) {
    printf("usage: %s <staged hash_aggregator.py path>\n", argv[0]);
    return 2;
  }
  snprintf(g_staged_path, sizeof(g_staged_path), "%s", argv[1]);

  UNITY_BEGIN();
  RUN_TEST(test_staged_script_matches_pin);
  RUN_TEST(test_tampered_script_does_not_match_pin);
  return UNITY_END();
}
