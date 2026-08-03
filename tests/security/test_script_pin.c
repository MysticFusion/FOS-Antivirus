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
 */
#include "unity.h"

#include <stdio.h>
#include <string.h>

#include "aggregator_hash.h"
#include "hash_util.h"

static char g_staged_path[MAX_PATH];

static void test_staged_script_matches_pin(void) {
  unsigned char hash[SHA256_SIZE];
  char hex[SHA256_SIZE * 2 + 1];
  TEST_ASSERT_EQUAL_INT(0, compute_file_sha256(g_staged_path, hash));
  for (int i = 0; i < SHA256_SIZE; i++) {
    static const char *k_hex = "0123456789abcdef";
    hex[i * 2] = k_hex[hash[i] >> 4];
    hex[i * 2 + 1] = k_hex[hash[i] & 0x0F];
  }
  hex[SHA256_SIZE * 2] = '\0';
  TEST_ASSERT_EQUAL_STRING(AGGREGATOR_SHA256_HEX, hex);
}

static void test_tampered_script_does_not_match_pin(void) {
  /* Append a byte and expect a different hash than the pin. */
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

  unsigned char hash[SHA256_SIZE];
  TEST_ASSERT_EQUAL_INT(0, compute_file_sha256(tmp, hash));
  remove(tmp);
  /* The pin is hex text; hash is raw bytes -- compare via recomputed hex. */
  char hex[SHA256_SIZE * 2 + 1];
  for (int i = 0; i < SHA256_SIZE; i++) {
    static const char *k_hex = "0123456789abcdef";
    hex[i * 2] = k_hex[hash[i] >> 4];
    hex[i * 2 + 1] = k_hex[hash[i] & 0x0F];
  }
  hex[SHA256_SIZE * 2] = '\0';
  TEST_ASSERT_NOT_EQUAL_STRING(AGGREGATOR_SHA256_HEX, hex);
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
