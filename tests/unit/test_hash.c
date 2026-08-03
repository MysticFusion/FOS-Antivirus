/**
 * test_hash.c -- SHA-2 known-answer tests (NIST FIPS 180-2 vectors).
 */
#include "unity.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha2.h"

static void to_hex(const uint8_t *d, size_t n, char *out) {
  for (size_t i = 0; i < n; i++)
    sprintf(out + 2 * i, "%02x", d[i]);
}

static void expect_digest(const char *name, void (*fn)(const uint8_t *, uint64_t, uint8_t *),
                          size_t dlen, const char *hex_expected,
                          const uint8_t *msg, uint64_t mlen) {
  uint8_t digest[64];
  char hex[130];
  fn(msg, mlen, digest);
  to_hex(digest, dlen, hex);
  TEST_ASSERT_EQUAL_STRING_MESSAGE(hex_expected, hex, name);
}

/* NIST FIPS 180-2 / CAVS vectors */
static const uint8_t msg_abc[] = {'a', 'b', 'c'};
static const uint8_t msg_448[] =
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
static const uint8_t msg_1m_a[] =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

static void test_sha256_empty(void) {
  expect_digest("sha256(\"\")",
                sha256, SHA256_DIGEST_SIZE,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                (const uint8_t *)"", 0);
}

static void test_sha256_abc(void) {
  expect_digest("sha256(\"abc\")",
                sha256, SHA256_DIGEST_SIZE,
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                msg_abc, sizeof(msg_abc));
}

static void test_sha256_448(void) {
  expect_digest("sha256(two-block)",
                sha256, SHA256_DIGEST_SIZE,
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
                msg_448, sizeof(msg_448) - 1);
}

static void test_sha256_1m_a(void) {
  /* 1,000,000 repetitions of 'a' */
  uint8_t *buf = (uint8_t *)malloc(1000000);
  uint8_t digest[SHA256_DIGEST_SIZE];
  char hex[65];
  TEST_ASSERT_NOT_NULL(buf);
  memset(buf, 'a', 1000000);
  sha256(buf, 1000000, digest);
  to_hex(digest, SHA256_DIGEST_SIZE, hex);
  TEST_ASSERT_EQUAL_STRING(
      "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", hex);
  free(buf);
}

static void test_sha256_incremental(void) {
  /* byte-at-a-time update must equal one-shot */
  sha256_ctx ctx;
  uint8_t one[32], two[32];
  char hex1[65], hex2[65];
  const uint8_t *m = msg_448;
  size_t n = sizeof(msg_448) - 1;

  sha256(m, n, one);
  sha256_init(&ctx);
  for (size_t i = 0; i < n; i++)
    sha256_update(&ctx, m + i, 1);
  sha256_final(&ctx, two);
  to_hex(one, 32, hex1);
  to_hex(two, 32, hex2);
  TEST_ASSERT_EQUAL_STRING(hex1, hex2);
}

static void test_sha512_abc(void) {
  expect_digest("sha512(\"abc\")",
                sha512, SHA512_DIGEST_SIZE,
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2"
                "192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
                msg_abc, sizeof(msg_abc));
}

void setUp(void) {}
void tearDown(void) {}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_sha256_empty);
  RUN_TEST(test_sha256_abc);
  RUN_TEST(test_sha256_448);
  RUN_TEST(test_sha256_1m_a);
  RUN_TEST(test_sha256_incremental);
  RUN_TEST(test_sha512_abc);
  return UNITY_END();
}
