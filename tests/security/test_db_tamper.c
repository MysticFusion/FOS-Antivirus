/**
 * test_db_tamper.c -- HMAC-SHA256 signature DB integrity (I-22/R-09).
 */
#include "unity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include "db_hmac.h"

static char g_db[MAX_PATH];

static void write_db(const char *content) {
  FILE *f = fopen(g_db, "wb");
  TEST_ASSERT_NOT_NULL(f);
  fwrite(content, 1, strlen(content), f);
  fclose(f);
}

static void remove_hmac(void) {
  char hmac_path[MAX_PATH];
  snprintf(hmac_path, sizeof(hmac_path), "%s.hmac", g_db);
  DeleteFileA(hmac_path);
}

static void test_hmac_write_and_verify(void) {
  write_db("a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90\n"
           "# comment line\n"
           "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n");
  TEST_ASSERT_EQUAL_INT(0, db_hmac_write_file(g_db));
  TEST_ASSERT_EQUAL_INT(0, db_hmac_verify_file(g_db));
}

static void test_hmac_tamper_detected(void) {
  write_db("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n");
  TEST_ASSERT_EQUAL_INT(0, db_hmac_write_file(g_db));

  /* Flip one byte in the DB */
  FILE *f = fopen(g_db, "r+b");
  TEST_ASSERT_NOT_NULL(f);
  fseek(f, 10, SEEK_SET);
  char b = '0';
  fread(&b, 1, 1, f);
  fseek(f, 10, SEEK_SET);
  b = (b == '0') ? '1' : '0';
  fwrite(&b, 1, 1, f);
  fclose(f);

  TEST_ASSERT_EQUAL_INT(-1, db_hmac_verify_file(g_db));
}

static void test_missing_hmac_fails(void) {
  write_db("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n");
  remove_hmac();
  TEST_ASSERT_EQUAL_INT(-1, db_hmac_verify_file(g_db));
}

static void test_truncated_hmac_fails(void) {
  write_db("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\n");
  {
    char hmac_path[MAX_PATH];
    snprintf(hmac_path, sizeof(hmac_path), "%s.hmac", g_db);
    FILE *f = fopen(hmac_path, "wb");
    TEST_ASSERT_NOT_NULL(f);
    fwrite("\x01\x02\x03\x04", 1, 4, f);
    fclose(f);
  }
  TEST_ASSERT_EQUAL_INT(-1, db_hmac_verify_file(g_db));
}

static void test_hmac_file_extra_bytes_fails(void) {
  write_db("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\n");
  TEST_ASSERT_EQUAL_INT(0, db_hmac_write_file(g_db));
  {
    char hmac_path[MAX_PATH];
    snprintf(hmac_path, sizeof(hmac_path), "%s.hmac", g_db);
    FILE *f = fopen(hmac_path, "ab");
    TEST_ASSERT_NOT_NULL(f);
    fwrite("\x00", 1, 1, f);
    fclose(f);
  }
  TEST_ASSERT_EQUAL_INT(-1, db_hmac_verify_file(g_db));
}

static void test_empty_db_still_verified(void) {
  write_db("");
  TEST_ASSERT_EQUAL_INT(0, db_hmac_write_file(g_db));
  TEST_ASSERT_EQUAL_INT(0, db_hmac_verify_file(g_db));
  TEST_ASSERT_EQUAL_INT(-1, db_hmac_verify_file("\\\\nonexistent\\\\db.bin"));
}

void setUp(void) {}
void tearDown(void) {
  remove_hmac();
  DeleteFileA(g_db);
}

int main(void) {
  const char *tmp = getenv("TEMP");
  if (!tmp) tmp = "C:\\Windows\\Temp";
  snprintf(g_db, sizeof(g_db), "%s\\fos_hmac_test.db", tmp);

  UNITY_BEGIN();
  RUN_TEST(test_hmac_write_and_verify);
  RUN_TEST(test_hmac_tamper_detected);
  RUN_TEST(test_missing_hmac_fails);
  RUN_TEST(test_truncated_hmac_fails);
  RUN_TEST(test_hmac_file_extra_bytes_fails);
  RUN_TEST(test_empty_db_still_verified);
  return UNITY_END();
}
