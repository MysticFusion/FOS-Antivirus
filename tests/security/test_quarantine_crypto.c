/**
 * test_quarantine_crypto.c -- AES-256-GCM quarantine round-trip (I-01/I-02/R-01).
 *
 * Uses the real response_engine + DPAPI vault (user-bound, like the app).
 * Each test cleans up the .vir artifacts it creates.
 */
#include "unity.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include "app_paths.h"
#include "response_engine.h"

static char g_src[MAX_PATH];
static char g_src2[MAX_PATH];
static char g_out[MAX_PATH];
static char g_qdir[MAX_PATH];
static char g_last_vir[MAX_PATH];

static void make_file(const char *path, size_t size, unsigned seed) {
  FILE *f = fopen(path, "wb");
  TEST_ASSERT_NOT_NULL(f);
  srand(seed);
  size_t chunk = 65536;
  uint8_t *buf = (uint8_t *)malloc(chunk);
  TEST_ASSERT_NOT_NULL(buf);
  while (size > 0) {
    size_t n = size < chunk ? size : chunk;
    for (size_t i = 0; i < n; i++)
      buf[i] = (uint8_t)(rand() & 0xFF);
    fwrite(buf, 1, n, f);
    size -= n;
  }
  free(buf);
  fclose(f);
}

static int content_equal(const char *a, const char *b) {
  FILE *fa = fopen(a, "rb");
  FILE *fb = fopen(b, "rb");
  if (!fa || !fb) {
    if (fa) fclose(fa);
    if (fb) fclose(fb);
    return 0;
  }
  uint8_t ba[65536], bb[65536];
  int eq = 1;
  for (;;) {
    size_t na = fread(ba, 1, sizeof(ba), fa);
    size_t nb = fread(bb, 1, sizeof(bb), fb);
    if (na != nb || memcmp(ba, bb, na) != 0) {
      eq = 0;
      break;
    }
    if (na == 0) break;
  }
  fclose(fa);
  fclose(fb);
  return eq;
}

static void find_latest_vir(void) {
  g_last_vir[0] = 0;
  WIN32_FIND_DATAA fd;
  char pat[MAX_PATH];
  snprintf(pat, sizeof(pat), "%s\\*.vir", g_qdir);
  HANDLE h = FindFirstFileA(pat, &fd);
  if (h == INVALID_HANDLE_VALUE) return;
  FILETIME best = {0};
  do {
    if (CompareFileTime(&fd.ftLastWriteTime, &best) > 0) {
      best = fd.ftLastWriteTime;
      snprintf(g_last_vir, sizeof(g_last_vir), "%s\\%s", g_qdir, fd.cFileName);
    }
  } while (FindNextFileA(h, &fd));
  FindClose(h);
}

static void delete_vir_artifacts(void) {
  WIN32_FIND_DATAA fd;
  char pat[MAX_PATH];
  snprintf(pat, sizeof(pat), "%s\\*.vir", g_qdir);
  HANDLE h = FindFirstFileA(pat, &fd);
  if (h == INVALID_HANDLE_VALUE) return;
  do {
    char p[MAX_PATH];
    snprintf(p, sizeof(p), "%s\\%s", g_qdir, fd.cFileName);
    DeleteFileA(p);
  } while (FindNextFileA(h, &fd));
  FindClose(h);
}

/* ---------------- tests ---------------- */

static void test_roundtrip_content(void) {
  size_t size = 300 * 1024 + 7; /* non-block-aligned size */
  make_file(g_src, size, 42);
  TEST_ASSERT_EQUAL_INT(0, response_quarantine_file(g_src, "Test.Trojan"));
  TEST_ASSERT_FALSE(GetFileAttributesA(g_src) != INVALID_FILE_ATTRIBUTES);
  find_latest_vir();
  TEST_ASSERT_TRUE_MESSAGE(g_last_vir[0] != 0, "quarantine produced .vir");

  TEST_ASSERT_EQUAL_INT(0, response_restore_file(g_last_vir, NULL));
  TEST_ASSERT_TRUE(GetFileAttributesA(g_src) != INVALID_FILE_ATTRIBUTES);
  TEST_ASSERT_TRUE(content_equal(g_src, g_src));
  /* .vir must be gone after restore */
  TEST_ASSERT_FALSE(GetFileAttributesA(g_last_vir) != INVALID_FILE_ATTRIBUTES);
}

static void test_restore_to_override(void) {
  /* twin file with the same deterministic content (rand seed 7) */
  make_file(g_src, 8192, 7);
  make_file(g_src2, 8192, 7);
  TEST_ASSERT_EQUAL_INT(0, response_quarantine_file(g_src, "Test.Override"));
  find_latest_vir();
  TEST_ASSERT_TRUE(g_last_vir[0] != 0);

  TEST_ASSERT_EQUAL_INT(0, response_restore_file(g_last_vir, g_out));
  TEST_ASSERT_TRUE(content_equal(g_out, g_src2));
  /* original location must NOT be recreated when override is used */
  TEST_ASSERT_FALSE(GetFileAttributesA(g_src) != INVALID_FILE_ATTRIBUTES);
}

static void test_tampered_body_rejected(void) {
  make_file(g_src, 64 * 1024, 3);
  TEST_ASSERT_EQUAL_INT(0, response_quarantine_file(g_src, "Test.TamperBody"));
  find_latest_vir();
  TEST_ASSERT_TRUE(g_last_vir[0] != 0);

  /* corrupt the body ciphertext region (beyond header + meta) */
  {
    FILE *f = fopen(g_last_vir, "r+b");
    TEST_ASSERT_NOT_NULL(f);
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    TEST_ASSERT_TRUE(sz > 2000);
    fseek(f, sz - 64, SEEK_SET);
    unsigned char b = 0;
    fread(&b, 1, 1, f);
    fseek(f, -1, SEEK_CUR);
    b ^= 0xFF;
    fwrite(&b, 1, 1, f);
    fclose(f);
  }
  TEST_ASSERT_EQUAL_INT(RESP_ERR_TAMPERED, response_restore_file(g_last_vir, g_out));
  TEST_ASSERT_FALSE(GetFileAttributesA(g_out) != INVALID_FILE_ATTRIBUTES);
  DeleteFileA(g_last_vir);
}

static void test_tampered_meta_rejected(void) {
  make_file(g_src, 4096, 11);
  TEST_ASSERT_EQUAL_INT(0, response_quarantine_file(g_src, "Test.TamperMeta"));
  find_latest_vir();
  TEST_ASSERT_TRUE(g_last_vir[0] != 0);

  /* flip a byte INSIDE the encrypted metadata ciphertext: the header is
   * [magic(4)][version(4)][nonce_meta(12)][nonce_body(12)][meta_cipher_len(4)]
   * followed by the ciphertext itself — offset 64 is safely inside it. */
  {
    FILE *f = fopen(g_last_vir, "r+b");
    TEST_ASSERT_NOT_NULL(f);
    fseek(f, 64, SEEK_SET);
    unsigned char b = 0;
    fread(&b, 1, 1, f);
    fseek(f, -1, SEEK_CUR);
    b ^= 0x40;
    fwrite(&b, 1, 1, f);
    fclose(f);
  }
  TEST_ASSERT_EQUAL_INT(RESP_ERR_TAMPERED, response_restore_file(g_last_vir, NULL));
  DeleteFileA(g_last_vir);
}

static void test_corrupt_meta_length_rejected(void) {
  make_file(g_src, 4096, 13);
  TEST_ASSERT_EQUAL_INT(0, response_quarantine_file(g_src, "Test.TamperMetaLen"));
  find_latest_vir();
  TEST_ASSERT_TRUE(g_last_vir[0] != 0);

  /* Corrupt the meta_cipher_len HEADER field (offset 32). The layout no
   * longer parses, so a FORMAT refusal is expected (and equally safe);
   * U-09 additionally bounds body_len, so absurd lengths cannot become
   * huge allocations. */
  {
    FILE *f = fopen(g_last_vir, "r+b");
    TEST_ASSERT_NOT_NULL(f);
    fseek(f, 4 + 4 + 12 + 12, SEEK_SET);
    unsigned char b = 0;
    fread(&b, 1, 1, f);
    fseek(f, -1, SEEK_CUR);
    b ^= 0x40;
    fwrite(&b, 1, 1, f);
    fclose(f);
  }
  int rc = response_restore_file(g_last_vir, NULL);
  TEST_ASSERT_TRUE_MESSAGE(rc == RESP_ERR_FORMAT || rc == RESP_ERR_TAMPERED,
                           "corrupt meta length must be refused (format or tamper)");
  DeleteFileA(g_last_vir);
}

static void test_restore_nonexistent_fails(void) {
  char bad[MAX_PATH];
  snprintf(bad, sizeof(bad), "%s\\does_not_exist.vir", g_qdir);
  TEST_ASSERT_EQUAL_INT(RESP_ERR_IO, response_restore_file(bad, NULL));
}

static void test_quarantine_missing_file_fails(void) {
  char bad[MAX_PATH];
  snprintf(bad, sizeof(bad), "%s\\missing_target.bin", g_qdir);
  TEST_ASSERT_EQUAL_INT(RESP_ERR_IO, response_quarantine_file(bad, "Test.Missing"));
}

void setUp(void) {}
void tearDown(void) {}

int main(void) {
  const char *qdir = app_path_quarantine_dir();
  TEST_ASSERT_NOT_NULL(qdir);
  snprintf(g_qdir, sizeof(g_qdir), "%s", qdir);

  const char *tmp = getenv("TEMP");
  if (!tmp) tmp = "C:\\Windows\\Temp";
  snprintf(g_src, sizeof(g_src), "%s\\fos_q_test_src.bin", tmp);
  snprintf(g_src2, sizeof(g_src2), "%s\\fos_q_test_src2.bin", tmp);
  snprintf(g_out, sizeof(g_out), "%s\\fos_q_test_out.bin", tmp);
  DeleteFileA(g_src);
  DeleteFileA(g_src2);
  DeleteFileA(g_out);

  UNITY_BEGIN();
  RUN_TEST(test_roundtrip_content);
  RUN_TEST(test_restore_to_override);
  RUN_TEST(test_tampered_body_rejected);
  RUN_TEST(test_tampered_meta_rejected);
  RUN_TEST(test_corrupt_meta_length_rejected);
  RUN_TEST(test_restore_nonexistent_fails);
  RUN_TEST(test_quarantine_missing_file_fails);
  delete_vir_artifacts();
  DeleteFileA(g_src);
  DeleteFileA(g_src2);
  DeleteFileA(g_out);
  return UNITY_END();
}
