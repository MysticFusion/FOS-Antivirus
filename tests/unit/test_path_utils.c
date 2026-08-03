/**
 * test_path_utils.c -- long-path conversion and I/O (I-06 / R-03).
 */
#include "unity.h"

#include <stdio.h>
#include <string.h>

#include "path_utils.h"

static void test_short_path_no_prefix(void) {
  fos_path_t p;
  TEST_ASSERT_TRUE(fos_path_init(&p, "C:\\test\\file.exe"));
  TEST_ASSERT_FALSE(p.is_long);
  TEST_ASSERT_TRUE(wcsstr(fos_path_w(&p), L"C:\\test\\file.exe") != NULL);
}

static void test_unicode_roundtrip(void) {
  fos_path_t p;
  char utf8_out[FOS_MAX_PATH * 4];
  const char *in = "D:\\x\\\xC3\xA9\\f\xC3\xBC.dll"; /* Ã© and Ã¼ in UTF-8 */
  TEST_ASSERT_TRUE(fos_path_init(&p, in));
  TEST_ASSERT_EQUAL_INT(0, fos_path_to_utf8(&p, utf8_out, sizeof(utf8_out)));
  TEST_ASSERT_EQUAL_STRING(in, utf8_out);
}

static void test_long_path_gets_prefix(void) {
  char path[512];
  size_t off = 0;
  memset(path, 0, sizeof(path));
  memcpy(path, "C:\\deep\\", 8);
  off = 8;
  /* Build a path of ~400 chars: dirs plus filename */
  for (int i = 0; i < 20; i++) {
    memcpy(path + off, "0123456789abcdefghij\\", 20);
    off += 20;
  }
  memcpy(path + off, "target.bin", 10);
  off += 10;
  path[off] = 0;
  TEST_ASSERT_TRUE(strlen(path) >= 248);

  fos_path_t p;
  TEST_ASSERT_TRUE(fos_path_init(&p, path));
  TEST_ASSERT_TRUE(p.is_long);
  const wchar_t *w = fos_path_w(&p);
  TEST_ASSERT_TRUE(wcsncmp(w, L"\\\\?\\C:\\deep\\", 10) == 0);
}

static void test_already_prefixed_left_alone(void) {
  fos_path_t p;
  /* Short path that is already prefixed: left intact, no re-prefixing.
   * is_long documents "prefix applied by us", so it stays false. */
  TEST_ASSERT_TRUE(fos_path_init(&p, "\\\\?\\C:\\short.bin"));
  TEST_ASSERT_FALSE(p.is_long);
  TEST_ASSERT_TRUE(wcscmp(fos_path_w(&p), L"\\\\?\\C:\\short.bin") == 0);
}

static void test_long_path_file_io(void) {
  /* Create a genuinely long directory chain and write/read a file through
   * the long-path layer. */
  char dir[700];
  char path[800];
  char tmpbase[300];
  const char *tmp = getenv("TEMP");
  if (!tmp) tmp = "C:\\Windows\\Temp";
  snprintf(tmpbase, sizeof(tmpbase), "%s\\fos_pu_test", tmp);

  memset(dir, 0, sizeof(dir));
  snprintf(dir, sizeof(dir), "%s\\", tmpbase);
  for (int i = 0; i < 25; i++) {
    size_t n = strlen(dir);
    snprintf(dir + n, sizeof(dir) - n, "subdir%02d\\", i);
  }
  /* ensure the long directory chain exists */
  fos_path_t d;
  TEST_ASSERT_TRUE(fos_path_init(&d, dir));
  {
    wchar_t cur[FOS_MAX_PATH];
    wcscpy(cur, L"\\\\?\\");
    wcscat(cur, L"C:\\");
    /* walk-create each component via CreateDirectoryW on prefixed paths */
    wchar_t walk[FOS_MAX_PATH] = L"";
    const wchar_t *wd = fos_path_w(&d);
    const wchar_t *prefix = L"\\\\?\\";
    wcscpy(walk, prefix);
    const wchar_t *rest = wd + wcslen(prefix);
    wchar_t part[FOS_MAX_PATH] = L"";
    for (const wchar_t *p = rest;; p++) {
      if (*p == L'\\' || *p == 0) {
        if (wcslen(part) > 0) {
          size_t wn = wcslen(walk);
          if (wn > 0 && walk[wn - 1] != L'\\') wcscat(walk, L"\\");
          wcscat(walk, part);
          CreateDirectoryW(walk, NULL);
          part[0] = 0;
        }
        if (*p == 0) break;
      } else {
        size_t pn = wcslen(part);
        if (pn < sizeof(part) / sizeof(wchar_t) - 1) {
          part[pn] = *p;
          part[pn + 1] = 0;
        }
      }
    }
  }

  snprintf(path, sizeof(path), "%starget.bin", dir);
  TEST_ASSERT_TRUE(strlen(path) >= 248);

  fos_path_t p;
  TEST_ASSERT_TRUE(fos_path_init(&p, path));
  TEST_ASSERT_TRUE(p.is_long);

  FILE *f = fos_fopen(&p, "wb");
  TEST_ASSERT_NOT_NULL_MESSAGE(f, "fos_fopen wb on long path");
  if (f) {
    const char payload[] = "long-path payload 1234567890";
    TEST_ASSERT_EQUAL(sizeof(payload) - 1, fwrite(payload, 1, sizeof(payload) - 1, f));
    fclose(f);
  }

  TEST_ASSERT_TRUE(fos_file_exists(&p));
  f = fos_fopen(&p, "rb");
  TEST_ASSERT_NOT_NULL_MESSAGE(f, "fos_fopen rb on long path");
  if (f) {
    char buf[128] = {0};
    size_t got = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    TEST_ASSERT_EQUAL_STRING("long-path payload 1234567890", buf);
    (void)got;
  }

  TEST_ASSERT_TRUE(fos_delete_file(&p));
  TEST_ASSERT_FALSE(fos_file_exists(&p));

  /* cleanup the tree */
  fos_path_t clean;
  TEST_ASSERT_TRUE(fos_path_init(&clean, dir));
  {
    char *end = (char *)dir + strlen(dir);
    while (end > dir) {
      end--;
      if (*end == '\\') {
        char sub[700];
        memcpy(sub, dir, (size_t)(end - dir));
        sub[end - dir] = 0;
        if (strlen(sub) > strlen(tmpbase)) {
          fos_path_t s;
          if (fos_path_init(&s, sub)) RemoveDirectoryW(fos_path_w(&s));
        }
      }
    }
    RemoveDirectoryW(fos_path_w(&clean));
  }
}

void setUp(void) {}
void tearDown(void) {}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_short_path_no_prefix);
  RUN_TEST(test_unicode_roundtrip);
  RUN_TEST(test_long_path_gets_prefix);
  RUN_TEST(test_already_prefixed_left_alone);
  RUN_TEST(test_long_path_file_io);
  return UNITY_END();
}
