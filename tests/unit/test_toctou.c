/**
 * test_toctou.c -- MAPv3 U-03/U-04: atomic open + handle-derived canonical
 * path (fos_open_canonical). Proves that:
 *   - a path that is really a junction is canonicalized to the TARGET's
 *     path when followed, so a scanner that re-opens the returned path
 *     hashes the same object that was validated at enumeration time,
 *   - opening with FILE_FLAG_OPEN_REPARSE_POINT (no follow) reports
 *     was_reparse=true atomically — no stale find-data decision,
 *   - nonexistent paths fail immediately, closing the check-then-open
 *     (CWE-367) window.
 */
#include "unity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "path_utils.h"

static char g_base[300];

static void make_dir(const char *path) {
  fos_path_t p;
  if (fos_path_init(&p, path)) CreateDirectoryW(fos_path_w(&p), NULL);
}

static void write_file(const char *path, const char *content) {
  fos_path_t p;
  if (fos_path_init(&p, path)) {
    FILE *f = fos_fopen(&p, "wb");
    if (f) {
      fwrite(content, 1, strlen(content), f);
      fclose(f);
    }
  }
}

/* MinGW's <windows.h> does not ship REPARSE_DATA_BUFFER; define the
 * mount-point layout (identical to the Microsoft SDK structure). */
typedef struct {
  ULONG ReparseTag;
  USHORT ReparseDataLength;
  USHORT Reserved;
  struct {
    USHORT SubstituteNameOffset;
    USHORT SubstituteNameLength;
    USHORT PrintNameOffset;
    USHORT PrintNameLength;
    WCHAR PathBuffer[1];
  } MountPointReparseBuffer;
} FOS_REPARSE_DATA_BUFFER;

/* Create a junction (mount-point reparse point). Junctions do NOT require
 * administrator rights (unlike symlinks), so this works in CI.
 *
 * Buffer layout (validated against what mklink /J writes, Windows 11 26200):
 * each name is followed by a NUL wchar INSIDE the buffer but OUTSIDE its
 * declared length, and ReparseDataLength accounts for both NULs:
 *   [subst chars][NUL][print chars][NUL]
 * Without the separating/trailing NULs, FSCTL_SET_REPARSE_POINT fails with
 * ERROR_INVALID_REPARSE_DATA (4392). */
static bool create_junction(const char *junction_path, const char *target) {
  fos_path_t jp, tp;
  if (!fos_path_init(&jp, junction_path)) return false;
  if (!fos_path_init(&tp, target)) return false;

  HANDLE h = CreateFileW(fos_path_w(&jp), GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                         FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                         NULL);
  if (h == INVALID_HANDLE_VALUE) return false;

  /* Substitute name must be an absolute NT path: \??\C:\...\target */
  wchar_t subst[FOS_MAX_PATH];
  _snwprintf_s(subst, FOS_MAX_PATH, _TRUNCATE, L"\\??\\%s", fos_path_w(&tp));

  size_t subst_len = wcslen(subst) * sizeof(wchar_t);
  size_t print_len = wcslen(fos_path_w(&tp)) * sizeof(wchar_t);

  char raw[sizeof(FOS_REPARSE_DATA_BUFFER) + FOS_MAX_PATH * 2];
  memset(raw, 0, sizeof(raw));
  FOS_REPARSE_DATA_BUFFER *rdb = (FOS_REPARSE_DATA_BUFFER *)raw;
  rdb->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
  rdb->ReparseDataLength =
      (USHORT)(8 + subst_len + 2 + print_len + 2); /* names + both NULs */
  rdb->Reserved = 0;
  rdb->MountPointReparseBuffer.SubstituteNameOffset = 0;
  rdb->MountPointReparseBuffer.SubstituteNameLength = (USHORT)subst_len;
  /* print name starts after the substitute's NUL wchar */
  rdb->MountPointReparseBuffer.PrintNameOffset = (USHORT)(subst_len + 2);
  rdb->MountPointReparseBuffer.PrintNameLength = (USHORT)print_len;
  memcpy(rdb->MountPointReparseBuffer.PathBuffer, subst, subst_len);
  memcpy((char *)rdb->MountPointReparseBuffer.PathBuffer + subst_len + 2,
         fos_path_w(&tp), print_len);

  DWORD bytes = 0;
  BOOL ok = DeviceIoControl(h, FSCTL_SET_REPARSE_POINT, rdb,
                            rdb->ReparseDataLength + 8, NULL, 0, &bytes, NULL);
  CloseHandle(h);
  return ok != 0;
}

static void to_wide(const char *ansi, wchar_t *out, size_t out_sz) {
  MultiByteToWideChar(CP_UTF8, 0, ansi, -1, out, (int)out_sz);
}

static void test_nonexistent_path_fails(void) {
  char canonical[FOS_MAX_PATH];
  TEST_ASSERT_EQUAL_INT(-1, fos_open_canonical(
      L"C:\\fos_toctou_nonexistent_xyz\\no_such_file.exe",
      true, canonical, sizeof(canonical), NULL));
}

static void test_follow_reparse_resolves_to_target(void) {
  char target_dir[340], real_file[360], junc_dir[340], junc_file[360];
  snprintf(target_dir, sizeof(target_dir), "%s\\real_dir", g_base);
  snprintf(real_file, sizeof(real_file), "%s\\real_dir\\payload.exe", g_base);
  snprintf(junc_dir, sizeof(junc_dir), "%s\\looks_normal", g_base);
  snprintf(junc_file, sizeof(junc_file), "%s\\looks_normal\\payload.exe", g_base);

  make_dir(target_dir);
  make_dir(junc_dir);
  write_file(real_file, "MZ fake payload");

  TEST_ASSERT_TRUE_MESSAGE(create_junction(junc_dir, target_dir),
                           "junction creation (mount point)");

  /* Sanity: the file exists when accessed through the junction. */
  wchar_t wide_junc_file[FOS_MAX_PATH];
  to_wide(junc_file, wide_junc_file, FOS_MAX_PATH);
  fos_path_t jf;
  TEST_ASSERT_TRUE(fos_path_init_w(&jf, wide_junc_file));
  TEST_ASSERT_TRUE(fos_file_exists(&jf));

  /* Follow mode: the canonical path must equal the REAL target's canonical
   * path — a later re-open by the returned path cannot be redirected to an
   * unrelated object via a junction swap. */
  char canonical[FOS_MAX_PATH];
  TEST_ASSERT_EQUAL_INT(0, fos_open_canonical(wide_junc_file, true, canonical,
                                              sizeof(canonical), NULL));

  char real_canon[FOS_MAX_PATH];
  wchar_t wide_real[FOS_MAX_PATH];
  to_wide(real_file, wide_real, FOS_MAX_PATH);
  TEST_ASSERT_EQUAL_INT(0, fos_open_canonical(wide_real, true, real_canon,
                                              sizeof(real_canon), NULL));

  TEST_ASSERT_EQUAL_STRING_MESSAGE(real_canon, canonical,
                                   "junction must canonicalize to the target path");
}

static void test_reparse_detected_atomically_without_follow(void) {
  /* Self-contained fixture: this test must not depend on the junction from
   * test_follow_reparse_resolves_to_target (tearDown removes it). */
  char target_dir[340], junc_dir[340];
  snprintf(target_dir, sizeof(target_dir), "%s\\real_dir", g_base);
  snprintf(junc_dir, sizeof(junc_dir), "%s\\looks_normal", g_base);
  make_dir(target_dir);
  make_dir(junc_dir);
  TEST_ASSERT_TRUE_MESSAGE(create_junction(junc_dir, target_dir),
                           "junction creation (mount point)");

  wchar_t wide_junc[FOS_MAX_PATH];
  to_wide(junc_dir, wide_junc, FOS_MAX_PATH);

  char canonical[FOS_MAX_PATH];
  bool was_reparse = false;
  TEST_ASSERT_EQUAL_INT(0, fos_open_canonical(wide_junc, false, canonical,
                                              sizeof(canonical), &was_reparse));
  TEST_ASSERT_TRUE_MESSAGE(was_reparse,
                           "opened junction must be flagged as reparse point");

  /* A plain directory must NOT be flagged. */
  char plain_dir[340];
  snprintf(plain_dir, sizeof(plain_dir), "%s\\plain_dir", g_base);
  make_dir(plain_dir);

  wchar_t wide_plain[FOS_MAX_PATH];
  to_wide(plain_dir, wide_plain, FOS_MAX_PATH);
  bool plain_reparse = true;
  TEST_ASSERT_EQUAL_INT(0, fos_open_canonical(wide_plain, false, canonical,
                                              sizeof(canonical), &plain_reparse));
  TEST_ASSERT_FALSE_MESSAGE(plain_reparse,
                            "plain directory must not be flagged as reparse");
}

static void remove_dir(const char *path) {
  fos_path_t p;
  if (fos_path_init(&p, path)) RemoveDirectoryW(fos_path_w(&p));
}

static void remove_file(const char *path) {
  fos_path_t p;
  if (fos_path_init(&p, path)) fos_delete_file(&p);
}

void setUp(void) {
  const char *tmp = getenv("TEMP");
  if (!tmp) tmp = "C:\\Windows\\Temp";
  snprintf(g_base, sizeof(g_base), "%s\\fos_toctou_test", tmp);
  make_dir(g_base);
}

void tearDown(void) {
  /* Best-effort cleanup (RemoveDirectory on a junction removes the LINK,
   * not the target). */
  char buf[360];
  snprintf(buf, sizeof(buf), "%s\\real_dir\\payload.exe", g_base);
  remove_file(buf);
  snprintf(buf, sizeof(buf), "%s\\real_dir", g_base);
  remove_dir(buf);
  snprintf(buf, sizeof(buf), "%s\\plain_dir", g_base);
  remove_dir(buf);
  snprintf(buf, sizeof(buf), "%s\\looks_normal", g_base);
  remove_dir(buf);
  remove_dir(g_base);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_nonexistent_path_fails);
  RUN_TEST(test_follow_reparse_resolves_to_target);
  RUN_TEST(test_reparse_detected_atomically_without_follow);
  return UNITY_END();
}
