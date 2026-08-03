/**
 * test_heuristic_pe.c -- R-07 (I-10 / I-20) tests.
 *
 * Part A: heuristic scoring of the new PE-aware signals.
 * Part B: exact known-folder path validation (no more loose substring match).
 * Part C: synthetic-PE parsing -- suspicious imports, RWX sections, packer
 *         markers, overlays, anomalous entry points, oversized resources.
 */
#include "unity.h"

#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <shlobj.h>

#include "feature_extract.h"
#include "heuristic_engine.h"

/* ============================================================================
 * Part A -- heuristic scoring
 * ========================================================================== */

static FileFeatures base_features(void) {
  FileFeatures f;
  memset(&f, 0, sizeof(f));
  f.is_pe = true;
  /* Suppress the "No-imports" (+15) baseline so each case tests one signal. */
  f.pe_import_count = 1;
  return f;
}

static void test_single_signal_scoring(void) {
  HeuristicResult r;
  FileFeatures f;

  f = base_features();
  f.pe_suspicious_import = true;
  evaluate_heuristics(&f, &r, TRUST_NONE, SCAN_REASON_MANUAL);
  TEST_ASSERT_EQUAL_INT(20, r.score);
  TEST_ASSERT_EQUAL(VERDICT_BENIGN, r.verdict);
  TEST_ASSERT_TRUE(strstr(r.explanation, "Suspicious-imports;") != NULL);

  f = base_features();
  f.pe_packer_marker = true;
  evaluate_heuristics(&f, &r, TRUST_NONE, SCAN_REASON_MANUAL);
  TEST_ASSERT_EQUAL_INT(25, r.score);
  TEST_ASSERT_TRUE(strstr(r.explanation, "Packer-marker;") != NULL);

  f = base_features();
  f.pe_import_count = 0;
  evaluate_heuristics(&f, &r, TRUST_NONE, SCAN_REASON_MANUAL);
  TEST_ASSERT_EQUAL_INT(15, r.score);
  TEST_ASSERT_TRUE(strstr(r.explanation, "No-imports;") != NULL);

  f = base_features();
  f.pe_overlay = true;
  evaluate_heuristics(&f, &r, TRUST_NONE, SCAN_REASON_MANUAL);
  TEST_ASSERT_EQUAL_INT(10, r.score);
  TEST_ASSERT_TRUE(strstr(r.explanation, "Overlay;") != NULL);

  f = base_features();
  f.pe_rwx_section = true;
  evaluate_heuristics(&f, &r, TRUST_NONE, SCAN_REASON_MANUAL);
  TEST_ASSERT_EQUAL_INT(20, r.score);
  TEST_ASSERT_TRUE(strstr(r.explanation, "RWX-section;") != NULL);

  f = base_features();
  f.pe_ep_outside_text = true;
  evaluate_heuristics(&f, &r, TRUST_NONE, SCAN_REASON_MANUAL);
  TEST_ASSERT_EQUAL_INT(15, r.score);
  TEST_ASSERT_TRUE(strstr(r.explanation, "Anomalous-EP;") != NULL);

  f = base_features();
  f.pe_resource_size = 2u * 1024u * 1024u;
  evaluate_heuristics(&f, &r, TRUST_NONE, SCAN_REASON_MANUAL);
  TEST_ASSERT_EQUAL_INT(10, r.score);
  TEST_ASSERT_TRUE(strstr(r.explanation, "Resource-heavy;") != NULL);

  memset(&f, 0, sizeof(f));
  f.in_temp_dir = true;
  evaluate_heuristics(&f, &r, TRUST_NONE, SCAN_REASON_MANUAL);
  TEST_ASSERT_EQUAL_INT(15, r.score);

  memset(&f, 0, sizeof(f));
  f.in_startup_dir = true;
  evaluate_heuristics(&f, &r, TRUST_NONE, SCAN_REASON_MANUAL);
  TEST_ASSERT_EQUAL_INT(25, r.score);
}

static void test_pe_signals_gated_on_is_pe(void) {
  /* A non-PE file must not earn PE-only points even if flags leak. */
  FileFeatures f = base_features();
  f.is_pe = false;
  f.pe_suspicious_import = true;
  f.pe_packer_marker = true;
  f.pe_rwx_section = true;
  f.pe_ep_outside_text = true;
  f.pe_import_count = 0;
  HeuristicResult r;
  evaluate_heuristics(&f, &r, TRUST_NONE, SCAN_REASON_MANUAL);
  TEST_ASSERT_EQUAL_INT(0, r.score);
  TEST_ASSERT_EQUAL(VERDICT_BENIGN, r.verdict);
}

static void test_full_combo_is_malicious_and_dampened(void) {
  FileFeatures f = base_features();
  f.is_executable = true;
  f.in_temp_dir = true;
  f.high_entropy = true;
  f.pe_suspicious_import = true;
  f.pe_packer_marker = true;
  f.pe_overlay = true;
  f.pe_rwx_section = true;
  f.pe_ep_outside_text = true;
  f.pe_resource_size = 2u * 1024u * 1024u;
  /* leave pe_import_count == 0 so "No-imports;" also fires */

  HeuristicResult r;
  evaluate_heuristics(&f, &r, TRUST_NONE, SCAN_REASON_MANUAL);
  TEST_ASSERT_TRUE(r.score >= 90);
  TEST_ASSERT_EQUAL(VERDICT_MALICIOUS, r.verdict);

  /* Trust dampening must still apply on top of the new signals. */
  evaluate_heuristics(&f, &r, TRUST_HIGH, SCAN_REASON_MANUAL);
  TEST_ASSERT_TRUE(r.score < 45);
}

/* ============================================================================
 * Part B -- exact known-folder validation (I-10)
 * ========================================================================== */

static char *make_temp_file(const char *subdir, const char *name) {
  static char path[FOS_MAX_PATH];
  char tmp[FOS_MAX_PATH];
  if (!GetTempPathA(FOS_MAX_PATH - 2, tmp))
    return NULL;
  snprintf(path, sizeof(path), "%s%s%s", tmp, subdir ? subdir : "", name);
  FILE *f = fopen(path, "wb");
  if (!f)
    return NULL;
  fwrite("x", 1, 1, f);
  fclose(f);
  return path;
}

static void test_real_temp_dir_is_detected(void) {
  char *path = make_temp_file("", "fos_tmp_true_1.exe");
  TEST_ASSERT_NOT_NULL(path);
  FileFeatures f;
  TEST_ASSERT_EQUAL_INT(0, extract_file_features(path, &f));
  TEST_ASSERT_TRUE(f.in_temp_dir);
  remove(path);
}

static void test_temp_substring_decoy_is_rejected(void) {
  /* A "Temp" directory that is NOT the system temp must not match. */
  CreateDirectoryA(".fos_decoy", NULL);
  CreateDirectoryA(".fos_decoy\\Temp", NULL);
  FILE *f = fopen(".fos_decoy\\Temp\\evil.exe", "wb");
  TEST_ASSERT_NOT_NULL(f);
  fwrite("x", 1, 1, f);
  fclose(f);
  FileFeatures feat;
  TEST_ASSERT_EQUAL_INT(
      0, extract_file_features(".fos_decoy\\Temp\\evil.exe", &feat));
  TEST_ASSERT_FALSE(feat.in_temp_dir);
  remove(".fos_decoy\\Temp\\evil.exe");
  RemoveDirectoryA(".fos_decoy\\Temp");
  RemoveDirectoryA(".fos_decoy");
}

static void test_startup_decoy_is_rejected(void) {
  /* A "Startup" directory outside the canonical known folder. */
  CreateDirectoryA(".fos_decoy", NULL);
  CreateDirectoryA(".fos_decoy\\Startup", NULL);
  FILE *f = fopen(".fos_decoy\\Startup\\evil.exe", "wb");
  TEST_ASSERT_NOT_NULL(f);
  fwrite("x", 1, 1, f);
  fclose(f);
  FileFeatures feat;
  TEST_ASSERT_EQUAL_INT(
      0, extract_file_features(".fos_decoy\\Startup\\evil.exe", &feat));
  TEST_ASSERT_FALSE(feat.in_startup_dir);
  remove(".fos_decoy\\Startup\\evil.exe");
  RemoveDirectoryA(".fos_decoy\\Startup");
  RemoveDirectoryA(".fos_decoy");
}

static void test_downloads_decoy_is_rejected(void) {
  CreateDirectoryA(".fos_decoy", NULL);
  CreateDirectoryA(".fos_decoy\\Downloads", NULL);
  FILE *f = fopen(".fos_decoy\\Downloads\\evil.exe", "wb");
  TEST_ASSERT_NOT_NULL(f);
  fwrite("x", 1, 1, f);
  fclose(f);
  FileFeatures feat;
  TEST_ASSERT_EQUAL_INT(
      0, extract_file_features(".fos_decoy\\Downloads\\evil.exe", &feat));
  TEST_ASSERT_FALSE(feat.in_downloads_dir);
  remove(".fos_decoy\\Downloads\\evil.exe");
  RemoveDirectoryA(".fos_decoy\\Downloads");
  RemoveDirectoryA(".fos_decoy");
}

static void test_real_startup_dir_is_detected(void) {
  PWSTR startup = NULL;
  if (FAILED(SHGetKnownFolderPath(&FOLDERID_Startup, 0, NULL, &startup))) {
    TEST_IGNORE_MESSAGE("no per-user Startup folder available");
  }
  char path[FOS_MAX_PATH];
  WideCharToMultiByte(CP_UTF8, 0, startup, -1, path, sizeof(path), NULL, NULL);
  CoTaskMemFree(startup);
  strncat(path, "\\fos_startup_true_1.exe", sizeof(path) - strlen(path) - 1);

  FILE *f = fopen(path, "wb");
  if (!f) {
    TEST_IGNORE_MESSAGE("cannot write to Startup folder");
  }
  fwrite("x", 1, 1, f);
  fclose(f);

  FileFeatures feat;
  TEST_ASSERT_EQUAL_INT(0, extract_file_features(path, &feat));
  TEST_ASSERT_TRUE(feat.in_startup_dir);
  remove(path);
}

static void test_real_downloads_dir_is_detected(void) {
  PWSTR dl = NULL;
  if (FAILED(SHGetKnownFolderPath(&FOLDERID_Downloads, 0, NULL, &dl))) {
    TEST_IGNORE_MESSAGE("no Downloads folder available");
  }
  char path[FOS_MAX_PATH];
  WideCharToMultiByte(CP_UTF8, 0, dl, -1, path, sizeof(path), NULL, NULL);
  CoTaskMemFree(dl);
  strncat(path, "\\fos_dl_true_1.exe", sizeof(path) - strlen(path) - 1);

  FILE *f = fopen(path, "wb");
  if (!f) {
    TEST_IGNORE_MESSAGE("cannot write to Downloads folder");
  }
  fwrite("x", 1, 1, f);
  fclose(f);

  FileFeatures feat;
  TEST_ASSERT_EQUAL_INT(0, extract_file_features(path, &feat));
  TEST_ASSERT_TRUE(feat.in_downloads_dir);
  remove(path);
}

/* ============================================================================
 * Part C -- synthetic PE parsing (I-20)
 * ========================================================================== */

typedef struct {
  bool rwx_data;          /* .data marked EXECUTE|WRITE */
  bool ep_in_text;        /* entry point inside .text */
  bool packer_name;       /* second section named UPX0 */
  bool suspicious_import; /* kernel32.dll!CreateRemoteThread */
  bool resource_heavy;    /* resource directory size 2 MB */
  bool overlay;           /* appended junk, SizeOfImage smaller than file */
} PEConfig;

#define PE_FILE_TEXT_RAW  0x200u
#define PE_FILE_DATA_RAW  0x300u
#define PE_FILE_IMPORTS   0x400u
#define PE_FILE_RES_DATA  0x500u
#define PE_FILE_END       0xB00u
#define PE_RVA_TEXT       0x1000u
#define PE_RVA_DATA       0x2000u
#define PE_RVA_IMPORTS    0x2100u
#define PE_RVA_THUNK      0x2140u
#define PE_RVA_FIRSTTHUNK 0x2148u
#define PE_RVA_LIBNAME    0x2150u
#define PE_RVA_HINTNAME   0x2160u

static size_t build_pe(uint8_t *buf, size_t cap, const PEConfig *cfg) {
  memset(buf, 0, cap);

  IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)buf;
  dos->e_magic = IMAGE_DOS_SIGNATURE;
  dos->e_lfanew = 0x40;

  IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(buf + 0x40);
  nt->Signature = IMAGE_NT_SIGNATURE;
  nt->FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
  nt->FileHeader.NumberOfSections = 2;
  nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);
  nt->FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE;
  nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
  nt->OptionalHeader.SizeOfImage = cfg->overlay ? 0x800u : 0x2800u;
  nt->OptionalHeader.AddressOfEntryPoint = cfg->ep_in_text ? 0x1050u : 0x2100u;
  nt->OptionalHeader.NumberOfRvaAndSizes = 16;

  /* Import directory: descriptors + thunks + names inside .data raw area. */
  IMAGE_DATA_DIRECTORY *dd = nt->OptionalHeader.DataDirectory;
  if (cfg->suspicious_import) {
    dd[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = PE_RVA_IMPORTS;
    dd[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0x60;
    dd[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = 0x2200u;
    dd[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size =
        cfg->resource_heavy ? (2u * 1024u * 1024u) : 0x100u;
  }

  /* Section table. */
  IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
  memcpy(sec[0].Name, ".text", 5);
  sec[0].VirtualAddress = PE_RVA_TEXT;
  sec[0].Misc.VirtualSize = 0x100;
  sec[0].PointerToRawData = PE_FILE_TEXT_RAW;
  sec[0].SizeOfRawData = 0x100;
  sec[0].Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

  memcpy(sec[1].Name, cfg->packer_name ? "UPX0" : ".data",
         cfg->packer_name ? 4 : 5);
  sec[1].VirtualAddress = PE_RVA_DATA;
  sec[1].Misc.VirtualSize = 0x800;
  sec[1].PointerToRawData = PE_FILE_DATA_RAW;
  sec[1].SizeOfRawData = 0x800;
  sec[1].Characteristics =
      cfg->rwx_data ? (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ)
                    : (IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);

  /* .text and .data raw payloads. */
  memset(buf + PE_FILE_TEXT_RAW, 0x90, 0x100);
  memset(buf + PE_FILE_DATA_RAW, 0xCC, 0x800);

  if (cfg->suspicious_import) {
    IMAGE_IMPORT_DESCRIPTOR *imp = (IMAGE_IMPORT_DESCRIPTOR *)(buf + PE_FILE_IMPORTS);
    imp[0].OriginalFirstThunk = PE_RVA_THUNK;
    imp[0].Name = PE_RVA_LIBNAME;
    imp[0].FirstThunk = PE_RVA_FIRSTTHUNK;
    /* imp[1] is the all-zero terminator (memset). */

    uint32_t *thunk = (uint32_t *)(buf + 0x440);
    thunk[0] = PE_RVA_HINTNAME;
    thunk[1] = 0;
    uint32_t *first = (uint32_t *)(buf + 0x448);
    first[0] = PE_RVA_HINTNAME;
    first[1] = 0;

    strcpy((char *)(buf + 0x450), "kernel32.dll");
    uint16_t *hint = (uint16_t *)(buf + 0x460);
    *hint = 0;
    strcpy((char *)(buf + 0x462), "CreateRemoteThread");
  }

  size_t total = PE_FILE_END;
  if (cfg->overlay) {
    memset(buf + PE_FILE_END, 0xAA, 0x200);
    total += 0x200;
  }
  return total;
}

static char *write_pe_at(const uint8_t *buf, size_t len, const char *tag,
                         const char *dir) {
  static char path[FOS_MAX_PATH];
  char tmp[FOS_MAX_PATH];
  if (!GetTempPathA(FOS_MAX_PATH - 2, tmp))
    return NULL;
  snprintf(path, sizeof(path), "%s%s_%lu.exe", dir, tag,
           GetCurrentProcessId());
  FILE *f = fopen(path, "wb");
  if (!f)
    return NULL;
  fwrite(buf, 1, len, f);
  fclose(f);
  return path;
}

static char *write_pe(const uint8_t *buf, size_t len, const char *tag) {
  char tmp[FOS_MAX_PATH];
  if (!GetTempPathA(FOS_MAX_PATH - 2, tmp))
    return NULL;
  return write_pe_at(buf, len, tag, tmp);
}

static void test_benign_control_pe(void) {
  uint8_t buf[0x2000];
  PEConfig cfg = {0};
  cfg.ep_in_text = true;
  size_t len = build_pe(buf, sizeof(buf), &cfg);
  char *path = write_pe_at(buf, len, "fos_pe_ctl", ".\\");
  TEST_ASSERT_NOT_NULL(path);

  FileFeatures f;
  TEST_ASSERT_EQUAL_INT(0, extract_file_features(path, &f));
  TEST_ASSERT_TRUE(f.is_pe);
  TEST_ASSERT_FALSE(f.pe_suspicious_import);
  TEST_ASSERT_FALSE(f.pe_packer_marker);
  TEST_ASSERT_FALSE(f.pe_overlay);
  TEST_ASSERT_FALSE(f.pe_rwx_section);
  TEST_ASSERT_FALSE(f.pe_ep_outside_text);
  TEST_ASSERT_EQUAL_INT(0, f.pe_import_count);
  TEST_ASSERT_FALSE(f.in_temp_dir);

  HeuristicResult r;
  evaluate_heuristics(&f, &r, TRUST_NONE, SCAN_REASON_MANUAL);
  TEST_ASSERT_TRUE(r.score < 45);
  remove(path);
}

static void test_suspicious_import_detected(void) {
  uint8_t buf[0x2000];
  PEConfig cfg = {0};
  cfg.ep_in_text = true;
  cfg.suspicious_import = true;
  size_t len = build_pe(buf, sizeof(buf), &cfg);
  char *path = write_pe(buf, len, "fos_pe_imp");
  TEST_ASSERT_NOT_NULL(path);

  FileFeatures f;
  TEST_ASSERT_EQUAL_INT(0, extract_file_features(path, &f));
  TEST_ASSERT_TRUE(f.is_pe);
  TEST_ASSERT_TRUE(f.pe_suspicious_import);
  TEST_ASSERT_EQUAL_INT(1, f.pe_import_count);
  remove(path);
}

static void test_rwx_section_detected(void) {
  uint8_t buf[0x2000];
  PEConfig cfg = {0};
  cfg.ep_in_text = true;
  cfg.rwx_data = true;
  size_t len = build_pe(buf, sizeof(buf), &cfg);
  char *path = write_pe(buf, len, "fos_pe_rwx");
  TEST_ASSERT_NOT_NULL(path);

  FileFeatures f;
  TEST_ASSERT_EQUAL_INT(0, extract_file_features(path, &f));
  TEST_ASSERT_TRUE(f.pe_rwx_section);
  remove(path);
}

static void test_anomalous_ep_detected(void) {
  uint8_t buf[0x2000];
  PEConfig cfg = {0};
  cfg.ep_in_text = false; /* EP in .data */
  size_t len = build_pe(buf, sizeof(buf), &cfg);
  char *path = write_pe(buf, len, "fos_pe_ep");
  TEST_ASSERT_NOT_NULL(path);

  FileFeatures f;
  TEST_ASSERT_EQUAL_INT(0, extract_file_features(path, &f));
  TEST_ASSERT_TRUE(f.pe_ep_outside_text);
  remove(path);
}

static void test_packer_marker_detected(void) {
  uint8_t buf[0x2000];
  PEConfig cfg = {0};
  cfg.ep_in_text = true;
  cfg.packer_name = true;
  size_t len = build_pe(buf, sizeof(buf), &cfg);
  char *path = write_pe(buf, len, "fos_pe_pack");
  TEST_ASSERT_NOT_NULL(path);

  FileFeatures f;
  TEST_ASSERT_EQUAL_INT(0, extract_file_features(path, &f));
  TEST_ASSERT_TRUE(f.pe_packer_marker);
  remove(path);
}

static void test_overlay_detected(void) {
  uint8_t buf[0x2000];
  PEConfig cfg = {0};
  cfg.ep_in_text = true;
  cfg.overlay = true;
  size_t len = build_pe(buf, sizeof(buf), &cfg);
  char *path = write_pe(buf, len, "fos_pe_ovl");
  TEST_ASSERT_NOT_NULL(path);

  FileFeatures f;
  TEST_ASSERT_EQUAL_INT(0, extract_file_features(path, &f));
  TEST_ASSERT_TRUE(f.pe_overlay);
  remove(path);
}

static void test_resource_heavy_detected(void) {
  uint8_t buf[0x2000];
  PEConfig cfg = {0};
  cfg.ep_in_text = true;
  cfg.suspicious_import = true; /* needed to set up the data directory */
  cfg.resource_heavy = true;
  size_t len = build_pe(buf, sizeof(buf), &cfg);
  char *path = write_pe(buf, len, "fos_pe_res");
  TEST_ASSERT_NOT_NULL(path);

  FileFeatures f;
  TEST_ASSERT_EQUAL_INT(0, extract_file_features(path, &f));
  TEST_ASSERT_TRUE(f.pe_resource_size > (1024u * 1024u));
  remove(path);
}

/* ========================================================================== */

void setUp(void) {}
void tearDown(void) {}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  UNITY_BEGIN();

  /* Part A */
  RUN_TEST(test_single_signal_scoring);
  RUN_TEST(test_pe_signals_gated_on_is_pe);
  RUN_TEST(test_full_combo_is_malicious_and_dampened);

  /* Part B */
  RUN_TEST(test_real_temp_dir_is_detected);
  RUN_TEST(test_temp_substring_decoy_is_rejected);
  RUN_TEST(test_startup_decoy_is_rejected);
  RUN_TEST(test_downloads_decoy_is_rejected);
  RUN_TEST(test_real_startup_dir_is_detected);
  RUN_TEST(test_real_downloads_dir_is_detected);

  /* Part C */
  RUN_TEST(test_benign_control_pe);
  RUN_TEST(test_suspicious_import_detected);
  RUN_TEST(test_rwx_section_detected);
  RUN_TEST(test_anomalous_ep_detected);
  RUN_TEST(test_packer_marker_detected);
  RUN_TEST(test_overlay_detected);
  RUN_TEST(test_resource_heavy_detected);

  return UNITY_END();
}
