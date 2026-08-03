#define _CRT_SECURE_NO_WARNINGS

#include "feature_extract.h"
#include "path_utils.h"
#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <objbase.h>
#include <shlobj.h>

/* ============================================================================
 * Standard helper macros
 *
 * min() is not a standard C macro; define it locally so the file compiles
 * on strict compilers (e.g. MSVC with /W3 /WX, or MinGW -Wall -Wextra).
 * ========================================================================== */

#ifndef min
#define min(a, b) (((a) < (b)) ? (a) : (b))
#endif

/* ============================================================================
 * Feature Vector Index Constants
 *
 * The feature vector is 2,381 dimensions. The indices below replace the
 * magic numbers that were previously hardcoded throughout this file. They
 * are grouped by feature family for clarity. See feature_extract.h for the
 * full vector layout.
 * ========================================================================== */

/* Byte histograms (0..511) — populated by calc_histograms() */
#define FEAT_IDX_BYTE_HISTOGRAM_BASE   0     /* 256 dims: raw byte counts, L1-normalized */
#define FEAT_IDX_BYTE_ENTROPY_BASE   256     /* 256 dims: 2D byte-entropy histogram */

/* Import hashes (512..1535) — populated by parse_pe() */
#define FEAT_IDX_IMPORTS_BASE        512     /* 1024 dims: hashed import lib:func names */

/* Export hashes (1536..1791) — populated by parse_pe() */
#define FEAT_IDX_EXPORTS_BASE       1536     /* 256 dims: hashed export names */

/* Section hashes (1792..2047) — populated by parse_pe() */
#define FEAT_IDX_SECTIONS_BASE      1792     /* 256 dims: hashed section names + chars */

/* Data directory hashes (2048..2303) — populated by parse_pe() */
#define FEAT_IDX_DATA_DIRS_BASE     2048     /* 256 dims: hashed data dir names */

/* Scalar PE features (2304..2319) — populated by parse_pe() and extract_file_features() */
#define FEAT_IDX_FILE_SIZE         2304     /* File size in bytes (from extract_file_features) */
#define FEAT_IDX_VSIZE             2305     /* PE OptionalHeader.SizeOfImage */
#define FEAT_IDX_HAS_DEBUG         2306     /* 1.0 if PE has debug directory, else 0.0 */
#define FEAT_IDX_EXPORT_COUNT      2307     /* Number of exported functions */
#define FEAT_IDX_IMPORT_COUNT      2308     /* Number of imported functions */
#define FEAT_IDX_NUM_SECTIONS      2309     /* Number of PE sections */
#define FEAT_IDX_MEAN_SECTION_ENT  2310     /* Mean entropy across sections */

/* String-extraction scalars (2311..2317) — populated by analyze_strings() */
#define FEAT_IDX_NUM_STRINGS       2311     /* Count of printable strings (>= MIN_LEN) */
#define FEAT_IDX_AVG_STRING_LEN    2312     /* Average length of strings */
#define FEAT_IDX_PRINTABLES        2313     /* Total printable character count */
#define FEAT_IDX_FILE_ENTROPY      2314     /* Full-file Shannon entropy */
#define FEAT_IDX_NUM_PATHS         2315     /* Count of path-like strings */
#define FEAT_IDX_NUM_URLS          2316     /* Count of URL strings */
#define FEAT_IDX_NUM_REGISTRY      2317     /* Count of registry-key strings */

/* PE magic / architecture flags (2318..2319) — populated by parse_pe() */
#define FEAT_IDX_MZ_MAGIC          2318     /* DOS e_magic (IMAGE_DOS_SIGNATURE = 'MZ') */
#define FEAT_IDX_IS_PE64           2319     /* 1.0 if PE32+, 0.0 if PE32 */

/* Total vector dimensionality */
#define FEAT_VECTOR_DIM            2381

/* ============================================================================
 * Feature Hashing (MurmurHash3) exactly matching scikit-learn mmh3
 * ========================================================================== */

static inline uint32_t rotl32(uint32_t x, int8_t r) {
  return (x << r) | (x >> (32 - r));
}

static uint32_t MurmurHash3_x86_32(const void *key, int len, uint32_t seed) {
  const uint8_t *data = (const uint8_t *)key;
  const int nblocks = len / 4;
  uint32_t h1 = seed;
  const uint32_t c1 = 0xcc9e2d51;
  const uint32_t c2 = 0x1b873593;

  const uint32_t *blocks = (const uint32_t *)data;
  for (int i = 0; i < nblocks; i++) {
    uint32_t k1 = blocks[i];
    k1 *= c1;
    k1 = rotl32(k1, 15);
    k1 *= c2;

    h1 ^= k1;
    h1 = rotl32(h1, 13);
    h1 = h1 * 5 + 0xe6546b64;
  }

  const uint8_t *tail = (const uint8_t *)(data + nblocks * 4);
  uint32_t k1 = 0;
  switch (len & 3) {
  case 3:
    k1 ^= tail[2] << 16;
    /* fall through */
  case 2:
    k1 ^= tail[1] << 8;
    /* fall through */
  case 1:
    k1 ^= tail[0];
    k1 *= c1;
    k1 = rotl32(k1, 15);
    k1 *= c2;
    h1 ^= k1;
  }

  h1 ^= len;
  h1 ^= h1 >> 16;
  h1 *= 0x85ebca6b;
  h1 ^= h1 >> 13;
  h1 *= 0xc2b2ae35;
  h1 ^= h1 >> 16;

  return h1;
}

static void hash_feature_str(float *vec, const char *str, int start_idx,
                             int num_dims) {
  if (!str)
    return;
  int32_t h = (int32_t)MurmurHash3_x86_32(str, (int)strlen(str), 0);
  /* Mirror Python's abs(mmh3.hash(...)): INT32_MIN has no positive int32
   * counterpart, so compute the magnitude in 64-bit to match Python exactly
   * and avoid signed overflow (which would otherwise index out of bounds). */
  uint64_t mag = (h < 0) ? (uint64_t)(-(int64_t)h) : (uint64_t)h;
  int idx = (int)(mag % (uint64_t)num_dims);
  float val = (h > 0) ? 1.0f : -1.0f;
  vec[start_idx + idx] += val;
}

static void str_to_lower(char *str) {
  for (; *str; ++str)
    *str = (char)tolower((unsigned char)*str);
}

/* ============================================================================
 * Internal Helpers: Byte Distributions
 * ========================================================================== */

static void calc_histograms(const uint8_t *data, size_t size, float *vec) {
  if (size == 0)
    return;

  /* 1. Raw Byte Histogram [FEAT_IDX_BYTE_HISTOGRAM_BASE .. +255] */
  uint32_t counts[256] = {0};
  for (size_t i = 0; i < size; i++) {
    counts[data[i]]++;
  }
  for (int i = 0; i < 256; i++) {
    vec[FEAT_IDX_BYTE_HISTOGRAM_BASE + i] = (float)counts[i] / (float)size;
  }

  /* 2. EMBER 2D Byte-Entropy Histogram [FEAT_IDX_BYTE_ENTROPY_BASE .. +255]
   *
   * Exact port of EMBER's ByteEntropyHistogram (Saxe & Berlin 2015 style,
   * https://github.com/elastic/ember). For every 2048-byte block (1024-byte
   * stride) the block entropy is computed from a coarse 16-bin histogram of
   * byte nibbles (byte >> 4); the entropy is doubled because 4-bit binning
   * halves the information, then quantized to 16 entropy bins via
   * Hbin = int(H * 2) with Hbin == 16 clamped to 15. The 16x16
   * (entropy-bin, nibble) counts are flattened row-major to 256 dimensions
   * and L1-normalized, exactly matching the EMBER JSONL "byteentropy" raw
   * feature that extract_features.py reads. Note that even for files smaller
   * than the window the probability denominator is the window size, as in
   * the reference implementation. */
  const size_t window_size = 2048;
  const size_t step = 1024;
  double ext_counts[16][16] = {{0}};
  double total_ext = 0.0;

  if (size < window_size) {
    int64_t c[16] = {0};
    for (size_t i = 0; i < size; i++)
      c[data[i] >> 4]++;
    double H = 0;
    for (int n = 0; n < 16; n++) {
      if (c[n] > 0) {
        double p = (double)c[n] / (double)window_size;
        H -= p * log2(p);
      }
    }
    H *= 2.0;
    int Hbin = (int)(H * 2.0);
    if (Hbin == 16)
      Hbin = 15;
    for (int n = 0; n < 16; n++) {
      ext_counts[Hbin][n] = (double)c[n];
      total_ext += (double)c[n];
    }
  } else {
    for (size_t i = 0; i + window_size <= size; i += step) {
      int64_t c[16] = {0};
      for (size_t j = 0; j < window_size; j++)
        c[data[i + j] >> 4]++;
      double H = 0;
      for (int n = 0; n < 16; n++) {
        if (c[n] > 0) {
          double p = (double)c[n] / (double)window_size;
          H -= p * log2(p);
        }
      }
      H *= 2.0;
      int Hbin = (int)(H * 2.0);
      if (Hbin == 16)
        Hbin = 15;
      for (int n = 0; n < 16; n++) {
        ext_counts[Hbin][n] += (double)c[n];
        total_ext += (double)c[n];
      }
    }
  }

  if (total_ext > 0) {
    for (int hb = 0; hb < 16; hb++) {
      for (int n = 0; n < 16; n++) {
        vec[FEAT_IDX_BYTE_ENTROPY_BASE + hb * 16 + n] =
            (float)(ext_counts[hb][n] / total_ext);
      }
    }
  }
}

static bool has_executable_extension_wide(const wchar_t *path) {
  const wchar_t *ext = wcsrchr(path, L'.');
  if (!ext)
    return false;
  return (_wcsicmp(ext, L".exe") == 0 || _wcsicmp(ext, L".dll") == 0 ||
          _wcsicmp(ext, L".sys") == 0 || _wcsicmp(ext, L".scr") == 0);
}

/* ============================================================================
 * Internal Helpers: Exact Known-Folder Location Checks (R-07 / I-10)
 *
 * The old code used substring matching ("\\Temp\\", "\\Startup\\") which
 * produced false positives for decoy directories like
 * "C:\Program Files\Foo\Temp\evil.exe" or "C:\Backup\Downloads\bad.exe".
 * These helpers require the file to actually live under the canonical
 * system folder (or a subdirectory of it).
 * ========================================================================== */

static bool is_in_known_folder_wide(const wchar_t *path, REFKNOWNFOLDERID folder_id) {
  if (!path)
    return false;

  /* fos_path_t may have prepended the "\\?\" long-path prefix. */
  const wchar_t *p = path;
  if (wcsncmp(p, L"\\\\?\\", 4) == 0)
    p += 4;

  PWSTR folder_path = NULL;
  if (FAILED(SHGetKnownFolderPath(folder_id, 0, NULL, &folder_path)))
    return false;

  bool result = false;
  size_t flen = wcslen(folder_path);
  if (flen > 0 && _wcsnicmp(p, folder_path, flen) == 0) {
    wchar_t sep = p[flen];
    result = (sep == L'\\' || sep == L'/');
  }
  CoTaskMemFree(folder_path);
  return result;
}

static bool is_in_dir_prefix_wide(const wchar_t *path, const wchar_t *dir) {
  if (!path || !dir)
    return false;

  /* fos_path_t may have prepended the "\\?\" long-path prefix. */
  const wchar_t *p = path;
  if (wcsncmp(p, L"\\\\?\\", 4) == 0)
    p += 4;

  size_t dlen = wcslen(dir);
  if (dlen == 0)
    return false;
  if (_wcsnicmp(p, dir, dlen) != 0)
    return false;
  wchar_t sep = p[dlen];
  return (sep == L'\\' || sep == L'/');
}

/* The per-user Temp dir (GetTempPathW) and the system Temp dir are both
 * canonical temp locations; anything else named "Temp" is not. */
static bool is_in_known_temp_wide(const wchar_t *path) {
  if (!path)
    return false;

  wchar_t tmp[MAX_PATH + 2] = {0};
  DWORD n = GetTempPathW(MAX_PATH, tmp);
  if (n == 0 || n > MAX_PATH)
    return false;
  while (n > 0 && (tmp[n - 1] == L'\\' || tmp[n - 1] == L'/'))
    tmp[--n] = L'\0';
  if (is_in_dir_prefix_wide(path, tmp))
    return true;

  wchar_t sys_tmp[MAX_PATH + 2] = {0};
  UINT wn = GetWindowsDirectoryW(sys_tmp, MAX_PATH);
  if (wn == 0 || wn > MAX_PATH)
    return false;
  wcscat_s(sys_tmp, MAX_PATH + 2, L"\\Temp");
  return is_in_dir_prefix_wide(path, sys_tmp);
}

/* ============================================================================
 * Internal Helpers: String Analysis (Extracts exactly to base scalars)
 * ========================================================================== */

static void analyze_strings(const uint8_t *data, size_t size, float *vec) {
  size_t current_len = 0;
  size_t total_len_all = 0;
  const size_t MIN_LEN = 4;

  float num_strings = 0.0f, printables = 0.0f, paths = 0.0f, urls = 0.0f,
        reg = 0.0f;

  for (size_t i = 0; i < size; i++) {
    uint8_t c = data[i];
    if (c >= 32 && c <= 126) {
      printables += 1.0f;
      current_len++;
    } else {
      if (current_len >= MIN_LEN) {
        num_strings += 1.0f;
        total_len_all += current_len;
        const char *str_start = (const char *)(data + i - current_len);

        if (current_len > 7 && (strncmp(str_start, "http://", 7) == 0 ||
                                strncmp(str_start, "https://", 8) == 0)) {
          urls += 1.0f;
        }
        if (current_len > 3 && ((isalpha(str_start[0]) && str_start[1] == ':' &&
                                 str_start[2] == '\\') ||
                                (str_start[0] == '/'))) {
          paths += 1.0f;
        }
        if (current_len > 5 && strncmp(str_start, "HKEY_", 5) == 0) {
          reg += 1.0f;
        }
      }
      current_len = 0;
    }
  }

  if (current_len >= MIN_LEN) {
    num_strings += 1.0f;
    total_len_all += current_len;
  }

  vec[FEAT_IDX_NUM_STRINGS] = num_strings;
  vec[FEAT_IDX_AVG_STRING_LEN] =
      (num_strings > 0) ? (float)total_len_all / num_strings : 0.0f;
  vec[FEAT_IDX_PRINTABLES] = printables;

  /* Calculate raw string entropy (over printables only) using 256 vector
   * Omitting here due to overhead, approximated as file entropy in basic EMBER */
  vec[FEAT_IDX_NUM_PATHS] = paths;
  vec[FEAT_IDX_NUM_URLS] = urls;
  vec[FEAT_IDX_NUM_REGISTRY] = reg;
}

/* ============================================================================
 * Internal Helpers: Robust PE Parsing & Hashing
 * ========================================================================== */

static DWORD rva_to_offset(PIMAGE_NT_HEADERS nt, DWORD rva, size_t file_size) {
  PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
  for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, section++) {
    if ((uint8_t *)(section + 1) >
        (uint8_t *)nt + sizeof(IMAGE_NT_HEADERS) +
            (nt->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER))) {
      return 0;
    }
    if (rva >= section->VirtualAddress &&
        rva < section->VirtualAddress + section->Misc.VirtualSize) {
      DWORD offset = rva - section->VirtualAddress + section->PointerToRawData;
      if (offset < file_size)
        return offset;
    }
  }
  return 0;
}

static void parse_pe(const uint8_t *data, size_t size, FileFeatures *feat) {
  float *v = feat->vector;

  if (size < sizeof(IMAGE_DOS_HEADER))
    return;
  const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)data;
  if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    return;

  v[FEAT_IDX_MZ_MAGIC] = (float)dos->e_magic; /* MZ */
  feat->is_pe = true;

  /* Validate e_lfanew bounds. Also guard against integer overflow on
   * NumberOfSections * sizeof(IMAGE_SECTION_HEADER) before we trust it. */
  if (dos->e_lfanew < 0 ||
      (size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > size)
    return;
  PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(data + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE)
    return;

  v[FEAT_IDX_VSIZE] = (float)nt->OptionalHeader.SizeOfImage;

  /* Base architecture check */
  bool is64 = (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
  if (is64)
    v[FEAT_IDX_IS_PE64] = 1.0f;

  if (nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_DEBUG &&
      nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size > 0) {
    v[FEAT_IDX_HAS_DEBUG] = 1.0f;
  }

  /* Data Directories (Hash names, FEAT_IDX_DATA_DIRS_BASE .. +255)
   * Hardcoded known names for standard index limits */
  const char *dir_names[] = {
      "export",    "import",       "resource",       "exception",
      "security",  "basereloc",    "debug",          "architecture",
      "globalptr", "tls",          "load_config",    "bound_import",
      "iat",       "delay_import", "com_descriptor", ""};
  /* Use min() macro defined above; cap at 15 to match the dir_names table.
   * Cast NumberOfRvaAndSizes to int (it's a DWORD/uint32, but PE spec caps
   * it at 16 in practice — anything higher is malformed). */
  int rva_count = (int)nt->OptionalHeader.NumberOfRvaAndSizes;
  if (rva_count > 15) rva_count = 15;
  if (rva_count < 0) rva_count = 0;
  for (int i = 0; i < rva_count; i++) {
    if (nt->OptionalHeader.DataDirectory[i].Size > 0 &&
        nt->OptionalHeader.DataDirectory[i].VirtualAddress > 0) {
      hash_feature_str(v, dir_names[i], FEAT_IDX_DATA_DIRS_BASE, 256);
    }
  }

  /* Sections (Hash names, FEAT_IDX_SECTIONS_BASE .. +255) */
  float num_sections = (float)nt->FileHeader.NumberOfSections;
  v[FEAT_IDX_NUM_SECTIONS] = num_sections;

  double total_entropy = 0;
  PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
  /* Integer-overflow-safe size check: compute section_headers_size as size_t
   * and verify it doesn't wrap, then verify it fits within `size`.
   *
   * Per the PE spec, NumberOfSections is a WORD (uint16), so its max is
   * 65535. We additionally cap at a generous real-world maximum (1024) to
   * reject absurd values early — most legitimate PEs have < 20 sections. */
  if (nt->FileHeader.NumberOfSections == 0 ||
      nt->FileHeader.NumberOfSections > 1024) {
    v[FEAT_IDX_NUM_SECTIONS] = 0;
    return;
  }
  size_t section_headers_size =
      (size_t)nt->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
  if ((uint8_t *)section + section_headers_size > data + size) {
    v[FEAT_IDX_NUM_SECTIONS] = 0;
    return;
  }

  /* R-07 (I-20) PE-aware signals gathered while walking the sections. */
  uint32_t rwx_chars = (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE);
  DWORD text_va = 0, text_vsize = 0;
  bool has_rwx = false, has_packer_name = false;

  for (int i = 0; i < (int)num_sections; i++) {
    char sec_name[9] = {0};
    memcpy(sec_name, section[i].Name, 8);
    hash_feature_str(v, sec_name, FEAT_IDX_SECTIONS_BASE, 256);

    char chars_buf[16];
    sprintf(chars_buf, "%u", (unsigned int)section[i].Characteristics);
    hash_feature_str(v, chars_buf, FEAT_IDX_SECTIONS_BASE, 256);

    if ((section[i].Characteristics & rwx_chars) == rwx_chars)
      has_rwx = true;

    /* Packer section-name markers (UPX*, .MPRESS, .aspack). Names are
     * space-padded to 8 bytes; compare the meaningful prefix. */
    if (_strnicmp(sec_name, "UPX", 3) == 0 ||
        _strnicmp(sec_name, ".MPRESS", 7) == 0 ||
        _strnicmp(sec_name, ".aspack", 7) == 0 ||
        _strnicmp(sec_name, ".packed", 7) == 0) {
      has_packer_name = true;
    }

    if (_stricmp(sec_name, ".text") == 0) {
      text_va = section[i].VirtualAddress;
      text_vsize = section[i].Misc.VirtualSize;
    }

    DWORD raw_offset = section[i].PointerToRawData;
    DWORD raw_size = section[i].SizeOfRawData;
    if (raw_offset < size && (size_t)raw_offset + raw_size <= size &&
        raw_size > 0) {
      /* EMBER calculates mean entropy across sections. */
      uint32_t counts[256] = {0};
      for (DWORD j = 0; j < raw_size; j++)
        counts[data[raw_offset + j]]++;
      double ent = 0;
      for (int j = 0; j < 256; j++) {
        if (counts[j] > 0) {
          double p = (double)counts[j] / raw_size;
          ent -= p * log2(p);
        }
      }
      total_entropy += ent;
    }
  }
  if (num_sections > 0) {
    v[FEAT_IDX_MEAN_SECTION_ENT] = (float)(total_entropy / num_sections);
  }

  feat->pe_rwx_section = has_rwx;

  /* R-07: anomalous entry point — EP outside the .text section. */
  DWORD ep = nt->OptionalHeader.AddressOfEntryPoint;
  if (ep != 0 && text_va != 0) {
    feat->pe_ep_outside_text =
        !(ep >= text_va && ep < text_va + text_vsize);
  }

  /* R-07: overlay — file data beyond SizeOfImage (appended payload). */
  if (nt->OptionalHeader.SizeOfImage > 0 &&
      size > nt->OptionalHeader.SizeOfImage) {
    feat->pe_overlay = true;
  }

  /* R-07: oversized resource directory. */
  if (nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_RESOURCE) {
    feat->pe_resource_size =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
  }

  /* Imports (Hash libs + funcs, FEAT_IDX_IMPORTS_BASE .. +1023) */
  float total_imports = 0.0f;
  bool suspicious_import = false;
  if (nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT) {
    DWORD import_rva =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
            .VirtualAddress;
    if (import_rva > 0) {
      DWORD import_offset = rva_to_offset(nt, import_rva, size);
      if (import_offset > 0 &&
          import_offset + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= size) {
        PIMAGE_IMPORT_DESCRIPTOR imports =
            (PIMAGE_IMPORT_DESCRIPTOR)(data + import_offset);
        DWORD import_dir_size =
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
                .Size;
        const uint8_t *import_end =
            (import_dir_size > 0)
                ? data + import_offset + import_dir_size
                : data + size;

        while ((uint8_t *)imports + sizeof(IMAGE_IMPORT_DESCRIPTOR) <=
                   (data + size) &&
               (uint8_t *)imports + sizeof(IMAGE_IMPORT_DESCRIPTOR) <=
                   import_end &&
               imports->Name != 0) {
          DWORD name_offset = rva_to_offset(nt, imports->Name, size);
          char lib_name[256] = {0};
          if (name_offset > 0 && name_offset < size) {
            const char *src_name = (const char *)(data + name_offset);
            int len = 0;
            while (name_offset + len < size && src_name[len] != 0 && len < 255)
              len++;
            memcpy(lib_name, src_name, len);
            str_to_lower(lib_name);
            hash_feature_str(v, lib_name, FEAT_IDX_IMPORTS_BASE, 1024);
          }

          DWORD thunk_rva = imports->OriginalFirstThunk
                                ? imports->OriginalFirstThunk
                                : imports->FirstThunk;
          if (thunk_rva > 0) {
            DWORD thunk_offset = rva_to_offset(nt, thunk_rva, size);
            if (thunk_offset > 0 && thunk_offset < size) {
              size_t step = is64 ? 8 : 4;
              uint8_t *thunk_ptr = (uint8_t *)(data + thunk_offset);

              while (thunk_ptr + step <= (data + size)) {
                /* Determine if thunk is filled */
                uint64_t thunk_val = 0;
                memcpy(&thunk_val, thunk_ptr, step);
                if (thunk_val == 0)
                  break;

                /* If it's an ordinal (high bit set) */
                bool is_ordinal = is64 ? (thunk_val & 0x8000000000000000ULL)
                                       : (thunk_val & 0x80000000);
                if (!is_ordinal) {
                  DWORD hint_name_rva = (DWORD)(thunk_val & 0x7FFFFFFF);
                  DWORD hint_name_off = rva_to_offset(nt, hint_name_rva, size);
                  if (hint_name_off > 0 && hint_name_off + 2 < size) {
                    const char *func_name =
                        (const char *)(data + hint_name_off + 2);
                    char full_import[512] = {0};
                    int f_len = 0;
                    while (hint_name_off + 2 + f_len < size &&
                           func_name[f_len] != 0 && f_len < 255)
                      f_len++;
                    snprintf(full_import, sizeof(full_import), "%s:%.*s",
                             lib_name, f_len, func_name);
                    hash_feature_str(v, full_import, FEAT_IDX_IMPORTS_BASE, 1024);

                    /* R-07 (I-20): suspicious API usage (process injection /
                     * persistence primitives). */
                    static const char *k_suspicious[] = {
                        "createremotethread", "virtualallocex",
                        "writeprocessmemory", "setwindowshookex",
                        "createservice"};
                    for (size_t s = 0;
                         s < sizeof(k_suspicious) / sizeof(k_suspicious[0]);
                         s++) {
                      if (f_len == (int)strlen(k_suspicious[s]) &&
                          _strnicmp(func_name, k_suspicious[s],
                                    strlen(k_suspicious[s])) == 0) {
                        suspicious_import = true;
                        break;
                      }
                    }
                  }
                }

                total_imports += 1.0f;
                thunk_ptr += step;
              }
            }
          }
          imports++;
        }
      }
    }
  }
  v[FEAT_IDX_IMPORT_COUNT] = total_imports;
  feat->pe_import_count = (int)total_imports;
  feat->pe_suspicious_import = suspicious_import;

  /* R-07 (I-20): packer — marker section names, or high mean section
   * entropy with a very small import table (packed/compressed code). */
  if (has_packer_name ||
      (v[FEAT_IDX_MEAN_SECTION_ENT] > 7.0f && total_imports < 10.0f)) {
    feat->pe_packer_marker = true;
  }

  /* Exports (FEAT_IDX_EXPORTS_BASE .. +255) */
  if (nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT) {
    DWORD export_rva =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
            .VirtualAddress;
    if (export_rva > 0) {
      DWORD export_offset = rva_to_offset(nt, export_rva, size);
      if (export_offset > 0 &&
          export_offset + sizeof(IMAGE_EXPORT_DIRECTORY) <= size) {
        PIMAGE_EXPORT_DIRECTORY exports =
            (PIMAGE_EXPORT_DIRECTORY)(data + export_offset);
        v[FEAT_IDX_EXPORT_COUNT] = (float)exports->NumberOfFunctions;

        DWORD names_rva = exports->AddressOfNames;
        DWORD names_offset = rva_to_offset(nt, names_rva, size);
        if (names_offset > 0 &&
            names_offset + (exports->NumberOfNames * 4) <= size) {
          uint32_t *name_rvas = (uint32_t *)(data + names_offset);
          for (DWORD i = 0; i < exports->NumberOfNames; i++) {
            DWORD n_off = rva_to_offset(nt, name_rvas[i], size);
            if (n_off > 0 && n_off < size) {
              const char *exp_name = (const char *)(data + n_off);
              int len = 0;
              while (n_off + len < size && exp_name[len] != 0 && len < 255)
                len++;
              char buf[256] = {0};
              memcpy(buf, exp_name, len);
              hash_feature_str(v, buf, FEAT_IDX_EXPORTS_BASE, 256);
            }
          }
        }
      }
    }
  }
}

/* ============================================================================
 * Public Functions
 * ========================================================================== */

int extract_file_features_wide(const fos_path_t *path, FileFeatures *out) {
  if (!path || !out)
    return -1;
  memset(out, 0, sizeof(FileFeatures));

  HANDLE hFile = CreateFileW(path->wide, GENERIC_READ, FILE_SHARE_READ, NULL,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile == INVALID_HANDLE_VALUE) {
    out->exists = false;
    return -2;
  }

  LARGE_INTEGER fs;
  if (!GetFileSizeEx(hFile, &fs)) {
    CloseHandle(hFile);
    return -1;
  }

  out->exists = true;
  out->is_executable = has_executable_extension_wide(path->wide);
  out->vector[FEAT_IDX_FILE_SIZE] = (float)fs.QuadPart;

  if (fs.QuadPart == 0) {
    CloseHandle(hFile);
    return 0;
  }

  HANDLE hMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
  if (!hMap) {
    CloseHandle(hFile);
    return -1;
  }

  const uint8_t *data =
      (const uint8_t *)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
  if (!data) {
    CloseHandle(hMap);
    CloseHandle(hFile);
    return -1;
  }

  size_t size = (size_t)fs.QuadPart;

  /* Global feature calculation overrides */
  calc_histograms(data, size, out->vector); /* Populates 0:512 */

  /* Calculate basic full file entropy string approximation and heur flag */
  uint32_t counts[256] = {0};
  for (size_t i = 0; i < size; i++)
    counts[data[i]]++;
  double ent = 0.0;
  for (int i = 0; i < 256; i++) {
    if (counts[i] > 0) {
      double p = (double)counts[i] / size;
      ent -= p * log2(p);
    }
  }
  out->vector[FEAT_IDX_FILE_ENTROPY] = (float)ent;
  out->high_entropy = (ent > 7.2);

  out->in_temp_dir = is_in_known_temp_wide(path->wide);
  out->in_downloads_dir =
      is_in_known_folder_wide(path->wide, &FOLDERID_Downloads);
  out->in_startup_dir =
      is_in_known_folder_wide(path->wide, &FOLDERID_Startup) ||
      is_in_known_folder_wide(path->wide, &FOLDERID_CommonStartup);

  analyze_strings(data, size, out->vector);
  parse_pe(data, size, out);

  UnmapViewOfFile(data);
  CloseHandle(hMap);
  CloseHandle(hFile);

  return 0;
}

int extract_file_features(const char *path, FileFeatures *out) {
  if (!path || !out)
    return -1;
  fos_path_t fp;
  if (!fos_path_init(&fp, path))
    return -1;
  return extract_file_features_wide(&fp, out);
}

/* Test-support hook (not part of the public API): exported only when the
 * feature-parity harness (tests/python/) compiles with
 * -DFOS_FEATURE_TEST_EXPORTS so it can compare the real hash against
 * Python's mmh3.hash(seed=0). */
#ifdef FOS_FEATURE_TEST_EXPORTS
int32_t fos_test_murmur3(const char *s) {
  return (int32_t)MurmurHash3_x86_32(s, (int)strlen(s), 0);
}
#endif


