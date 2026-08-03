/*
 * feature_parity_helper.c -- test-only driver for tests/python/test_feature_parity.py
 *
 * Compiles the REAL src/engine/feature_extract.c (with
 * -DFOS_FEATURE_TEST_EXPORTS) and prints:
 *   --hist <file>   feature indices + values for vec[0:512] and the
 *                   file-scope scalar indices (2304, 2311..2317)
 *   --hash <s...>   signed MurmurHash3 x86_32 (seed 0) of each string
 */
#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "feature_extract.h"

#ifdef FOS_FEATURE_TEST_EXPORTS
extern int32_t fos_test_murmur3(const char *s);
#else
#error "compile with -DFOS_FEATURE_TEST_EXPORTS"
#endif

static void print_feat(int idx, float v) {
  /* %.9g round-trips float32 through double without loss */
  printf("%d %.9g\n", idx, (double)v);
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: helper --hist <file> | --hash <str>...\n");
    return 2;
  }
  if (strcmp(argv[1], "--hist") == 0) {
    if (argc < 3) return 2;
    FileFeatures ff;
    int rc = extract_file_features(argv[2], &ff);
    if (rc != 0) {
      fprintf(stderr, "extract_file_features(%s) = %d\n", argv[2], rc);
      return 3;
    }
    for (int i = 0; i < 512; i++) print_feat(i, ff.vector[i]);
    const int scalars[] = {2304, 2311, 2312, 2313, 2314, 2315, 2316, 2317};
    for (size_t i = 0; i < sizeof(scalars) / sizeof(scalars[0]); i++)
      print_feat(scalars[i], ff.vector[scalars[i]]);
    return 0;
  }
  if (strcmp(argv[1], "--hash") == 0) {
    for (int i = 2; i < argc; i++)
      printf("%d %d\n", i - 2, (int)fos_test_murmur3(argv[i]));
    return 0;
  }
  fprintf(stderr, "unknown mode '%s'\n", argv[1]);
  return 2;
}
