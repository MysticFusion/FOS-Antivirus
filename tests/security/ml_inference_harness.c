/**
 * @file ml_inference_harness.c
 * @brief Dev tool: score real files through the production C pipeline
 *        (feature_extract + ml_engine) and optionally dump features for
 *        cross-validation against the Python reference.
 *
 * Usage:
 *   ml_inference_harness <model.bin> <file...> [--dump scores.json]
 *
 * The JSON dump is consumed by scripts/validate_model.py --scores-file to
 * prove C/Python inference parity on real binaries. See the "ML model:
 * training & validation" section in README.md.
 *
 * Not wired into CTest: depends on real system binaries at runtime.
 */
#include "ml_engine.h"
#include "feature_extract.h"
#include "path_utils.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc < 2) {
        printf("usage: ml_inference_harness <model.bin> <file...> [--dump out.json]\n");
        return 2;
    }

    FILE *dump = NULL;
    int last = argc - 1;
    if (last >= 1 && strcmp(argv[last], "--dump") == 0) {
        last--;
    }
    if (last >= 2 && strcmp(argv[last - 1], "--dump") == 0) {
        dump = fopen(argv[last], "w");
        last -= 2;
    }

    ml_engine_pre_init();
    if (ml_engine_init(argv[1]) != 0) {
        printf("ML INIT FAIL\n");
        return 1;
    }

    if (dump) fprintf(dump, "[\n");
    for (int i = 2; i <= last; i++) {
        fos_path_t p;
        if (!fos_path_init(&p, argv[i])) {
            printf("%-62s PATH FAIL\n", argv[i]);
            continue;
        }
        FileFeatures f;
        int r = extract_file_features_wide(&p, &f);
        if (r != 0) {
            printf("%-62s EXTRACT FAIL %d\n", argv[i], r);
            continue;
        }
        double s = ml_engine_scan(&f);
        printf("%-62s score=%8.5f %s\n", argv[i], s,
               s >= 0.8 ? "*** > 0.8 THRESHOLD" : (s >= 0.5 ? "(0.5-0.8 zone)" : ""));

        if (dump) {
            if (i > 2) fprintf(dump, ",\n");
            fprintf(dump, "  {\"path\": \"");
            for (const char *c = argv[i]; *c; c++) {
                if (*c == '\\' || *c == '"') fputc('\\', dump);
                fputc(*c, dump);
            }
            fprintf(dump, "\", \"score\": %.10f, \"feat\": [", s);
            for (int k = 0; k < 2381; k++) {
                fprintf(dump, "%s%.9g", k ? "," : "", (double)f.vector[k]);
            }
            fprintf(dump, "]}");
        }
    }
    if (dump) {
        fprintf(dump, "\n]\n");
        fclose(dump);
    }

    ml_engine_cleanup();
    return 0;
}
