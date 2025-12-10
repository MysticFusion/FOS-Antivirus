#include "signature_scan.h"
#include "scan_core.h"
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <signature_db_path> <path_to_scan>\n", argv[0]);
        return 1;
    }

    const char *sigdb_path = argv[1];
    const char *path_to_scan = argv[2];

    printf("Starting signature scan...\n");
    printf("  Database: %s\n", sigdb_path);
    printf("  Target:   %s\n", path_to_scan);
    printf("----------------------------------------\n");

    int result = signature_scan(sigdb_path, path_to_scan);

    printf("----------------------------------------\n");
    printf("Scan complete.\n");

    if (result == SCANCORE_FATAL_ERR) {
        fprintf(stderr, "Scan finished with a fatal error.\n");
        return 1;
    }

    return 0;
}