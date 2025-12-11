#ifndef SIGNATURE_SCAN_H
#define SIGNATURE_SCAN_H

/* Signature-based scanning (FR.2)
 * Uses scan_core (FR.1) to traverse and hash files.
 * Matches file SHA-256 values against a signature DB.
 *
 * int signature_scan(const char *sigdb_path, const char *path_to_scan);
 * Returns 0 if scan completed, non-zero on fatal error.
 */
extern volatile int update_progress;
int signature_scan(const char *sigdb_path, const char *path_to_scan);
int update_signature_db(const char *db_path);

#endif
