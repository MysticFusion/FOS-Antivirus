/**
 * @file db_hmac.h
 * @brief HMAC-SHA256 integrity protection for the signature database (I-22/R-09).
 *
 * The signature database is authenticated with a keyed HMAC-SHA256 using a
 * key embedded in the binary. The HMAC file lives next to the database as
 * "<db>.hmac" (32 raw bytes). Loaders refuse databases whose HMAC is missing
 * or mismatched, so tampering with the database is detected even when the
 * database itself sits in a user-writable location.
 */

#ifndef DB_HMAC_H
#define DB_HMAC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#define DB_HMAC_SIZE 32

/**
 * @brief Compute the HMAC-SHA256 of a database file.
 *
 * @param[in]  db_path Path to the database file.
 * @param[out] out     Buffer for the 32-byte HMAC.
 * @return 0 on success, -1 on failure (I/O error).
 */
int db_hmac_compute_file(const char *db_path, uint8_t out[DB_HMAC_SIZE]);

/**
 * @brief Verify "<db_path>.hmac" against the file contents.
 *
 * @return 0 if the HMAC file exists and matches, -1 otherwise
 *         (missing file, I/O error, or mismatch).
 */
int db_hmac_verify_file(const char *db_path);

/**
 * @brief Compute and write "<db_path>.hmac" (used after a DB update).
 *
 * @return 0 on success, -1 on failure.
 */
int db_hmac_write_file(const char *db_path);

#ifdef __cplusplus
}
#endif

#endif /* DB_HMAC_H */
