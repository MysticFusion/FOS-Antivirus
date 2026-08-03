/**
 * @file script_verify.h
 * @brief SHA-256 pin verification for the staged hash_aggregator.py (I-19).
 *
 * The updater refuses to execute a script whose SHA-256 does not match the
 * build-time pin (AGGREGATOR_SHA256_HEX from aggregator_hash.h). This single
 * production function is used both at runtime and by the CTest, so the test
 * can never diverge from the shipped check.
 */

#ifndef SCRIPT_VERIFY_H
#define SCRIPT_VERIFY_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Verify the script at @p path against the build-time SHA-256 pin.
 *
 * @param path Absolute path to the staged hash_aggregator.py.
 * @return 0 if the file exists and its SHA-256 matches the pin;
 *         -1 on read failure or hash mismatch.
 */
int signature_script_verify(const char *path);

#ifdef __cplusplus
}
#endif

#endif /* SCRIPT_VERIFY_H */
