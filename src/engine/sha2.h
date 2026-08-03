/**
 * @file sha2.h
 * @brief SHA-224/256/384/512 Cryptographic Hash Implementation
 *
 * Provides the standard SHA-2 family of hashing algorithms for file
 * integrity and signature verification.
 * 
 * Original Copyright (C) 2005-2023 Olivier Gay <olivier.gay@a3.epfl.ch>
 * Adapted for FOS-Antivirus Project.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SHA2_H
#define SHA2_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/* ============================================================================
 * Constants & Algorithm Parameters
 * ========================================================================== */

#define SHA224_DIGEST_SIZE (224 / 8)
#define SHA256_DIGEST_SIZE (256 / 8)
#define SHA384_DIGEST_SIZE (384 / 8)
#define SHA512_DIGEST_SIZE (512 / 8)

#define SHA256_BLOCK_SIZE  (512 / 8)
#define SHA512_BLOCK_SIZE  (1024 / 8)
#define SHA384_BLOCK_SIZE  SHA512_BLOCK_SIZE
#define SHA224_BLOCK_SIZE  SHA256_BLOCK_SIZE

/* ============================================================================
 * Context Structures
 * ========================================================================== */

/**
 * @brief SHA-256 (and SHA-224) context structure.
 */
typedef struct {
    uint64_t tot_len;
    uint64_t len;
    uint8_t  block[2 * SHA256_BLOCK_SIZE];
    uint32_t h[8];
} sha256_ctx;

/**
 * @brief SHA-512 (and SHA-384) context structure.
 */
typedef struct {
    uint64_t tot_len;
    uint64_t len;
    uint8_t  block[2 * SHA512_BLOCK_SIZE];
    uint64_t h[8];
} sha512_ctx;

typedef sha512_ctx sha384_ctx;
typedef sha256_ctx sha224_ctx;

/* ============================================================================
 * Public Functions
 * ========================================================================== */

/* SHA-224 */
void sha224_init(sha224_ctx *ctx);
void sha224_update(sha224_ctx *ctx, const uint8_t *message, uint64_t len);
void sha224_final(sha224_ctx *ctx, uint8_t *digest);
void sha224(const uint8_t *message, uint64_t len, uint8_t *digest);

/* SHA-256 */
void sha256_init(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, const uint8_t *message, uint64_t len);
void sha256_final(sha256_ctx *ctx, uint8_t *digest);
void sha256(const uint8_t *message, uint64_t len, uint8_t *digest);

/* SHA-384 */
void sha384_init(sha384_ctx *ctx);
void sha384_update(sha384_ctx *ctx, const uint8_t *message, uint64_t len);
void sha384_final(sha384_ctx *ctx, uint8_t *digest);
void sha384(const uint8_t *message, uint64_t len, uint8_t *digest);

/* SHA-512 */
void sha512_init(sha512_ctx *ctx);
void sha512_update(sha512_ctx *ctx, const uint8_t *message, uint64_t len);
void sha512_final(sha512_ctx *ctx, uint8_t *digest);
void sha512(const uint8_t *message, uint64_t len, uint8_t *digest);

#ifdef __cplusplus
}
#endif

#endif /* SHA2_H */
