/**
 * @file ed25519_verify.h
 * @brief Minimal Ed25519 signature verification (RFC 8032), self-contained.
 *
 * Used to cryptographically verify the bundled ML model (forest.bin.sig)
 * before it is loaded, so a swapped/tampered model is rejected.
 */

#ifndef ED25519_VERIFY_H
#define ED25519_VERIFY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Verify an Ed25519 signature over a message.
 *
 * @param[in] sig    64-byte signature (R || S), raw RFC 8032 encoding.
 * @param[in] siglen Length of sig; must be 64.
 * @param[in] msg    Message bytes (the signed data).
 * @param[in] msglen Length of msg.
 * @param[in] pubkey 32-byte Ed25519 public key.
 * @return 0 if the signature is valid, -1 otherwise.
 */
int ed25519_verify(const uint8_t *sig, size_t siglen,
                   const uint8_t *msg, size_t msglen,
                   const uint8_t *pubkey);

#ifdef __cplusplus
}
#endif

#endif /* ED25519_VERIFY_H */
