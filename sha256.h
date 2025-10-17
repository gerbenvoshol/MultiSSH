/*
 * SHA-256 hash implementation for key derivation
 * Minimal implementation for MultiSSH password-based key derivation
 */

#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

#define SHA256_DIGEST_SIZE 32

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[64];
} sha256_ctx_t;

/* Initialize SHA-256 context */
void sha256_init(sha256_ctx_t *ctx);

/* Update SHA-256 with data */
void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len);

/* Finalize SHA-256 and get digest */
void sha256_final(sha256_ctx_t *ctx, uint8_t digest[SHA256_DIGEST_SIZE]);

/* Convenience function to hash data in one call */
void sha256_hash(const uint8_t *data, size_t len, uint8_t digest[SHA256_DIGEST_SIZE]);

#endif /* SHA256_H */