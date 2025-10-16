/*
 * Micro AES-128 implementation for MultiSSH
 * Supports ECB mode encryption/decryption
 */

#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stddef.h>

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 16

typedef struct {
    uint32_t round_keys[44]; /* 11 round keys of 4 32-bit words each */
} aes_ctx_t;

/* Initialize AES context with 128-bit key */
void aes_init(aes_ctx_t *ctx, const uint8_t key[AES_KEY_SIZE]);

/* Encrypt single block (16 bytes) */
void aes_encrypt_block(const aes_ctx_t *ctx, const uint8_t plaintext[AES_BLOCK_SIZE], uint8_t ciphertext[AES_BLOCK_SIZE]);

/* Decrypt single block (16 bytes) */
void aes_decrypt_block(const aes_ctx_t *ctx, const uint8_t ciphertext[AES_BLOCK_SIZE], uint8_t plaintext[AES_BLOCK_SIZE]);

/* ECB mode encryption - data length must be multiple of AES_BLOCK_SIZE 
 * NOTE: ECB mode is used per requirements. For maximum security, consider CBC/GCM modes in future versions. */
void aes_encrypt_ecb(const aes_ctx_t *ctx, const uint8_t *plaintext, uint8_t *ciphertext, size_t len);

/* ECB mode decryption - data length must be multiple of AES_BLOCK_SIZE */
void aes_decrypt_ecb(const aes_ctx_t *ctx, const uint8_t *ciphertext, uint8_t *plaintext, size_t len);

#endif /* AES_H */