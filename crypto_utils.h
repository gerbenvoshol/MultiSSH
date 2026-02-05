/*
 * Crypto utilities for MultiSSH
 * Password-based key derivation using micro-AES library
 */

#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <stdint.h>
#include <stddef.h>

/* Derive AES key from password using SHA-256 */
void derive_aes_key_from_password(const char *password, uint8_t key[16]);

/* Encrypt data using AES-128 ECB with password-based key derivation and PKCS#7 padding */
int encrypt_data_aes(const uint8_t *plaintext, size_t plaintext_len, const char *password, uint8_t **ciphertext, size_t *ciphertext_len);

/* Decrypt data using AES-128 ECB with password-based key derivation and PKCS#7 padding removal */
int decrypt_data_aes(const uint8_t *ciphertext, size_t ciphertext_len, const char *password, uint8_t **plaintext, size_t *plaintext_len);

#endif /* CRYPTO_UTILS_H */