/*
 * Crypto utilities for MultiSSH
 * Password-based key derivation using industry-standard micro-AES library
 * https://github.com/gerbenvoshol/micro-AES
 */

#include "crypto_utils.h"
#include "sha256.h"
#include "micro_aes.h"
#include <stdlib.h>
#include <string.h>

void derive_aes_key_from_password(const char *password, uint8_t key[16]) {
    uint8_t hash[SHA256_DIGEST_SIZE];
    sha256_hash((const uint8_t *)password, strlen(password), hash);
    /* Use first 16 bytes as AES-128 key */
    memcpy(key, hash, 16);
}

int encrypt_data_aes(const uint8_t *plaintext, size_t plaintext_len, const char *password, uint8_t **ciphertext, size_t *ciphertext_len) {
    uint8_t key[16];
    
    /* Derive key from password */
    derive_aes_key_from_password(password, key);
    
    /* Calculate output size with PKCS#7 padding */
    size_t padding_len = 16 - (plaintext_len % 16);
    size_t padded_len = plaintext_len + padding_len;
    
    /* Allocate output buffer */
    *ciphertext = malloc(padded_len);
    if (*ciphertext == NULL) {
        return -1;
    }
    
    /* Encrypt using micro-AES (handles PKCS#7 padding automatically) */
    AES_ECB_encrypt(key, plaintext, plaintext_len, *ciphertext);
    
    *ciphertext_len = padded_len;
    
    /* Clear sensitive data */
    memset(key, 0, sizeof(key));
    
    return 0;
}

int decrypt_data_aes(const uint8_t *ciphertext, size_t ciphertext_len, const char *password, uint8_t **plaintext, size_t *plaintext_len) {
    uint8_t key[16];
    
    if (ciphertext_len == 0 || ciphertext_len % 16 != 0) {
        return -1; /* Invalid ciphertext length */
    }
    
    /* Derive key from password */
    derive_aes_key_from_password(password, key);
    
    /* Allocate buffer for decrypted data (maximum size) */
    *plaintext = malloc(ciphertext_len);
    if (*plaintext == NULL) {
        return -1;
    }
    
    /* Decrypt using micro-AES */
    char result = AES_ECB_decrypt(key, ciphertext, ciphertext_len, *plaintext);
    
    /* Clear sensitive data */
    memset(key, 0, sizeof(key));
    
    if (result != 0) {
        free(*plaintext);
        *plaintext = NULL;
        return -1; /* Decryption failed */
    }
    
    /* Remove PKCS#7 padding manually */
    uint8_t padding_len = (*plaintext)[ciphertext_len - 1];
    
    /* Validate padding */
    if (padding_len == 0 || padding_len > 16) {
        free(*plaintext);
        *plaintext = NULL;
        return -1; /* Invalid padding */
    }
    
    if (padding_len > ciphertext_len) {
        free(*plaintext);
        *plaintext = NULL;
        return -1; /* Invalid padding */
    }
    
    /* Check all padding bytes */
    for (size_t i = ciphertext_len - padding_len; i < ciphertext_len; i++) {
        if ((*plaintext)[i] != padding_len) {
            free(*plaintext);
            *plaintext = NULL;
            return -1; /* Invalid padding */
        }
    }
    
    /* The plaintext length is the ciphertext length minus padding */
    *plaintext_len = ciphertext_len - padding_len;
    
    return 0;
}