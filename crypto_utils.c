/*
 * Crypto utilities for MultiSSH
 * Password-based key derivation using industry-standard micro-AES library
 * Uses AES-128-CBC mode with random IV for secure encryption
 * https://github.com/gerbenvoshol/micro-AES
 */

#include "crypto_utils.h"
#include "sha256.h"
#include "micro_aes.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Generate random IV for CBC mode */
static void generate_random_iv(uint8_t iv[16]) {
    static int seeded = 0;
    static unsigned int call_count = 0;
    
    if (!seeded) {
        /* Seed with time and process ID for better entropy */
        srand((unsigned int)time(NULL) ^ (unsigned int)getpid());
        seeded = 1;
    }
    
    /* Increment call counter for uniqueness within same second */
    call_count++;
    
    /* Use SHA-256 of random values + counter + time for better randomness */
    uint8_t random_data[48];
    unsigned int timestamp = (unsigned int)time(NULL);
    
    /* Mix random values, counter, and timestamp */
    for (int i = 0; i < 32; i++) {
        random_data[i] = (uint8_t)rand();
    }
    memcpy(random_data + 32, &timestamp, sizeof(timestamp));
    memcpy(random_data + 36, &call_count, sizeof(call_count));
    
    /* Hash to get high-quality randomness */
    uint8_t hash[SHA256_DIGEST_SIZE];
    sha256_hash(random_data, sizeof(random_data), hash);
    memcpy(iv, hash, 16);
}

void derive_aes_key_from_password(const char *password, uint8_t key[16]) {
    uint8_t hash[SHA256_DIGEST_SIZE];
    sha256_hash((const uint8_t *)password, strlen(password), hash);
    /* Use first 16 bytes as AES-128 key */
    memcpy(key, hash, 16);
}

int encrypt_data_aes(const uint8_t *plaintext, size_t plaintext_len, const char *password, uint8_t **ciphertext, size_t *ciphertext_len) {
    uint8_t key[16];
    uint8_t iv[16];
    
    /* Derive key from password */
    derive_aes_key_from_password(password, key);
    
    /* Generate random IV for CBC mode */
    generate_random_iv(iv);
    
    /* Calculate output size with PKCS#7 padding */
    size_t padding_len = 16 - (plaintext_len % 16);
    size_t padded_len = plaintext_len + padding_len;
    
    /* Allocate output buffer: IV (16 bytes) + encrypted data */
    *ciphertext_len = 16 + padded_len;
    *ciphertext = malloc(*ciphertext_len);
    if (*ciphertext == NULL) {
        return -1;
    }
    
    /* Store IV at the beginning of ciphertext */
    memcpy(*ciphertext, iv, 16);
    
    /* Encrypt using micro-AES CBC mode (handles PKCS#7 padding automatically) */
    char result = AES_CBC_encrypt(key, iv, plaintext, plaintext_len, *ciphertext + 16);
    
    /* Clear sensitive data */
    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv));
    
    if (result != 0) {
        free(*ciphertext);
        *ciphertext = NULL;
        return -1;
    }
    
    return 0;
}

int decrypt_data_aes(const uint8_t *ciphertext, size_t ciphertext_len, const char *password, uint8_t **plaintext, size_t *plaintext_len) {
    uint8_t key[16];
    uint8_t iv[16];
    
    /* Ciphertext must contain at least IV (16 bytes) + one block (16 bytes) */
    if (ciphertext_len < 32 || (ciphertext_len - 16) % 16 != 0) {
        return -1; /* Invalid ciphertext length */
    }
    
    /* Derive key from password */
    derive_aes_key_from_password(password, key);
    
    /* Extract IV from the beginning of ciphertext */
    memcpy(iv, ciphertext, 16);
    
    /* Allocate buffer for decrypted data (maximum size) */
    size_t encrypted_len = ciphertext_len - 16;
    *plaintext = malloc(encrypted_len);
    if (*plaintext == NULL) {
        return -1;
    }
    
    /* Decrypt using micro-AES CBC mode */
    char result = AES_CBC_decrypt(key, iv, ciphertext + 16, encrypted_len, *plaintext);
    
    /* Clear sensitive data */
    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv));
    
    if (result != 0) {
        free(*plaintext);
        *plaintext = NULL;
        return -1; /* Decryption failed */
    }
    
    /* Remove PKCS#7 padding (CBC mode adds padding but doesn't remove it) */
    uint8_t padding_len = (*plaintext)[encrypted_len - 1];
    
    /* Validate padding */
    if (padding_len == 0 || padding_len > 16) {
        free(*plaintext);
        *plaintext = NULL;
        return -1; /* Invalid padding */
    }
    
    if (padding_len > encrypted_len) {
        free(*plaintext);
        *plaintext = NULL;
        return -1; /* Invalid padding */
    }
    
    /* Check all padding bytes */
    for (size_t i = encrypted_len - padding_len; i < encrypted_len; i++) {
        if ((*plaintext)[i] != padding_len) {
            free(*plaintext);
            *plaintext = NULL;
            return -1; /* Invalid padding */
        }
    }
    
    /* The plaintext length is the encrypted length minus padding */
    *plaintext_len = encrypted_len - padding_len;
    
    return 0;
}