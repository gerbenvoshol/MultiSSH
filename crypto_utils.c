/*
 * Crypto utilities for MultiSSH
 * Password-based key derivation and padding functions
 */

#include "crypto_utils.h"
#include "sha256.h"
#include "aes.h"
#include <stdlib.h>
#include <string.h>

void derive_aes_key_from_password(const char *password, uint8_t key[16]) {
    uint8_t hash[SHA256_DIGEST_SIZE];
    sha256_hash((const uint8_t *)password, strlen(password), hash);
    /* Use first 16 bytes as AES-128 key */
    memcpy(key, hash, 16);
}

size_t add_pkcs7_padding(const uint8_t *input, size_t input_len, uint8_t **output) {
    size_t padding_len = AES_BLOCK_SIZE - (input_len % AES_BLOCK_SIZE);
    size_t output_len = input_len + padding_len;
    
    *output = malloc(output_len);
    if (*output == NULL) {
        return 0;
    }
    
    memcpy(*output, input, input_len);
    
    /* Add PKCS#7 padding */
    for (size_t i = input_len; i < output_len; i++) {
        (*output)[i] = (uint8_t)padding_len;
    }
    
    return output_len;
}

size_t remove_pkcs7_padding(const uint8_t *input, size_t input_len, uint8_t **output) {
    if (input_len == 0 || input_len % AES_BLOCK_SIZE != 0) {
        return 0; /* Invalid input */
    }
    
    uint8_t padding_len = input[input_len - 1];
    
    /* Validate padding */
    if (padding_len == 0 || padding_len > AES_BLOCK_SIZE) {
        return 0; /* Invalid padding */
    }
    
    if (padding_len > input_len) {
        return 0; /* Invalid padding */
    }
    
    /* Check all padding bytes */
    for (size_t i = input_len - padding_len; i < input_len; i++) {
        if (input[i] != padding_len) {
            return 0; /* Invalid padding */
        }
    }
    
    size_t output_len = input_len - padding_len;
    *output = malloc(output_len);
    if (*output == NULL) {
        return 0;
    }
    
    memcpy(*output, input, output_len);
    return output_len;
}

int encrypt_data_aes(const uint8_t *plaintext, size_t plaintext_len, const char *password, uint8_t **ciphertext, size_t *ciphertext_len) {
    uint8_t key[16];
    uint8_t *padded_data;
    size_t padded_len;
    aes_ctx_t ctx;
    
    /* Derive key from password */
    derive_aes_key_from_password(password, key);
    
    /* Add PKCS#7 padding */
    padded_len = add_pkcs7_padding(plaintext, plaintext_len, &padded_data);
    if (padded_len == 0) {
        return -1; /* Memory allocation failed */
    }
    
    /* Allocate output buffer */
    *ciphertext = malloc(padded_len);
    if (*ciphertext == NULL) {
        free(padded_data);
        return -1;
    }
    
    /* Initialize AES context and encrypt */
    aes_init(&ctx, key);
    aes_encrypt_ecb(&ctx, padded_data, *ciphertext, padded_len);
    
    *ciphertext_len = padded_len;
    
    /* Clear sensitive data */
    memset(key, 0, sizeof(key));
    memset(padded_data, 0, padded_len);
    free(padded_data);
    
    return 0;
}

int decrypt_data_aes(const uint8_t *ciphertext, size_t ciphertext_len, const char *password, uint8_t **plaintext, size_t *plaintext_len) {
    uint8_t key[16];
    uint8_t *decrypted_data;
    aes_ctx_t ctx;
    
    if (ciphertext_len == 0 || ciphertext_len % AES_BLOCK_SIZE != 0) {
        return -1; /* Invalid ciphertext length */
    }
    
    /* Derive key from password */
    derive_aes_key_from_password(password, key);
    
    /* Allocate buffer for decrypted data */
    decrypted_data = malloc(ciphertext_len);
    if (decrypted_data == NULL) {
        return -1;
    }
    
    /* Initialize AES context and decrypt */
    aes_init(&ctx, key);
    aes_decrypt_ecb(&ctx, ciphertext, decrypted_data, ciphertext_len);
    
    /* Remove PKCS#7 padding */
    *plaintext_len = remove_pkcs7_padding(decrypted_data, ciphertext_len, plaintext);
    
    /* Clear sensitive data */
    memset(key, 0, sizeof(key));
    memset(decrypted_data, 0, ciphertext_len);
    free(decrypted_data);
    
    if (*plaintext_len == 0) {
        return -1; /* Padding removal failed */
    }
    
    return 0;
}