/*
 * Simple test program to validate AES encryption and SHA-256 key derivation
 * This validates the core crypto functionality for MultiSSH using micro-AES library
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "crypto_utils.h"
#include "sha256.h"
#include "micro_aes.h"

int main() {
    printf("Testing MultiSSH crypto components...\n\n");
    
    // Test 1: SHA-256 key derivation
    printf("1. Testing SHA-256 key derivation...\n");
    const char *password = "testpassword123";
    uint8_t key1[16], key2[16];
    
    derive_aes_key_from_password(password, key1);
    derive_aes_key_from_password(password, key2);
    
    // Keys should be identical for same password
    assert(memcmp(key1, key2, 16) == 0);
    printf("   ✓ Same password produces same key\n");
    
    // Different passwords should produce different keys
    derive_aes_key_from_password("different", key2);
    assert(memcmp(key1, key2, 16) != 0);
    printf("   ✓ Different passwords produce different keys\n");
    
    // Test 2: AES encryption/decryption round trip
    printf("\n2. Testing AES encryption/decryption...\n");
    const char *test_data = "127.0.0.1:22:testuser:testpass\n192.168.1.1:22:user2:pass2\n";
    size_t test_len = strlen(test_data);
    
    uint8_t *encrypted;
    size_t encrypted_len;
    uint8_t *decrypted;
    size_t decrypted_len;
    
    // Encrypt
    int result = encrypt_data_aes((const uint8_t *)test_data, test_len, password, &encrypted, &encrypted_len);
    assert(result == 0);
    printf("   ✓ Encryption successful (len: %zu -> %zu)\n", test_len, encrypted_len);
    
    // Decrypt
    result = decrypt_data_aes(encrypted, encrypted_len, password, &decrypted, &decrypted_len);
    assert(result == 0);
    printf("   ✓ Decryption successful (len: %zu -> %zu)\n", encrypted_len, decrypted_len);
    
    // Verify content
    assert(decrypted_len == test_len);
    assert(memcmp(test_data, decrypted, test_len) == 0);
    printf("   ✓ Decrypted data matches original\n");
    
    // Test 3: Wrong password should fail decryption
    printf("\n3. Testing wrong password handling...\n");
    uint8_t *wrong_decrypted;
    size_t wrong_decrypted_len;
    
    result = decrypt_data_aes(encrypted, encrypted_len, "wrongpassword", &wrong_decrypted, &wrong_decrypted_len);
    if (result == 0) {
        // If decryption "succeeds" with wrong password, content should be garbage
        assert(memcmp(test_data, wrong_decrypted, test_len) != 0);
        printf("   ✓ Wrong password produces different/invalid content\n");
        free(wrong_decrypted);
    } else {
        printf("   ✓ Wrong password fails decryption (as expected)\n");
    }
    
    // Clean up
    free(encrypted);
    free(decrypted);
    
    printf("\n✅ All crypto tests passed!\n");
    printf("MultiSSH AES-128 CBC encryption using micro-AES library is working correctly.\n");
    
    return 0;
}