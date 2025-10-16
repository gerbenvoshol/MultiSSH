/*
 * SSH Servers File Encryption Utility
 * Encrypts/decrypts SSH servers list files for MultiSSH
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "crypto_utils.h"

// AES encryption/decryption functions using password-based key derivation
int encrypt_data(const uint8_t *input, size_t input_len, const char *password, uint8_t **output, size_t *output_len) {
  return encrypt_data_aes(input, input_len, password, output, output_len);
}

int decrypt_data(const uint8_t *input, size_t input_len, const char *password, uint8_t **output, size_t *output_len) {
  return decrypt_data_aes(input, input_len, password, output, output_len);
}

void print_usage(const char *program_name) {
  fprintf(stderr, "Usage: %s [OPTIONS] input_file output_file\n", program_name);
  fprintf(stderr, "Options:\n");
  fprintf(stderr, "  -p PASSWORD    Password for encryption/decryption\n");
  fprintf(stderr, "  -d             Decrypt mode (default is encrypt)\n");
  fprintf(stderr, "  -h             Show this help message\n");
  fprintf(stderr, "\nExamples:\n");
  fprintf(stderr, "  %s -p mypassword sshservers.txt sshservers.encrypted\n", program_name);
  fprintf(stderr, "  %s -p mypassword -d sshservers.encrypted sshservers.txt\n", program_name);
}

int main(int argc, char *argv[]) {
  char *password = NULL;
  int decrypt_mode = 0;
  int opt;
  
  // Parse command line arguments
  while ((opt = getopt(argc, argv, "p:dh")) != -1) {
    switch (opt) {
      case 'p':
        password = optarg;
        break;
      case 'd':
        decrypt_mode = 1;
        break;
      case 'h':
        print_usage(argv[0]);
        exit(EXIT_SUCCESS);
        break;
      default:
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }
  }
  
  // Check if password is provided
  if (password == NULL) {
    fprintf(stderr, "Error: Password is required (-p option)\n\n");
    print_usage(argv[0]);
    exit(EXIT_FAILURE);
  }
  
  // Check if input and output files are provided
  if (optind + 2 != argc) {
    fprintf(stderr, "Error: Input and output files are required\n\n");
    print_usage(argv[0]);
    exit(EXIT_FAILURE);
  }
  
  const char *input_file = argv[optind];
  const char *output_file = argv[optind + 1];
  
  // Open input file
  FILE *input_fp = fopen(input_file, "rb");
  if (input_fp == NULL) {
    fprintf(stderr, "Error: Cannot open input file '%s'\n", input_file);
    exit(EXIT_FAILURE);
  }
  
  // Get file size
  fseek(input_fp, 0, SEEK_END);
  size_t file_size = ftell(input_fp);
  fseek(input_fp, 0, SEEK_SET);
  
  // Allocate buffer
  uint8_t *buffer = malloc(file_size);
  if (buffer == NULL) {
    fprintf(stderr, "Error: Memory allocation failed\n");
    fclose(input_fp);
    exit(EXIT_FAILURE);
  }
  
  // Read file
  if (fread(buffer, 1, file_size, input_fp) != file_size) {
    fprintf(stderr, "Error: Failed to read input file\n");
    free(buffer);
    fclose(input_fp);
    exit(EXIT_FAILURE);
  }
  
  fclose(input_fp);
  
  // Encrypt/decrypt the data
  uint8_t *processed_data;
  size_t processed_len;
  int result;
  
  if (decrypt_mode) {
    result = decrypt_data(buffer, file_size, password, &processed_data, &processed_len);
  } else {
    result = encrypt_data(buffer, file_size, password, &processed_data, &processed_len);
  }
  
  if (result != 0) {
    fprintf(stderr, "Error: %s operation failed\n", decrypt_mode ? "Decryption" : "Encryption");
    free(buffer);
    exit(EXIT_FAILURE);
  }
  
  // Open output file
  FILE *output_fp = fopen(output_file, "wb");
  if (output_fp == NULL) {
    fprintf(stderr, "Error: Cannot create output file '%s'\n", output_file);
    free(buffer);
    free(processed_data);
    exit(EXIT_FAILURE);
  }
  
  // Write encrypted/decrypted data
  if (fwrite(processed_data, 1, processed_len, output_fp) != processed_len) {
    fprintf(stderr, "Error: Failed to write output file\n");
    free(buffer);
    free(processed_data);
    fclose(output_fp);
    exit(EXIT_FAILURE);
  }
  
  fclose(output_fp);
  free(buffer);
  free(processed_data);
  
  printf("Successfully %s '%s' to '%s'\n", 
         decrypt_mode ? "decrypted" : "encrypted", 
         input_file, output_file);
  
  return 0;
}