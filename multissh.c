/*
 * Multi SSH 0.2
 * Run commands on multiple SSH Servers easily.
 * Author: Hifzurrahman Patel <hifzu@hifzu.tech>
 */
#define SSH_SERVERS_LIST "sshservers"
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <libssh/libssh.h>

extern int errno;

// Function prototypes
int valid_port(int *port);
void remove_new_line(char *string);
int run_command(ssh_session session, char *command);
void print_usage(const char *program_name);
int is_server_selected(const char *server, const char *selected_servers);
void decrypt_data(char *data, size_t length, const char *password);
int read_encrypted_file(const char *filename, const char *password, char **buffer, size_t *size);

// Function implementations
int valid_port(int *port) {

  int result = 0;

  if ((*port > 0) && (*port < 65536))
    result = 1;

 return result;

}

void remove_new_line(char *string) {
  char *newline = strchr(string, '\n');
  if (newline) {
    *newline = '\0';
  }
}

// run command(s), and display any resulting output
int run_command(ssh_session session, char *command) {
  ssh_channel channel;
  int rc;
  char buffer[2048];
  int nbytes;

  channel = ssh_channel_new(session);

  if (channel == NULL)
    return SSH_ERROR;

  rc = ssh_channel_open_session(channel);

  if (rc != SSH_OK) {
    ssh_channel_free(channel);
    return rc;
  }

 rc = ssh_channel_request_exec(channel, command);

 if (rc != SSH_OK) {
  ssh_channel_close(channel);
  ssh_channel_free(channel);
  return rc;
  }

  nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);

  while (nbytes > 0) {

    if (fwrite(buffer, 1, (size_t)nbytes, stdout) != (size_t)nbytes) {
      ssh_channel_close(channel);
      ssh_channel_free(channel);
      return SSH_ERROR;
    }

  nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);

 }

 if (nbytes < 0) {
   ssh_channel_close(channel);
   ssh_channel_free(channel);
   return SSH_ERROR;
 }

 ssh_channel_send_eof(channel);
 ssh_channel_close(channel);
 ssh_channel_free(channel);

return SSH_OK;

}

void print_usage(const char *program_name) {
  fprintf(stderr, "Usage: %s [OPTIONS] 'command(s)'\n", program_name);
  fprintf(stderr, "Options:\n");
  fprintf(stderr, "  -f FILE    Use FILE as the SSH servers list (default: sshservers)\n");
  fprintf(stderr, "  -s LIST    Select specific servers (comma-separated list of server:port)\n");
  fprintf(stderr, "  -p PASS    Password for decrypting the SSH servers file\n");
  fprintf(stderr, "  -h         Show this help message\n");
  fprintf(stderr, "\nExamples:\n");
  fprintf(stderr, "  %s 'ls -la'\n", program_name);
  fprintf(stderr, "  %s -f /path/to/servers 'uptime'\n", program_name);
  fprintf(stderr, "  %s -s '192.168.1.10:22,192.168.1.11:22' 'df -h'\n", program_name);
  fprintf(stderr, "  %s -p mypassword 'df -h'\n", program_name);
}

// Check if a server:port combination is in the selected servers list
int is_server_selected(const char *server, const char *selected_servers) {
  if (selected_servers == NULL || strlen(selected_servers) == 0) {
    return 1; // If no specific servers selected, include all
  }
  
  // Create a copy of selected_servers to tokenize
  char *servers_copy = strdup(selected_servers);
  if (servers_copy == NULL) {
    fprintf(stderr, "Error: Memory allocation failed\n");
    return 0;
  }
  
  char *token = strtok(servers_copy, ",");
  
  while (token != NULL) {
    // Trim whitespace
    while (*token == ' ' || *token == '\t') token++;
    char *end = token + strlen(token) - 1;
    while (end > token && (*end == ' ' || *end == '\t' || *end == '\n')) end--;
    *(end + 1) = '\0';
    
    if (strcmp(server, token) == 0) {
      free(servers_copy);
      return 1;
    }
    token = strtok(NULL, ",");
  }
  
  free(servers_copy);
  return 0;
}

// Simple XOR encryption/decryption function
void decrypt_data(char *data, size_t length, const char *password) {
  if (password == NULL || strlen(password) == 0) {
    return; // No decryption if no password provided
  }
  
  size_t pass_len = strlen(password);
  for (size_t i = 0; i < length; i++) {
    data[i] ^= password[i % pass_len];
  }
}

// Read and decrypt a file
int read_encrypted_file(const char *filename, const char *password, char **buffer, size_t *size) {
  FILE *file = fopen(filename, "rb");
  if (file == NULL) {
    return -1;
  }
  
  // Get file size
  fseek(file, 0, SEEK_END);
  *size = ftell(file);
  fseek(file, 0, SEEK_SET);
  
  // Allocate buffer
  *buffer = malloc(*size + 1);
  if (*buffer == NULL) {
    fclose(file);
    return -1;
  }
  
  // Read file
  if (fread(*buffer, 1, *size, file) != *size) {
    free(*buffer);
    *buffer = NULL;
    fclose(file);
    return -1;
  }
  
  fclose(file);
  
  // Decrypt if password provided
  if (password != NULL && strlen(password) > 0) {
    decrypt_data(*buffer, *size, password);
  }
  
  // Null terminate
  (*buffer)[*size] = '\0';
  
  return 0;
}

int main(int argc, char *argv[]) {

  FILE * ssh_fp;
  int error_number, rc, ssh_port, line_number;
  char *ssh_server;
  char *string_ssh_port;
  char *ssh_username;
  char *ssh_password;
  ssh_session single_ssh_session;
  char *ssh_servers_file = SSH_SERVERS_LIST;
  char *selected_servers = NULL;
  char *command = NULL;
  char *password = NULL;
  int opt;

  // Parse command line arguments
  while ((opt = getopt(argc, argv, "f:s:p:h")) != -1) {
    switch (opt) {
      case 'f':
        ssh_servers_file = optarg;
        break;
      case 's':
        selected_servers = optarg;
        break;
      case 'p':
        password = optarg;
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

  // Check if command is provided
  if (optind >= argc) {
    fprintf(stderr, "Error: Command is required\n\n");
    print_usage(argv[0]);
    exit(EXIT_FAILURE);
  }

  command = argv[optind];

  // Read and decrypt the SSH servers file
  char *file_content;
  size_t file_size;
  
  // Try to read as encrypted file first if password provided, otherwise as plain text
  if (password != NULL) {
    if (read_encrypted_file(ssh_servers_file, password, &file_content, &file_size) != 0) {
      error_number = errno;
      fprintf(stderr, "Error opening encrypted SSH servers list '%s': %s\n", ssh_servers_file, strerror(error_number));
      exit(EXIT_FAILURE);
    }
  } else {
    // Read as plain text file
    ssh_fp = fopen(ssh_servers_file, "r");
    if (ssh_fp == NULL) {
      error_number = errno;
      fprintf(stderr, "Error opening SSH servers list '%s': %s\n", ssh_servers_file, strerror(error_number));
      exit(EXIT_FAILURE);
    }
    
    // Get file size
    fseek(ssh_fp, 0, SEEK_END);
    file_size = ftell(ssh_fp);
    fseek(ssh_fp, 0, SEEK_SET);
    
    // Allocate buffer
    file_content = malloc(file_size + 1);
    if (file_content == NULL) {
      fprintf(stderr, "Error: Memory allocation failed\n");
      fclose(ssh_fp);
      exit(EXIT_FAILURE);
    }
    
    // Read file
    if (fread(file_content, 1, file_size, ssh_fp) != file_size) {
      fprintf(stderr, "Error reading SSH servers list '%s'\n", ssh_servers_file);
      free(file_content);
      fclose(ssh_fp);
      exit(EXIT_FAILURE);
    }
    
    file_content[file_size] = '\0';
    fclose(ssh_fp);
  }

  // Process the file content line by line
  line_number = 0;
  char *line_start = file_content;
  char *line_end;
  
  while ((line_end = strchr(line_start, '\n')) != NULL || strlen(line_start) > 0) {
    line_number++;
    
    // Handle last line without newline
    if (line_end == NULL) {
      line_end = line_start + strlen(line_start);
    }
    
    // Extract the line
    size_t line_len = line_end - line_start;
    if (line_len == 0) break;
    
    char *current_line = malloc(line_len + 1);
    if (current_line == NULL) {
      fprintf(stderr, "Error: Memory allocation failed\n");
      free(file_content);
      exit(EXIT_FAILURE);
    }
    
    strncpy(current_line, line_start, line_len);
    current_line[line_len] = '\0';
    
    // Skip empty lines
    if (strlen(current_line) == 0) {
      free(current_line);
      line_start = line_end + 1;
      continue;
    }

    ssh_server = strtok(current_line,":");
    string_ssh_port = strtok(NULL,":");
    ssh_username = strtok(NULL,":");
    ssh_password = strtok(NULL,":");

    // Validate parsed data (may be corrupted if decryption failed)
    if (ssh_server == NULL || string_ssh_port == NULL || ssh_username == NULL || ssh_password == NULL) {
      fprintf(stderr, "Error parsing line %d in '%s' - possibly corrupted or wrong password\n", line_number, ssh_servers_file);
      free(current_line);
      line_start = line_end + 1;
      continue;
    }

    ssh_port = atoi(string_ssh_port);

    // Create server:port string for selection check
    char server_port[256];
    snprintf(server_port, sizeof(server_port), "%s:%d", ssh_server, ssh_port);

    // Check if this server is selected (if selection is specified)
    if (!is_server_selected(server_port, selected_servers)) {
      free(current_line);
      line_start = line_end + 1;
      continue; // Skip this server
    }

    if (strlen(current_line) > 512)
       fprintf(stderr, "Error with line %d, maximum length reached in %s, each line must be no more than 512 characters long.\n", line_number, ssh_servers_file);

    if (!(valid_port(&ssh_port)))
       fprintf(stderr, "Error invalid port number %d in the file '%s', line %d.\n", ssh_port, ssh_servers_file, line_number);

    single_ssh_session = ssh_new();

    if (single_ssh_session == NULL)
       fprintf(stderr, "Error creating new session.\n");

    ssh_options_set(single_ssh_session, SSH_OPTIONS_HOST, ssh_server);
    ssh_options_set(single_ssh_session, SSH_OPTIONS_PORT, &ssh_port);
    ssh_options_set(single_ssh_session, SSH_OPTIONS_USER, ssh_username);

    rc = ssh_connect(single_ssh_session);

    if (rc != SSH_OK)
      fprintf(stderr, "Error connecting to %s: %s\n", ssh_server, ssh_get_error(single_ssh_session));

    remove_new_line(ssh_password);

    rc = ssh_userauth_password(single_ssh_session, NULL, ssh_password);

    // if logged in, run command(s)
    if (rc == SSH_AUTH_SUCCESS)
      run_command(single_ssh_session, command);

    else {
      fprintf(stderr, "Error: %s, in %s line %d\n",
      ssh_get_error(single_ssh_session), ssh_servers_file, line_number);
    }

    ssh_disconnect(single_ssh_session);
    ssh_free(single_ssh_session);
    
    free(current_line);
    
    // Move to next line
    if (line_end == line_start + strlen(line_start)) break; // Last line
    line_start = line_end + 1;
  }

  free(file_content);

  return 0;

}
