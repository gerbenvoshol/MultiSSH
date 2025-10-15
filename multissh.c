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
  fprintf(stderr, "  -h         Show this help message\n");
  fprintf(stderr, "\nExamples:\n");
  fprintf(stderr, "  %s 'ls -la'\n", program_name);
  fprintf(stderr, "  %s -f /path/to/servers 'uptime'\n", program_name);
  fprintf(stderr, "  %s -s '192.168.1.10:22,192.168.1.11:22' 'df -h'\n", program_name);
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

int main(int argc, char *argv[]) {

  FILE * ssh_fp;
  char *ssh_line = NULL;
  int error_number, rc, ssh_port, line_number;
  size_t ssh_line_len = 0;
  ssize_t ssh_line_read;
  char *ssh_server;
  char *string_ssh_port;
  char *ssh_username;
  char *ssh_password;
  ssh_session single_ssh_session;
  char *ssh_servers_file = SSH_SERVERS_LIST;
  char *selected_servers = NULL;
  char *command = NULL;
  int opt;

  // Parse command line arguments
  while ((opt = getopt(argc, argv, "f:s:h")) != -1) {
    switch (opt) {
      case 'f':
        ssh_servers_file = optarg;
        break;
      case 's':
        selected_servers = optarg;
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

  ssh_fp = fopen(ssh_servers_file, "r");

// check for ssh list file
   if (ssh_fp == NULL) {

      error_number = errno;
      fprintf(stderr, "Error opening SSH servers list '%s': %s\n", ssh_servers_file, strerror(error_number));
      exit(EXIT_FAILURE);

    }

// read ssh list file
  line_number = 0;
  while ((ssh_line_read = getline(&ssh_line, &ssh_line_len, ssh_fp)) != -1) {

      line_number++;

      ssh_server = strtok(ssh_line,":");
      string_ssh_port = strtok(NULL,":");
      ssh_username = strtok(NULL,":");
      ssh_password = strtok(NULL,":");

      ssh_port = atoi(string_ssh_port);

      // Create server:port string for selection check
      char server_port[256];
      snprintf(server_port, sizeof(server_port), "%s:%d", ssh_server, ssh_port);

      // Check if this server is selected (if selection is specified)
      if (!is_server_selected(server_port, selected_servers)) {
        continue; // Skip this server
      }

      if (strlen(ssh_line) > 512)
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

    }

  free(ssh_line);
  fclose(ssh_fp);

  return 0;

}
