# Makefile for MultiSSH
# Multi SSH 0.2 - Run commands on multiple SSH Servers easily

CC = gcc
CFLAGS = -Wall -Wextra -std=c99
LIBS = -lssh
TARGET = multissh
SOURCE = multissh.c
ENCRYPT_TARGET = encrypt_servers
ENCRYPT_SOURCE = encrypt_servers.c
CRYPTO_SOURCES = sha256.c aes.c crypto_utils.c

# Default target
all: $(TARGET) $(ENCRYPT_TARGET)

# Build the main executable
$(TARGET): $(SOURCE) $(CRYPTO_SOURCES)
	$(CC) $(CFLAGS) $(SOURCE) $(CRYPTO_SOURCES) -o $(TARGET) $(LIBS)

# Build the encryption utility
$(ENCRYPT_TARGET): $(ENCRYPT_SOURCE) $(CRYPTO_SOURCES)
	$(CC) $(CFLAGS) $(ENCRYPT_SOURCE) $(CRYPTO_SOURCES) -o $(ENCRYPT_TARGET)

# Clean up build artifacts
clean:
	rm -f $(TARGET) $(ENCRYPT_TARGET)

# Install to system (requires sudo)
install: $(TARGET) $(ENCRYPT_TARGET)
	install -m 755 $(TARGET) /usr/local/bin/
	install -m 755 $(ENCRYPT_TARGET) /usr/local/bin/

# Uninstall from system (requires sudo)
uninstall:
	rm -f /usr/local/bin/$(TARGET)
	rm -f /usr/local/bin/$(ENCRYPT_TARGET)

# Check if dependencies are available
check-deps:
	@echo "Checking dependencies..."
	@pkg-config --exists libssh && echo "libssh: OK" || echo "libssh: MISSING - install libssh-dev"

# Help target
help:
	@echo "MultiSSH Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  all        - Build the multissh executable and encryption utility (default)"
	@echo "  clean      - Remove build artifacts"
	@echo "  install    - Install to /usr/local/bin (requires sudo)"
	@echo "  uninstall  - Remove from /usr/local/bin (requires sudo)"
	@echo "  check-deps - Check if required dependencies are installed"
	@echo "  help       - Show this help message"

.PHONY: all clean install uninstall check-deps help