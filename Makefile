# Makefile for MultiSSH
# Multi SSH 0.2 - Run commands on multiple SSH Servers easily

CC = gcc
CFLAGS = -Wall -Wextra -std=c99
LIBS = -lssh
TARGET = multissh
SOURCE = multissh.c

# Default target
all: $(TARGET)

# Build the main executable
$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) $(SOURCE) -o $(TARGET) $(LIBS)

# Clean up build artifacts
clean:
	rm -f $(TARGET)

# Install to system (requires sudo)
install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/

# Uninstall from system (requires sudo)
uninstall:
	rm -f /usr/local/bin/$(TARGET)

# Check if dependencies are available
check-deps:
	@echo "Checking dependencies..."
	@pkg-config --exists libssh && echo "libssh: OK" || echo "libssh: MISSING - install libssh-dev"

# Help target
help:
	@echo "MultiSSH Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  all        - Build the multissh executable (default)"
	@echo "  clean      - Remove build artifacts"
	@echo "  install    - Install to /usr/local/bin (requires sudo)"
	@echo "  uninstall  - Remove from /usr/local/bin (requires sudo)"
	@echo "  check-deps - Check if required dependencies are installed"
	@echo "  help       - Show this help message"

.PHONY: all clean install uninstall check-deps help