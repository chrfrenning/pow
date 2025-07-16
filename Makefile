# Makefile for pow_ledger project

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -D_GNU_SOURCE -O2
LDFLAGS = -lpthread -lssl -lcrypto -lm

# Project structure
SRCDIR = src
TARGET = pow$(EXEEXT)
SOURCES = $(SRCDIR)/main.c $(SRCDIR)/checksum.c $(SRCDIR)/pow.c $(SRCDIR)/ledger.c $(SRCDIR)/utils.c
OBJECTS = $(SOURCES:.c=.o)

# Cross-platform binary extension
EXEEXT = $(if $(filter Windows%,$(OS)),.exe,)

# Default target
all: $(TARGET)

# Build the main target
$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)

# Compile source files
$(SRCDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -I$(SRCDIR) -c $< -o $@

# Clean build artifacts
clean:
	rm -f $(TARGET) $(OBJECTS)

# Installation directories
PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin
MANDIR = $(PREFIX)/share/man/man1

# Install the binary system-wide (requires sudo)
install: $(TARGET)
	@echo "Installing pow to $(BINDIR)..."
	@mkdir -p $(BINDIR)
	@install -m 755 $(TARGET) $(BINDIR)/pow
	@echo "Installation complete. You can now run 'pow' from anywhere."
	@echo "Note: You may need to run 'sudo make install' for system-wide installation."

# Install the binary for current user only
user-install: $(TARGET)
	@echo "Installing pow to ~/.local/bin..."
	@mkdir -p ~/.local/bin
	@install -m 755 $(TARGET) ~/.local/bin/pow
	@echo "Installation complete. You can now run 'pow' from anywhere."
	@echo "Note: Make sure ~/.local/bin is in your PATH."
	@echo "Add 'export PATH=\"\$$HOME/.local/bin:\$$PATH\"' to your ~/.bashrc if needed."

# Uninstall the binary (system-wide)
uninstall:
	@echo "Removing pow from $(BINDIR)..."
	@rm -f $(BINDIR)/pow
	@echo "Uninstallation complete."

# Uninstall the binary (user-local)
user-uninstall:
	@echo "Removing pow from ~/.local/bin..."
	@rm -f ~/.local/bin/pow
	@echo "Uninstallation complete."

# Debug build
debug: CFLAGS += -g -DDEBUG
debug: $(TARGET)

# Run the program
run: $(TARGET)
	./$(TARGET) -h

# Show help
help:
	@echo "Available targets:"
	@echo "  all          - Build the program (default)"
	@echo "  clean        - Remove build artifacts"
	@echo "  debug        - Build with debug symbols"
	@echo "  run          - Build and run the program"
	@echo "  install      - Install to /usr/local/bin (requires sudo)"
	@echo "  user-install - Install to ~/.local/bin (current user only)"
	@echo "  uninstall    - Remove from /usr/local/bin"
	@echo "  user-uninstall - Remove from ~/.local/bin"
	@echo "  help         - Show this help message"

# Phony targets
.PHONY: all clean debug run install user-install uninstall user-uninstall help