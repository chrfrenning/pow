# POW Ledger

A proof-of-work ledger implementation in C that demonstrates blockchain-style hash chain generation using SHA-512.

## Features

- Multi-threaded proof-of-work mining with configurable difficulty
- SHA-512 hash chain generation
- Performance timing and statistics
- Configurable thread count for optimal performance

## Building

```bash
make          # Build the program
make clean    # Remove build artifacts
make debug    # Build with debug symbols
make run      # Build and run
make help     # Show all available targets
```

## Requirements

- GCC compiler
- OpenSSL development libraries
- pthread support

## Usage

The program generates a chain of 128 proof-of-work entries, each requiring a hash with a configurable number of leading zeros (difficulty = 5 by default). 