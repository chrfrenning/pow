# ZenTransfer Ledger Utility

A command line utility in C that combines file-checksumming with 
proof-of-work mining for building trusted ledgers, and is a
building block for building a decentralized, socially validated,
proof-of-work based photo authenticity system for Web 3.0.

Copyright (C) Christopher Frenning / Perceptron AS 2025. All rights
reserved. Licensed under AGPLv3.

## Features

### Proof-of-Work Mining
- Multiple hash algorithms: MD5, MD5-double, SHA-256, SHA-256-double, SHA-512, SHA-512-double
- Salt support for enhanced security (random generation or custom salt)
- Multi-threaded proof-of-work mining with configurable difficulty
- Configurable thread count for optimal performance
- Command-line interface

### File Checksumming
- MD5 and SHA-512 checksum generation for individual files
- Batch processing for entire directories (recursive)
- JSON output format for easy integration
- Cross-platform file system support

### Ledgers
- Build ledgers based on checksums and POW
- Maintains ledgers in CSV format for append and interoperability
- Verifies ledger integrity and indicates complexity of POW

## Building

```bash
make          # Build the program (creates 'pow' binary)
make clean    # Remove build artifacts
make debug    # Build with debug symbols
make run      # Build and run with help
make help     # Show all available targets
```

## Installation

### System-wide Installation (Recommended)
```bash
sudo make install    # Install to /usr/local/bin (requires sudo)
sudo make uninstall  # Remove from /usr/local/bin
```

### User-local Installation
```bash
make user-install     # Install to ~/.local/bin (current user only)
make user-uninstall   # Remove from ~/.local/bin
```

After user-local installation, ensure `~/.local/bin` is in your PATH:
```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

Once installed, you can run `pow` from anywhere instead of `./pow`.

### Requirements

- GCC compiler (or compatible: clang, MSVC)
- OpenSSL development libraries
- pthread support
- Cross-platform compatibility: Windows, macOS, Linux (x86_64, ARM64)

## Usage

**Note:** A mode must be specified. Running without a mode shows the help message.

### POW Mining Mode
```bash
./pow -p <previous_hash> <next_hash> [OPTIONS]
```

**Options:**
- `-t, --threads <num>`: Number of threads (default: 4)
- `-x, --complexity <num>`: Difficulty level in bits (default: 5)
- `-a, --algorithm <algo>`: Hash algorithm: `md5`, `md5d`, `sha256`, `sha256d`, `sha512`, `sha512d` (default: sha512)
- `--salt`: Generate random cryptographically secure salt
- `--use-salt <salt>`: Use specific 32-character hexadecimal salt

**Algorithm Options:**
- `md5`: Standard MD5 hashing
- `md5d`: Double MD5 hashing (MD5 applied twice)
- `sha256`: Standard SHA-256 hashing
- `sha256d`: Double SHA-256 hashing (SHA-256 applied twice)
- `sha512`: Standard SHA-512 hashing (default)
- `sha512d`: Double SHA-512 hashing (SHA-512 applied twice)

**Examples:**
```bash
# Basic POW with default SHA-512
./pow -p 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111 -t 8 -x 8

# Using SHA-256 algorithm
./pow -p 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111 -a sha256 -t 4 -x 6

# Using MD5 with random salt
./pow -p 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111 -a md5 --salt -t 2 -x 4

# Using SHA-512 double with specific salt
./pow -p 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111 -a sha512d --use-salt abcdef1234567890abcdef1234567890 -t 4 -x 5
```

### Checksum Mode
```bash
./pow -c <path>               # File or directory
./pow -c <directory_path> -r  # Directory (recursive)
```

**Options:**
- `-r, --recursive`: Include subdirectories (default: off)

**Examples:**
```bash
./pow -c document.pdf
./pow -c /path/to/project
./pow -c /path/to/project -r  # Include subdirectories
```

### Ledger Mode
```bash
./pow -l <ledger_file> <path>     # File or directory
./pow -l <ledger_file> <path> -r  # Directory (recursive)
./pow -l <ledger_file> <path> -s <start_hash>  # Use custom start hash
```

**Options:**
- `-t, --threads <num>`: Number of threads (default: 4)
- `-x, --complexity <num>`: Difficulty level in bits (default: 5)
- `-r, --recursive`: Include subdirectories (default: off)
- `-s, --start-hash <hash>`: Start hash for new ledger (requires non-existing file)

**Examples:**
```bash
./pow -l secure.csv document.pdf -t 8 -x 8
./pow -l project.csv /path/to/project -r -t 4 -x 10
./pow -l batch.csv /path/to/files -s abc123...def456 -t 4 -x 12
```

### Output Format
All operations output JSON for easy integration with Electron apps:

**POW Mining:**
```json
{
  "previous_hash": "000...",
  "next_hash": "111...",
  "algorithm": "sha256",
  "salt": "1d0c4e71c85efcdc615b30c02234e748",
  "difficulty": 8,
  "threads": 4,
  "nonce": 123456,
  "result_hash": "abc...",
  "time_seconds": 1.234567
}
```

**Note:** The `algorithm` field is always present. The `salt` field is only included when salt is used (either `--salt` or `--use-salt` options).

**Single File Checksum:**
```json
{
  "filepath": "document.pdf",
  "size": 1024,
  "md5": "abc123...",
  "sha512": "def456...",
  "error": false
}
```

**Directory Checksum:**
```json
{
  "files": [
    {
      "filepath": "file1.txt",
      "size": 1024,
      "md5": "abc123...",
      "sha512": "def456...",
      "error": false
    }
  ],
  "total_files": 1
}
```

**Ledger Mode:**
- Creates/updates a CSV ledger file with ZenTransfer Ledger version 1.0 format
- Each file entry includes: filename, size, SHA-512d checksum, nonce, POW hash, complexity
- Displays progress during POW calculation
- Maintains cryptographic chain linking all entries
- Supports both individual files and directory processing

**Batch Mode with Start Hash:**
- Use `-s, --start-hash` to specify a custom starting hash for new ledger files
- Useful when creating POW for batches to be added to a main ledger elsewhere
- Requires that the specified ledger file does not already exist
- Creates a START entry instead of the default NULL entry
- Hash must be exactly 128 characters long (SHA-512 hex format)

### Verification Mode
```bash
./pow -v <ledger_file>           # Verify ledger integrity
./pow -v <ledger_file> -f        # Verify ledger + file checksums
./pow -v <ledger_file> -i        # Continue on errors
./pow -v <ledger_file> -f -i     # Verify files, ignore errors
```

**Options:**
- `-f, --file-verify`: Verify file checksums exist and match (default: off)
- `-i, --ignore-errors`: Continue verification even if errors occur (default: off)

**Examples:**
```bash
./pow -v secure.csv
./pow -v project.csv -f -i
```

**Verification Mode:**
- Reads entire ledger from start to end
- Verifies POW hash and nonce for each entry
- Optionally verifies file checksums if -f flag is used
- Can continue on errors with -i flag
- Displays progress and comprehensive results 

## Salt Security Features

The POW mode supports salt for enhanced security, making it more difficult to precompute or attack the proof-of-work process.

### Salt Options

**Random Salt Generation:**
```bash
./pow -p prev_hash next_hash --salt -a sha256 -t 4 -x 6
```
- Generates a cryptographically secure random 32-character hexadecimal salt
- Salt is included in the JSON output for verification purposes
- Each run produces different results even with identical inputs

**Custom Salt:**
```bash
./pow -p prev_hash next_hash --use-salt abcdef1234567890abcdef1234567890 -a sha256 -t 4 -x 6
```
- Use a specific 32-character hexadecimal salt
- Allows reproducible results for verification
- Salt must be exactly 32 characters long

### How Salt Works

1. The salt is prepended to the input data before hashing
2. Makes rainbow table attacks impractical
3. Salt is included in JSON output for verification purposes

## Algorithm Selection Guide

### Supported Algorithms

The POW mode supports 6 different hash algorithms, each with different security characteristics and performance profiles:

#### Standard Algorithms
- **MD5** (`md5`): Fastest, lowest security (128-bit output)
- **SHA-256** (`sha256`): Good balance of speed and security (256-bit output)
- **SHA-512** (`sha512`): Highest security, slower (512-bit output) - **Default**

#### Double-Hash Algorithms
- **MD5 Double** (`md5d`): MD5 applied twice, slightly more secure than MD5
- **SHA-256 Double** (`sha256d`): SHA-256 applied twice, Bitcoin-style double hashing
- **SHA-512 Double** (`sha512d`): SHA-512 applied twice, maximum security

## Complexity and Proof-of-Work Difficulty

The `-x, --complexity` parameter sets the proof-of-work difficulty in **bits**, following standard blockchain conventions. The system requires finding a hash with the specified number of leading zero bits using the selected algorithm.

### How It Works

Each difficulty level requires finding a hash that begins with a specific number of zero bits:
- **Complexity 4**: Hash must start with `0000` (4 zero bits)
- **Complexity 8**: Hash must start with `00000000` (8 zero bits)  
- **Complexity 12**: Hash must start with `000000000000` (12 zero bits)

The probability of finding such a hash is `1 / 2^difficulty`, making each additional bit exponentially harder.

### Recommended Complexity Levels

#### **Development and Testing**
- **Complexity 5-8**: 0.01-0.1 seconds on modern laptops
- **Use case**: Educational purposes, personal integrity validation

#### **Light Security**
- **Complexity 13-16**: 5-300 seconds on modern laptops
- **Use case**: Low-value files, or with substantial volume of files

#### **High Security**
- **Complexity 17-20**: 5-80 minutes on modern laptops
- **Use case**: High value files, acceptable for public scrutiny

#### **Maximum Security**
- **Complexity 24-32**: 30-160 minutes on modern laptops
- **Use case**: Few, high-value files

**Multi-threading Impact:**
- Performance scales roughly linearly with thread count
- Use `-t 8` on 8-core systems for optimal performance
- Thread count beyond CPU cores provides diminishing returns

### Practical Examples

**Quick Test (2 seconds):**
```bash
./pow -l my_files.csv document.pdf -x 13 -t 4
```

**High Security (30 seconds):**
```bash
./pow -l secure_archive.csv politician.jpg -r -x 18 -t 8
```

**Maximum Security (20 minutes):**
```bash
./pow -l critical.csv contract.pdf -x 28 -t 8
```

### Advanced POW Examples

**Combining Algorithm and Salt:**
```bash
# SHA-256 double with random salt for enhanced security
./pow -p prev_hash next_hash -a sha256d --salt -x 15 -t 4

# MD5 with custom salt for fast reproducible testing
./pow -p prev_hash next_hash -a md5 --use-salt 0123456789abcdef0123456789abcdef -x 8 -t 2

# Maximum security: SHA-512 double with random salt
./pow -p prev_hash next_hash -a sha512d --salt -x 20 -t 8
```

**Algorithm Performance Comparison:**
```bash
# Fast development testing
./pow -p prev_hash next_hash -a md5 -x 16 -t 4

# Production security
./pow -p prev_hash next_hash -a sha256 -x 16 -t 4

# Maximum security
./pow -p prev_hash next_hash -a sha512d -x 16 -t 4
```
