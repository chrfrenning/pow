# ZenTransfer Ledger Utility

A command line utility in C that combines file-checksumming with 
proof-of-work mining for building trusted ledgers, and is a
building block for building a decentralized, socially validated,
proof-of-work based photo authenticity system for Web 3.0.

Copyright (C) Christopher Frenning / Perceptron AS 2025. All rights
reserved. Licensed under AGPLv3.

## Features

### Proof-of-Work Mining
- SHA-512 hash chain generation
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

**Example:**
```bash
./pow -p 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111 -t 8 -x 8
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
  "difficulty": 8,
  "threads": 4,
  "nonce": 123456,
  "result_hash": "abc...",
  "time_seconds": 1.234567
}
```

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
- Each file entry includes: filename, size, SHA-512 checksum, nonce, POW hash, complexity
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

## Complexity and Proof-of-Work Difficulty

The `-x, --complexity` parameter sets the proof-of-work difficulty in **bits** (not hex characters), following standard blockchain conventions. The system requires finding a SHA-512 hash with the specified number of leading zero bits.

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
