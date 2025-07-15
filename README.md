# POW Ledger

A multi-purpose utility in C that combines proof-of-work mining with file checksumming capabilities, designed for use in Electron applications.

## Features

### Proof-of-Work Mining
- Multi-threaded proof-of-work mining with configurable difficulty
- SHA-512 hash chain generation
- Performance timing and statistics
- Configurable thread count for optimal performance
- Command-line interface for custom hash inputs

### File Checksumming
- MD5 and SHA-512 checksum generation for individual files
- Batch processing for entire directories (recursive)
- JSON output format for easy integration with Electron apps
- Cross-platform file system support

## Building

```bash
make          # Build the program
make clean    # Remove build artifacts
make debug    # Build with debug symbols
make run      # Build and run
make help     # Show all available targets
```

## Requirements

- GCC compiler (or compatible: clang, MSVC)
- OpenSSL development libraries
- pthread support
- Cross-platform compatibility: Windows, macOS, Linux (x86_64, ARM64)

## Usage

**Note:** A mode must be specified. Running without a mode shows the help message.

### POW Mining Mode
```bash
./pow_ledger -p <previous_hash> <next_hash> [OPTIONS]
```

**Options:**
- `-t, --threads <num>`: Number of threads (default: 4)
- `-x, --complexity <num>`: Difficulty level (default: 5)

**Example:**
```bash
./pow_ledger -p 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111 -t 8 -x 6
```

### Checksum Mode
```bash
./pow_ledger -c <path>               # File or directory
./pow_ledger -c <directory_path> -r  # Directory (recursive)
```

**Options:**
- `-r, --recursive`: Include subdirectories (default: off)

**Examples:**
```bash
./pow_ledger -c document.pdf
./pow_ledger -c /path/to/project
./pow_ledger -c /path/to/project -r  # Include subdirectories
```

### Output Format
All operations output JSON for easy integration with Electron apps:

**POW Mining:**
```json
{
  "previous_hash": "000...",
  "next_hash": "111...",
  "difficulty": 5,
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