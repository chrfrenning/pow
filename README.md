# POW Ledger

A command line utility in C that combines file-checksumming with proof-of-work mining for building trusted ledgers.

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
make          # Build the program
make clean    # Remove build artifacts
make debug    # Build with debug symbols
make run      # Build and run
make help     # Show all available targets
```

### Requirements

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

### Ledger Mode
```bash
./pow_ledger -l <ledger_file> <path>     # File or directory
./pow_ledger -l <ledger_file> <path> -r  # Directory (recursive)
./pow_ledger -l <ledger_file> <path> -s <start_hash>  # Use custom start hash
```

**Options:**
- `-t, --threads <num>`: Number of threads (default: 4)
- `-x, --complexity <num>`: Difficulty level (default: 5)
- `-r, --recursive`: Include subdirectories (default: off)
- `-s, --start-hash <hash>`: Start hash for new ledger (requires non-existing file)

**Examples:**
```bash
./pow_ledger -l secure.csv document.pdf -t 8 -x 6
./pow_ledger -l project.csv /path/to/project -r -t 4 -x 5
./pow_ledger -l batch.csv /path/to/files -s abc123...def456 -t 4 -x 5
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
./pow_ledger -v <ledger_file>           # Verify ledger integrity
./pow_ledger -v <ledger_file> -f        # Verify ledger + file checksums
./pow_ledger -v <ledger_file> -i        # Continue on errors
./pow_ledger -v <ledger_file> -f -i     # Verify files, ignore errors
```

**Options:**
- `-f, --file-verify`: Verify file checksums exist and match (default: off)
- `-i, --ignore-errors`: Continue verification even if errors occur (default: off)

**Examples:**
```bash
./pow_ledger -v secure.csv
./pow_ledger -v project.csv -f -i
```

**Verification Mode:**
- Reads entire ledger from start to end
- Verifies POW hash and nonce for each entry
- Optionally verifies file checksums if -f flag is used
- Can continue on errors with -i flag
- Displays progress and comprehensive results 
