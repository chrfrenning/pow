#include "utils.h"

double current_time(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

void print_usage(const char *program_name) {
    printf("Usage: %s <MODE> [OPTIONS]\n", program_name);
    printf("\nModes (required):\n");
    printf("  -p, --pow <prev_hash> <next_hash>  Run proof-of-work mining\n");
    printf("  -c, --checksum <path>              Generate file checksums\n");
    printf("  -l, --ledger <ledger_file> <path>  Maintain trusted ledger\n");
    printf("  -v, --verify <ledger_file>         Verify ledger integrity\n");
    printf("\nPOW Mode Options:\n");
    printf("  -t, --threads <num>                Number of threads (default: %d)\n", DEFAULT_THREADS);
    printf("  -x, --complexity <num>             Difficulty level in bits (default: %d)\n", DEFAULT_DIFFICULTY);
    printf("\nChecksum Mode Options:\n");
    printf("  -r, --recursive                    Include subdirectories (default: off)\n");
    printf("\nLedger Mode Options:\n");
    printf("  -t, --threads <num>                Number of threads (default: %d)\n", DEFAULT_THREADS);
    printf("  -x, --complexity <num>             Difficulty level in bits (default: %d)\n", DEFAULT_DIFFICULTY);
    printf("  -r, --recursive                    Include subdirectories (default: off)\n");
    printf("  -s, --start-hash <hash>            Start hash for new ledger (requires non-existing file)\n");
    printf("\nVerify Mode Options:\n");
    printf("  -f, --file-verify                  Verify file checksums (default: off)\n");
    printf("  -i, --ignore-errors                Continue on verification errors (default: off)\n");
    printf("\nGeneral:\n");
    printf("  -h, --help                         Show this help message\n");
    printf("\nExamples:\n");
    printf("  %s -p prev_hash next_hash -t 8 -x 6\n", program_name);
    printf("  %s -c myfile.txt\n", program_name);
    printf("  %s -c /path/to/directory -r\n", program_name);
    printf("  %s -l ledger.csv /path/to/files -t 4 -x 5\n", program_name);
    printf("  %s -v ledger.csv\n", program_name);
    printf("  %s -v ledger.csv -f -i\n", program_name);
}