#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <time.h>
#include <unistd.h>
#include <stdatomic.h>
#include <sys/stat.h>
#include <dirent.h>
#include <getopt.h>
#include <errno.h>
#include <inttypes.h>

#ifdef _WIN32
#include <windows.h>
#define PATH_SEPARATOR '\\'
#else
#define PATH_SEPARATOR '/'
#endif

#define HASH_HEX_LEN 128
#define MAX_THREADS 64
#define MAX_PATH_LEN 4096
#define MAX_FILES 10000
#define DEFAULT_THREADS 4
#define DEFAULT_DIFFICULTY 5

typedef struct {
    char previous_entry[HASH_HEX_LEN + 1];
    char current_entry[HASH_HEX_LEN + 1];
    int difficulty;
    int thread_id;
    int num_threads;
} thread_args_t;

typedef struct {
    atomic_int found;
    char result_hash[HASH_HEX_LEN + 1];
    uint64_t result_nonce;
} pow_result_t;

typedef struct {
    char filepath[MAX_PATH_LEN];
    char md5[33];
    char sha512[129];
    long size;
    int error;
} file_checksum_t;

typedef struct {
    char filename[MAX_PATH_LEN];
    long size;
    char checksum[129];
    char salt[33];
    uint64_t nonce;
    char pow_hash[129];
    int complexity;
} ledger_entry_t;

typedef struct {
    int total_entries;
    int verified_entries;
    int failed_entries;
    int missing_files;
    int file_mismatch;
    int pow_failures;
    int chain_breaks;
    int complexity_failures;
} verification_stats_t;

typedef enum {
    MODE_NONE,
    MODE_POW,
    MODE_CHECKSUM,
    MODE_LEDGER,
    MODE_VERIFY
} operation_mode_t;

pow_result_t pow_result;

void sha512_hex(const char *input, char *output) {
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512((const unsigned char*)input, strlen(input), hash);
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[HASH_HEX_LEN] = '\0';
}

void md5_file(const char *filepath, char *output) {
    FILE *file = fopen(filepath, "rb");
    if (!file) {
        output[0] = '\0';
        return;
    }
    
    MD5_CTX ctx;
    MD5_Init(&ctx);
    
    unsigned char buffer[8192];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        MD5_Update(&ctx, buffer, bytes);
    }
    fclose(file);
    
    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5_Final(hash, &ctx);
    
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[32] = '\0';
}

void generate_salt(char *salt_hex) {
    unsigned char salt_bytes[16];
    
    if (RAND_bytes(salt_bytes, 16) != 1) {
        fprintf(stderr, "Error: Failed to generate cryptographically secure random salt\n");
        exit(1);
    }
    
    for (int i = 0; i < 16; i++) {
        sprintf(salt_hex + (i * 2), "%02x", salt_bytes[i]);
    }
    salt_hex[32] = '\0';
}

void sha512_file(const char *filepath, char *output) {
    FILE *file = fopen(filepath, "rb");
    if (!file) {
        output[0] = '\0';
        return;
    }
    
    SHA512_CTX ctx;
    SHA512_Init(&ctx);
    
    unsigned char buffer[8192];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        SHA512_Update(&ctx, buffer, bytes);
    }
    fclose(file);
    
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512_Final(hash, &ctx);
    
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[128] = '\0';
}

void sha512_file_with_salt(const char *filepath, const char *salt_hex, char *output) {
    FILE *file = fopen(filepath, "rb");
    if (!file) {
        output[0] = '\0';
        return;
    }
    
    SHA512_CTX ctx;
    SHA512_Init(&ctx);
    
    SHA512_Update(&ctx, salt_hex, 32);
    
    unsigned char buffer[8192];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        SHA512_Update(&ctx, buffer, bytes);
    }
    fclose(file);
    
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512_Final(hash, &ctx);
    
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[128] = '\0';
}

void* pow_worker(void *arg) {
    thread_args_t *args = (thread_args_t *)arg;
    uint64_t block_size = 100000;
    uint64_t block = args->thread_id;
    char data[512], hash_hex[HASH_HEX_LEN + 1];
    char prefix[65];

    memset(prefix, '0', args->difficulty);
    prefix[args->difficulty] = '\0';

    while (!atomic_load(&pow_result.found)) {
        uint64_t start = block * block_size;
        uint64_t end = start + block_size;
        for (uint64_t nonce = start; nonce < end; nonce++) {
            snprintf(data, sizeof(data), "%s%s%lu", args->previous_entry, args->current_entry, nonce);
            sha512_hex(data, hash_hex);
            if (strncmp(hash_hex, prefix, args->difficulty) == 0) {
                if (!atomic_exchange(&pow_result.found, 1)) {
                    strncpy(pow_result.result_hash, hash_hex, HASH_HEX_LEN);
                    pow_result.result_hash[HASH_HEX_LEN] = '\0';
                    pow_result.result_nonce = nonce;
                }
                return NULL;
            }
        }
        block += args->num_threads;
    }

    return NULL;
}

double current_time() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + (ts.tv_nsec / 1e9);
}

long get_file_size(const char *filepath) {
    struct stat st;
    if (stat(filepath, &st) == 0) {
        return st.st_size;
    }
    return -1;
}

int is_regular_file(const char *filepath) {
    struct stat st;
    if (stat(filepath, &st) == 0) {
        return S_ISREG(st.st_mode);
    }
    return 0;
}

int is_directory(const char *filepath) {
    struct stat st;
    if (stat(filepath, &st) == 0) {
        return S_ISDIR(st.st_mode);
    }
    return 0;
}

void process_file(const char *filepath, file_checksum_t *result) {
    strncpy(result->filepath, filepath, MAX_PATH_LEN - 1);
    result->filepath[MAX_PATH_LEN - 1] = '\0';
    result->error = 0;
    
    if (!is_regular_file(filepath)) {
        result->error = 1;
        return;
    }
    
    result->size = get_file_size(filepath);
    if (result->size < 0) {
        result->error = 1;
        return;
    }
    
    md5_file(filepath, result->md5);
    sha512_file(filepath, result->sha512);
    
    if (result->md5[0] == '\0' || result->sha512[0] == '\0') {
        result->error = 1;
    }
}

int scan_directory(const char *dirpath, file_checksum_t *results, int max_files, int recursive) {
    DIR *dir = opendir(dirpath);
    if (!dir) {
        return -1;
    }
    
    int count = 0;
    struct dirent *entry;
    char filepath[MAX_PATH_LEN];
    
    while ((entry = readdir(dir)) != NULL && count < max_files) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        snprintf(filepath, MAX_PATH_LEN, "%s%c%s", dirpath, PATH_SEPARATOR, entry->d_name);
        
        if (is_regular_file(filepath)) {
            process_file(filepath, &results[count]);
            count++;
        } else if (is_directory(filepath) && recursive) {
            int subcount = scan_directory(filepath, &results[count], max_files - count, recursive);
            if (subcount > 0) {
                count += subcount;
            }
        }
    }
    
    closedir(dir);
    return count;
}

void print_json_single(const file_checksum_t *result) {
    printf("{\n");
    printf("  \"filepath\": \"%s\",\n", result->filepath);
    printf("  \"size\": %ld,\n", result->size);
    printf("  \"md5\": \"%s\",\n", result->md5);
    printf("  \"sha512\": \"%s\",\n", result->sha512);
    printf("  \"error\": %s\n", result->error ? "true" : "false");
    printf("}\n");
}

void print_json_multiple(const file_checksum_t *results, int count) {
    printf("{\n");
    printf("  \"files\": [\n");
    for (int i = 0; i < count; i++) {
        printf("    {\n");
        printf("      \"filepath\": \"%s\",\n", results[i].filepath);
        printf("      \"size\": %ld,\n", results[i].size);
        printf("      \"md5\": \"%s\",\n", results[i].md5);
        printf("      \"sha512\": \"%s\",\n", results[i].sha512);
        printf("      \"error\": %s\n", results[i].error ? "true" : "false");
        printf("    }%s\n", i < count - 1 ? "," : "");
    }
    printf("  ],\n");
    printf("  \"total_files\": %d\n", count);
    printf("}\n");
}

int read_last_ledger_entry(const char *ledger_file, ledger_entry_t *entry) {
    FILE *file = fopen(ledger_file, "r");
    if (!file) {
        return 0;
    }
    
    char line[2048];
    char last_line[2048] = "";
    
    while (fgets(line, sizeof(line), file)) {
        if (line[0] != '#' && strlen(line) > 10) {
            strncpy(last_line, line, sizeof(last_line) - 1);
            last_line[sizeof(last_line) - 1] = '\0';
        }
    }
    fclose(file);
    
    if (strlen(last_line) == 0) {
        return 0;
    }
    
    char *token = strtok(last_line, ",");
    if (!token) return 0;
    strncpy(entry->filename, token, MAX_PATH_LEN - 1);
    
    token = strtok(NULL, ",");
    if (!token) return 0;
    entry->size = atol(token);
    
    token = strtok(NULL, ",");
    if (!token) return 0;
    strncpy(entry->checksum, token, 128);
    entry->checksum[128] = '\0';
    
    token = strtok(NULL, ",");
    if (!token) return 0;
    strncpy(entry->salt, token, 32);
    entry->salt[32] = '\0';
    
    token = strtok(NULL, ",");
    if (!token) return 0;
    entry->nonce = strtoull(token, NULL, 10);
    
    token = strtok(NULL, ",");
    if (!token) return 0;
    strncpy(entry->pow_hash, token, 128);
    entry->pow_hash[128] = '\0';
    
    token = strtok(NULL, ",");
    if (!token) return 0;
    entry->complexity = atoi(token);
    
    
    return 1;
}

void write_ledger_header(const char *ledger_file) {
    FILE *file = fopen(ledger_file, "w");
    if (!file) {
        fprintf(stderr, "Error: Cannot create ledger file '%s'\n", ledger_file);
        return;
    }
    
    fprintf(file, "# ZenTransfer Ledger version 1.0\n");
    fprintf(file, "filename,size,checksum,salt,nonce,pow_hash,complexity\n");
    fclose(file);
}

void append_ledger_entry(const char *ledger_file, const ledger_entry_t *entry) {
    FILE *file = fopen(ledger_file, "a");
    if (!file) {
        fprintf(stderr, "Error: Cannot append to ledger file '%s'\n", ledger_file);
        return;
    }
    
    fprintf(file, "%s,%ld,%s,%s,%lu,%s,%d\n",
            entry->filename,
            entry->size,
            entry->checksum,
            entry->salt,
            entry->nonce,
            entry->pow_hash,
            entry->complexity);
    fclose(file);
}

void create_null_entry(ledger_entry_t *entry) {
    strncpy(entry->filename, "NULL", MAX_PATH_LEN - 1);
    entry->size = 0;
    memset(entry->checksum, '0', 128);
    entry->checksum[128] = '\0';
    memset(entry->salt, '0', 32);
    entry->salt[32] = '\0';
    entry->nonce = 0;
    memset(entry->pow_hash, '0', 128);
    entry->pow_hash[128] = '\0';
    entry->complexity = 0;
}

void create_start_entry(ledger_entry_t *entry, const char *start_hash) {
    strncpy(entry->filename, "START", MAX_PATH_LEN - 1);
    entry->size = 0;
    memset(entry->checksum, '0', 128);
    entry->checksum[128] = '\0';
    memset(entry->salt, '0', 32);
    entry->salt[32] = '\0';
    entry->nonce = 0;
    strncpy(entry->pow_hash, start_hash, 128);
    entry->pow_hash[128] = '\0';
    entry->complexity = 0;
}

int calculate_ledger_pow(const char *prev_hash, const char *current_data, int difficulty, int num_threads, uint64_t *result_nonce, char *result_hash) {
    atomic_store(&pow_result.found, 0);
    pow_result.result_nonce = 0;
    
    pthread_t threads[MAX_THREADS];
    thread_args_t args[MAX_THREADS];
    
    for (int t = 0; t < num_threads; t++) {
        strncpy(args[t].previous_entry, prev_hash, HASH_HEX_LEN);
        strncpy(args[t].current_entry, current_data, HASH_HEX_LEN);
        args[t].difficulty = difficulty;
        args[t].thread_id = t;
        args[t].num_threads = num_threads;
        pthread_create(&threads[t], NULL, pow_worker, &args[t]);
    }
    
    for (int t = 0; t < num_threads; t++) {
        pthread_join(threads[t], NULL);
    }
    
    *result_nonce = pow_result.result_nonce;
    strncpy(result_hash, pow_result.result_hash, 128);
    result_hash[128] = '\0';
    
    return 1;
}

void print_progress(const char *filename, int current, int total, double elapsed) {
    printf("[%d/%d] Processing: %s (%.2fs)\n", current, total, filename, elapsed);
    fflush(stdout);
}

int read_all_ledger_entries(const char *ledger_file, ledger_entry_t **entries, int *count) {
    FILE *file = fopen(ledger_file, "r");
    if (!file) {
        return -1;
    }
    
    *entries = malloc(MAX_FILES * sizeof(ledger_entry_t));
    if (!*entries) {
        fclose(file);
        return -1;
    }
    
    char line[2048];
    *count = 0;
    
    while (fgets(line, sizeof(line), file) && *count < MAX_FILES) {
        if (line[0] == '#' || strlen(line) < 10 || strstr(line, "filename,size,checksum") != NULL) {
            continue;
        }
        
        char *line_copy = strdup(line);
        if (!line_copy) continue;
        
        char *token = strtok(line_copy, ",");
        if (!token) { free(line_copy); continue; }
        strncpy((*entries)[*count].filename, token, MAX_PATH_LEN - 1);
        
        token = strtok(NULL, ",");
        if (!token) { free(line_copy); continue; }
        (*entries)[*count].size = atol(token);
        
        token = strtok(NULL, ",");
        if (!token) { free(line_copy); continue; }
        strncpy((*entries)[*count].checksum, token, 128);
        (*entries)[*count].checksum[128] = '\0';
        
        token = strtok(NULL, ",");
        if (!token) { free(line_copy); continue; }
        strncpy((*entries)[*count].salt, token, 32);
        (*entries)[*count].salt[32] = '\0';
        
        token = strtok(NULL, ",");
        if (!token) { free(line_copy); continue; }
        (*entries)[*count].nonce = strtoull(token, NULL, 10);
        
        token = strtok(NULL, ",");
        if (!token) { free(line_copy); continue; }
        strncpy((*entries)[*count].pow_hash, token, 128);
        (*entries)[*count].pow_hash[128] = '\0';
        
        token = strtok(NULL, ",");
        if (!token) { free(line_copy); continue; }
        (*entries)[*count].complexity = atoi(token);
        
        
        free(line_copy);
        (*count)++;
    }
    
    fclose(file);
    return 0;
}

int verify_pow_hash(const char *prev_hash, const char *current_data, uint64_t nonce, const char *expected_hash, int complexity) {
    char data[512];
    snprintf(data, sizeof(data), "%s%s%lu", prev_hash, current_data, nonce);
    
    char computed_hash[129];
    sha512_hex(data, computed_hash);
    
    if (strcmp(computed_hash, expected_hash) != 0) {
        return 0;
    }
    
    char prefix[65];
    memset(prefix, '0', complexity);
    prefix[complexity] = '\0';
    
    return strncmp(computed_hash, prefix, complexity) == 0;
}

int verify_file_checksum_with_salt(const char *filepath, const char *expected_checksum, const char *salt_hex) {
    if (!is_regular_file(filepath)) {
        return -1;
    }
    
    char computed_checksum[129];
    sha512_file_with_salt(filepath, salt_hex, computed_checksum);
    
    if (computed_checksum[0] == '\0') {
        return -1;
    }
    
    return strcmp(computed_checksum, expected_checksum) == 0;
}

int count_leading_zeros(const char *hash) {
    int count = 0;
    for (int i = 0; i < 128 && hash[i] == '0'; i++) {
        count++;
    }
    return count;
}

void print_strength_indicator(int complexity) {
    printf(" ");
    for (int i = 0; i < complexity; i++) {
        printf("✓");
    }
}

void print_verification_stats(const verification_stats_t *stats) {
    printf("\n=== Verification Results ===\n");
    printf("Total entries: %d\n", stats->total_entries);
    printf("Verified entries: %d\n", stats->verified_entries);
    printf("Failed entries: %d\n", stats->failed_entries);
    
    if (stats->missing_files > 0) {
        printf("Missing files: %d\n", stats->missing_files);
    }
    if (stats->file_mismatch > 0) {
        printf("File checksum mismatches: %d\n", stats->file_mismatch);
    }
    if (stats->pow_failures > 0) {
        printf("POW verification failures: %d\n", stats->pow_failures);
    }
    if (stats->chain_breaks > 0) {
        printf("Chain breaks: %d\n", stats->chain_breaks);
    }
    if (stats->complexity_failures > 0) {
        printf("Complexity verification failures: %d\n", stats->complexity_failures);
    }
    
    if (stats->failed_entries == 0) {
        printf("\n✓ Ledger verification PASSED\n");
    } else {
        printf("\n✗ Ledger verification FAILED\n");
    }
}

int run_ledger_verification(const char *ledger_file, int file_verify, int ignore_errors) {
    ledger_entry_t *entries;
    int count;
    
    if (read_all_ledger_entries(ledger_file, &entries, &count) != 0) {
        fprintf(stderr, "Error: Cannot read ledger file '%s'\n", ledger_file);
        return 1;
    }
    
    if (count == 0) {
        fprintf(stderr, "Error: Empty ledger file\n");
        free(entries);
        return 1;
    }
    
    printf("Verifying ledger '%s' with %d entries...\n", ledger_file, count);
    
    verification_stats_t stats = {0};
    stats.total_entries = count;
    
    for (int i = 0; i < count; i++) {
        printf("[%d/%d] Verifying: %s ... ", i + 1, count, entries[i].filename);
        fflush(stdout);
        
        int entry_valid = 1;
        
        if (strcmp(entries[i].filename, "NULL") != 0) {
            char current_data[256];
            snprintf(current_data, sizeof(current_data), "%s_%ld_%s", 
                     entries[i].filename, entries[i].size, entries[i].checksum);
            
            char padded_data[129];
            memset(padded_data, '0', 128);
            int data_len = strlen(current_data);
            if (data_len > 128) data_len = 128;
            memcpy(padded_data, current_data, data_len);
            padded_data[128] = '\0';
            
            char prev_hash[129];
            if (i == 0) {
                memset(prev_hash, '0', 128);
                prev_hash[128] = '\0';
            } else {
                strncpy(prev_hash, entries[i-1].pow_hash, 128);
                prev_hash[128] = '\0';
            }
            
            if (!verify_pow_hash(prev_hash, padded_data, entries[i].nonce, entries[i].pow_hash, entries[i].complexity)) {
                printf("POW FAILED\n");
                stats.pow_failures++;
                entry_valid = 0;
            } else {
                printf("POW OK");
                
                // Verify complexity by counting leading zeros
                int actual_complexity = count_leading_zeros(entries[i].pow_hash);
                if (actual_complexity < entries[i].complexity) {
                    printf(", COMPLEXITY FAILED (expected: %d, actual: %d)", entries[i].complexity, actual_complexity);
                    stats.complexity_failures++;
                    entry_valid = 0;
                } else {
                    printf(", COMPLEXITY OK");
                    print_strength_indicator(entries[i].complexity);
                }
            }
            
            if (file_verify) {
                int file_result = verify_file_checksum_with_salt(entries[i].filename, entries[i].checksum, entries[i].salt);
                if (file_result == -1) {
                    printf(", FILE MISSING");
                    stats.missing_files++;
                    if (!ignore_errors) entry_valid = 0;
                } else if (file_result == 0) {
                    printf(", FILE MISMATCH");
                    stats.file_mismatch++;
                    entry_valid = 0;
                } else {
                    printf(", FILE OK");
                }
            }
        } else {
            printf("NULL ENTRY OK");
            print_strength_indicator(entries[i].complexity);
        }
        
        if (entry_valid) {
            stats.verified_entries++;
            printf("\n");
        } else {
            stats.failed_entries++;
            printf(" - FAILED\n");
            if (!ignore_errors) {
                printf("\nVerification stopped due to error (use -i to continue)\n");
                break;
            }
        }
    }
    
    print_verification_stats(&stats);
    free(entries);
    
    return (stats.failed_entries > 0) ? 1 : 0;
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
    printf("  -x, --complexity <num>             Difficulty level (default: %d)\n", DEFAULT_DIFFICULTY);
    printf("\nChecksum Mode Options:\n");
    printf("  -r, --recursive                    Include subdirectories (default: off)\n");
    printf("\nLedger Mode Options:\n");
    printf("  -t, --threads <num>                Number of threads (default: %d)\n", DEFAULT_THREADS);
    printf("  -x, --complexity <num>             Difficulty level (default: %d)\n", DEFAULT_DIFFICULTY);
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
    printf("  %s -l batch.csv /path/to/files -s <start_hash> -t 4 -x 5\n", program_name);
    printf("  %s -v ledger.csv\n", program_name);
    printf("  %s -v ledger.csv -f -i\n", program_name);
}

int run_pow_mining(const char *prev_hash, const char *next_hash, int num_threads, int difficulty) {
    if (strlen(prev_hash) != HASH_HEX_LEN || strlen(next_hash) != HASH_HEX_LEN) {
        fprintf(stderr, "Error: Hash values must be %d characters long\n", HASH_HEX_LEN);
        return 1;
    }
    
    if (num_threads < 1 || num_threads > MAX_THREADS) {
        fprintf(stderr, "Error: Number of threads must be between 1 and %d\n", MAX_THREADS);
        return 1;
    }
    
    if (difficulty < 1 || difficulty > 64) {
        fprintf(stderr, "Error: Difficulty must be between 1 and 64\n");
        return 1;
    }
    
    atomic_store(&pow_result.found, 0);
    pow_result.result_nonce = 0;
    
    pthread_t threads[MAX_THREADS];
    thread_args_t args[MAX_THREADS];
    
    double start = current_time();
    
    for (int t = 0; t < num_threads; t++) {
        strncpy(args[t].previous_entry, prev_hash, HASH_HEX_LEN + 1);
        strncpy(args[t].current_entry, next_hash, HASH_HEX_LEN + 1);
        args[t].difficulty = difficulty;
        args[t].thread_id = t;
        args[t].num_threads = num_threads;
        pthread_create(&threads[t], NULL, pow_worker, &args[t]);
    }
    
    for (int t = 0; t < num_threads; t++) {
        pthread_join(threads[t], NULL);
    }
    
    double elapsed = current_time() - start;
    
    printf("{\n");
    printf("  \"previous_hash\": \"%s\",\n", prev_hash);
    printf("  \"next_hash\": \"%s\",\n", next_hash);
    printf("  \"difficulty\": %d,\n", difficulty);
    printf("  \"threads\": %d,\n", num_threads);
    printf("  \"nonce\": %lu,\n", pow_result.result_nonce);
    printf("  \"result_hash\": \"%s\",\n", pow_result.result_hash);
    printf("  \"time_seconds\": %.6f\n", elapsed);
    printf("}\n");
    
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    operation_mode_t mode = MODE_NONE;
    char *prev_hash = NULL;
    char *next_hash = NULL;
    char *target_path = NULL;
    char *ledger_file = NULL;
    char *start_hash = NULL;
    int num_threads = DEFAULT_THREADS;
    int difficulty = DEFAULT_DIFFICULTY;
    int recursive = 0;
    int file_verify = 0;
    int ignore_errors = 0;
    
    struct option long_options[] = {
        {"pow", required_argument, 0, 'p'},
        {"checksum", required_argument, 0, 'c'},
        {"ledger", required_argument, 0, 'l'},
        {"verify", required_argument, 0, 'v'},
        {"threads", required_argument, 0, 't'},
        {"complexity", required_argument, 0, 'x'},
        {"recursive", no_argument, 0, 'r'},
        {"file-verify", no_argument, 0, 'f'},
        {"ignore-errors", no_argument, 0, 'i'},
        {"start-hash", required_argument, 0, 's'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "p:c:l:v:t:x:rfis:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'p':
                if (mode != MODE_NONE) {
                    fprintf(stderr, "Error: Only one mode can be specified\n");
                    return 1;
                }
                mode = MODE_POW;
                prev_hash = optarg;
                if (optind < argc) {
                    next_hash = argv[optind++];
                } else {
                    fprintf(stderr, "Error: POW mode requires two hash arguments\n");
                    return 1;
                }
                break;
            case 'c':
                if (mode != MODE_NONE) {
                    fprintf(stderr, "Error: Only one mode can be specified\n");
                    return 1;
                }
                mode = MODE_CHECKSUM;
                target_path = optarg;
                break;
            case 'l':
                if (mode != MODE_NONE) {
                    fprintf(stderr, "Error: Only one mode can be specified\n");
                    return 1;
                }
                mode = MODE_LEDGER;
                ledger_file = optarg;
                if (optind < argc) {
                    target_path = argv[optind++];
                } else {
                    fprintf(stderr, "Error: Ledger mode requires ledger file and source path\n");
                    return 1;
                }
                break;
            case 'v':
                if (mode != MODE_NONE) {
                    fprintf(stderr, "Error: Only one mode can be specified\n");
                    return 1;
                }
                mode = MODE_VERIFY;
                ledger_file = optarg;
                break;
            case 't':
                num_threads = atoi(optarg);
                break;
            case 'x':
                difficulty = atoi(optarg);
                break;
            case 'r':
                recursive = 1;
                break;
            case 'f':
                file_verify = 1;
                break;
            case 'i':
                ignore_errors = 1;
                break;
            case 's':
                start_hash = optarg;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    if (mode == MODE_NONE) {
        fprintf(stderr, "Error: No mode specified\n\n");
        print_usage(argv[0]);
        return 1;
    }
    
    switch (mode) {
        case MODE_POW:
            if (!prev_hash || !next_hash) {
                fprintf(stderr, "Error: POW mode requires previous and next hash arguments\n");
                return 1;
            }
            return run_pow_mining(prev_hash, next_hash, num_threads, difficulty);
            
        case MODE_CHECKSUM:
            if (!target_path) {
                fprintf(stderr, "Error: Checksum mode requires a file or directory path\n");
                return 1;
            }
            
            if (is_regular_file(target_path)) {
                file_checksum_t result;
                process_file(target_path, &result);
                
                if (result.error) {
                    fprintf(stderr, "Error: Cannot process file '%s': %s\n", target_path, strerror(errno));
                    return 1;
                }
                
                print_json_single(&result);
            } else if (is_directory(target_path)) {
                file_checksum_t *results = malloc(MAX_FILES * sizeof(file_checksum_t));
                if (!results) {
                    fprintf(stderr, "Error: Memory allocation failed\n");
                    return 1;
                }
                
                int count = scan_directory(target_path, results, MAX_FILES, recursive);
                if (count < 0) {
                    fprintf(stderr, "Error: Cannot read directory '%s': %s\n", target_path, strerror(errno));
                    free(results);
                    return 1;
                }
                
                if (count == 0) {
                    printf("{\"files\": [], \"total_files\": 0}\n");
                } else {
                    print_json_multiple(results, count);
                }
                
                free(results);
            } else {
                fprintf(stderr, "Error: '%s' is not a valid file or directory\n", target_path);
                return 1;
            }
            break;
            
        case MODE_LEDGER:
            if (!ledger_file || !target_path) {
                fprintf(stderr, "Error: Ledger mode requires ledger file and source path\n");
                return 1;
            }
            
            // Validate start_hash if provided
            if (start_hash) {
                if (strlen(start_hash) != HASH_HEX_LEN) {
                    fprintf(stderr, "Error: Start hash must be %d characters long\n", HASH_HEX_LEN);
                    return 1;
                }
                
                // Check if ledger file already exists
                FILE *check_file = fopen(ledger_file, "r");
                if (check_file) {
                    fclose(check_file);
                    fprintf(stderr, "Error: Ledger file '%s' already exists. Start hash can only be used with new ledger files\n", ledger_file);
                    return 1;
                }
            }
            
            ledger_entry_t last_entry;
            int has_last_entry = read_last_ledger_entry(ledger_file, &last_entry);
            
            if (!has_last_entry) {
                write_ledger_header(ledger_file);
                if (start_hash) {
                    create_start_entry(&last_entry, start_hash);
                    append_ledger_entry(ledger_file, &last_entry);
                    printf("Created new ledger with START entry using provided hash\n");
                } else {
                    create_null_entry(&last_entry);
                    append_ledger_entry(ledger_file, &last_entry);
                    printf("Created new ledger with NULL entry\n");
                }
            } else if (start_hash) {
                fprintf(stderr, "Error: Cannot use start hash with existing ledger file\n");
                return 1;
            }
            
            file_checksum_t *files;
            int file_count;
            
            if (is_regular_file(target_path)) {
                files = malloc(sizeof(file_checksum_t));
                if (!files) {
                    fprintf(stderr, "Error: Memory allocation failed\n");
                    return 1;
                }
                process_file(target_path, files);
                if (files[0].error) {
                    fprintf(stderr, "Error: Cannot process file '%s'\n", target_path);
                    free(files);
                    return 1;
                }
                file_count = 1;
            } else if (is_directory(target_path)) {
                files = malloc(MAX_FILES * sizeof(file_checksum_t));
                if (!files) {
                    fprintf(stderr, "Error: Memory allocation failed\n");
                    return 1;
                }
                
                file_count = scan_directory(target_path, files, MAX_FILES, recursive);
                if (file_count < 0) {
                    fprintf(stderr, "Error: Cannot read directory '%s'\n", target_path);
                    free(files);
                    return 1;
                }
            } else {
                fprintf(stderr, "Error: '%s' is not a valid file or directory\n", target_path);
                return 1;
            }
            
            printf("Processing %d files into ledger...\n", file_count);
            
            for (int i = 0; i < file_count; i++) {
                if (files[i].error) {
                    printf("Skipping file with error: %s\n", files[i].filepath);
                    continue;
                }
                
                double start_time = current_time();
                printf("Processing file: %s ... ", files[i].filepath);
                fflush(stdout);
                
                ledger_entry_t entry;
                strncpy(entry.filename, files[i].filepath, MAX_PATH_LEN - 1);
                entry.size = files[i].size;
                
                generate_salt(entry.salt);
                sha512_file_with_salt(files[i].filepath, entry.salt, entry.checksum);
                entry.checksum[128] = '\0';
                entry.complexity = difficulty;
                
                char current_data[256];
                snprintf(current_data, sizeof(current_data), "%s_%ld_%s", 
                         entry.filename, entry.size, entry.checksum);
                
                char padded_data[129];
                memset(padded_data, '0', 128);
                int data_len = strlen(current_data);
                if (data_len > 128) data_len = 128;
                memcpy(padded_data, current_data, data_len);
                padded_data[128] = '\0';
                
                uint64_t nonce;
                char pow_hash[129];
                
                calculate_ledger_pow(last_entry.pow_hash, padded_data, difficulty, num_threads, &nonce, pow_hash);
                
                entry.nonce = nonce;
                strncpy(entry.pow_hash, pow_hash, 128);
                entry.pow_hash[128] = '\0';
                
                append_ledger_entry(ledger_file, &entry);
                
                double elapsed = current_time() - start_time;
                printf("POW completed (nonce: %lu, time: %.2fs)\n", nonce, elapsed);
                
                print_progress(files[i].filepath, i + 1, file_count, elapsed);
                
                last_entry = entry;
            }
            
            printf("\nLedger update completed. %d files processed.\n", file_count);
            free(files);
            break;
            
        case MODE_VERIFY:
            if (!ledger_file) {
                fprintf(stderr, "Error: Verify mode requires ledger file\n");
                return 1;
            }
            
            return run_ledger_verification(ledger_file, file_verify, ignore_errors);
            
        default:
            fprintf(stderr, "Error: Invalid mode\n");
            return 1;
    }
    
    return 0;
}
