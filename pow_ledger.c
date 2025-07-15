#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <time.h>
#include <unistd.h>
#include <stdatomic.h>
#include <sys/stat.h>
#include <dirent.h>
#include <getopt.h>
#include <errno.h>

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

typedef enum {
    MODE_NONE,
    MODE_POW,
    MODE_CHECKSUM
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

void print_usage(const char *program_name) {
    printf("Usage: %s <MODE> [OPTIONS]\n", program_name);
    printf("\nModes (required):\n");
    printf("  -p, --pow <prev_hash> <next_hash>  Run proof-of-work mining\n");
    printf("  -c, --checksum <path>              Generate file checksums\n");
    printf("\nPOW Mode Options:\n");
    printf("  -t, --threads <num>                Number of threads (default: %d)\n", DEFAULT_THREADS);
    printf("  -x, --complexity <num>             Difficulty level (default: %d)\n", DEFAULT_DIFFICULTY);
    printf("\nChecksum Mode Options:\n");
    printf("  -r, --recursive                    Include subdirectories (default: off)\n");
    printf("\nGeneral:\n");
    printf("  -h, --help                         Show this help message\n");
    printf("\nExamples:\n");
    printf("  %s -p prev_hash next_hash -t 8 -x 6\n", program_name);
    printf("  %s -c myfile.txt\n", program_name);
    printf("  %s -c /path/to/directory\n", program_name);
    printf("  %s -c /path/to/directory -r\n", program_name);
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
    int num_threads = DEFAULT_THREADS;
    int difficulty = DEFAULT_DIFFICULTY;
    int recursive = 0;
    
    struct option long_options[] = {
        {"pow", required_argument, 0, 'p'},
        {"checksum", required_argument, 0, 'c'},
        {"threads", required_argument, 0, 't'},
        {"complexity", required_argument, 0, 'x'},
        {"recursive", no_argument, 0, 'r'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "p:c:t:x:rh", long_options, NULL)) != -1) {
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
            case 't':
                num_threads = atoi(optarg);
                break;
            case 'x':
                difficulty = atoi(optarg);
                break;
            case 'r':
                recursive = 1;
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
            
        default:
            fprintf(stderr, "Error: Invalid mode\n");
            return 1;
    }
    
    return 0;
}
