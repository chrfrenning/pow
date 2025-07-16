#include "pow.h"
#include "checksum.h"
#include "utils.h"

void *pow_worker(void *arg) {
    thread_args_t *args = (thread_args_t *)arg;
    uint64_t nonce = args->thread_id;
    
    while (atomic_load(&pow_result.found) == 0) {
        char data[512];
        snprintf(data, sizeof(data), "%s%s%lu", args->previous_entry, args->current_entry, nonce);
        
        char hash_hex[129];
        
        /* Select hash algorithm */
        if (args->salt[0] != '\0') {
            /* Hash with salt */
            switch (args->algorithm) {
                case ALGO_MD5:
                    md5_hex_with_salt(data, args->salt, hash_hex);
                    break;
                case ALGO_MD5D:
                    md5_double_hex_with_salt(data, args->salt, hash_hex);
                    break;
                case ALGO_SHA256:
                    sha256_hex_with_salt(data, args->salt, hash_hex);
                    break;
                case ALGO_SHA256D:
                    sha256_double_hex_with_salt(data, args->salt, hash_hex);
                    break;
                case ALGO_SHA512:
                    sha512_hex_with_salt(data, args->salt, hash_hex);
                    break;
                case ALGO_SHA512D:
                    sha512_double_hex_with_salt(data, args->salt, hash_hex);
                    break;
                default:
                    sha512_hex(data, hash_hex);
                    break;
            }
        } else {
            /* Hash without salt */
            switch (args->algorithm) {
                case ALGO_MD5:
                    md5_hex(data, hash_hex);
                    break;
                case ALGO_MD5D:
                    md5_double_hex(data, hash_hex);
                    break;
                case ALGO_SHA256:
                    sha256_hex(data, hash_hex);
                    break;
                case ALGO_SHA256D:
                    sha256_double_hex(data, hash_hex);
                    break;
                case ALGO_SHA512:
                    sha512_hex(data, hash_hex);
                    break;
                case ALGO_SHA512D:
                    sha512_double_hex(data, hash_hex);
                    break;
                default:
                    sha512_hex(data, hash_hex);
                    break;
            }
        }
        
        if (count_leading_zero_bits(hash_hex) >= args->difficulty) {
            int expected = 0;
            if (atomic_compare_exchange_strong(&pow_result.found, &expected, 1)) {
                pow_result.result_nonce = nonce;
                strncpy(pow_result.result_hash, hash_hex, 128);
                pow_result.result_hash[128] = '\0';
                return NULL;
            }
        }
        
        nonce += args->num_threads;
        
        if (nonce % 100000 == 0) {
            if (atomic_load(&pow_result.found) != 0) {
                return NULL;
            }
        }
    }
    
    return NULL;
}

int count_leading_zero_bits(const char *hash_hex) {
    int count = 0;
    for (int i = 0; i < 128; i++) {
        char hex_char = hash_hex[i];
        int hex_value;
        
        if (hex_char >= '0' && hex_char <= '9') {
            hex_value = hex_char - '0';
        } else if (hex_char >= 'a' && hex_char <= 'f') {
            hex_value = hex_char - 'a' + 10;
        } else if (hex_char >= 'A' && hex_char <= 'F') {
            hex_value = hex_char - 'A' + 10;
        } else {
            break;
        }
        
        if (hex_value == 0) {
            count += 4;
        } else if (hex_value < 2) {
            count += 3;
            break;
        } else if (hex_value < 4) {
            count += 2;
            break;
        } else if (hex_value < 8) {
            count += 1;
            break;
        } else {
            break;
        }
    }
    return count;
}

int count_leading_zeros(const char *hash_hex) {
    int count = 0;
    for (int i = 0; i < 128 && hash_hex[i] == '0'; i++) {
        count++;
    }
    return count;
}

int verify_pow_hash(const char *prev_hash, const char *current_data, uint64_t nonce, const char *expected_hash, int complexity) {
    char data[512];
    snprintf(data, sizeof(data), "%s%s%lu", prev_hash, current_data, nonce);
    
    char computed_hash[129];
    sha512_hex(data, computed_hash);
    
    if (strcmp(computed_hash, expected_hash) != 0) {
        return 0;
    }
    
    return count_leading_zero_bits(computed_hash) >= complexity;
}

int calculate_ledger_pow(ledger_entry_t *entry, int difficulty, int num_threads, const char *prev_hash) {
    /* Initialize POW result */
    atomic_store(&pow_result.found, 0);
    pow_result.result_nonce = 0;
    memset(pow_result.result_hash, 0, sizeof(pow_result.result_hash));
    
    /* Prepare current data */
    char current_data[MAX_PATH_LEN + 64 + HASH_HEX_LEN]; // filename + size + checksum + separators
    int ret = snprintf(current_data, sizeof(current_data), "%s_%ld_%s",
                       entry->filename, entry->size, entry->checksum);
    if (ret >= (int)sizeof(current_data) || ret < 0) {
        fprintf(stderr, "Error: Data string too long for buffer\n");
        return -1;
    }
    
    /* Create thread arguments */
    thread_args_t args[MAX_THREADS];
    pthread_t threads[MAX_THREADS];
    
    if (num_threads > MAX_THREADS) {
        num_threads = MAX_THREADS;
    }
    
    /* Hash the current data first */
    char current_hash[129];
    sha512_hex(current_data, current_hash);
    
    for (int t = 0; t < num_threads; t++) {
        memcpy(args[t].previous_entry, prev_hash, HASH_HEX_LEN);
        args[t].previous_entry[HASH_HEX_LEN] = '\0';
        memcpy(args[t].current_entry, current_hash, HASH_HEX_LEN);
        args[t].current_entry[HASH_HEX_LEN] = '\0';
        args[t].difficulty = difficulty;
        args[t].thread_id = t;
        args[t].num_threads = num_threads;
        pthread_create(&threads[t], NULL, pow_worker, &args[t]);
    }
    
    for (int t = 0; t < num_threads; t++) {
        pthread_join(threads[t], NULL);
    }
    
    /* Store results in ledger entry */
    entry->nonce = pow_result.result_nonce;
    strncpy(entry->pow_hash, pow_result.result_hash, 128);
    entry->pow_hash[128] = '\0';
    entry->complexity = difficulty;
    
    return atomic_load(&pow_result.found) ? 0 : -1;
}

int run_pow_mining(const char *prev_hash, const char *next_hash, int difficulty, int num_threads) {
    return run_pow_mining_with_options(prev_hash, next_hash, difficulty, num_threads, ALGO_SHA512, NULL);
}

int run_pow_mining_with_options(const char *prev_hash, const char *next_hash, int difficulty, int num_threads, hash_algorithm_t algorithm, const char *salt) {
    /* Initialize POW result */
    atomic_store(&pow_result.found, 0);
    pow_result.result_nonce = 0;
    memset(pow_result.result_hash, 0, sizeof(pow_result.result_hash));
    
    /* Create thread arguments */
    thread_args_t args[MAX_THREADS];
    pthread_t threads[MAX_THREADS];
    
    if (num_threads > MAX_THREADS) {
        num_threads = MAX_THREADS;
    }
    
    double start_time = current_time();
    
    for (int t = 0; t < num_threads; t++) {
        memcpy(args[t].previous_entry, prev_hash, HASH_HEX_LEN);
        args[t].previous_entry[HASH_HEX_LEN] = '\0';
        memcpy(args[t].current_entry, next_hash, HASH_HEX_LEN);
        args[t].current_entry[HASH_HEX_LEN] = '\0';
        args[t].difficulty = difficulty;
        args[t].thread_id = t;
        args[t].num_threads = num_threads;
        args[t].algorithm = algorithm;
        if (salt) {
            strcpy(args[t].salt, salt);
        } else {
            args[t].salt[0] = '\0';
        }
        pthread_create(&threads[t], NULL, pow_worker, &args[t]);
    }
    
    for (int t = 0; t < num_threads; t++) {
        pthread_join(threads[t], NULL);
    }
    
    double elapsed_time = current_time() - start_time;
    
    /* Get algorithm name for output */
    const char *algo_name;
    switch (algorithm) {
        case ALGO_MD5: algo_name = "md5"; break;
        case ALGO_MD5D: algo_name = "md5d"; break;
        case ALGO_SHA256: algo_name = "sha256"; break;
        case ALGO_SHA256D: algo_name = "sha256d"; break;
        case ALGO_SHA512: algo_name = "sha512"; break;
        case ALGO_SHA512D: algo_name = "sha512d"; break;
        default: algo_name = "unknown"; break;
    }
    
    /* Output JSON result */
    printf("{\n");
    printf("  \"previous_hash\": \"%s\",\n", prev_hash);
    printf("  \"next_hash\": \"%s\",\n", next_hash);
    printf("  \"algorithm\": \"%s\",\n", algo_name);
    if (salt) {
        printf("  \"salt\": \"%s\",\n", salt);
    }
    printf("  \"difficulty\": %d,\n", difficulty);
    printf("  \"threads\": %d,\n", num_threads);
    printf("  \"nonce\": %lu,\n", pow_result.result_nonce);
    printf("  \"result_hash\": \"%s\",\n", pow_result.result_hash);
    printf("  \"time_seconds\": %.6f\n", elapsed_time);
    printf("}\n");
    
    return atomic_load(&pow_result.found) ? 0 : 1;
}

void print_strength_indicator(int complexity) {
    for (int i = 0; i < complexity; i++) {
        printf("✓");
    }
}