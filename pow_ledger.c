#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <openssl/sha.h>
#include <time.h>
#include <unistd.h>
#include <stdatomic.h>

#define HASH_HEX_LEN 128
#define MAX_THREADS 64

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

pow_result_t pow_result;

void sha512_hex(const char *input, char *output) {
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512((const unsigned char*)input, strlen(input), hash);
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[HASH_HEX_LEN] = '\0';
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

int main() {
    const int difficulty = 5;
    const int num_threads = 24;

    char previous[HASH_HEX_LEN + 1];
    memset(previous, '0', HASH_HEX_LEN);
    previous[HASH_HEX_LEN] = '\0';

    srand(time(NULL));
    double total_time = 0.0;

    for (int i = 1; i <= 128; i++) {
        char current[HASH_HEX_LEN + 1];
        for (int j = 0; j < HASH_HEX_LEN / 2; j++) {
            sprintf(current + j * 2, "%02x", rand() % 256);
        }

        atomic_store(&pow_result.found, 0);
        pow_result.result_nonce = 0;

        pthread_t threads[MAX_THREADS];
        thread_args_t args[MAX_THREADS];

        double start = current_time();
        for (int t = 0; t < num_threads; t++) {
            strncpy(args[t].previous_entry, previous, HASH_HEX_LEN + 1);
            strncpy(args[t].current_entry, current, HASH_HEX_LEN + 1);
            args[t].difficulty = difficulty;
            args[t].thread_id = t;
            args[t].num_threads = num_threads;
            pthread_create(&threads[t], NULL, pow_worker, &args[t]);
        }

        for (int t = 0; t < num_threads; t++) {
            pthread_join(threads[t], NULL);
        }

        double elapsed = current_time() - start;
        printf("%3d | Nonce: %-10lu | Hash: %.20s... | Time: %.4fs\n", i, pow_result.result_nonce, pow_result.result_hash, elapsed);

        strncpy(previous, pow_result.result_hash, HASH_HEX_LEN + 1);
        total_time += elapsed;
    }

    printf("\nAverage time per operation: %.4fs\n", total_time / 128.0);
    return 0;
}
