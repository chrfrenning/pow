#ifndef COMMON_H
#define COMMON_H
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

/* Constants */
#define HASH_HEX_LEN 128
#define MAX_THREADS 64
#define MAX_PATH_LEN 4096
#define MAX_FILES 10000
#define DEFAULT_THREADS 4
#define DEFAULT_DIFFICULTY 5

/* Enums */
typedef enum {
    ALGO_MD5,
    ALGO_MD5D,
    ALGO_SHA256,
    ALGO_SHA256D,
    ALGO_SHA512,
    ALGO_SHA512D
} hash_algorithm_t;

/* Common data structures */
typedef struct {
    char previous_entry[HASH_HEX_LEN + 1];
    char current_entry[HASH_HEX_LEN + 1];
    int difficulty;
    int thread_id;
    int num_threads;
    hash_algorithm_t algorithm;
    char salt[33];
} thread_args_t;

typedef struct {
    atomic_int found;
    char result_hash[HASH_HEX_LEN + 1];
    uint64_t result_nonce;
} pow_result_t;

typedef struct {
    char filepath[MAX_PATH_LEN];
    char md5[33];
    char sha256[65];
    char sha256_double[65];
    char sha512[129];
    char sha512_double[129];
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

/* Global variables */
extern pow_result_t pow_result;

#endif /* COMMON_H */