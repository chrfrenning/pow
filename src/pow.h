#ifndef POW_H
#define POW_H

#include "common.h"

/* Proof-of-work functions */
void *pow_worker(void *arg);
int count_leading_zero_bits(const char *hash_hex);
int count_leading_zeros(const char *hash_hex);
int verify_pow_hash(const char *prev_hash, const char *current_data, uint64_t nonce, const char *expected_hash, int complexity);
int calculate_ledger_pow(ledger_entry_t *entry, int difficulty, int num_threads, const char *prev_hash);
int run_pow_mining(const char *prev_hash, const char *next_hash, int difficulty, int num_threads);

/* Display functions */
void print_strength_indicator(int complexity);

#endif /* POW_H */