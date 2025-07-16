#ifndef LEDGER_H
#define LEDGER_H

#include "common.h"

/* Ledger I/O functions */
int read_last_ledger_entry(const char *filename, ledger_entry_t *entry);
int write_ledger_header(const char *filename);
int append_ledger_entry(const char *filename, const ledger_entry_t *entry);
int read_all_ledger_entries(const char *filename, ledger_entry_t **entries, int *count);

/* Ledger creation functions */
void create_null_entry(ledger_entry_t *entry);
void create_start_entry(ledger_entry_t *entry, const char *start_hash);

/* Ledger verification */
int run_ledger_verification(const char *filename, int file_verify, int ignore_errors);

/* Display functions */
void print_progress(int current, int total, const char *filename, double elapsed_time);
void print_verification_stats(const verification_stats_t *stats);

#endif /* LEDGER_H */