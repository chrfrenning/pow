#include "ledger.h"
#include "checksum.h"
#include "pow.h"
#include "utils.h"

int read_last_ledger_entry(const char *filename, ledger_entry_t *entry) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        return -1;
    }
    
    char line[2048];
    int found = 0;
    
    while (fgets(line, sizeof(line), file)) {
        if (line[0] == '#' || strlen(line) < 10 || strstr(line, "filename,size,checksum") != NULL) {
            continue;
        }
        
        char *line_copy = strdup(line);
        if (!line_copy) continue;
        
        char *token = strtok(line_copy, ",");
        if (!token) { free(line_copy); continue; }
        strncpy(entry->filename, token, MAX_PATH_LEN - 1);
        
        token = strtok(NULL, ",");
        if (!token) { free(line_copy); continue; }
        entry->size = atol(token);
        
        token = strtok(NULL, ",");
        if (!token) { free(line_copy); continue; }
        strncpy(entry->checksum, token, 128);
        entry->checksum[128] = '\0';
        
        token = strtok(NULL, ",");
        if (!token) { free(line_copy); continue; }
        strncpy(entry->salt, token, 32);
        entry->salt[32] = '\0';
        
        token = strtok(NULL, ",");
        if (!token) { free(line_copy); continue; }
        entry->nonce = strtoull(token, NULL, 10);
        
        token = strtok(NULL, ",");
        if (!token) { free(line_copy); continue; }
        strncpy(entry->pow_hash, token, 128);
        entry->pow_hash[128] = '\0';
        
        token = strtok(NULL, ",");
        if (!token) { free(line_copy); continue; }
        entry->complexity = atoi(token);
        
        free(line_copy);
        found = 1;
    }
    
    fclose(file);
    return found ? 0 : -1;
}

int write_ledger_header(const char *filename) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        return -1;
    }
    
    fprintf(file, "# ZenTransfer Ledger version 1.0\n");
    fprintf(file, "filename,size,checksum,salt,nonce,pow_hash,complexity\n");
    
    fclose(file);
    return 0;
}

int append_ledger_entry(const char *filename, const ledger_entry_t *entry) {
    FILE *file = fopen(filename, "a");
    if (!file) {
        return -1;
    }
    
    fprintf(file, "%s,%ld,%s,%s,%lu,%s,%d\n",
            entry->filename, entry->size, entry->checksum,
            entry->salt, entry->nonce, entry->pow_hash, entry->complexity);
    
    fclose(file);
    return 0;
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

void create_null_entry(ledger_entry_t *entry) {
    strcpy(entry->filename, "NULL");
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
    strcpy(entry->filename, "START");
    entry->size = 0;
    strncpy(entry->checksum, start_hash, 128);
    entry->checksum[128] = '\0';
    memset(entry->salt, '0', 32);
    entry->salt[32] = '\0';
    entry->nonce = 0;
    memset(entry->pow_hash, '0', 128);
    entry->pow_hash[128] = '\0';
    entry->complexity = 0;
}

void print_progress(int current, int total, const char *filename, double elapsed_time) {
    printf("[%d/%d] Processing: %s (%.2fs)\n", current, total, filename, elapsed_time);
    fflush(stdout);
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
    if (stats->chain_breaks > 0) {
        printf("Chain breaks: %d\n", stats->chain_breaks);
    }
    if (stats->pow_failures > 0) {
        printf("POW verification failures: %d\n", stats->pow_failures);
    }
    if (stats->complexity_failures > 0) {
        printf("Complexity verification failures: %d\n", stats->complexity_failures);
    }
    
    printf("\n");
    if (stats->failed_entries == 0) {
        printf("✓ Ledger verification PASSED\n");
    } else {
        printf("✗ Ledger verification FAILED\n");
    }
}

int run_ledger_verification(const char *filename, int file_verify, int ignore_errors) {
    ledger_entry_t *entries;
    int count;
    
    if (read_all_ledger_entries(filename, &entries, &count) != 0) {
        fprintf(stderr, "Error: Cannot read ledger file '%s'\n", filename);
        return 1;
    }
    
    if (count == 0) {
        fprintf(stderr, "Error: Empty ledger file\n");
        free(entries);
        return 1;
    }
    
    printf("Verifying ledger '%s' with %d entries...\n", filename, count);
    
    verification_stats_t stats = {0};
    stats.total_entries = count;
    
    for (int i = 0; i < count; i++) {
        printf("[%d/%d] Verifying: %s ... ", i + 1, count, entries[i].filename);
        fflush(stdout);
        
        int entry_failed = 0;
        
        /* Check for NULL entry */
        if (strcmp(entries[i].filename, "NULL") == 0) {
            printf("NULL ENTRY OK");
            print_strength_indicator(0);
            printf(" \n");
            stats.verified_entries++;
            continue;
        }
        
        /* Verify POW hash */
        char current_data[256];
        snprintf(current_data, sizeof(current_data), "%s_%ld_%s",
                 entries[i].filename, entries[i].size, entries[i].checksum);
        
        char prev_hash[129];
        if (i == 0) {
            memset(prev_hash, '0', 128);
            prev_hash[128] = '\0';
        } else {
            strncpy(prev_hash, entries[i-1].pow_hash, 128);
            prev_hash[128] = '\0';
        }
        
        if (verify_pow_hash(prev_hash, current_data, entries[i].nonce, entries[i].pow_hash, entries[i].complexity)) {
            printf("POW OK");
            
            /* Check complexity */
            int actual_complexity = count_leading_zero_bits(entries[i].pow_hash);
            if (actual_complexity >= entries[i].complexity) {
                printf(", COMPLEXITY OK");
                print_strength_indicator(entries[i].complexity);
            } else {
                printf(", COMPLEXITY FAILED (expected: %d bits, actual: %d bits)", entries[i].complexity, actual_complexity);
                stats.complexity_failures++;
                entry_failed = 1;
            }
            
            /* Verify file checksum if requested */
            if (file_verify) {
                if (is_regular_file(entries[i].filename)) {
                    if (verify_file_checksum_with_salt(entries[i].filename, entries[i].checksum, entries[i].salt)) {
                        printf(", FILE OK");
                    } else {
                        printf(", FILE MISMATCH");
                        stats.file_mismatch++;
                        entry_failed = 1;
                    }
                } else {
                    printf(", FILE MISSING");
                    stats.missing_files++;
                    entry_failed = 1;
                }
            }
            
            printf(" - %s\n", entry_failed ? "FAILED" : "PASSED");
            
        } else {
            printf("POW FAILED\n");
            stats.pow_failures++;
            entry_failed = 1;
        }
        
        if (entry_failed) {
            stats.failed_entries++;
            if (!ignore_errors) {
                printf("\nVerification stopped due to error (use -i to continue)\n");
                free(entries);
                return 1;
            }
        } else {
            stats.verified_entries++;
        }
    }
    
    print_verification_stats(&stats);
    free(entries);
    
    return stats.failed_entries > 0 ? 1 : 0;
}