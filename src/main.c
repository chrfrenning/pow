#include "common.h"
#include "checksum.h"
#include "pow.h"
#include "ledger.h"
#include "utils.h"

/* Global variables */
pow_result_t pow_result = {0};

int main(int argc, char *argv[]) {
    
    int opt;
    operation_mode_t mode = MODE_NONE;
    char *ledger_file = NULL;
    char *source_path = NULL;
    char *prev_hash = NULL;
    char *next_hash = NULL;
    char *start_hash = NULL;
    int threads = DEFAULT_THREADS;
    int difficulty = DEFAULT_DIFFICULTY;
    int recursive = 0;
    int file_verify = 0;
    int ignore_errors = 0;
    hash_algorithm_t algorithm = ALGO_SHA512;
    char *salt = NULL;
    char *use_salt = NULL;
    int generate_salt_flag = 0;
    
    static struct option long_options[] = {
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
        {"algorithm", required_argument, 0, 'a'},
        {"salt", no_argument, 0, 1000},
        {"use-salt", required_argument, 0, 1001},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "p:c:l:v:t:x:rfis:a:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'p':
                if (mode != MODE_NONE) {
                    fprintf(stderr, "Error: Only one mode can be specified\n");
                    return 1;
                }
                mode = MODE_POW;
                prev_hash = optarg;
                break;
            case 'c':
                if (mode != MODE_NONE) {
                    fprintf(stderr, "Error: Only one mode can be specified\n");
                    return 1;
                }
                mode = MODE_CHECKSUM;
                source_path = optarg;
                break;
            case 'l':
                if (mode != MODE_NONE) {
                    fprintf(stderr, "Error: Only one mode can be specified\n");
                    return 1;
                }
                mode = MODE_LEDGER;
                ledger_file = optarg;
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
                threads = atoi(optarg);
                if (threads < 1 || threads > MAX_THREADS) {
                    fprintf(stderr, "Error: Number of threads must be between 1 and %d\n", MAX_THREADS);
                    return 1;
                }
                break;
            case 'x':
                difficulty = atoi(optarg);
                if (difficulty < 1 || difficulty > 512) {
                    fprintf(stderr, "Error: Difficulty must be between 1 and 512 bits\n");
                    return 1;
                }
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
                if (strlen(start_hash) != HASH_HEX_LEN) {
                    fprintf(stderr, "Error: Start hash must be %d characters long\n", HASH_HEX_LEN);
                    return 1;
                }
                break;
            case 'a':
                if (strcmp(optarg, "md5") == 0) {
                    algorithm = ALGO_MD5;
                } else if (strcmp(optarg, "md5d") == 0) {
                    algorithm = ALGO_MD5D;
                } else if (strcmp(optarg, "sha256") == 0) {
                    algorithm = ALGO_SHA256;
                } else if (strcmp(optarg, "sha256d") == 0) {
                    algorithm = ALGO_SHA256D;
                } else if (strcmp(optarg, "sha512") == 0) {
                    algorithm = ALGO_SHA512;
                } else if (strcmp(optarg, "sha512d") == 0) {
                    algorithm = ALGO_SHA512D;
                } else {
                    fprintf(stderr, "Error: Invalid algorithm. Supported: md5, md5d, sha256, sha256d, sha512, sha512d\n");
                    return 1;
                }
                break;
            case 1000: /* --salt */
                generate_salt_flag = 1;
                break;
            case 1001: /* --use-salt */
                use_salt = optarg;
                if (strlen(use_salt) != 32) {
                    fprintf(stderr, "Error: Salt must be 32 characters long\n");
                    return 1;
                }
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

    /* Mode-specific argument validation and execution */
    switch (mode) {
        case MODE_POW:
            if (optind >= argc) {
                fprintf(stderr, "Error: POW mode requires two hash arguments\n");
                return 1;
            }
            next_hash = argv[optind];
            
            if (strlen(prev_hash) != HASH_HEX_LEN || strlen(next_hash) != HASH_HEX_LEN) {
                fprintf(stderr, "Error: Hash values must be %d characters long\n", HASH_HEX_LEN);
                return 1;
            }
            
            /* Handle salt generation and validation */
            if (generate_salt_flag && use_salt) {
                fprintf(stderr, "Error: Cannot specify both --salt and --use-salt\n");
                return 1;
            }
            
            char salt_buffer[33];
            if (generate_salt_flag) {
                generate_salt_hex(salt_buffer);
                salt = salt_buffer;
            } else if (use_salt) {
                salt = use_salt;
            } else {
                salt = NULL;
            }
            
            return run_pow_mining_with_options(prev_hash, next_hash, difficulty, threads, algorithm, salt);

        case MODE_CHECKSUM:
            if (!source_path) {
                fprintf(stderr, "Error: Checksum mode requires a file or directory path\n");
                return 1;
            }
            
            if (is_regular_file(source_path)) {
                file_checksum_t result;
                if (process_file(source_path, &result) == 0) {
                    print_json_single(&result);
                    return 0;
                } else {
                    fprintf(stderr, "Error: Cannot process file '%s'\n", source_path);
                    return 1;
                }
            } else if (is_directory(source_path)) {
                file_checksum_t *results = malloc(MAX_FILES * sizeof(file_checksum_t));
                if (!results) {
                    fprintf(stderr, "Error: Memory allocation failed\n");
                    return 1;
                }
                int count = scan_directory(source_path, recursive, results, MAX_FILES);
                if (count >= 0) {
                    print_json_multiple(results, count);
                    free(results);
                    return 0;
                } else {
                    fprintf(stderr, "Error: Cannot read directory '%s'\n", source_path);
                    free(results);
                    return 1;
                }
            } else {
                fprintf(stderr, "Error: '%s' is not a valid file or directory\n", source_path);
                return 1;
            }

        case MODE_LEDGER:
            if (optind >= argc) {
                fprintf(stderr, "Error: Ledger mode requires ledger file and source path\n");
                return 1;
            }
            source_path = argv[optind];
            
            if (start_hash) {
                FILE *test_file = fopen(ledger_file, "r");
                if (test_file) {
                    fclose(test_file);
                    fprintf(stderr, "Error: Ledger file '%s' already exists. Start hash can only be used with new ledger files\n", ledger_file);
                    return 1;
                }
            }
            
            /* Create ledger header if file doesn't exist */
            FILE *ledger_test = fopen(ledger_file, "r");
            if (!ledger_test) {
                if (write_ledger_header(ledger_file) != 0) {
                    fprintf(stderr, "Error: Cannot create ledger file '%s'\n", ledger_file);
                    return 1;
                }
                
                /* Create initial entry */
                ledger_entry_t initial_entry;
                if (start_hash) {
                    create_start_entry(&initial_entry, start_hash);
                    printf("Created new ledger with START entry using provided hash\n");
                } else {
                    create_null_entry(&initial_entry);
                    printf("Created new ledger with NULL entry\n");
                }
                
                if (append_ledger_entry(ledger_file, &initial_entry) != 0) {
                    fprintf(stderr, "Error: Cannot append to ledger file '%s'\n", ledger_file);
                    return 1;
                }
            } else {
                fclose(ledger_test);
                if (start_hash) {
                    fprintf(stderr, "Error: Cannot use start hash with existing ledger file\n");
                    return 1;
                }
            }
            
            /* Process files */
            if (is_regular_file(source_path)) {
                file_checksum_t result;
                if (process_file(source_path, &result) == 0) {
                    printf("Processing 1 files into ledger...\n");
                    
                    /* Read last ledger entry */
                    ledger_entry_t last_entry;
                    if (read_last_ledger_entry(ledger_file, &last_entry) != 0) {
                        fprintf(stderr, "Error: Cannot read ledger file '%s'\n", ledger_file);
                        return 1;
                    }
                    
                    /* Create new ledger entry */
                    ledger_entry_t new_entry;
                    strcpy(new_entry.filename, result.filepath);
                    new_entry.size = result.size;
                    
                    /* Generate salt and salted checksum */
                    generate_salt(new_entry.salt);
                    sha512_double_file_with_salt(result.filepath, new_entry.salt, new_entry.checksum);
                    
                    /* Calculate POW */
                    printf("Processing file: %s ... ", result.filepath);
                    fflush(stdout);
                    
                    double start_time = current_time();
                    if (calculate_ledger_pow(&new_entry, difficulty, threads, last_entry.pow_hash) == 0) {
                        double elapsed = current_time() - start_time;
                        printf("POW completed (nonce: %lu, time: %.2fs)\n", new_entry.nonce, elapsed);
                        
                        /* Append to ledger */
                        if (append_ledger_entry(ledger_file, &new_entry) == 0) {
                            print_progress(1, 1, result.filepath, elapsed);
                            printf("\nLedger update completed. 1 files processed.\n");
                            return 0;
                        } else {
                            fprintf(stderr, "Error: Cannot append to ledger file '%s'\n", ledger_file);
                            return 1;
                        }
                    } else {
                        fprintf(stderr, "Error: POW calculation failed\n");
                        return 1;
                    }
                } else {
                    fprintf(stderr, "Error: Cannot process file '%s'\n", source_path);
                    return 1;
                }
            } else if (is_directory(source_path)) {
                file_checksum_t *results = malloc(MAX_FILES * sizeof(file_checksum_t));
                if (!results) {
                    fprintf(stderr, "Error: Memory allocation failed\n");
                    return 1;
                }
                int count = scan_directory(source_path, recursive, results, MAX_FILES);
                if (count > 0) {
                    printf("Processing %d files into ledger...\n", count);
                    
                    /* Read last ledger entry */
                    ledger_entry_t last_entry;
                    if (read_last_ledger_entry(ledger_file, &last_entry) != 0) {
                        fprintf(stderr, "Error: Cannot read ledger file '%s'\n", ledger_file);
                        free(results);
                        return 1;
                    }
                    
                    /* Process each file */
                    for (int i = 0; i < count; i++) {
                        if (results[i].error) {
                            fprintf(stderr, "Skipping file with error: %s\n", results[i].filepath);
                            continue;
                        }
                        
                        /* Create new ledger entry */
                        ledger_entry_t new_entry;
                        strcpy(new_entry.filename, results[i].filepath);
                        new_entry.size = results[i].size;
                        
                        /* Generate salt and salted checksum */
                        generate_salt(new_entry.salt);
                        sha512_double_file_with_salt(results[i].filepath, new_entry.salt, new_entry.checksum);
                        
                        /* Calculate POW */
                        printf("Processing file: %s ... ", results[i].filepath);
                        fflush(stdout);
                        
                        double start_time = current_time();
                        if (calculate_ledger_pow(&new_entry, difficulty, threads, last_entry.pow_hash) == 0) {
                            double elapsed = current_time() - start_time;
                            printf("POW completed (nonce: %lu, time: %.2fs)\n", new_entry.nonce, elapsed);
                            
                            /* Append to ledger */
                            if (append_ledger_entry(ledger_file, &new_entry) == 0) {
                                print_progress(i + 1, count, results[i].filepath, elapsed);
                            } else {
                                fprintf(stderr, "Error: Cannot append to ledger file '%s'\n", ledger_file);
                                free(results);
                                return 1;
                            }
                        } else {
                            fprintf(stderr, "Error: POW calculation failed for '%s'\n", results[i].filepath);
                            free(results);
                            return 1;
                        }
                    }
                    
                    printf("\nLedger update completed. %d files processed.\n", count);
                    free(results);
                    return 0;
                } else {
                    fprintf(stderr, "Error: Cannot process directory '%s'\n", source_path);
                    free(results);
                    return 1;
                }
            } else {
                fprintf(stderr, "Error: '%s' is not a valid file or directory\n", source_path);
                return 1;
            }

        case MODE_VERIFY:
            if (!ledger_file) {
                fprintf(stderr, "Error: Verify mode requires ledger file\n");
                return 1;
            }
            
            return run_ledger_verification(ledger_file, file_verify, ignore_errors);

        default:
            fprintf(stderr, "Error: Unknown mode\n");
            return 1;
    }
}