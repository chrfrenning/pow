#include "checksum.h"

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

void sha256_file(const char *filepath, char *output) {
    FILE *file = fopen(filepath, "rb");
    if (!file) {
        output[0] = '\0';
        return;
    }
    
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    
    unsigned char buffer[8192];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        SHA256_Update(&ctx, buffer, bytes);
    }
    fclose(file);
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &ctx);
    
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[64] = '\0';
}

void sha256_double_file(const char *filepath, char *output) {
    FILE *file = fopen(filepath, "rb");
    if (!file) {
        output[0] = '\0';
        return;
    }
    
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    
    unsigned char buffer[8192];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        SHA256_Update(&ctx, buffer, bytes);
    }
    fclose(file);
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &ctx);
    
    /* Apply SHA256 again to the hash */
    SHA256_CTX ctx2;
    SHA256_Init(&ctx2);
    SHA256_Update(&ctx2, hash, SHA256_DIGEST_LENGTH);
    SHA256_Final(hash, &ctx2);
    
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[64] = '\0';
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

void generate_salt_hex(char *salt_hex) {
    generate_salt(salt_hex);
}

void md5_hex(const char *input, char *output) {
    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5((const unsigned char*)input, strlen(input), hash);
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[32] = '\0';
}

void md5_double_hex(const char *input, char *output) {
    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5((const unsigned char*)input, strlen(input), hash);
    
    /* Apply MD5 again to the hash */
    unsigned char hash2[MD5_DIGEST_LENGTH];
    MD5(hash, MD5_DIGEST_LENGTH, hash2);
    
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash2[i]);
    }
    output[32] = '\0';
}

void sha256_hex(const char *input, char *output) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)input, strlen(input), hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[64] = '\0';
}

void sha256_double_hex(const char *input, char *output) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)input, strlen(input), hash);
    
    /* Apply SHA256 again to the hash */
    unsigned char hash2[SHA256_DIGEST_LENGTH];
    SHA256(hash, SHA256_DIGEST_LENGTH, hash2);
    
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash2[i]);
    }
    output[64] = '\0';
}

void sha512_double_hex(const char *input, char *output) {
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512((const unsigned char*)input, strlen(input), hash);
    
    /* Apply SHA512 again to the hash */
    unsigned char hash2[SHA512_DIGEST_LENGTH];
    SHA512(hash, SHA512_DIGEST_LENGTH, hash2);
    
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash2[i]);
    }
    output[HASH_HEX_LEN] = '\0';
}

void md5_hex_with_salt(const char *input, const char *salt, char *output) {
    size_t salt_len = strlen(salt);
    size_t input_len = strlen(input);
    char *salted_input = malloc(salt_len + input_len + 1);
    
    strcpy(salted_input, salt);
    strcat(salted_input, input);
    
    md5_hex(salted_input, output);
    free(salted_input);
}

void md5_double_hex_with_salt(const char *input, const char *salt, char *output) {
    size_t salt_len = strlen(salt);
    size_t input_len = strlen(input);
    char *salted_input = malloc(salt_len + input_len + 1);
    
    strcpy(salted_input, salt);
    strcat(salted_input, input);
    
    md5_double_hex(salted_input, output);
    free(salted_input);
}

void sha256_hex_with_salt(const char *input, const char *salt, char *output) {
    size_t salt_len = strlen(salt);
    size_t input_len = strlen(input);
    char *salted_input = malloc(salt_len + input_len + 1);
    
    strcpy(salted_input, salt);
    strcat(salted_input, input);
    
    sha256_hex(salted_input, output);
    free(salted_input);
}

void sha256_double_hex_with_salt(const char *input, const char *salt, char *output) {
    size_t salt_len = strlen(salt);
    size_t input_len = strlen(input);
    char *salted_input = malloc(salt_len + input_len + 1);
    
    strcpy(salted_input, salt);
    strcat(salted_input, input);
    
    sha256_double_hex(salted_input, output);
    free(salted_input);
}

void sha512_hex_with_salt(const char *input, const char *salt, char *output) {
    size_t salt_len = strlen(salt);
    size_t input_len = strlen(input);
    char *salted_input = malloc(salt_len + input_len + 1);
    
    strcpy(salted_input, salt);
    strcat(salted_input, input);
    
    sha512_hex(salted_input, output);
    free(salted_input);
}

void sha512_double_hex_with_salt(const char *input, const char *salt, char *output) {
    size_t salt_len = strlen(salt);
    size_t input_len = strlen(input);
    char *salted_input = malloc(salt_len + input_len + 1);
    
    strcpy(salted_input, salt);
    strcat(salted_input, input);
    
    sha512_double_hex(salted_input, output);
    free(salted_input);
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
    output[HASH_HEX_LEN] = '\0';
}

void sha512_double_file(const char *filepath, char *output) {
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
    
    /* Apply SHA512 again to the hash */
    SHA512_CTX ctx2;
    SHA512_Init(&ctx2);
    SHA512_Update(&ctx2, hash, SHA512_DIGEST_LENGTH);
    SHA512_Final(hash, &ctx2);
    
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[HASH_HEX_LEN] = '\0';
}

void sha512_file_with_salt(const char *filepath, const char *salt, char *output) {
    FILE *file = fopen(filepath, "rb");
    if (!file) {
        output[0] = '\0';
        return;
    }
    
    SHA512_CTX ctx;
    SHA512_Init(&ctx);
    
    /* Update with salt first */
    SHA512_Update(&ctx, salt, strlen(salt));
    
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
    output[HASH_HEX_LEN] = '\0';
}

void sha512_double_file_with_salt(const char *filepath, const char *salt, char *output) {
    FILE *file = fopen(filepath, "rb");
    if (!file) {
        output[0] = '\0';
        return;
    }
    
    SHA512_CTX ctx;
    SHA512_Init(&ctx);
    
    /* Update with salt first */
    SHA512_Update(&ctx, salt, strlen(salt));
    
    unsigned char buffer[8192];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        SHA512_Update(&ctx, buffer, bytes);
    }
    fclose(file);
    
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512_Final(hash, &ctx);
    
    /* Apply SHA512 again to the hash */
    SHA512_CTX ctx2;
    SHA512_Init(&ctx2);
    SHA512_Update(&ctx2, hash, SHA512_DIGEST_LENGTH);
    SHA512_Final(hash, &ctx2);
    
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[HASH_HEX_LEN] = '\0';
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

int process_file(const char *filepath, file_checksum_t *result) {
    strncpy(result->filepath, filepath, MAX_PATH_LEN - 1);
    result->filepath[MAX_PATH_LEN - 1] = '\0';
    
    result->size = get_file_size(filepath);
    if (result->size == -1) {
        result->error = 1;
        return -1;
    }
    
    md5_file(filepath, result->md5);
    sha256_file(filepath, result->sha256);
    sha256_double_file(filepath, result->sha256_double);
    sha512_file(filepath, result->sha512);
    sha512_double_file(filepath, result->sha512_double);
    
    if (result->md5[0] == '\0' || result->sha256[0] == '\0' || result->sha256_double[0] == '\0' || 
        result->sha512[0] == '\0' || result->sha512_double[0] == '\0') {
        result->error = 1;
        return -1;
    }
    
    result->error = 0;
    return 0;
}

int scan_directory(const char *dirpath, int recursive, file_checksum_t results[], int max_files) {
    DIR *dir = opendir(dirpath);
    if (!dir) {
        return -1;
    }
    
    struct dirent *entry;
    int count = 0;
    
    while ((entry = readdir(dir)) != NULL && count < max_files) {
        if (entry->d_name[0] == '.') {
            continue;
        }
        
        char fullpath[MAX_PATH_LEN];
        int ret = snprintf(fullpath, sizeof(fullpath), "%s%c%s", dirpath, PATH_SEPARATOR, entry->d_name);
        if (ret >= (int)sizeof(fullpath)) {
            continue;
        }
        
        if (is_regular_file(fullpath)) {
            if (process_file(fullpath, &results[count]) == 0) {
                count++;
            }
        } else if (recursive && is_directory(fullpath)) {
            int subcount = scan_directory(fullpath, recursive, &results[count], max_files - count);
            if (subcount > 0) {
                count += subcount;
            }
        }
    }
    
    closedir(dir);
    return count;
}

int verify_file_checksum_with_salt(const char *filepath, const char *expected_checksum, const char *salt) {
    char computed_checksum[129];
    sha512_double_file_with_salt(filepath, salt, computed_checksum);
    
    return strcmp(computed_checksum, expected_checksum) == 0;
}

void print_json_single(const file_checksum_t *result) {
    printf("{\n");
    printf("  \"filepath\": \"%s\",\n", result->filepath);
    printf("  \"size\": %ld,\n", result->size);
    printf("  \"md5\": \"%s\",\n", result->md5);
    printf("  \"sha256\": \"%s\",\n", result->sha256);
    printf("  \"sha256_double\": \"%s\",\n", result->sha256_double);
    printf("  \"sha512\": \"%s\",\n", result->sha512);
    printf("  \"sha512_double\": \"%s\"", result->sha512_double);
    if (result->error) {
        printf(",\n  \"error\": true");
    }
    printf("\n");
    printf("}\n");
}

void print_json_multiple(const file_checksum_t results[], int count) {
    printf("{\n");
    printf("  \"files\": [\n");
    
    for (int i = 0; i < count; i++) {
        printf("    {\n");
        printf("      \"filepath\": \"%s\",\n", results[i].filepath);
        printf("      \"size\": %ld,\n", results[i].size);
        printf("      \"md5\": \"%s\",\n", results[i].md5);
        printf("      \"sha256\": \"%s\",\n", results[i].sha256);
        printf("      \"sha256_double\": \"%s\",\n", results[i].sha256_double);
        printf("      \"sha512\": \"%s\",\n", results[i].sha512);
        printf("      \"sha512_double\": \"%s\"", results[i].sha512_double);
        if (results[i].error) {
            printf(",\n      \"error\": true");
        }
        printf("\n");
        printf("    }%s\n", (i < count - 1) ? "," : "");
    }
    
    printf("  ],\n");
    printf("  \"total_files\": %d\n", count);
    printf("}\n");
}