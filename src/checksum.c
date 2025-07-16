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
    sha512_file(filepath, result->sha512);
    
    if (result->md5[0] == '\0' || result->sha512[0] == '\0') {
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
    sha512_file_with_salt(filepath, salt, computed_checksum);
    
    return strcmp(computed_checksum, expected_checksum) == 0;
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

void print_json_multiple(const file_checksum_t results[], int count) {
    printf("{\n");
    printf("  \"files\": [\n");
    
    for (int i = 0; i < count; i++) {
        printf("    {\n");
        printf("      \"filepath\": \"%s\",\n", results[i].filepath);
        printf("      \"size\": %ld,\n", results[i].size);
        printf("      \"md5\": \"%s\",\n", results[i].md5);
        printf("      \"sha512\": \"%s\",\n", results[i].sha512);
        printf("      \"error\": %s\n", results[i].error ? "true" : "false");
        printf("    }%s\n", (i < count - 1) ? "," : "");
    }
    
    printf("  ],\n");
    printf("  \"total_files\": %d\n", count);
    printf("}\n");
}