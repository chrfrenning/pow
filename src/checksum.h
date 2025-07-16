#ifndef CHECKSUM_H
#define CHECKSUM_H

#include "common.h"

/* Cryptographic hash functions */
void sha512_hex(const char *input, char *output);
void md5_file(const char *filepath, char *output);
void sha256_file(const char *filepath, char *output);
void sha256_double_file(const char *filepath, char *output);
void sha512_file(const char *filepath, char *output);
void sha512_double_file(const char *filepath, char *output);
void sha512_file_with_salt(const char *filepath, const char *salt, char *output);
void sha512_double_file_with_salt(const char *filepath, const char *salt, char *output);
void generate_salt(char *salt_hex);
void generate_salt_hex(char *salt_hex);
void md5_hex(const char *input, char *output);
void md5_double_hex(const char *input, char *output);
void sha256_hex(const char *input, char *output);
void sha256_double_hex(const char *input, char *output);
void sha512_double_hex(const char *input, char *output);
void md5_hex_with_salt(const char *input, const char *salt, char *output);
void md5_double_hex_with_salt(const char *input, const char *salt, char *output);
void sha256_hex_with_salt(const char *input, const char *salt, char *output);
void sha256_double_hex_with_salt(const char *input, const char *salt, char *output);
void sha512_hex_with_salt(const char *input, const char *salt, char *output);
void sha512_double_hex_with_salt(const char *input, const char *salt, char *output);

/* File operations */
long get_file_size(const char *filepath);
int is_regular_file(const char *filepath);
int is_directory(const char *filepath);
int process_file(const char *filepath, file_checksum_t *result);
int scan_directory(const char *dirpath, int recursive, file_checksum_t results[], int max_files);

/* Verification functions */
int verify_file_checksum_with_salt(const char *filepath, const char *expected_checksum, const char *salt);

/* Output functions */
void print_json_single(const file_checksum_t *result);
void print_json_multiple(const file_checksum_t results[], int count);

#endif /* CHECKSUM_H */