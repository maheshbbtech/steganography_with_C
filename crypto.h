#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Derives a 256-bit key (32 bytes) from the password using SHA-256.
void derive_key(const char *password, unsigned char *key);

// Encrypts plaintext using AES-256-CBC with PKCS#7 padding.
// Returns the length of the ciphertext.
// ciphertext is allocated by this function and must be freed by caller.
int encrypt_aes256(const char *plaintext, int len, const unsigned char *key, unsigned char **ciphertext);

// Decrypts ciphertext using AES-256-CBC with PKCS#7 padding.
// Returns a pointer to the null-terminated plaintext.
// plaintext is allocated by this function and must be freed by caller.
// Returns NULL on failure.
char *decrypt_aes256(const unsigned char *ciphertext, int len, const unsigned char *key);

#endif
