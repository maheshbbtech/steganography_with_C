#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "limits.h"
#include "error.h"
#include "stegno_interface.h"


char* encrypt_pass(const char* password) {
    const char *xor_key = "maheshbaero";
    const char *and_key = "Knight64";
    const char *or_key  = "VishyAnand";

    size_t pass_len = strlen(password);
    size_t max_len = 16;  // Limit key to 16 characters

    // Allocate memory for encrypted key (plus null terminator)
    char *encrypted = (char *)malloc(max_len + 1);
    if (encrypted == NULL) return NULL;

    for (size_t i = 0; i < max_len; ++i) {
        unsigned char ch = (i < pass_len) ? password[i] : 0;

        // Step 1: XOR with "maheshbaero"
        if (i < strlen(xor_key))
            ch ^= xor_key[i];

        // Step 2: AND with "Knight64"
        if (i < strlen(and_key))
            ch &= and_key[i];

        // Step 3: OR with "VishyAnand"
        if (i < strlen(or_key))
            ch |= or_key[i];

        encrypted[i] = ch;
    }

    encrypted[max_len] = '\0';  // Null terminate
    return encrypted;
}

char* encrypt_msg(FILE *txt_file, const char *key) {
    if (!txt_file || !key) return NULL;

    const char *xor_string = "ababababaa";
    size_t key_len = strlen(key);
    size_t xor_len = strlen(xor_string);

    size_t max_len = 1024U * 10U;
    char *gibrish = (char *)malloc(max_len);
    if (!gibrish) return NULL;

    size_t i = 0;
    int ch;
    while ((ch = fgetc(txt_file)) != EOF && i < max_len) {
        unsigned char byte = (unsigned char)ch;

        byte ^= key[i % key_len];               // Step 1: XOR with key
        byte ^= xor_string[i % xor_len];        // Step 2: XOR with "ababababaa"

        gibrish[i++] = byte;
    }

    if (i < max_len)
        gibrish[i] = '\0';

    return gibrish;
}

int encode_msg(FILE *img_file, const char *gibrish) {
    if (!img_file || !gibrish) return 1;

    fseek(img_file, 0, SEEK_SET);  // Start at beginning of image

    size_t msg_len = strlen(gibrish);
    if (msg_len > 65535) {  // Because we’re storing length in 2 bytes (16 bits)
        printf("Gibrish text too long to encode.\n");
        return 1;
    }

    unsigned char img_byte;

    // --- Step 1: Encode message length (2 bytes = 16 bits) ---
    for (int bit = 15; bit >= 0; --bit) {
        if (fread(&img_byte, 1, 1, img_file) != 1) return 1;
        img_byte = (img_byte & 0xFE) | ((msg_len >> bit) & 1);
        fseek(img_file, -1, SEEK_CUR);
        fwrite(&img_byte, 1, 1, img_file);
    }

    // --- Step 2: Encode the gibrish message ---
    for (size_t i = 0; i < msg_len; ++i) {
        unsigned char ch = gibrish[i];
        for (int bit = 7; bit >= 0; --bit) {
            if (fread(&img_byte, 1, 1, img_file) != 1) {
                printf("Image too small to encode message.\n");
                return 1;
            }
            img_byte = (img_byte & 0xFE) | ((ch >> bit) & 1);
            fseek(img_file, -1, SEEK_CUR);
            fwrite(&img_byte, 1, 1, img_file);
        }
    }

    // --- Step 3: Encode "Mikhail" signature at the END of the image ---
    const char *signature = "Mikhail";
    const size_t sig_len = strlen(signature); // 7 chars
    const size_t sig_bits = sig_len * 8;      // 56 bits

    if (fseek(img_file, -((long)sig_bits), SEEK_END) != 0) {
        printf("Failed to seek to end of image for signature.\n");
        return 1;
    }

    for (int i = 0; i < sig_len; ++i) {
        unsigned char ch = signature[i];
        for (int bit = 7; bit >= 0; --bit) {
            if (fread(&img_byte, 1, 1, img_file) != 1) return 1;
            img_byte = (img_byte & 0xFE) | ((ch >> bit) & 1);
            fseek(img_file, -1, SEEK_CUR);
            fwrite(&img_byte, 1, 1, img_file);
        }
    }

    return 0;
}
