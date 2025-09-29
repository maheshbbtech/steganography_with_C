#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <string.h>
#include <stdbool.h>
#include "limits.h"
#include "error.h"
#include "stegno_interface.h"

char *decode_msg(FILE *img_file) {
    fseek(img_file, 0, SEEK_END);
    long img_size = ftell(img_file);

    if (img_size < SIGNATURE_BITS) {
        printf("Image file too small.\n");
        return NULL;
    }

    // --- Step 1: Verify Signature at the end ---
    fseek(img_file, -SIGNATURE_BITS, SEEK_END);

    const char *sig = SIGNATURE;
    for (int i = 0; i < SIGNATURE_LEN; ++i) {
        unsigned char ch = 0;
        for (int bit = 7; bit >= 0; --bit) {
            unsigned char img_byte;
            if (fread(&img_byte, 1, 1, img_file) != 1) return NULL;
            ch = (ch << 1) | (img_byte & 1);
        }
        if (ch != sig[i]) {
            printf("Signature mismatch. Not an encoded image.\n");
            return NULL;
        }
    }

    // --- Step 2: Extract length of gibrish (first 16 bits) ---
    fseek(img_file, 0, SEEK_SET);
    unsigned short gibrish_len = 0;

    for (int bit = 15; bit >= 0; --bit) {
        unsigned char img_byte;
        if (fread(&img_byte, 1, 1, img_file) != 1) return NULL;
        gibrish_len = (gibrish_len << 1) | (img_byte & 1);
    }

    if (gibrish_len == 0 || gibrish_len > 10240) {
        printf("Invalid message length.\n");
        return NULL;
    }

    // --- Step 3: Decode gibrish text ---
    char *gibrish = malloc(gibrish_len + 1);
    if (gibrish == NULL) {
        printf("Memory allocation failed.\n");
        return NULL;
    }

    for (int i = 0; i < gibrish_len; ++i) {
        unsigned char ch = 0;
        for (int bit = 7; bit >= 0; --bit) {
            unsigned char img_byte;
            if (fread(&img_byte, 1, 1, img_file) != 1) {
                free(gibrish);
                return NULL;
            }
            ch = (ch << 1) | (img_byte & 1);
        }
        gibrish[i] = ch;
    }

    gibrish[gibrish_len] = '\0';
    return gibrish;
}

char* decrypt_msg(const char *cipher_txt, const char *key, const char *output_filename) {
    if (!cipher_txt || !key || !output_filename) return NULL;

    const char *xor_string = "ababababaa";
    size_t key_len = strlen(key);
    size_t xor_len = strlen(xor_string);

    FILE *out_file = fopen(output_filename, "w");
    if (!out_file) {
        perror("Failed to open output file for writing");
        return NULL;
    }

    size_t i = 0;
    char ch;
    while ((ch = cipher_txt[i]) != '\0') {
        unsigned char byte = (unsigned char)ch;

        byte ^= xor_string[i % xor_len];        // Reverse Step 2
        byte ^= key[i % key_len];               // Reverse Step 1

        fputc(byte, out_file);
        i++;
    }

    fclose(out_file);

    // Optional: also return the plain text
    char *plain_txt = (char *)malloc(i + 1);
    if (!plain_txt) return NULL;

    for (size_t j = 0; j < i; ++j) {
        unsigned char byte = (unsigned char)cipher_txt[j];
        byte ^= xor_string[j % xor_len];
        byte ^= key[j % key_len];
        plain_txt[j] = byte;
    }
    plain_txt[i] = '\0';

    return plain_txt;
}
