#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "limits.h"
#include "error.h"
#include "stegno_interface.h"




#include "crypto.h"

int encode_msg(FILE *img_file, const char *message, const char *password) {
    if (!img_file || !message || !password) return 1;

    // --- Step 0: Encrypt Message ---
    unsigned char key[32]; // 256 bits
    derive_key(password, key);

    unsigned char *ciphertext = NULL;
    int ciphertext_len = encrypt_aes256(message, strlen(message), key, &ciphertext);
    if (ciphertext_len < 0) {
        printf("Encryption failed.\n");
        return 1;
    }

    fseek(img_file, 0, SEEK_SET);  // Start at beginning of image

    if (ciphertext_len > 65535) {
        printf("Message text too long to encode.\n");
        free(ciphertext);
        return 1;
    }

    unsigned char img_byte;

    // --- Step 1: Encode ciphertext length (2 bytes = 16 bits) ---
    for (int bit = 15; bit >= 0; --bit) {
        if (fread(&img_byte, 1, 1, img_file) != 1) {free(ciphertext); return 1;}
        img_byte = (img_byte & 0xFE) | ((ciphertext_len >> bit) & 1);
        fseek(img_file, -1, SEEK_CUR);
        fwrite(&img_byte, 1, 1, img_file);
    }

    // --- Step 2: Encode the ciphertext ---
    for (int i = 0; i < ciphertext_len; ++i) {
        unsigned char ch = ciphertext[i];
        for (int bit = 7; bit >= 0; --bit) {
            if (fread(&img_byte, 1, 1, img_file) != 1) {
                printf("Image too small to encode message.\n");
                free(ciphertext);
                return 1;
            }
            img_byte = (img_byte & 0xFE) | ((ch >> bit) & 1);
            fseek(img_file, -1, SEEK_CUR);
            fwrite(&img_byte, 1, 1, img_file);
        }
    }
    
    free(ciphertext);

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
