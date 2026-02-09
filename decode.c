#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <string.h>
#include <stdbool.h>
#include "limits.h"
#include "error.h"
#include "stegno_interface.h"

#include "crypto.h"

char *decode_msg(FILE *img_file, const char *password) {
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

    // --- Step 2: Extract length of ciphertext (first 16 bits) ---
    fseek(img_file, 0, SEEK_SET);
    unsigned short msg_len = 0;

    for (int bit = 15; bit >= 0; --bit) {
        unsigned char img_byte;
        if (fread(&img_byte, 1, 1, img_file) != 1) return NULL;
        msg_len = (msg_len << 1) | (img_byte & 1);
    }

    if (msg_len == 0 || msg_len > 10240) { // Limit sanity check
        printf("Invalid message length: %d\n", msg_len);
        return NULL;
    }

    // --- Step 3: Extract ciphertext ---
    unsigned char *ciphertext = malloc(msg_len);
    if (ciphertext == NULL) {
        printf("Memory allocation failed.\n");
        return NULL;
    }

    for (int i = 0; i < msg_len; ++i) {
        unsigned char ch = 0;
        for (int bit = 7; bit >= 0; --bit) {
            unsigned char img_byte;
            if (fread(&img_byte, 1, 1, img_file) != 1) {
                free(ciphertext);
                return NULL;
            }
            ch = (ch << 1) | (img_byte & 1);
        }
        ciphertext[i] = ch;
    }

    // --- Step 4: Decrypt ---
    unsigned char key[32]; // 256 bits
    derive_key(password, key);

    char *plaintext = decrypt_aes256(ciphertext, msg_len, key);
    free(ciphertext);

    if (plaintext == NULL) {
        printf("Decryption failed (wrong password?)\n");
        return NULL;
    }

    return plaintext;
}


