#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <stdbool.h>
#include <string.h>
#include "limits.h"
#include "error.h"
#include "stegno_interface.h"


int validate_txt_file(FILE *txt_file) {

    fseek(txt_file, 0, SEEK_END);
    long size = ftell(txt_file);
    rewind(txt_file); // reset file position for future use

    if (size < 1U || size > MAX_TXT_LEN ) {
        printf("invalid image size (%lu)\n", size);
        return 1; // validation failedz
    }

    return 0; // validation passed
}

int validate_img_file(FILE *img_file, FILE *txt_file) {
    fseek(txt_file, 0, SEEK_END);
    long txt_size = ftell(txt_file);
    rewind(txt_file);

    fseek(img_file, 0, SEEK_END);
    long img_size = ftell(img_file);
    rewind(img_file);

    long threshold_size = (txt_size + 16U + 7U) * 8U;

    if (img_size < threshold_size || img_size > MAX_IMG_SIZE) {
        printf("invalid image size (%ld)\n", img_size);
        return 1;
    }

    return 0;
}

bool is_img_enc(FILE *img_file) {
    const char *marker = "Mikhail";
    const size_t marker_len = strlen(marker); // 7 bytes
    const size_t total_bits = marker_len * 8; // 56 bits
    const size_t total_bytes_needed = total_bits; // 1 bit per byte = 56 bytes

    // Seek to the position in the image file where the marker is stored
    if (fseek(img_file, -((long)total_bytes_needed), SEEK_END) != 0) {
        return false;
    }

    unsigned char buffer[56];
    if (fread(buffer, 1, total_bytes_needed, img_file) != total_bytes_needed) {
        return false;
    }

    // Extract the LSBs and reconstruct the marker string
    char extracted_marker[8] = {0}; // 7 chars + null terminator
    for (size_t i = 0; i < marker_len; ++i) {
        unsigned char ch = 0;
        for (size_t bit = 0; bit < 8; ++bit) {
            ch <<= 1;
            ch |= (buffer[i * 8 + bit] & 0x01);
        }
        extracted_marker[i] = ch;
    }

    // Reset file pointer
    rewind(img_file);

    // Compare with original marker
    return (strncmp(extracted_marker, marker, marker_len) == 0);
}

