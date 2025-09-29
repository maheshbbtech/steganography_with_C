#ifndef STENOGRAPHER_LIMITS_H
#define STENOGRAPHER_LIMITS_H

#define INVALID_NUM_ARGS 2U          // Incorrect number of command-line args
#define MAX_IMG_SIZE_EXCEED 3U       // Image size exceeds limit
#define MIN_IMG_SIZE_INVALID 4U      // Image too small to embed message
#define INVALID_TXT_LEN 5U           // Message text is invalid length
#define INVALID_PASS_LEN 6U          // Password length outside allowed range
#define MALLOC_FAIL 7U               // Memory allocation failed
#define TXT_OPEN_FAIL 8U             // Could not open text file
#define IMAGE_OPEN_FAIL 9U           // Could not open image file
#define INVALID_TXT_FILE 10U         // Text file failed validation
#define IMAGE_VALIDATION_FAIL 11U    // Image file failed validation
#define TXT_VALIDATION_FAIL 12U      // Text file failed validation
#define NON_ENC_IMG  13U             // image provided is not encoded
#define PASS_MISMATCH  13U           // image provided is not encoded
#define ENC_FAIL  14U           // image provided is not encoded
#define DEC_FAIL  15U           // image provided is not encoded

#endif