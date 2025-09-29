#define SIGNATURE "Mikhail"
#define SIGNATURE_LEN 7
#define SIGNATURE_BITS (SIGNATURE_LEN * 8)

int validate_txt_file(FILE *txt_file);
int validate_img_file(FILE *img_file, FILE *txt_file);
bool is_img_enc(FILE *img_file);
int encode_msg(FILE *img_file, const char *gibrish);
char *decode_msg(FILE *img_file);
char* encrypt_pass(const char* password);
char* encrypt_msg(FILE *txt_file, const char *key);
char* decrypt_msg(const char *cipher_txt, const char *key, const char *output_filename);