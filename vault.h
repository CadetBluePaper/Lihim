#ifndef VAULT_H
#define VAULT_H

#include <gpgme.h>

struct Profile {
    char name[100];
    char username[100];
    char password[512];
    char url[100];
};

void write_file(char vault_dir[], int size, struct Profile *profiles);
void read_file(char vault_dir[], int *size, int *capacity,
    struct Profile **profiles);

gpgme_error_t passphrase_cb(void *hook, const char *uid_hint,
                            const char *passphrase_info, int last_bad, int fd);

int encrypt_password(gpgme_ctx_t ctx, const char *plaintxt, char *out_cipher,
                    size_t out_len);
int decrypt_password(gpgme_ctx_t ctx, const char *cipher_b64, char *out_plain,
                    size_t out_len);

char *base64_encode(const unsigned char *data, size_t input_len,
                    size_t *output_len);
unsigned char *base64_decode(const char *data, size_t input_len,
                            size_t *output_len);

#endif
