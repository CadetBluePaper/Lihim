#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <gpgme.h>
#include <unistd.h>
#include <sys/stat.h>

#include "vault.h"

static const char base64_chars[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static FILE *vault = NULL;

void write_file(char vault_dir[], int size, struct Profile *profiles) {
    vault = fopen(vault_dir, "w");
    if (vault == NULL) { printf("Couldn't write password directory"); return; }

    for (int i = 0; i < size; i++) {
        fprintf(vault, "%s|%s|%s|%s\n",
            profiles[i].name, profiles[i].username,
            profiles[i].password, profiles[i].url);
    }
    fclose(vault);
}

void read_file(char vault_dir[], int *size, int *capacity,
    struct Profile **profiles) {
    char buff[sizeof(struct Profile) + 4];

    FILE *temp = fopen(vault_dir, "a");
    if (temp) fclose(temp);

    vault = fopen(vault_dir, "r");
    if (vault == NULL) { printf("Couldn't find vault directory"); return; }

    while (fgets(buff, sizeof(buff), vault) != NULL) {
        buff[strcspn(buff, "\n")] = '\0';

        struct Profile p = {0};
        char *tok = strtok(buff, "|");
        if (tok) strncpy(p.name, tok, sizeof(p.name) - 1);
        tok = strtok(NULL, "|");
        if (tok) strncpy(p.username, tok, sizeof(p.username) - 1);
        tok = strtok(NULL, "|");
        if (tok) strncpy(p.password, tok, sizeof(p.password) - 1);
        tok = strtok(NULL, "|");
        if (tok) strncpy(p.url, tok, sizeof(p.url) - 1);

        if (*size >= *capacity) {
            *capacity *= 2;
            struct Profile *tmp =
                realloc(*profiles, *capacity * sizeof(struct Profile));
            if (!tmp) { printf("Memory Allocation Failed"); break; }
            *profiles = tmp;
        }
        (*profiles)[(*size)++] = p;
    }
    fclose(vault);
}

gpgme_error_t passphrase_cb(void *hook, const char *uid_hint,
                            const char *passphrase_info, int last_bad, int fd) {

    (void)uid_hint;
    (void)passphrase_info;
    (void)last_bad;

    const char *passphrase = (const char *)hook;
    write(fd, passphrase, strlen(passphrase));
    write(fd, "\n", 1);

    return 0;
}

int encrypt_password(gpgme_ctx_t ctx, const char *plaintxt, char *out_cipher,
                    size_t out_len) {

    gpgme_data_t plain_data, cipher_data;
    gpgme_error_t err;

    err = gpgme_data_new_from_mem(&plain_data, plaintxt, strlen(plaintxt), 1);

    if (err) return 0;

    err = gpgme_data_new(&cipher_data);
    if (err) {
        gpgme_data_release(plain_data);
        return 0;
    }

    err = gpgme_op_encrypt(ctx, NULL, GPGME_ENCRYPT_SYMMETRIC,
        plain_data, cipher_data);
    if (err) {
        printf("Encryption failed: %s\n", gpgme_strerror(err));
        gpgme_data_release(plain_data);
        gpgme_data_release(cipher_data);
        return 0;
    }

    size_t cipher_len;
    char *cipher_buf = gpgme_data_release_and_get_mem(cipher_data, &cipher_len);

    size_t b64_len;
    char *b64 = base64_encode((unsigned char *)cipher_buf,
        cipher_len, &b64_len);

    gpgme_free(cipher_buf);
    gpgme_data_release(plain_data);

    if (!b64 || b64_len >= out_len) {
        free(b64);
        return 0;
    }

    strcpy(out_cipher, b64);
    free(b64);
    return 1;
}

int decrypt_password(gpgme_ctx_t ctx, const char *cipher_b64, char *out_plain,
                    size_t out_len) {

    gpgme_data_t plain_data, cipher_data;
    gpgme_error_t err;

    size_t cipher_len;
    unsigned char *cipher_raw = base64_decode(cipher_b64,
        strlen(cipher_b64), &cipher_len);
    if (!cipher_raw) return 0;

    err = gpgme_data_new_from_mem(&cipher_data, (char *)cipher_raw,
        cipher_len, 1);
    free(cipher_raw);
    if (err) return 0;

    err = gpgme_data_new(&plain_data);
    if (err) {
        gpgme_data_release(cipher_data);
        return 0;
    }

    err = gpgme_op_decrypt(ctx, cipher_data, plain_data);
    if (err) {
        printf("Decryption failed: %s\n", gpgme_strerror(err));
        gpgme_data_release(cipher_data);
        gpgme_data_release(plain_data);
        return 0;
    }

    size_t plain_len;
    char *plain_buf = gpgme_data_release_and_get_mem(plain_data,
        &plain_len);
    gpgme_data_release(cipher_data);

    if (plain_len >= out_len) {
        gpgme_free(plain_buf);
        return 0;
    }

    memcpy(out_plain, plain_buf, plain_len);
    out_plain[plain_len] = '\0';
    gpgme_free(plain_buf);
    return 1;
}

char *base64_encode(const unsigned char *data, size_t input_len,
                    size_t *output_len) {

    *output_len = 4 * ((input_len + 2) / 3);
    char *encoded = malloc(*output_len + 1);
    if (!encoded) return NULL;

    for (size_t i = 0, j = 0; i < input_len;) {
        uint32_t octet_a = i < input_len ? data[i++] : 0;
        uint32_t octet_b = i < input_len ? data[i++] : 0;
        uint32_t octet_c = i < input_len ? data[i++] : 0;
        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded[j++] = base64_chars[(triple >> 3 * 6) & 0x3F];
        encoded[j++] = base64_chars[(triple >> 2 * 6) & 0x3F];
        encoded[j++] = base64_chars[(triple >> 1 * 6) & 0x3F];
        encoded[j++] = base64_chars[(triple >> 0 * 6) & 0x3F];
    }

    for (size_t i = 0; i < (3 - input_len % 3) % 3; i++) {
        encoded[*output_len - 1 - i] = '=';
    }

    encoded[*output_len] = '\0';
    return encoded;
}

unsigned char *base64_decode(const char *data, size_t input_len,
                            size_t *output_len) {

    if (input_len % 4 != 0) return NULL;

    *output_len = input_len / 4 * 3;
    if (data[input_len - 1] == '=') (*output_len)--;
    if (data[input_len - 2] == '=') (*output_len)--;

    unsigned char *decoded = malloc(*output_len);
    if (!decoded) return NULL;

    for (size_t i = 0, j = 0; i < input_len;) {
        uint32_t sextet_a
            = data[i] == '=' ? 0 & i++ : (size_t)(strchr(base64_chars, data[i++]) - base64_chars);
        uint32_t sextet_b =
            data[i] == '=' ? 0 & i++ : (size_t)(strchr(base64_chars, data[i++]) - base64_chars);
        uint32_t sextet_c =
            data[i] == '=' ? 0 & i++ : (size_t)(strchr(base64_chars, data[i++]) - base64_chars);
        uint32_t sextet_d =
            data[i] == '=' ? 0 & i++ : (size_t)(strchr(base64_chars, data[i++]) - base64_chars);
        uint32_t triple =
            (sextet_a << 3 * 6) + (sextet_b << 2 * 6) +
            (sextet_c << 1 * 6) + (sextet_d << 0 * 6);

        if (j < *output_len) decoded[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_len) decoded[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_len) decoded[j++] = (triple >> 0 * 8) & 0xFF;

    }

    return decoded;
}
