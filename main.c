#include <gpg-error.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <gpgme.h>
#include <unistd.h>

struct Profile {
  char name[100];
  char username[100];
  char password[512];
  char url[100];
};

static const char base64_chars[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

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

void add_profile(gpgme_ctx_t ctx, int *size, int *capacity, struct Profile **profiles);
void remove_profile(int *size, struct Profile *profiles);
//edit these last two to encrypt and decrypt
void edit_profile(gpgme_ctx_t ctx, int size, struct Profile *profiles);
void list_profiles(gpgme_ctx_t ctx, int size, struct Profile *profiles);

int main() {

    gpgme_ctx_t ctx;
    gpgme_error_t err;

    int run = 1;
    char masterPass[100];

    int size = 0;
    int capacity = 1;

    struct Profile *profiles = malloc(capacity * sizeof(struct Profile));
    if (profiles == NULL) {
        printf("Memory Allocation Failed");
        return 1;
    }

    gpgme_check_version(NULL);
    err = gpgme_new(&ctx);
    if (err) {
        printf("%s: %s\n", gpgme_strsource(err), gpgme_strerror(err));
        exit(1);
    }

    gpgme_set_protocol(ctx, GPGME_PROTOCOL_OPENPGP);

    gpgme_set_pinentry_mode(ctx, GPGME_PINENTRY_MODE_LOOPBACK);

    printf("Master Password: ");
    fgets(masterPass, sizeof(masterPass), stdin);
    masterPass[strcspn(masterPass, "\n")] = '\0';

    gpgme_set_passphrase_cb(ctx, passphrase_cb, masterPass);

    while (run) {
        printf("\033[H\033[J");

        printf("1. Add Profile\n");
        printf("2. Remove Profile\n");
        printf("3. Edit Profile\n");
        printf("4. List Profiles\n");
        printf("5. Exit\n\n");

        printf("Select an option: ");

        char choice[10];
        fgets(choice, sizeof(choice), stdin);
        choice[strcspn(choice, "\n")] = '\0';

        if (strcmp(choice, "1") == 0)
            add_profile(ctx, &size, &capacity, &profiles);
        else if (strcmp(choice, "2") == 0)
            remove_profile(&size, profiles);
        else if (strcmp(choice, "3") == 0)
            edit_profile(ctx, size, profiles);
        else if (strcmp(choice, "4") == 0)
            list_profiles(ctx, size, profiles);
        else if (strcmp(choice, "5") == 0)
            return 0;
        else
            printf("Invalid Input");
    }

    free(profiles);
    profiles = NULL;
    gpgme_release(ctx);

    return 0;
}

gpgme_error_t passphrase_cb(void *hook, const char *uid_hint,
                            const char *passphrase_info, int last_bad, int fd) {

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

    err = gpgme_op_encrypt(ctx, NULL, 0, plain_data, cipher_data);
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
            = data[i] == '=' ? 0 & i++ : strchr(base64_chars, data[i++]) - base64_chars;
        uint32_t sextet_b =
            data[i] == '=' ? 0 & i++ : strchr(base64_chars, data[i++]) - base64_chars;
        uint32_t sextet_c =
            data[i] == '=' ? 0 & i++ : strchr(base64_chars, data[i++]) - base64_chars;
        uint32_t sextet_d =
            data[i] == '=' ? 0 & i++ : strchr(base64_chars, data[i++]) - base64_chars;
        uint32_t triple =
            (sextet_a << 3 * 6) + (sextet_b << 2 * 6) +
            (sextet_c << 1 * 6) + (sextet_d << 0 * 6);

        if (j < *output_len) decoded[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_len) decoded[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_len) decoded[j++] = (triple >> 0 * 8) & 0xFF;

    }

    return decoded;
}

void add_profile(gpgme_ctx_t ctx, int *size, int *capacity, struct Profile **profiles) {

    struct Profile *new_profile = malloc(sizeof(struct Profile));
    char buff[100];

    printf("\033[H\033[J");

    printf("Enter a name: ");
    fgets(buff, sizeof(buff), stdin);
    buff[strcspn(buff, "\n")] = '\0';
    strcpy(new_profile->name, buff);

    printf("Enter a username: ");
    fgets(buff, sizeof(buff), stdin);
    buff[strcspn(buff, "\n")] = '\0';
    strcpy(new_profile->username, buff);

    printf("Enter a password: ");
    fgets(buff, sizeof(buff), stdin);
    buff[strcspn(buff, "\n")] = '\0';

    if (!encrypt_password(ctx, buff, new_profile->password,
        sizeof(new_profile->password))) {
            printf("Failed to encrypt password\n");
            fgets(buff, sizeof(buff), stdin);
            return;
    }

    printf("Enter a url: ");
    fgets(buff, sizeof(buff), stdin);
    buff[strcspn(buff, "\n")] = '\0';
    strcpy(new_profile->url, buff);

    if (*size >= *capacity) {
        *capacity *= 2;
        struct Profile *temp = realloc(*profiles, *capacity * sizeof(struct Profile));
        if (temp == NULL) {
            printf("Memory Allocation Failed");
            free(new_profile);
            return;
        }
        *profiles = temp;
    }
    (*profiles)[(*size)++] = *new_profile;

    printf("Added Profile \"%s\"\n", new_profile->name);
    fgets(buff, sizeof(buff), stdin);

    free(new_profile);
    new_profile = NULL;
}

void remove_profile(int *size, struct Profile *profiles) {

    char toDelete[100];

    printf("\033[H\033[J");

    printf("Enter a profile to delete: ");
    fgets(toDelete, sizeof(toDelete), stdin);
    toDelete[strcspn(toDelete, "\n")] = '\0';

    for (int i = 0; i <= *size - 1; i++) {
        if (strcmp(profiles[i].name, toDelete) == 0) {
            profiles[i] = profiles[*size - 1];
            (*size)--;

            printf("Deleted profile \"%s\"", toDelete);
            fgets(toDelete, sizeof(toDelete), stdin);
            return;
        }
    }
    printf("Couldn't find profile \"%s\"", toDelete);
    fgets(toDelete, sizeof(toDelete), stdin);
}

void edit_profile(gpgme_ctx_t ctx, int size, struct Profile *profiles) {

    char name[100];
    char field[100];
    char value[100];

    printf("\033[H\033[J");

    printf("Enter a profile to edit: ");
    fgets(name, sizeof(name), stdin);
    name[strcspn(name, "\n")] = '\0';

    printf("Enter a field to edit (name, username, password, url): ");
    fgets(field, sizeof(field), stdin);
    field[strcspn(field, "\n")] = '\0';

    printf("Enter the value for the %s: ", field);
    fgets(value, sizeof(value), stdin);
    value[strcspn(value, "\n")] = '\0';

    for (int i = 0; i <= size - 1; i++) {
        if (strcmp(name, profiles[i].name) == 0) {
            if (strcmp(field, "name") == 0)
                strcpy(profiles[i].name, value);
            else if (strcmp(field, "username") == 0)
                strcpy(profiles[i].username, value);
            else if (strcmp(field, "password") == 0) {
                if (!encrypt_password(ctx, value, profiles[i].password,
                    sizeof(profiles[i].password))) {

                    printf("Failed to encrypt password\n");
                    fgets(name, sizeof(name), stdin);
                    return;
                }
            }
            else if (strcmp(field, "url") == 0)
                strcpy(profiles[i].url, value);
            else {
                printf("Invalid field type");
                return;
            }


            printf("Changed %s's %s to %s\n", name, field, value);
            fgets(name, sizeof(name), stdin);
            return;
        }
    }
    printf("Couldn't find profile\"%s\"", name);
    fgets(name, sizeof(name), stdin);
}

void list_profiles(gpgme_ctx_t ctx, int size, struct Profile *profiles) {

    char buff[100];
    char decrypted[100];

    printf("\033[H\033[J");

    for (int i = 0; i <= size - 1; i++) {
        printf("Name: %s\n", profiles[i].name);
        printf("Username: %s\n", profiles[i].username);

        if (decrypt_password(ctx, profiles[i].password, decrypted,
            sizeof(decrypted))) {
                printf("Password: %s\n", decrypted);
                memset(decrypted, 0, sizeof(decrypted));
        }
        else {
            printf("Password: [decryption failed]\n");
        }

        printf("Url: %s\n\n", profiles[i].url);
    }

    fgets(buff, sizeof(buff), stdin);

}
