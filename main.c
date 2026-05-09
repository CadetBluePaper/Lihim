#include <gpg-error.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <gpgme.h>
#include <unistd.h>
#include <sys/stat.h>

#include "vault.h"

void add_profile(gpgme_ctx_t ctx, int *size, int *capacity,
    struct Profile **profiles);
void remove_profile(int *size, struct Profile *profiles);
void edit_profile(gpgme_ctx_t ctx, int size, struct Profile *profiles);
void list_profiles(gpgme_ctx_t ctx, int size, struct Profile *profiles);

int main() {

    gpgme_ctx_t ctx;
    gpgme_error_t err;

    char vault_dir[256];
    const char *home = getenv("HOME");

    snprintf(vault_dir, sizeof(vault_dir), "%s/.config/lihim", home);
    mkdir(vault_dir, 0700);

    snprintf(vault_dir, sizeof(vault_dir), "%s/.config/lihim/vault.txt", home);

    char masterPass[100];

    int size = 0;
    int capacity = 4;

    struct Profile *profiles = malloc(capacity * sizeof(struct Profile));
    if (profiles == NULL) {
        printf("Memory Allocation Failed");
        return 1;
    }
    read_file(vault_dir, &size, &capacity, &profiles);

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

    while (1) {
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

        if (strcmp(choice, "1") == 0) {
            add_profile(ctx, &size, &capacity, &profiles);
            write_file(vault_dir, size, profiles);
        }
        else if (strcmp(choice, "2") == 0) {
            remove_profile(&size, profiles);
            write_file(vault_dir, size, profiles);
        }
        else if (strcmp(choice, "3") == 0) {
            edit_profile(ctx, size, profiles);
            write_file(vault_dir, size, profiles);
        }
        else if (strcmp(choice, "4") == 0)
            list_profiles(ctx, size, profiles);
        else if (strcmp(choice, "5") == 0)
            break;
        else
            printf("Invalid Input");
    }

    memset(masterPass, 0, sizeof(masterPass));
    free(profiles);
    profiles = NULL;
    gpgme_release(ctx);

    return 0;
}

void add_profile(gpgme_ctx_t ctx, int *size, int *capacity, struct Profile **profiles) {

    struct Profile *new_profile = malloc(sizeof(struct Profile));
    char buff[100];

    printf("\033[H\033[J");

    printf("Enter a name: ");
    fgets(buff, sizeof(buff), stdin);
    buff[strcspn(buff, "\n")] = '\0';
    strncpy(new_profile->name, buff, sizeof(new_profile->name) - 1);
    new_profile->name[sizeof(new_profile->name) - 1] = '\0';

    printf("Enter a username: ");
    fgets(buff, sizeof(buff), stdin);
    buff[strcspn(buff, "\n")] = '\0';
    strncpy(new_profile->username, buff, sizeof(new_profile->username) - 1);
    new_profile->username[sizeof(new_profile->username) - 1] = '\0';

    printf("Enter a password: ");
    fgets(buff, sizeof(buff), stdin);
    buff[strcspn(buff, "\n")] = '\0';

    if (!encrypt_password(ctx, buff, new_profile->password,
        sizeof(new_profile->password))) {
            printf("Failed to encrypt password\n");
            fgets(buff, sizeof(buff), stdin);
            free(new_profile);
            return;
    }

    printf("Enter a url: ");
    fgets(buff, sizeof(buff), stdin);
    buff[strcspn(buff, "\n")] = '\0';
    strncpy(new_profile->url, buff, sizeof(new_profile->url) - 1);
    new_profile->url[sizeof(new_profile->url) - 1] = '\0';

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
            if (strcmp(field, "name") == 0) {
                snprintf(profiles[i].name, sizeof(profiles[i].name), "%s", value);
                profiles[i].name[sizeof(profiles[i].name) - 1] = '\0';
            }
            else if (strcmp(field, "username") == 0) {
                strncpy(profiles[i].username, value, sizeof(profiles[i].username) - 1);
                profiles[i].username[sizeof(profiles[i].username) - 1] = '\0';
            }
            else if (strcmp(field, "password") == 0) {
                if (!encrypt_password(ctx, value, profiles[i].password,
                    sizeof(profiles[i].password))) {

                    printf("Failed to encrypt password\n");
                    fgets(name, sizeof(name), stdin);
                    return;
                }
            }
            else if (strcmp(field, "url") == 0) {
                strncpy(profiles[i].url, value, sizeof(profiles[i].url) - 1);
                profiles[i].url[sizeof(profiles[i].url) - 1] = '\0';
            }
            else {
                printf("Invalid field type");
                return;
            }

            printf("Changed %s's %s to %s\n", name, field, value);
            fgets(name, sizeof(name), stdin);
            return;
        }
    }
    printf("Couldn't find profile \"%s\"", name);
    fgets(name, sizeof(name), stdin);
}

void list_profiles(gpgme_ctx_t ctx, int size, struct Profile *profiles) {

    char buff[100];
    char decrypted[512];

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
