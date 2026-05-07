#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>

#define AES_KEY_LEN 32
#define AES_IV_LEN 12
#define GCM_TAG_LEN 16
#define SALT_LEN 16
#define PBKDF2_ITER 600000

struct Profile {
  char name[100];
  char username[100];
  char password[100];
  char url[100];
};

void master_password_derivation(char masterPassword[]);

void add_profile(int *size, int *capacity, struct Profile **profiles);
void remove_profile(int *size, struct Profile *profiles);
void edit_profile(int size, struct Profile *profiles);
void list_profiles(int size, struct Profile *profiles);

int main() {

    int run = 1;
    char masterPass[100];

    int size = 0;
    int capacity = 1;
    struct Profile *profiles = malloc(capacity * sizeof(struct Profile));
    if (profiles == NULL) {
        printf("Memory Allocation Failed");
        return 1;
    }

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
            add_profile(&size, &capacity, &profiles);
        else if (strcmp(choice, "2") == 0)
            remove_profile(&size, profiles);
        else if (strcmp(choice, "3") == 0)
            edit_profile(size, profiles);
        else if (strcmp(choice, "4") == 0)
            list_profiles(size, profiles);
        else if (strcmp(choice, "5") == 0)
            return 0;
        else
            printf("Invalid Input");
    }

    free(profiles);
    profiles = NULL;

    return 0;
}

void master_password_derivation(char masterPassword[]) {

    unsigned char salt[SALT_LEN];
    RAND_bytes(salt, sizeof(salt));

    unsigned char key[AES_KEY_LEN];

    PKCS5_PBKDF2_HMAC(
        masterPassword, strlen(masterPassword),
        salt, SALT_LEN,
        PBKDF2_ITER,
        EVP_sha256(),
        AES_KEY_LEN,
        key
    );

    //todo

}

void add_profile(int *size, int *capacity, struct Profile **profiles) {

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
    strcpy(new_profile->password, buff);

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

void edit_profile(int size, struct Profile *profiles) {

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
            else if (strcmp(field, "password") == 0)
                strcpy(profiles[i].password, value);
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

void list_profiles(int size, struct Profile *profiles) {

    char buff[100];

    printf("\033[H\033[J");

    for (int i = 0; i <= size - 1; i++) {
        printf("Name: %s\n", profiles[i].name);
        printf("Username: %s\n", profiles[i].username);
        printf("Password: %s\n", profiles[i].password);
        printf("Url: %s\n\n", profiles[i].url);
    }

    fgets(buff, sizeof(buff), stdin);

}
