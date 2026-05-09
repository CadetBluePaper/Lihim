#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <gpgme.h>

#include "vault.h"
#include "vault.c"

char *read_message(void);
void write_message(const char *json);

int json_get_string(const char *json, const char *key,
                    char *out, size_t out_len);

int url_matches(const char *profile_url, const char *page_url);

void handle_request(gpgme_ctx_t ctx, int size, struct Profile *profiles,
                    const char *json);

int main() {

    char *json;
    char masterpass[100] = {0};

    gpgme_ctx_t ctx;
    gpgme_error_t err;

    char vault_dir[256];
    const char *home = getenv("HOME");
    if (!home) {
        write_message("{\"status\":\"error\",\"message\":\"no HOME\"}");
        return 1;
    }

    snprintf(vault_dir, sizeof(vault_dir), "%s/.config/lihim", home);
    mkdir(vault_dir, 0700);
    snprintf(vault_dir, sizeof(vault_dir), "%s/.config/lihim/vault.txt", home);

    int size = 0;
    int capacity = 4;
    struct Profile *profiles = malloc(capacity * sizeof(struct Profile));

    if (!profiles) {
        write_message("{\"status\":\"error\",\"message\":\"malloc failed\"}");
        return 1;
    }

    read_file(vault_dir, &size, &capacity, &profiles);

    json = read_message();
    if (!json) {
        free(profiles);
        return 1;
    }

    if (!json_get_string(json, "masterpass", masterpass, sizeof(masterpass))) {
        write_message("{\"status\":\"error\",\"message\":\"missing masterpass\"}");
        free(json);
        free(profiles);
    }

    gpgme_check_version(NULL);

    err = gpgme_new(&ctx);
    if (err) {
        write_message("{\"status\":\"error\",\"message\":\"gpgme init failed\"}");
        free(json);
        free(profiles);
        return 1;
    }

    gpgme_set_protocol(ctx, GPGME_PROTOCOL_OPENPGP);
    gpgme_set_pinentry_mode(ctx, GPGME_PINENTRY_MODE_LOOPBACK);
    gpgme_set_passphrase_cb(ctx, passphrase_cb, masterpass);

    handle_request(ctx, size, profiles, json);

    memset(masterpass, 0, sizeof(masterpass));
    memset(json, 0, strlen(json));
    free(json);
    free(profiles);
    gpgme_release(ctx);

    return 0;
}

char *read_message(void) {

    uint32_t len = 0;
    char *buff;

    if (fread(&len, sizeof(len), 1, stdin) != 1) {
        return NULL;
    }

    if (len == 0 || len > 1024 * 1024) {
        return NULL;
    }

    buff = malloc(len + 1);
    if (!buff) {
        return NULL;
    }

    if (fread(buff, 1, len, stdin) != len) {
        free(buff);
        return NULL;
    }

    buff[len] = '\0';
    return buff;

}

void write_message(const char *json) {

    uint32_t len = (uint32_t)strlen(json);

    fwrite(&len, sizeof(len), 1, stdout);
    fwrite(json, 1, len, stdout);

    fflush(stdout);
}

int json_get_string(const char *json, const char *key,
                    char *out, size_t out_len) {

    char pattern[128];

    const char *find;

    const char *val_start;
    const char *val_end;
    size_t val_len;

    snprintf(pattern, sizeof(pattern), "\"%s\":\"", key);

    find = strstr(json, pattern);
    if (!find) {
        return 0;
    }

    val_start = find + strlen(pattern);
    val_end = strchr(val_start, '"');
    if (!val_end) {
        return 0;
    }


    val_len = (size_t)(val_end - val_start);
    if (val_len >= out_len) {
        return 0;
    }

    memcpy(out, val_start, val_len);
    out[val_len] = '\0';
    return 1;

}

int url_matches(const char *profile_url, const char *page_url) {

    if (!profile_url || !page_url) {
        return 0;
    }
    if (strlen(profile_url) == 0) {
        return 0;
    }

    return strstr(page_url, profile_url) != NULL
    ||strstr(profile_url, page_url);

}

void handle_request(gpgme_ctx_t ctx, int size, struct Profile *profiles,
                    const char *json) {

    char action[32] = {0};
    char url[100] = {0};
    char decrypted[512] = {0};
    char response[768];

    if (!json_get_string(json, "action", action, sizeof(action))) {
        write_message("{\"status\":\"error\",\"message\":\"missing action\"}");
        return;
    }
    if (strcmp(action, "get") != 0) {
        write_message("{\"status\":\"error\",\"message\":\"unkown action\"}");
        return;
    }
    if (!json_get_string(json, "url", url, sizeof(url))) {
        write_message("{\"status\":\"error\",\"message\":\"missing url\"}");
        return;
    }

    for (int i = 0; i < size; i++) {

        if (!url_matches(profiles[i].url, url)) {
            continue;
        }

        if (!decrypt_password(ctx, profiles[i].password,
            decrypted, sizeof(decrypted))) {

            write_message("{\"status\":\"error\",\"message\":\"decryption failed\"}");
            return;
        }

        snprintf(response, sizeof(response),
            "{\"status\":\"ok\","
            "\"username\":\"%s\","
            "\"password\":\"%s\"}",
            profiles[i].username,
            decrypted);

        memset(decrypted, 0, sizeof(decrypted));

        write_message(response);

        memset(response, 0, sizeof(response));
        return;
    }

    write_message("{\"status\":\"notfound\"}");

}
