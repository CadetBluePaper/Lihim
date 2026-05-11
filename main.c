#define _XOPEN_SOURCE 700
#include <gpgme.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <termios.h>
#include <fcntl.h>
#include "vault.h"

#define RED     "\x1b[31m"
#define GREEN   "\x1b[32m"
#define YELLOW  "\x1b[33m"
#define BLUE    "\x1b[34m"
#define MAGENTA "\x1b[35m"
#define CYAN    "\x1b[36m"
#define WHITE   "\x1b[37m"
#define BOLD    "\x1b[1m"
#define DIM     "\x1b[2m"
#define RESET   "\x1b[0m"

static void disable_echo(void) {
    struct termios tty;
    int fd = open("/dev/tty", O_RDWR);
    if (fd == -1) fd = STDIN_FILENO;
    if (tcgetattr(fd, &tty) == 0) {
        tty.c_lflag &= ~(ECHO | ECHONL);
        tcsetattr(fd, TCSAFLUSH, &tty);
    }
    if (fd != STDIN_FILENO) close(fd);
}

static void enable_echo(void) {
    struct termios tty;
    int fd = open("/dev/tty", O_RDWR);
    if (fd == -1) fd = STDIN_FILENO;
    if (tcgetattr(fd, &tty) == 0) {
        tty.c_lflag |= ECHO;
        tcsetattr(fd, TCSANOW, &tty);
    }
    if (fd != STDIN_FILENO) close(fd);
}

static void clear_screen(void) {
    printf("\x1b[2J\x1b[H");
}

static void print_header(const char *title) {
    printf("\n" BOLD CYAN "  %s" RESET "\n", title);
    printf(CYAN "  %s" RESET "\n\n", "═══════════════════════════════════════");
}

static void print_menu(int size, int selected) {
    printf("\n" DIM "  ── Commands ──" RESET "\n");
    if (size > 0) {
        printf("  " GREEN "[j]" RESET " down    " GREEN "[k]" RESET " up     " GREEN "[v]" RESET " reveal  " GREEN "[c]" RESET " copy\n");
        printf("  " GREEN "[e]" RESET " edit    " GREEN "[d]" RESET " delete\n");
    }
    printf("  " GREEN "[a]" RESET " add     " GREEN "[q]" RESET " quit\n");
    if (size > 0) {
        printf("\n  " DIM "Selected: %d / %d" RESET "\n", selected + 1, size);
    }
    printf("\n  " DIM "choice> " RESET);
    fflush(stdout);
}

static void read_line_hidden(char *buf, size_t len) {
    disable_echo();
    if (fgets(buf, len, stdin)) {
        buf[strcspn(buf, "\n")] = '\0';
    }
    enable_echo();
    printf("\n");
}

static void read_line(char *buf, size_t len) {
    if (fgets(buf, len, stdin)) {
        buf[strcspn(buf, "\n")] = '\0';
    }
}

static void print_profile(int idx, struct Profile *p, int selected) {
    if (selected) {
        printf(BOLD CYAN "  ▶ [%d] %-20s" RESET "\n", idx + 1, p->name);
    } else {
        printf("    [%d] %-20s\n", idx + 1, p->name);
    }
}

static void print_detail(gpgme_ctx_t ctx, struct Profile *p, int reveal) {
    char decrypted[512] = {0};
    printf("\n" BOLD WHITE "  Profile: %s" RESET "\n\n", p->name);
    printf("  " DIM "Username:" RESET "  %s\n", p->username);
    printf("  " DIM "URL:" RESET "        %s\n", p->url);
    if (decrypt_password(ctx, p->password, decrypted, sizeof(decrypted))) {
        if (reveal) {
            printf("  " DIM "Password:" RESET "  " GREEN "%s" RESET "\n", decrypted);
        } else {
            int n = strlen(decrypted);
            printf("  " DIM "Password:" RESET "  ");
            for (int i = 0; i < n; i++) printf("*");
            printf("\n");
        }
        memset(decrypted, 0, sizeof(decrypted));
    } else {
        printf("  " DIM "Password:" RESET "  " RED "[decryption failed]" RESET "\n");
    }
    printf("\n");
}

int main(void) {
    char vault_dir[256];
    const char *home = getenv("HOME");
    snprintf(vault_dir, sizeof(vault_dir), "%s/.config/lihim", home);
    mkdir(vault_dir, 0700);
    snprintf(vault_dir, sizeof(vault_dir), "%s/.config/lihim/vault.txt", home);

    int size = 0;
    int capacity = 4;
    struct Profile *profiles = malloc(capacity * sizeof(struct Profile));
    if (!profiles) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }
    read_file(vault_dir, &size, &capacity, &profiles);

    gpgme_check_version(NULL);
    gpgme_ctx_t ctx;
    gpgme_new(&ctx);
    gpgme_set_protocol(ctx, GPGME_PROTOCOL_OPENPGP);
    gpgme_set_pinentry_mode(ctx, GPGME_PINENTRY_MODE_LOOPBACK);

    char masterPass[100] = {0};
    printf(BOLD "Master Password: " RESET);
    fflush(stdout);
    read_line_hidden(masterPass, sizeof(masterPass));
    gpgme_set_passphrase_cb(ctx, passphrase_cb, masterPass);

    int selected = 0;
    int reveal = 0;
    int running = 1;

    while (running) {
        clear_screen();
        print_header("Lihim Password Vault");

        if (size == 0) {
            printf("  " DIM "No profiles yet. Press [a] to add." RESET "\n");
        } else {
            for (int i = 0; i < size; i++) {
                print_profile(i, &profiles[i], i == selected);
            }
            if (selected >= 0 && selected < size) {
                print_detail(ctx, &profiles[selected], reveal);
            }
        }

        print_menu(size, selected);

        char choice[16] = {0};
        read_line(choice, sizeof(choice));

        switch (choice[0]) {
        case 'q':
        case 'Q':
            running = 0;
            break;

        case 'v':
        case 'V':
            if (size > 0) reveal = !reveal;
            break;

        case 'a':
        case 'A': {
            char name[100] = {0};
            char user[100] = {0};
            char pass[100] = {0};
            char url[100] = {0};
            printf("\n" BOLD CYAN "  Add Profile" RESET "\n\n");
            printf("  Name:     "); read_line(name, sizeof(name));
            printf("  Username: "); read_line(user, sizeof(user));
            printf("  Password: "); read_line_hidden(pass, sizeof(pass));
            printf("  URL:      "); read_line(url, sizeof(url));
            if (strlen(name) > 0) {
                if (size >= capacity) {
                    capacity *= 2;
                    struct Profile *tmp = realloc(profiles, capacity * sizeof(struct Profile));
                    if (tmp) profiles = tmp;
                }
                struct Profile *np = &profiles[size];
                memset(np, 0, sizeof(*np));
                snprintf(np->name, sizeof(np->name), "%s", name);
                snprintf(np->username, sizeof(np->username), "%s", user);
                snprintf(np->url, sizeof(np->url), "%s", url);
                if (encrypt_password(ctx, pass, np->password, sizeof(np->password))) {
                    size++;
                    selected = size - 1;
                    write_file(vault_dir, size, profiles);
                }
                memset(pass, 0, sizeof(pass));
            }
            break;
        }

        case 'e':
        case 'E': {
            if (size == 0 || selected < 0 || selected >= size) break;
            struct Profile *ep = &profiles[selected];
            char name[100] = {0};
            char user[100] = {0};
            char pass[100] = {0};
            char url[100] = {0};
            printf("\n" BOLD CYAN "  Edit Profile" RESET "\n\n");
            printf("  Name [%s]:     ", ep->name); read_line(name, sizeof(name));
            printf("  Username [%s]: ", ep->username); read_line(user, sizeof(user));
            printf("  Password [keep]: "); read_line_hidden(pass, sizeof(pass));
            printf("  URL [%s]:      ", ep->url); read_line(url, sizeof(url));
            if (strlen(name) > 0) snprintf(ep->name, sizeof(ep->name), "%s", name);
            if (strlen(user) > 0) snprintf(ep->username, sizeof(ep->username), "%s", user);
            if (strlen(url) > 0) snprintf(ep->url, sizeof(ep->url), "%s", url);
            if (strlen(pass) > 0) {
                encrypt_password(ctx, pass, ep->password, sizeof(ep->password));
                memset(pass, 0, sizeof(pass));
            }
            write_file(vault_dir, size, profiles);
            reveal = 0;
            break;
        }

        case 'd':
        case 'D': {
            if (size == 0 || selected < 0 || selected >= size) break;
            printf("\n" RED "  Delete \"%s\"? [y/N]: " RESET, profiles[selected].name);
            fflush(stdout);
            char confirm[8] = {0};
            read_line(confirm, sizeof(confirm));
            if (confirm[0] == 'y' || confirm[0] == 'Y') {
                profiles[selected] = profiles[size - 1];
                size--;
                if (selected >= size) selected = size > 0 ? size - 1 : 0;
                write_file(vault_dir, size, profiles);
            }
            reveal = 0;
            break;
        }

        case 'c':
        case 'C': {
            if (size == 0 || selected < 0 || selected >= size) break;
            char decrypted[512] = {0};
            if (decrypt_password(ctx, profiles[selected].password, decrypted, sizeof(decrypted))) {
                FILE *pipe = popen("xclip -selection clipboard 2>/dev/null || pbcopy 2>/dev/null || wl-copy 2>/dev/null", "w");
                if (pipe) {
                    fprintf(pipe, "%s", decrypted);
                    pclose(pipe);
                    printf(GREEN "\n  Password copied to clipboard." RESET "\n");
                } else {
                    printf(YELLOW "\n  Copy failed. Password: %s" RESET "\n", decrypted);
                }
                memset(decrypted, 0, sizeof(decrypted));
            } else {
                printf(RED "\n  Decryption failed." RESET "\n");
            }
            printf("\n  Press Enter to continue...");
            fflush(stdout);
            char dummy[8];
            read_line(dummy, sizeof(dummy));
            break;
        }

        case 'k':
        case 'K':
            if (selected > 0) {
                selected--;
                reveal = 0;
            }
            break;

        case 'j':
        case 'J':
            if (selected < size - 1) {
                selected++;
                reveal = 0;
            }
            break;
        }
    }

    clear_screen();
    memset(masterPass, 0, sizeof(masterPass));
    free(profiles);
    gpgme_release(ctx);
    return 0;
}
