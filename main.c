#define _XOPEN_SOURCE 700
#include <notcurses/nckeys.h>
#include <notcurses/notcurses.h>
#include <gpgme.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include "vault.h"

#define COL_BG_DARK   0x0d0f1a
#define COL_BG_MID    0x1a1d2e
#define COL_BG_LIGHT  0x252840
#define COL_ACCENT    0x7c3aed
#define COL_ACCENT2   0x06b6d4
#define COL_GREEN     0x10b981
#define COL_RED       0xef4444
#define COL_TEXT      0xe2e8f0
#define COL_MUTED     0x64748b
#define COL_BORDER    0x334155

typedef enum {
    MODE_LIST,
    MODE_ADD,
    MODE_EDIT,
    MODE_DELETE
} Mode;

typedef struct {

    struct notcurses *nc;
    struct ncplane *stdplane;
    struct ncplane *sidebar;
    struct ncplane *main_panel;
    struct ncplane *statusbar;

    int term_rows;
    int term_cols;

    int selected;

    char form_name[100];
    char form_username[100];
    char form_password[100];
    char form_url[100];
    int form_field;

    int show_password;

    Mode mode;
} UIState;

void draw_box(struct ncplane *plane, int y, int x, int rows, int cols,
              const char *title, uint64_t border_ch, uint64_t title_ch);
void draw_sidebar(UIState *ui, int size, struct Profile *profiles);
void draw_detail(UIState *ui, gpgme_ctx_t ctx, int size,
                struct Profile *profiles);
void draw_form(UIState *ui, const char *title);
void draw_delete(UIState *ui, int size, struct Profile *profiles);
void draw_statusbar(UIState *ui);

void redraw(UIState *ui, gpgme_ctx_t ctx,
            int size, struct Profile *profile);
int handle_form_key(UIState *ui, uint32_t key);

int main() {

    char vault_dir[256];
    const char *home = getenv("HOME");
    snprintf(vault_dir, sizeof(vault_dir), "%s/.config/lihim", home);
    mkdir(vault_dir, 0700);
    snprintf(vault_dir, sizeof(vault_dir), "%s/.config/lihim/vault.txt", home);

    int size = 0;
    int capacity = 4;
    struct Profile *profiles = malloc(capacity * sizeof(struct Profile));
    if (profiles == NULL) {
        printf("Memory Allocation Failed");
        return 1;
    }
    read_file(vault_dir, &size, &capacity, &profiles);

    gpgme_check_version(NULL);
    gpgme_ctx_t ctx;
    gpgme_new(&ctx);
    gpgme_set_protocol(ctx, GPGME_PROTOCOL_OPENPGP);
    gpgme_set_pinentry_mode(ctx, GPGME_PINENTRY_MODE_LOOPBACK);

    char masterPass[100] = {0};

    printf("Master Password: ");
    fflush(stdout);
    fgets(masterPass, sizeof(masterPass), stdin);
    masterPass[strcspn(masterPass, "\n")] = '\0';
    gpgme_set_passphrase_cb(ctx, passphrase_cb, masterPass);

    struct notcurses_options opts = {
        .flags = NCOPTION_SUPPRESS_BANNERS,
    };
    struct notcurses *nc = notcurses_init(&opts, NULL);
    if (!nc) {
        printf("notcurses init failed\n");
        return 1;
    }

    unsigned int term_rows, term_cols;
    struct ncplane *stdplane =
        notcurses_stddim_yx(nc, &term_rows, &term_cols);

    ncplane_set_bg_rgb8(stdplane,
        (COL_BG_DARK >> 16) & 0xff,
        (COL_BG_DARK >> 8)  & 0xff,
        (COL_BG_DARK)       & 0xff);
    ncplane_erase(stdplane);

    int sidebar_w   = 28;
    int statusbar_h = 1;
    int panel_h     = term_rows - statusbar_h;
    int main_w      = term_cols - sidebar_w;

    struct ncplane_options sidebar_opts = {
        .y = 0, .x = 0,
        .rows = panel_h, .cols = sidebar_w,
    };
    struct ncplane *sidebar = ncplane_create(stdplane, &sidebar_opts);

    struct ncplane_options main_opts = {
        .y = 0, .x = sidebar_w,
        .rows = panel_h, .cols = main_w,
    };
    struct ncplane *main_panel = ncplane_create(stdplane, &main_opts);

    struct ncplane_options status_opts = {
        .y = term_rows - statusbar_h, .x = 0,
        .rows = statusbar_h, .cols = term_cols,
    };
    struct ncplane *statusbar = ncplane_create(stdplane, &status_opts);

    UIState ui = {
        .nc          = nc,
        .stdplane    = stdplane,
        .sidebar     = sidebar,
        .main_panel  = main_panel,
        .statusbar   = statusbar,
        .term_rows   = term_rows,
        .term_cols   = term_cols,
        .selected    = 0,
        .mode        = MODE_LIST,
        .show_password = 0,
        .form_field  = 0,
    };

    redraw(&ui, ctx, size, profiles);

    struct ncinput ni;
    while (1) {
        uint32_t key = notcurses_get_blocking(nc, &ni);

        if (ui.mode == MODE_LIST) {

            if (key == 'q' || key == 'Q') {
                break;
            }
            else if (key == NCKEY_UP && ui.selected > 0) {
                ui.selected--;
                ui.show_password = 0;
            }
            else if (key == NCKEY_DOWN && ui.selected < size - 1) {
                ui.selected++;
                ui.show_password = 0;
            }
            else if (key == 'v' || key == 'V') {
                ui.show_password = !ui.show_password;
            }
            else if (key == 'a' || key == 'A') {
                memset(ui.form_name, 0, sizeof(ui.form_name));
                memset(ui.form_username, 0, sizeof(ui.form_username));
                memset(ui.form_password, 0, sizeof(ui.form_password));
                memset(ui.form_url, 0, sizeof(ui.form_url));
                ui.form_field = 0;
                ui.mode = MODE_ADD;
            }
            else if (key == 'e' || key == 'E') {
                if (size > 0) {
                    strncpy(ui.form_name,
                            profiles[ui.selected].name,
                            sizeof(ui.form_name) - 1);
                    strncpy(ui.form_username,
                            profiles[ui.selected].username,
                            sizeof(ui.form_username) - 1);
                    strncpy(ui.form_url,
                            profiles[ui.selected].url,
                            sizeof(ui.form_url) - 1);
                    memset(ui.form_password, 0, sizeof(ui.form_password));
                    ui.form_field = 0;
                    ui.mode = MODE_EDIT;
                }
            }
            else if (key == 'd' || key == 'D') {
                if (size > 0) {
                    ui.mode = MODE_DELETE;
                }
            }
        }
        else if (ui.mode == MODE_ADD) {
            if (key == NCKEY_ESC) {
                ui.mode = MODE_LIST;
            }
            else if (key == NCKEY_ENTER) {
                if (strlen(ui.form_name) > 0) {
                    if (size >= capacity) {
                        capacity *= 2;
                        struct Profile *tmp = realloc(profiles,
                            capacity * sizeof(struct Profile));
                        if (tmp) profiles = tmp;
                    }
                    struct Profile *np = &profiles[size];
                    memset(np, 0, sizeof(*np));
                    strncpy(np->name,     ui.form_name,
                            sizeof(np->name) - 1);
                    strncpy(np->username, ui.form_username,
                            sizeof(np->username) - 1);
                    strncpy(np->url,      ui.form_url,
                            sizeof(np->url) - 1);
                    if (encrypt_password(ctx, ui.form_password,
                                            np->password,
                                            sizeof(np->password))) {
                        size++;
                        ui.selected = size - 1;
                        write_file(vault_dir, size, profiles);
                    }
                    memset(ui.form_password, 0, sizeof(ui.form_password));
                }
                ui.mode = MODE_LIST;
            }
            else {
                handle_form_key(&ui, key);
            }
        }
        else if (ui.mode == MODE_EDIT) {
            if (key == NCKEY_ESC) {
                ui.mode = MODE_LIST;
            }
            else if (key == NCKEY_ENTER) {
                struct Profile *ep = &profiles[ui.selected];
                strncpy(ep->name, ui.form_name,
                        sizeof(ep->name) - 1);
                strncpy(ep->username, ui.form_username,
                        sizeof(ep->username) - 1);
                strncpy(ep->url, ui.form_url,
                        sizeof(ep->url) - 1);
                if (strlen(ui.form_password) > 0) {
                    encrypt_password(ctx, ui.form_password,
                                        ep->password, sizeof(ep->password));
                    memset(ui.form_password, 0, sizeof(ui.form_password));
                }
                write_file(vault_dir, size, profiles);
                ui.mode = MODE_LIST;
            }
            else {
                handle_form_key(&ui, key);
            }
        }
        else if (ui.mode == MODE_DELETE) {
            if (key == 'y' || key == 'Y') {
                profiles[ui.selected] = profiles[size - 1];
                size--;
                if (ui.selected >= size) ui.selected = size - 1;
                write_file(vault_dir, size, profiles);
                ui.mode = MODE_LIST;
            }
            else if (key == 'n' || key == 'N' || key == NCKEY_ESC) {
                ui.mode = MODE_LIST;
            }
        }
        redraw(&ui, ctx, size, profiles);
    }

    notcurses_stop(nc);
    memset(masterPass, 0, sizeof(masterPass));
    free(profiles);
    gpgme_release(ctx);

    return 0;
}

void draw_box(struct ncplane *plane, int y, int x, int rows, int cols,
              const char *title, uint64_t border_ch, uint64_t title_ch) {

    ncplane_set_channels(plane, border_ch);

    ncplane_putstr_yx(plane, y, x, "╭");
    for (int i = 1; i < cols - 1; i++) {
        ncplane_putstr_yx(plane, y, x, "─");
    }
    ncplane_putstr_yx(plane, y, x + cols - 1, "╮");

    for (int i = 1; i < rows - 1; i++) {
        ncplane_putstr_yx(plane, y + i, x, "|");
        ncplane_putstr_yx(plane, y + i, x + cols - 1, "|");
    }

    ncplane_putstr_yx(plane, y + rows - 1, x,          "╰");
    for (int i = 1; i < cols - 1; i++)
        ncplane_putstr_yx(plane, y + rows - 1, x + i, "─");
    ncplane_putstr_yx(plane, y + rows - 1, x + cols-1, "╯");

    if (title) {
        ncplane_set_channels(plane, title_ch);
        int tx = x + 2;

        ncplane_putstr_yx(plane, y, tx, " ");
        ncplane_putstr_yx(plane, y, tx + 1, title);
        ncplane_putstr_yx(plane, y, tx + 1 + (int)strlen(title), " ");
    }
}

void draw_sidebar(UIState *ui, int size, struct Profile *profiles) {

    struct ncplane *p = ui->sidebar;
    unsigned int rows, cols;
    ncplane_dim_yx(p, &rows, &cols);

    ncplane_set_bg_rgb8(p,
        (COL_BG_MID >> 16) & 0xff,
        (COL_BG_MID >> 8) & 0xff,
        (COL_BG_MID) & 0xff);
    ncplane_erase(p);

    uint64_t border_ch = NCCHANNELS_INITIALIZER(
        (COL_ACCENT >> 16) & 0xff, (COL_ACCENT >> 8) & 0xff, COL_ACCENT & 0xff,
        (COL_BG_MID >> 16) & 0xff, (COL_BG_MID >> 8) & 0xff, COL_BG_MID & 0xff);

    uint64_t title_ch = NCCHANNELS_INITIALIZER(
        (COL_ACCENT2 >> 16) & 0xff, (COL_ACCENT2 >> 8) & 0xff, COL_ACCENT2 & 0xff,
        (COL_BG_MID >> 16)  & 0xff, (COL_BG_MID >> 8)  & 0xff, COL_BG_MID  & 0xff);

    draw_box(p, 0, 0, rows - 1, cols, "Lihim", border_ch, title_ch);

    for (unsigned int i = 0; i < size && i < rows - 4; i++) {
        int row = i + 2;
        int is_selected = (i == ui->selected);

        if (is_selected) {
            ncplane_set_bg_rgb8(p,
                (COL_BG_LIGHT >> 16) & 0xff,
                (COL_BG_LIGHT >> 8) & 0xff,
                (COL_BG_LIGHT) & 0xff);
            ncplane_set_fg_rgb8(p,
                (COL_ACCENT2 >> 16) & 0xff,
                (COL_ACCENT2 >> 8) & 0xff,
                (COL_ACCENT2) & 0xff);
            ncplane_putstr_yx(p, row, 2, "▶ ");
        }
        else {
            ncplane_set_bg_rgb8(p,
                (COL_BG_MID >> 16) & 0xff,
                (COL_BG_MID >> 8)  & 0xff,
                (COL_BG_MID)       & 0xff);
            ncplane_set_fg_rgb8(p,
                (COL_TEXT >> 16) & 0xff,
                (COL_TEXT >> 8)  & 0xff,
                (COL_TEXT)       & 0xff);
            ncplane_putstr_yx(p, row, 2, "  ");
        }

        char display[64];
        snprintf(display, sizeof(display), "%-*.*s",
            cols - 6, cols - 6, profiles[i].name);
        ncplane_putstr_yx(p, row, 4, display);

        if (size == 0) {
            ncplane_set_fg_rgb8(p,
                (COL_MUTED >> 16) & 0xff,
                (COL_MUTED >> 8)  & 0xff,
                (COL_MUTED)       & 0xff);
            ncplane_set_bg_rgb8(p,
                (COL_BG_MID >> 16) & 0xff,
                (COL_BG_MID >> 8)  & 0xff,
                (COL_BG_MID)       & 0xff);
            ncplane_putstr_yx(p, 2, 2, "No profiles yet.");
            ncplane_putstr_yx(p, 3, 2, "Press [A] to add.");
        }
    }
}

void draw_detail(UIState *ui, gpgme_ctx_t ctx, int size,
                struct Profile *profiles) {

    struct ncplane *p = ui->main_panel;
    unsigned rows, cols;
    ncplane_dim_yx(p, &rows, &cols);

    ncplane_set_bg_rgb8(p,
        (COL_BG_MID >> 16) & 0xff,
        (COL_BG_MID >> 8)  & 0xff,
        (COL_BG_MID)       & 0xff);
    ncplane_erase(p);

    uint64_t border_ch = NCCHANNELS_INITIALIZER(
        (COL_BORDER >> 16) & 0xff, (COL_BORDER >> 8) & 0xff, COL_BORDER & 0xff,
        (COL_BG_MID >> 16) & 0xff, (COL_BG_MID >> 8) & 0xff, COL_BG_MID & 0xff);

    uint64_t title_ch = NCCHANNELS_INITIALIZER(
        (COL_TEXT >> 16) & 0xff, (COL_TEXT >> 8) & 0xff, COL_TEXT & 0xff,
        (COL_BG_MID >> 16) & 0xff, (COL_BG_MID >> 8) & 0xff, COL_BG_MID & 0xff);

    draw_box(p, 0, 0, rows - 1, cols, "Profile Details", border_ch, title_ch);

    if (size == 0 || ui->selected < 0 || ui->selected >= size) {
        ncplane_set_fg_rgb8(p,
            (COL_MUTED >> 16) & 0xff,
            (COL_MUTED >> 8)  & 0xff,
            (COL_MUTED)       & 0xff);
        ncplane_set_bg_rgb8(p,
            (COL_BG_MID >> 16) & 0xff,
            (COL_BG_MID >> 8)  & 0xff,
            (COL_BG_MID)       & 0xff);
        ncplane_putstr_yx(p, rows/2, cols/2 - 10, "No profile selected");
        return;
    }

    struct Profile *profile = &profiles[ui->selected];

    #define DRAW_FIELD(row, label, value, val_color)                      \
        do {                                                               \
            ncplane_set_fg_rgb8(p,                                         \
                (COL_MUTED >> 16) & 0xff,                                  \
                (COL_MUTED >> 8)  & 0xff,                                  \
                (COL_MUTED)       & 0xff);                                 \
            ncplane_set_bg_rgb8(p,                                         \
                (COL_BG_MID >> 16) & 0xff,                                 \
                (COL_BG_MID >> 8)  & 0xff,                                 \
                (COL_BG_MID)       & 0xff);                                \
            ncplane_putstr_yx(p, row, 3, label);                           \
            ncplane_set_fg_rgb8(p,                                         \
                (val_color >> 16) & 0xff,                                  \
                (val_color >> 8)  & 0xff,                                  \
                (val_color)       & 0xff);                                 \
            ncplane_putstr_yx(p, (row) + 1, 3, value);                    \
        } while(0)

    DRAW_FIELD(2,  "NAME",     profile->name,     COL_TEXT);
    DRAW_FIELD(5,  "USERNAME", profile->username, COL_ACCENT2);
    DRAW_FIELD(11, "URL",      profile->url,      COL_ACCENT);

    #undef DRAW_FIELD

    char decrypted[512] = {0};
    char pass_display[512];

    ncplane_set_fg_rgb8(p,
        (COL_MUTED >> 16) & 0xff,
        (COL_MUTED >> 8)  & 0xff,
        (COL_MUTED)       & 0xff);
    ncplane_set_bg_rgb8(p,
        (COL_BG_MID >> 16) & 0xff,
        (COL_BG_MID >> 8)  & 0xff,
        (COL_BG_MID)       & 0xff);
    ncplane_putstr_yx(p, 8, 3, "PASSWORD");

    if (decrypt_password(ctx, profile->password,
                        decrypted, sizeof(decrypted))) {
        if (ui->show_password) {
            snprintf(pass_display, sizeof(pass_display), "%s", decrypted);
            ncplane_set_fg_rgb8(p,
                (COL_GREEN >> 16) & 0xff,
                (COL_GREEN >> 8)  & 0xff,
                (COL_GREEN)       & 0xff);
        }
        else {
            int len = strlen(decrypted);
            memset(pass_display, '*', len);
            pass_display[len] = '\0';
            ncplane_set_fg_rgb8(p,
                (COL_MUTED >> 16) & 0xff,
                (COL_MUTED >> 8)  & 0xff,
                (COL_MUTED)       & 0xff);
        }

        memset(decrypted, 0, sizeof(decrypted));
    }
    else {
        snprintf(pass_display, sizeof(pass_display), "[decryption failed]");
        ncplane_set_fg_rgb8(p,
            (COL_RED >> 16) & 0xff,
            (COL_RED >> 8)  & 0xff,
            (COL_RED)       & 0xff);
    }

    ncplane_set_bg_rgb8(p,
        (COL_BG_MID >> 16) & 0xff,
        (COL_BG_MID >> 8)  & 0xff,
        (COL_BG_MID)       & 0xff);
    ncplane_putstr_yx(p, 9, 3, pass_display);
    memset(pass_display, 0, sizeof(pass_display));

    ncplane_set_fg_rgb8(p,
        (COL_MUTED >> 16) & 0xff,
        (COL_MUTED >> 8)  & 0xff,
        (COL_MUTED)       & 0xff);
    ncplane_putstr_yx(p, 9, cols - 18,
        ui->show_password ? "[V] Hide" : "[V] Show");

}

void draw_form(UIState *ui, const char *title) {

    struct ncplane *p = ui->main_panel;
    unsigned int rows, cols;
    ncplane_dim_yx(p, &rows, &cols);


    ncplane_set_bg_rgb8(p,
        (COL_BG_MID >> 16) & 0xff,
        (COL_BG_MID >> 8)  & 0xff,
        (COL_BG_MID)       & 0xff);
    ncplane_erase(p);

    uint64_t border_ch = NCCHANNELS_INITIALIZER(
        (COL_ACCENT >> 16) & 0xff, (COL_ACCENT >> 8) & 0xff, COL_ACCENT & 0xff,
        (COL_BG_MID >> 16) & 0xff, (COL_BG_MID >> 8) & 0xff, COL_BG_MID & 0xff);

    uint64_t title_ch = NCCHANNELS_INITIALIZER(
        (COL_ACCENT2 >> 16) & 0xff, (COL_ACCENT2 >> 8) & 0xff, COL_ACCENT2 & 0xff,
        (COL_BG_MID >> 16)  & 0xff, (COL_BG_MID >> 8)  & 0xff, COL_BG_MID  & 0xff);

    draw_box(p, 0, 0, rows - 1, cols, title, border_ch, title_ch);

    const char *labels[] = { "Name", "Username", "Password", "URL" };
    const char *values[] = {
        ui->form_name, ui->form_username,
        ui->form_password, ui->form_url
    };

    for (int i = 0; i < 4; i++) {
        int row = 2 + i * 4;
        int is_active = (i == ui->form_field);

        if (is_active) {
            ncplane_set_fg_rgb8(p,
                (COL_ACCENT2 >> 16) & 0xff,
                (COL_ACCENT2 >> 8)  & 0xff,
                (COL_ACCENT2)       & 0xff);
        }
        else {
            ncplane_set_fg_rgb8(p,
                (COL_ACCENT2 >> 16) & 0xff,
                (COL_ACCENT2 >> 8)  & 0xff,
                (COL_ACCENT2)       & 0xff);
        }
        ncplane_set_bg_rgb8(p,
            (COL_BG_MID >> 16) & 0xff,
            (COL_BG_MID >> 8)  & 0xff,
            (COL_BG_MID)       & 0xff);
        ncplane_putstr_yx(p, row, 3, labels[i]);

        int input_width = cols - 8;

        if (is_active) {
            ncplane_set_bg_rgb8(p,
                (COL_BG_LIGHT >> 16) & 0xff,
                (COL_BG_LIGHT >> 8)  & 0xff,
                (COL_BG_LIGHT)       & 0xff);
            ncplane_set_fg_rgb8(p,
                (COL_TEXT >> 16) & 0xff,
                (COL_TEXT >> 8)  & 0xff,
                (COL_TEXT)       & 0xff);
        }
        else {
            ncplane_set_bg_rgb8(p,
                (COL_BG_MID >> 16) & 0xff,
                (COL_BG_MID >> 8)  & 0xff,
                (COL_BG_MID)       & 0xff);
            ncplane_set_fg_rgb8(p,
                (COL_MUTED >> 16) & 0xff,
                (COL_MUTED >> 8)  & 0xff,
                (COL_MUTED)       & 0xff);
        }

        char blank[256];
        memset(blank, ' ', input_width);
        blank[input_width] = '\0';
        ncplane_putstr_yx(p, row + 1, 4, blank);

        char display[256] = {0};
        if (i == 2 && !ui->show_password) {
            int len = strlen(values[i]);
            memset(display, '*', len);
            display[len] = '\0';
        }
        else {
            snprintf(display, sizeof(display), "%s", values[i]);
        }
        ncplane_putstr_yx(p, row + 1, 4, display);

        if (is_active) {
            int cursor_x = 4 + (int)strlen(values[i]);
            ncplane_putstr_yx(p, row + 1, cursor_x, "█");
        }
    }

    ncplane_set_fg_rgb8(p,
        (COL_MUTED >> 16) & 0xff,
        (COL_MUTED >> 8)  & 0xff,
        (COL_MUTED)       & 0xff);
    ncplane_set_bg_rgb8(p,
        (COL_BG_MID >> 16) & 0xff,
        (COL_BG_MID >> 8)  & 0xff,
        (COL_BG_MID)       & 0xff);
    ncplane_putstr_yx(p, rows - 3, 3,
        "[Tab] Next field   [Enter] Save   [Esc] Cancel");
}

void draw_delete(UIState *ui, int size, struct Profile *profiles) {

    struct ncplane *p = ui->main_panel;
    unsigned int rows, cols;
    ncplane_dim_yx(p, &rows, &cols);

    ncplane_set_bg_rgb8(p,
        (COL_BG_MID >> 16) & 0xff,
        (COL_BG_MID >> 8)  & 0xff,
        (COL_BG_MID)       & 0xff);
    ncplane_erase(p);


    uint64_t border_ch = NCCHANNELS_INITIALIZER(
        (COL_RED >> 16) & 0xff, (COL_RED >> 8) & 0xff, COL_RED & 0xff,
        (COL_BG_MID >> 16) & 0xff, (COL_BG_MID >> 8) & 0xff, COL_BG_MID & 0xff);

    uint64_t title_ch = NCCHANNELS_INITIALIZER(
        (COL_RED >> 16) & 0xff, (COL_RED >> 8) & 0xff, COL_RED & 0xff,
        (COL_BG_MID >> 16) & 0xff, (COL_BG_MID >> 8) & 0xff, COL_BG_MID & 0xff);

    draw_box(p, 0, 0, rows - 1, cols,
                "⚠ Delete Profile", border_ch, title_ch);

    if (ui->selected >= 0 && ui -> selected < size) {
        char msg[256];
        snprintf(msg, sizeof(msg),
            "Delete \"%s\"? This cannot be undone.",
            profiles[ui->selected].name);

        ncplane_set_fg_rgb8(p,
            (COL_TEXT >> 16) & 0xff,
            (COL_TEXT >> 8)  & 0xff,
            (COL_TEXT)       & 0xff);
        ncplane_set_bg_rgb8(p,
            (COL_BG_MID >> 16) & 0xff,
            (COL_BG_MID >> 8)  & 0xff,
            (COL_BG_MID)       & 0xff);
        ncplane_putstr_yx(p, rows/2 - 1,
                            cols/2 - (int)strlen(msg)/2, msg);

        ncplane_set_fg_rgb8(p,
            (COL_MUTED >> 16) & 0xff,
            (COL_MUTED >> 8)  & 0xff,
            (COL_MUTED)       & 0xff);
        ncplane_putstr_yx(p, rows/2 + 1,
                            cols/2 - 16,
                            "[Y] Confirm Delete    [N / Esc] Cancel");
    }
}

void draw_statusbar(UIState *ui) {

    struct ncplane *p = ui->statusbar;

    ncplane_set_bg_rgb8(p,
        (COL_ACCENT >> 16) & 0xff,
        (COL_ACCENT >> 8)  & 0xff,
        (COL_ACCENT)       & 0xff);
    ncplane_erase(p);

    ncplane_set_fg_rgb8(p, 0xff, 0xff, 0xff);

    if (ui->mode == MODE_LIST)
        ncplane_putstr_yx(p, 0, 2,
            "[A] Add  [E] Edit  [D] Delete  [V] Show/Hide  [↑↓] Navigate  [Q] Quit");
    else if (ui->mode == MODE_ADD)
        ncplane_putstr_yx(p, 0, 2, "Adding new profile...");
    else if (ui->mode == MODE_EDIT)
        ncplane_putstr_yx(p, 0, 2, "Editing profile...");
    else if (ui->mode == MODE_DELETE)
        ncplane_putstr_yx(p, 0, 2, "Confirm deletion...");
}

void redraw(UIState *ui, gpgme_ctx_t ctx,
            int size, struct Profile *profiles) {

    draw_sidebar(ui, size, profiles);

    switch(ui->mode) {
        case MODE_LIST:
            draw_detail(ui, ctx, size, profiles);
            break;
        case MODE_ADD:
            draw_form(ui, "✚ Add Profile");
            break;
        case MODE_EDIT:
            draw_form(ui, "✎ Edit Profile");
            break;
        case MODE_DELETE:
            draw_delete(ui, size, profiles);
            break;
    }

    draw_statusbar(ui);
    notcurses_render(ui->nc);
}

int handle_form_key(UIState *ui, uint32_t key) {

    char *fields[] = { ui->form_name, ui->form_username,
                       ui->form_password, ui->form_url};
    size_t field_sizes[] = { 100, 100, 100, 100 };

    char *cur = fields[ui->form_field];
    size_t cur_len = strlen(cur);

    if (key == NCKEY_TAB) {
        ui->form_field = (ui->form_field + 1) % 4;
        return 1;
    }

    if (key == NCKEY_BACKSPACE || key == 127) {
        if (cur_len > 0) {
            cur[cur_len - 1] = '\0';\
        }
        return 1;
    }

    if (key >= 32 && key < 127) {
        if (cur_len < field_sizes[ui->form_field] - 1) {
            cur[cur_len] = (char)key;
            cur[cur_len + 1] = '\0';
        }
        return 1;
    }

    return 0;
}
