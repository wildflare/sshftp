// main.c - SSH クライアント with SFTP ファイラー
// Build: gcc -Wall -O2 -o sshftp.exe main.c
//        -Wl,-Bstatic -lssh2 -lssl -lcrypto -lz
//        -Wl,-Bdynamic -lws2_32 -lgdi32 -lcrypt32 -lbcrypt -static-libgcc

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <time.h>
#include <ctype.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <libssh2.h>
#include <libssh2_sftp.h>
#include <windows.h>

// ===== 定数 ===================================================
#define MAX_CONNECTIONS 64
#define FILER_MAX       512
#define SFTP_DIR_MODE \
    (LIBSSH2_SFTP_S_IRWXU | LIBSSH2_SFTP_S_IRGRP | LIBSSH2_SFTP_S_IXGRP | \
     LIBSSH2_SFTP_S_IROTH | LIBSSH2_SFTP_S_IXOTH)

// ===== 型定義 =================================================
typedef enum { AUTH_PASSWORD = 0, AUTH_PUBKEY = 1 } AuthType;

typedef struct {
    char     name[64];
    char     host[256];
    int      port;
    char     user[64];
    AuthType auth_type;
    char     pass[64];
    char     keyfile[512];
    char     passphrase[64];
} Connection;

typedef struct {
    char     name[512];
    int      is_dir;
    uint64_t size;
    char     date[20];
} FilerEntry;

typedef struct {
    int        is_remote;
    char       path[1024];
    FilerEntry entries[FILER_MAX];
    int        count;
    int        selected;
    int        scroll;
    int        marked[FILER_MAX];  // スペースでマーク
} FilerPane;

typedef struct { LIBSSH2_CHANNEL *ch; char host[256]; } RecvArgs;

// ===== グローバル =============================================
static Connection g_conns[MAX_CONNECTIONS];
static int        g_conn_count = 0;

static HANDLE g_hIn  = INVALID_HANDLE_VALUE;
static HANDLE g_hOut = INVALID_HANDLE_VALUE;
static DWORD  g_orig_in_mode  = 0;
static DWORD  g_orig_out_mode = 0;

static volatile int g_running       = 0;
static volatile int g_filer_active  = 0;
static volatile int g_in_alt_screen = 0;  // リモートが代替スクリーン使用中

static HANDLE g_filer_event = NULL;
static HANDLE g_filer_done  = NULL;
static HANDLE g_recv_paused = NULL;
static CRITICAL_SECTION g_ssh_cs;

static char g_filer_seq[8] = "\x1b[24~";  // F12 デフォルト（send_thread 用 VT シーケンス）
static int  g_filer_seq_len = 5;
static WORD g_filer_vk  = VK_F12;  // read_key 用 VK コード
static int  g_filer_ctrl_char = 0; // Ctrl+key の場合の制御文字（1-26）

static char g_config_path[MAX_PATH + 32];

// ===== 文字列ユーティリティ ===================================
static void safe_copy(char *dst, size_t dstsz, const char *src) {
    size_t n = strlen(src);
    if (n >= dstsz) n = dstsz - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

// ===== 設定ファイルパス =======================================
static void init_config_path(void) {
    char exe[MAX_PATH];
    GetModuleFileNameA(NULL, exe, sizeof(exe));
    char *last = strrchr(exe, '\\');
    if (last) {
        *(last + 1) = '\0';
        snprintf(g_config_path, sizeof(g_config_path), "%sconnections.json", exe);
    } else {
        safe_copy(g_config_path, sizeof(g_config_path), "connections.json");
    }
}

// ===== ホットキー設定 =========================================
static void parse_hotkey(const char *str) {
    if (!str || !*str) return;
    if (strncmp(str, "ctrl-", 5) == 0 && str[5]) {
        char ch = (char)tolower((unsigned char)str[5]);
        if (ch >= 'a' && ch <= 'z') {
            g_filer_seq[0] = ch-'a'+1; g_filer_seq_len = 1;
            g_filer_ctrl_char = ch-'a'+1; g_filer_vk = 0;
        }
        return;
    }
    g_filer_ctrl_char = 0;
    static const struct { const char *name; const char *seq; int len; WORD vk; } fkeys[] = {
        {"f1","\x1bOP",3,VK_F1}, {"f2","\x1bOQ",3,VK_F2},
        {"f3","\x1bOR",3,VK_F3}, {"f4","\x1bOS",3,VK_F4},
        {"f5","\x1b[15~",5,VK_F5},  {"f6","\x1b[17~",5,VK_F6},
        {"f7","\x1b[18~",5,VK_F7},  {"f8","\x1b[19~",5,VK_F8},
        {"f9","\x1b[20~",5,VK_F9},  {"f10","\x1b[21~",5,VK_F10},
        {"f11","\x1b[23~",5,VK_F11},{"f12","\x1b[24~",5,VK_F12},
    };
    for (int i=0; i<(int)(sizeof(fkeys)/sizeof(fkeys[0])); i++)
        if (strcmp(str,fkeys[i].name)==0) {
            memcpy(g_filer_seq,fkeys[i].seq,fkeys[i].len);
            g_filer_seq_len = fkeys[i].len;
            g_filer_vk = fkeys[i].vk;
            return;
        }
}

// ===== JSON 簡易パーサー ======================================
static char *jval(const char *json, const char *key, char *out, size_t sz) {
    char search[128];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(json, search);
    if (!p) return NULL;
    p += strlen(search);
    while (*p == ' ' || *p == ':') p++;
    size_t i = 0;
    if (*p == '"') {
        p++;
        while (*p && *p != '"' && i < sz-1) out[i++] = *p++;
    } else {
        while (*p && *p != ',' && *p != '}' && i < sz-1) out[i++] = *p++;
    }
    out[i] = '\0';
    return out;
}

// ===== 接続先の保存・読み込み =================================
static void load_connections(void) {
    g_conn_count = 0;
    FILE *f = fopen(g_config_path, "r"); if (!f) return;
    fseek(f, 0, SEEK_END); long sz = ftell(f); rewind(f);
    char *buf = malloc(sz + 1); if (!buf) { fclose(f); return; }
    fread(buf, 1, sz, f); buf[sz] = '\0'; fclose(f);
    const char *p = buf;
    while (g_conn_count < MAX_CONNECTIONS) {
        p = strchr(p, '{'); if (!p) break;
        const char *end = strchr(p + 1, '}'); if (!end) break;
        size_t bl = end - p + 1;
        char *blk = malloc(bl + 1); memcpy(blk, p, bl); blk[bl] = '\0';
        Connection *c = &g_conns[g_conn_count];
        memset(c, 0, sizeof(*c)); c->port = 22;
        char tmp[16];
        jval(blk, "name",       c->name,       sizeof(c->name));
        jval(blk, "host",       c->host,       sizeof(c->host));
        if (jval(blk, "port",   tmp, sizeof(tmp))) c->port = atoi(tmp);
        jval(blk, "user",       c->user,       sizeof(c->user));
        jval(blk, "pass",       c->pass,       sizeof(c->pass));
        jval(blk, "keyfile",    c->keyfile,    sizeof(c->keyfile));
        jval(blk, "passphrase", c->passphrase, sizeof(c->passphrase));
        if (jval(blk, "auth_type", tmp, sizeof(tmp))) c->auth_type = atoi(tmp);
        free(blk);
        if (c->host[0] && c->user[0]) g_conn_count++;
        p = end + 1;
    }
    free(buf);
}

static void save_connections(void) {
    FILE *f = fopen(g_config_path, "w"); if (!f) return;
    fprintf(f, "[\n");
    for (int i = 0; i < g_conn_count; i++) {
        Connection *c = &g_conns[i];
        fprintf(f,
            "  {\"name\":\"%s\",\"host\":\"%s\",\"port\":%d,\"user\":\"%s\","
            "\"auth_type\":%d,\"pass\":\"%s\",\"keyfile\":\"%s\","
            "\"passphrase\":\"%s\"}%s\n",
            c->name, c->host, c->port, c->user, (int)c->auth_type,
            c->pass, c->keyfile, c->passphrase,
            i < g_conn_count - 1 ? "," : "");
    }
    fprintf(f, "]\n"); fclose(f);
}

// ===== TUI 出力ヘルパー =======================================
#define ESC     "\x1b"
#define CLEAR   ESC "[2J" ESC "[H"
#define RESET   ESC "[0m"
#define C_TITLE ESC "[1;36m"
#define C_SEL   ESC "[1;7m"
#define C_DIM   ESC "[2m"
#define C_ERR   ESC "[1;31m"
#define C_OK    ESC "[1;32m"
#define C_YEL   ESC "[1;33m"

static char g_dir_color[40] = ESC "[1;34m";  // フォルダ色（LS_COLORS で上書き）

static void wprint(const char *s) {
    DWORD w; WriteConsoleA(g_hOut, s, (DWORD)strlen(s), &w, NULL);
}
static void wprintf2(const char *fmt, ...) {
    char buf[2048]; va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    wprint(buf);
}
static void move_xy(int r, int c) { wprintf2(ESC "[%d;%dH", r, c); }
static void clr_line(void)        { wprint(ESC "[2K"); }

static void get_console_size(int *cols, int *rows) {
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    int c = 80, r = 24;
    if (GetConsoleScreenBufferInfo(g_hOut, &csbi)) {
        c = csbi.srWindow.Right  - csbi.srWindow.Left + 1;
        r = csbi.srWindow.Bottom - csbi.srWindow.Top  + 1;
    }
    if (cols) *cols = c;
    if (rows) *rows = r;
}

static void draw_hline(int cols) {
    char line[512];
    int n = cols < (int)sizeof(line)-2 ? cols : (int)sizeof(line)-2;
    memset(line, '-', n); line[n] = '\0';
    wprint(line); wprint("\r\n");
}

// ===== コンソールモード管理 ===================================
static void tui_restore(void) {
    if (g_hIn  != INVALID_HANDLE_VALUE) SetConsoleMode(g_hIn,  g_orig_in_mode);
    if (g_hOut != INVALID_HANDLE_VALUE) SetConsoleMode(g_hOut, g_orig_out_mode);
}
static void tui_init(void) {
    g_hIn  = GetStdHandle(STD_INPUT_HANDLE);
    g_hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    GetConsoleMode(g_hIn,  &g_orig_in_mode);
    GetConsoleMode(g_hOut, &g_orig_out_mode);
    SetConsoleMode(g_hOut, ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    SetConsoleMode(g_hIn,  ENABLE_PROCESSED_INPUT  | ENABLE_EXTENDED_FLAGS);
    SetConsoleCP(CP_UTF8); SetConsoleOutputCP(CP_UTF8);
    atexit(tui_restore);
}

static DWORD g_raw_in = 0, g_raw_out = 0;
static void console_raw(void) {
    GetConsoleMode(g_hIn,  &g_raw_in);
    GetConsoleMode(g_hOut, &g_raw_out);
    // VTI: キーボード・マウスを VT シーケンスとして ReadFile に流す
    // Windows Terminal がマウス VT 形式（SGR/X10）を自動で正しく生成する
    SetConsoleMode(g_hIn,  ENABLE_VIRTUAL_TERMINAL_INPUT);
    SetConsoleMode(g_hOut, ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}
static void console_unraw(void) {
    SetConsoleMode(g_hIn,  g_raw_in);
    SetConsoleMode(g_hOut, g_raw_out);
}

// ===== UTF-8 表示幅対応 =======================================
static int utf8_display_width(unsigned cp) {
    if ((cp >= 0x1100 && cp <= 0x115F) || cp == 0x2329 || cp == 0x232A ||
        (cp >= 0x2E80 && cp <= 0xA4CF) || (cp >= 0xAC00 && cp <= 0xD7FF) ||
        (cp >= 0xF900 && cp <= 0xFAFF) || (cp >= 0xFE10 && cp <= 0xFE6F) ||
        (cp >= 0xFF01 && cp <= 0xFF60) || (cp >= 0xFFE0 && cp <= 0xFFE6))
        return 2;
    return 1;
}

static void wprint_w(const char *s, int width) {
    const unsigned char *p = (const unsigned char *)s;
    char buf[2048]; int bi = 0, used = 0;
    while (*p) {
        unsigned cp; int bytes;
        if      (*p < 0x80) { cp = *p;        bytes = 1; }
        else if (*p < 0xE0) { cp = *p & 0x1F; bytes = 2; }
        else if (*p < 0xF0) { cp = *p & 0x0F; bytes = 3; }
        else                { cp = *p & 0x07;  bytes = 4; }
        for (int i = 1; i < bytes && p[i]; i++) cp = (cp << 6) | (p[i] & 0x3F);
        int cw = utf8_display_width(cp);
        if (used + cw > width) break;
        if (bi + bytes < (int)sizeof(buf) - 1) { memcpy(buf + bi, p, bytes); bi += bytes; }
        used += cw; p += bytes;
    }
    buf[bi] = '\0';
    wprint(buf);
    int pad = width - used;
    if (pad > 0) {
        char spaces[512];
        if (pad > (int)sizeof(spaces)-1) pad = (int)sizeof(spaces)-1;
        memset(spaces, ' ', pad); spaces[pad] = '\0';
        wprint(spaces);
    }
}

// ===== キー入力 ===============================================
#define KEY_UP       1001
#define KEY_DOWN     1002
#define KEY_ENTER    13
#define KEY_ESC      27
#define KEY_TAB      9
#define KEY_F5       1005
#define KEY_F6       1006
#define KEY_F8       1008
#define KEY_RESIZE   1009
#define KEY_SHIFT_UP   1010
#define KEY_SHIFT_DOWN 1011
#define KEY_HOTKEY     1012  // ファイラー起動キー（ファイラー内では終了キー）

static int read_key(void) {
    INPUT_RECORD ir; DWORD n;
    while (1) {
        ReadConsoleInput(g_hIn, &ir, 1, &n);
        if (n == 0) return 0;
        if (ir.EventType == WINDOW_BUFFER_SIZE_EVENT) return KEY_RESIZE;
        if (ir.EventType != KEY_EVENT || !ir.Event.KeyEvent.bKeyDown) continue;
        KEY_EVENT_RECORD *ke = &ir.Event.KeyEvent;
        // ホットキー検出（ファイラー内で同じキーを押すと終了）
        if (g_filer_vk  && ke->wVirtualKeyCode == g_filer_vk)     return KEY_HOTKEY;
        if (g_filer_ctrl_char && ke->uChar.AsciiChar == g_filer_ctrl_char) return KEY_HOTKEY;
        switch (ke->wVirtualKeyCode) {
            case VK_UP:
                return (ke->dwControlKeyState & SHIFT_PRESSED) ? KEY_SHIFT_UP : KEY_UP;
            case VK_DOWN:
                return (ke->dwControlKeyState & SHIFT_PRESSED) ? KEY_SHIFT_DOWN : KEY_DOWN;
            case VK_ESCAPE: return KEY_ESC;
            case VK_RETURN: return KEY_ENTER;
            case VK_TAB:    return KEY_TAB;
            case VK_F5:     return KEY_F5;
            case VK_F6:     return KEY_F6;
            case VK_F8:     return KEY_F8;
            case VK_DELETE: return KEY_F8;
            default:
                if (ke->uChar.AsciiChar) return (unsigned char)ke->uChar.AsciiChar;
        }
    }
}

static void readline_field(const char *prompt, char *dst, size_t dstsz, int secret) {
    wprint(prompt);
    DWORD mode = ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT;
    if (secret) mode &= ~ENABLE_ECHO_INPUT;
    SetConsoleMode(g_hIn, mode);
    char tmp[512]; DWORD n;
    ReadFile(g_hIn, tmp, (DWORD)(sizeof(tmp) - 1), &n, NULL);
    SetConsoleMode(g_hIn, ENABLE_PROCESSED_INPUT | ENABLE_EXTENDED_FLAGS);
    while (n > 0 && (tmp[n-1] == '\r' || tmp[n-1] == '\n')) n--;
    tmp[n] = '\0';
    if (secret) wprint("\r\n");
    if (tmp[0]) safe_copy(dst, dstsz, tmp);
}

// ===== 接続先マネージャー =====================================
static void draw_manager(int sel) {
    int cols; get_console_size(&cols, NULL);
    wprint(CLEAR C_TITLE " SSH Connection Manager\r\n" RESET);
    wprint(C_DIM " Up/Down:Select  Shift+Up/Down:Reorder  Enter:Connect"
                 "  N:New  E:Edit  D:Delete  Q:Quit\r\n");
    draw_hline(cols); wprint(RESET);
    if (g_conn_count == 0) {
        wprint(C_DIM "  (No connections. Press N to add.)\r\n" RESET);
    } else {
        for (int i = 0; i < g_conn_count; i++) {
            Connection *c = &g_conns[i];
            char addr[128];
            snprintf(addr, sizeof(addr), "%s@%s:%d", c->user, c->host, c->port);
            if (i == sel) wprint(C_SEL);
            wprintf2("  %-20s  %-36s  ", c->name, addr);
            wprint(c->auth_type == AUTH_PUBKEY ? C_YEL "[key]" RESET
                                               : C_DIM "[pw] " RESET);
            if (i == sel) wprint(RESET);
            wprint("\r\n");
        }
    }
    wprint("\r\n" C_DIM); draw_hline(cols); wprint(RESET);
}

static void edit_connection(Connection *c, int is_new) {
    int cols; get_console_size(&cols, NULL);
    wprint(CLEAR);
    wprint(is_new ? C_TITLE " Add New Connection\r\n" RESET
                  : C_TITLE " Edit Connection\r\n"    RESET);
    wprint(C_DIM); draw_hline(cols);
    wprint(" (Press Enter to keep current value)\r\n\r\n" RESET);
    char prompt[640];
    snprintf(prompt, sizeof(prompt), " %-16s [%.50s] : ", "Name", c->name);
    readline_field(prompt, c->name, sizeof(c->name), 0);
    snprintf(prompt, sizeof(prompt), " %-16s [%.200s] : ", "Host/IP", c->host);
    readline_field(prompt, c->host, sizeof(c->host), 0);
    char port_tmp[16] = {0};
    snprintf(prompt, sizeof(prompt), " %-16s [%d] : ", "Port", c->port);
    readline_field(prompt, port_tmp, sizeof(port_tmp), 0);
    if (port_tmp[0]) c->port = atoi(port_tmp);
    snprintf(prompt, sizeof(prompt), " %-16s [%.50s] : ", "User", c->user);
    readline_field(prompt, c->user, sizeof(c->user), 0);
    wprint("\r\n");
    while (1) {
        wprintf2(" Auth [%s] (P=Password / K=Pubkey) : ",
                 c->auth_type == AUTH_PUBKEY ? "Pubkey" : "Password");
        SetConsoleMode(g_hIn, ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT);
        char ch[4]; DWORD n; ReadFile(g_hIn, ch, sizeof(ch), &n, NULL);
        SetConsoleMode(g_hIn, ENABLE_PROCESSED_INPUT | ENABLE_EXTENDED_FLAGS);
        if (!n || ch[0] == '\r' || ch[0] == '\n') break;
        if (ch[0] == 'p' || ch[0] == 'P') { c->auth_type = AUTH_PASSWORD; break; }
        if (ch[0] == 'k' || ch[0] == 'K') { c->auth_type = AUTH_PUBKEY;   break; }
    }
    wprint("\r\n");
    if (c->auth_type == AUTH_PASSWORD) {
        snprintf(prompt, sizeof(prompt), " %-16s [%s] : ",
                 "Password", c->pass[0] ? "********" : "");
        readline_field(prompt, c->pass, sizeof(c->pass), 1);
        c->keyfile[0] = c->passphrase[0] = '\0';
    } else {
        snprintf(prompt, sizeof(prompt), " %-16s [%.50s] : ", "Private Key", c->keyfile);
        readline_field(prompt, c->keyfile, sizeof(c->keyfile), 0);
        snprintf(prompt, sizeof(prompt), " %-16s [%s] : ",
                 "Passphrase", c->passphrase[0] ? "********" : "(none)");
        readline_field(prompt, c->passphrase, sizeof(c->passphrase), 1);
        c->pass[0] = '\0';
    }
}

static void mgr_add(void) {
    if (g_conn_count >= MAX_CONNECTIONS) return;
    Connection *c = &g_conns[g_conn_count];
    memset(c, 0, sizeof(*c)); c->port = 22;
    edit_connection(c, 1);
    if (c->host[0] && c->user[0]) {
        g_conn_count++; save_connections();
        wprint(C_OK "\r\n Saved.\r\n" RESET);
    } else {
        wprint(C_ERR "\r\n host/user is empty, not saved.\r\n" RESET);
    }
    Sleep(800);
}
static void mgr_edit(int idx) {
    if (idx < 0 || idx >= g_conn_count) return;
    edit_connection(&g_conns[idx], 0);
    save_connections();
    wprint(C_OK "\r\n Saved.\r\n" RESET); Sleep(800);
}
static void mgr_del(int idx) {
    if (idx < 0 || idx >= g_conn_count) return;
    for (int i = idx; i < g_conn_count - 1; i++) g_conns[i] = g_conns[i+1];
    g_conn_count--; save_connections();
}

static Connection *run_manager(void) {
    int sel = 0;
    while (1) {
        if (sel >= g_conn_count) sel = g_conn_count - 1;
        if (sel < 0) sel = 0;
        draw_manager(sel);
        switch (read_key()) {
        case KEY_UP:   if (sel > 0) sel--; break;
        case KEY_DOWN: if (sel < g_conn_count - 1) sel++; break;
        case KEY_SHIFT_UP:
            if (sel > 0) {
                Connection tmp = g_conns[sel];
                g_conns[sel] = g_conns[sel-1]; g_conns[sel-1] = tmp;
                sel--; save_connections();
            }
            break;
        case KEY_SHIFT_DOWN:
            if (sel < g_conn_count - 1) {
                Connection tmp = g_conns[sel];
                g_conns[sel] = g_conns[sel+1]; g_conns[sel+1] = tmp;
                sel++; save_connections();
            }
            break;
        case KEY_ENTER:  if (g_conn_count > 0) return &g_conns[sel]; break;
        case KEY_RESIZE: break;
        case 'n': case 'N': mgr_add();     break;
        case 'e': case 'E': mgr_edit(sel); break;
        case 'd': case 'D': if (g_conn_count > 0) mgr_del(sel); break;
        case 'q': case 'Q': case KEY_ESC: return NULL;
        }
    }
}

// ===== SFTP ファイラー ========================================
static void fmt_size(uint64_t sz, char *out, size_t n) {
    if      (sz >= (uint64_t)1 << 30) snprintf(out, n, "%.1fG", sz / (double)(1<<30));
    else if (sz >= (uint64_t)1 << 20) snprintf(out, n, "%.1fM", sz / (double)(1<<20));
    else if (sz >= (uint64_t)1 << 10) snprintf(out, n, "%.1fK", sz / (double)(1<<10));
    else                              snprintf(out, n, "%llu",   (unsigned long long)sz);
}

static int entry_cmp(const void *a, const void *b) {
    const FilerEntry *ea = a, *eb = b;
    if (strcmp(ea->name, "..") == 0) return -1;
    if (strcmp(eb->name, "..") == 0) return  1;
    if (ea->is_dir != eb->is_dir) return eb->is_dir - ea->is_dir;
    return strcmp(ea->name, eb->name);
}

static int list_local(FilerPane *p) {
    p->count = 0;
    if (p->path[0] == '\0') {
        // ドライブ一覧モード
        DWORD mask = GetLogicalDrives();
        for (int d = 0; d < 26; d++) {
            if (!(mask & (1 << d))) continue;
            FilerEntry *e = &p->entries[p->count];
            snprintf(e->name, sizeof(e->name), "%c:", 'A' + d);
            e->is_dir = 1; e->size = 0; e->date[0] = '\0';
            if (++p->count >= FILER_MAX) break;
        }
        return 0;
    }
    // ".." を必ず追加（ドライブルートは FindFirstFile が返さないため）
    { FilerEntry *e = &p->entries[p->count];
      safe_copy(e->name, sizeof(e->name), "..");
      e->is_dir = 1; e->size = 0; e->date[0] = '\0'; p->count++; }

    char search[1200]; snprintf(search, sizeof(search), "%s\\*", p->path);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(search, &fd);
    if (h == INVALID_HANDLE_VALUE) return -1;
    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
        FilerEntry *e = &p->entries[p->count];
        safe_copy(e->name, sizeof(e->name), fd.cFileName);
        e->is_dir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        e->size   = ((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
        SYSTEMTIME st; FileTimeToSystemTime(&fd.ftLastWriteTime, &st);
        snprintf(e->date, sizeof(e->date), "%04u-%02u-%02u",
                 st.wYear % 10000, st.wMonth % 100, st.wDay % 100);
        if (++p->count >= FILER_MAX) break;
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    qsort(p->entries, p->count, sizeof(FilerEntry), entry_cmp);
    return 0;
}

static int list_remote(FilerPane *p, LIBSSH2_SESSION *session, LIBSSH2_SFTP *sftp) {
    p->count = 0;
    LIBSSH2_SFTP_HANDLE *dh;
    while (!(dh = libssh2_sftp_opendir(sftp, p->path))) {
        if (libssh2_session_last_error(session, NULL, NULL, 0) != LIBSSH2_ERROR_EAGAIN)
            return -1;
        Sleep(10);
    }
    char name[512]; LIBSSH2_SFTP_ATTRIBUTES attrs;
    while (p->count < FILER_MAX) {
        int rc;
        while ((rc = libssh2_sftp_readdir(dh, name, sizeof(name), &attrs))
               == LIBSSH2_ERROR_EAGAIN) Sleep(10);
        if (rc <= 0) break;
        if (strcmp(name, ".") == 0) continue;
        FilerEntry *e = &p->entries[p->count];
        safe_copy(e->name, sizeof(e->name), name);
        e->is_dir = LIBSSH2_SFTP_S_ISDIR(attrs.permissions);
        e->size   = (attrs.flags & LIBSSH2_SFTP_ATTR_SIZE) ? attrs.filesize : 0;
        if (attrs.flags & LIBSSH2_SFTP_ATTR_ACMODTIME) {
            time_t t = attrs.mtime; struct tm *tm = gmtime(&t);
            strftime(e->date, sizeof(e->date), "%Y-%m-%d", tm);
        } else safe_copy(e->date, sizeof(e->date), "----------");
        p->count++;
    }
    libssh2_sftp_closedir(dh);
    qsort(p->entries, p->count, sizeof(FilerEntry), entry_cmp);
    return 0;
}

static void pane_up(FilerPane *p) {
    if (p->is_remote) {
        if (strcmp(p->path, "/") == 0) return;
        char *last = strrchr(p->path, '/');
        if (!last) return;
        if (last == p->path) { last[1] = '\0'; return; }
        *last = '\0';
    } else {
        if (p->path[0] == '\0') return;
        char *last = strrchr(p->path, '\\');
        if (!last) return;
        if (last == p->path + 2 && p->path[1] == ':') { p->path[0] = '\0'; return; }
        *last = '\0';
        if (strlen(p->path) == 2 && p->path[1] == ':') strcat(p->path, "\\");
    }
}

static void pane_enter(FilerPane *p, const char *dir) {
    char tmp[1024]; size_t l = strlen(p->path);
    if (p->is_remote) {
        // ルート "/" のとき末尾スラッシュ除去不要、それ以外は除去
        if (l > 1 && p->path[l-1] == '/') p->path[l-1] = '\0';
        if (strcmp(p->path, "") == 0)  // ルートだった場合
            snprintf(tmp, sizeof(tmp), "/%s", dir);
        else
            snprintf(tmp, sizeof(tmp), "%s/%s", p->path, dir);
    } else if (p->path[0] == '\0') {
        snprintf(tmp, sizeof(tmp), "%s\\", dir);  // "C:" → "C:\"
    } else {
        if (l > 3 && p->path[l-1] == '\\') p->path[l-1] = '\0';
        snprintf(tmp, sizeof(tmp), "%s\\%s", p->path, dir);
    }
    safe_copy(p->path, sizeof(p->path), tmp);
}

static void pane_reload(FilerPane *p, LIBSSH2_SESSION *session, LIBSSH2_SFTP *sftp) {
    if (p->is_remote) list_remote(p, session, sftp);
    else              list_local(p);
    if (p->selected >= p->count) p->selected = p->count > 0 ? p->count - 1 : 0;
    memset(p->marked, 0, sizeof(p->marked));  // リロード時はマークをクリア
}

// ===== ファイル転送 ===========================================
static int upload_file(const char *lpath, const char *rpath,
                       LIBSSH2_SESSION *session, LIBSSH2_SFTP *sftp) {
    FILE *f = fopen(lpath, "rb"); if (!f) return -1;
    LIBSSH2_SFTP_HANDLE *rh;
    while (!(rh = libssh2_sftp_open(sftp, rpath,
                 LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC,
                 LIBSSH2_SFTP_S_IRUSR | LIBSSH2_SFTP_S_IWUSR |
                 LIBSSH2_SFTP_S_IRGRP | LIBSSH2_SFTP_S_IROTH))) {
        if (libssh2_session_last_error(session, NULL, NULL, 0) != LIBSSH2_ERROR_EAGAIN)
            { fclose(f); return -1; }
        Sleep(10);
    }
    char buf[32768]; size_t nr; int ok = 0;
    while ((nr = fread(buf, 1, sizeof(buf), f)) > 0) {
        size_t sent = 0;
        while (sent < nr) {
            int rc;
            while ((rc = libssh2_sftp_write(rh, buf+sent, nr-sent)) == LIBSSH2_ERROR_EAGAIN)
                Sleep(10);
            if (rc < 0) { ok = -1; goto up_done; }
            sent += rc;
        }
    }
up_done:
    libssh2_sftp_close(rh); fclose(f); return ok;
}

static int download_file(const char *rpath, const char *lpath,
                         LIBSSH2_SESSION *session, LIBSSH2_SFTP *sftp) {
    LIBSSH2_SFTP_HANDLE *rh;
    while (!(rh = libssh2_sftp_open(sftp, rpath, LIBSSH2_FXF_READ, 0))) {
        if (libssh2_session_last_error(session, NULL, NULL, 0) != LIBSSH2_ERROR_EAGAIN)
            return -1;
        Sleep(10);
    }
    FILE *f = fopen(lpath, "wb");
    if (!f) { libssh2_sftp_close(rh); return -1; }
    char buf[32768]; int rc, ok = 0;
    while (1) {
        while ((rc = libssh2_sftp_read(rh, buf, sizeof(buf))) == LIBSSH2_ERROR_EAGAIN)
            Sleep(10);
        if (rc == 0) break;
        if (rc < 0) { ok = -1; break; }
        fwrite(buf, 1, rc, f);
    }
    libssh2_sftp_close(rh); fclose(f);
    if (ok < 0) DeleteFileA(lpath);
    return ok;
}

// ===== ディレクトリ操作（再帰） ===============================
static int delete_local_recursive(const char *path) {
    char search[1200]; snprintf(search, sizeof(search), "%s\\*", path);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(search, &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
            char child[1200]; snprintf(child, sizeof(child), "%s\\%s", path, fd.cFileName);
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                delete_local_recursive(child);
            else DeleteFileA(child);
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
    return RemoveDirectoryA(path) ? 0 : -1;
}

static int delete_remote_recursive(const char *path,
                                   LIBSSH2_SESSION *session, LIBSSH2_SFTP *sftp) {
    LIBSSH2_SFTP_HANDLE *dh;
    while (!(dh = libssh2_sftp_opendir(sftp, path))) {
        if (libssh2_session_last_error(session, NULL, NULL, 0) != LIBSSH2_ERROR_EAGAIN)
            return -1;
        Sleep(10);
    }
    char name[512]; LIBSSH2_SFTP_ATTRIBUTES attrs;
    while (1) {
        int rc;
        while ((rc = libssh2_sftp_readdir(dh, name, sizeof(name), &attrs))
               == LIBSSH2_ERROR_EAGAIN) Sleep(10);
        if (rc <= 0) break;
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) continue;
        char child[1200]; snprintf(child, sizeof(child), "%s/%s", path, name);
        if (LIBSSH2_SFTP_S_ISDIR(attrs.permissions))
            delete_remote_recursive(child, session, sftp);
        else { int rc; while ((rc=libssh2_sftp_unlink(sftp,child))==LIBSSH2_ERROR_EAGAIN) Sleep(10); }
    }
    libssh2_sftp_closedir(dh);
    int rc;
    while ((rc = libssh2_sftp_rmdir(sftp, path)) == LIBSSH2_ERROR_EAGAIN) Sleep(10);
    return rc;
}

static int upload_dir(const char *lpath, const char *rpath,
                      LIBSSH2_SESSION *session, LIBSSH2_SFTP *sftp) {
    while (libssh2_sftp_mkdir(sftp, rpath, SFTP_DIR_MODE) == LIBSSH2_ERROR_EAGAIN) Sleep(10);
    char search[1200]; snprintf(search, sizeof(search), "%s\\*", lpath);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(search, &fd);
    if (h == INVALID_HANDLE_VALUE) return -1;
    int ok = 0;
    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
        char lc[1200], rc2[1200];
        snprintf(lc,  sizeof(lc),  "%s\\%s", lpath, fd.cFileName);
        snprintf(rc2, sizeof(rc2), "%s/%s",  rpath, fd.cFileName);
        ok |= (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            ? upload_dir(lc, rc2, session, sftp)
            : upload_file(lc, rc2, session, sftp);
    } while (FindNextFileA(h, &fd));
    FindClose(h); return ok;
}

static int download_dir(const char *rpath, const char *lpath,
                        LIBSSH2_SESSION *session, LIBSSH2_SFTP *sftp) {
    CreateDirectoryA(lpath, NULL);
    LIBSSH2_SFTP_HANDLE *dh;
    while (!(dh = libssh2_sftp_opendir(sftp, rpath))) {
        if (libssh2_session_last_error(session, NULL, NULL, 0) != LIBSSH2_ERROR_EAGAIN)
            return -1;
        Sleep(10);
    }
    char name[512]; LIBSSH2_SFTP_ATTRIBUTES attrs; int ok = 0;
    while (1) {
        int rc;
        while ((rc = libssh2_sftp_readdir(dh, name, sizeof(name), &attrs))
               == LIBSSH2_ERROR_EAGAIN) Sleep(10);
        if (rc <= 0) break;
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) continue;
        char rc2[1200], lc[1200];
        snprintf(rc2, sizeof(rc2), "%s/%s",  rpath, name);
        snprintf(lc,  sizeof(lc),  "%s\\%s", lpath, name);
        ok |= LIBSSH2_SFTP_S_ISDIR(attrs.permissions)
            ? download_dir(rc2, lc, session, sftp)
            : download_file(rc2, lc, session, sftp);
    }
    libssh2_sftp_closedir(dh); return ok;
}

static int copy_remote_dir(const char *src, const char *dst,
                           LIBSSH2_SESSION *session, LIBSSH2_SFTP *sftp) {
    while (libssh2_sftp_mkdir(sftp, dst, SFTP_DIR_MODE) == LIBSSH2_ERROR_EAGAIN) Sleep(10);
    LIBSSH2_SFTP_HANDLE *dh;
    while (!(dh = libssh2_sftp_opendir(sftp, src))) {
        if (libssh2_session_last_error(session, NULL, NULL, 0) != LIBSSH2_ERROR_EAGAIN)
            return -1;
        Sleep(10);
    }
    char tmpdir[MAX_PATH]; GetTempPathA(MAX_PATH, tmpdir);
    char name[512]; LIBSSH2_SFTP_ATTRIBUTES attrs; int ok = 0;
    while (1) {
        int rc;
        while ((rc = libssh2_sftp_readdir(dh, name, sizeof(name), &attrs))
               == LIBSSH2_ERROR_EAGAIN) Sleep(10);
        if (rc <= 0) break;
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) continue;
        char sc[1200], dc[1200];
        snprintf(sc, sizeof(sc), "%s/%s", src, name);
        snprintf(dc, sizeof(dc), "%s/%s", dst, name);
        if (LIBSSH2_SFTP_S_ISDIR(attrs.permissions)) {
            ok |= copy_remote_dir(sc, dc, session, sftp);
        } else {
            char tmpf[MAX_PATH + 216];
            snprintf(tmpf, sizeof(tmpf), "%s\\sftp_tmp_%.200s", tmpdir, name);
            if (download_file(sc, tmpf, session, sftp) == 0)
                ok |= upload_file(tmpf, dc, session, sftp);
            DeleteFileA(tmpf);
        }
    }
    libssh2_sftp_closedir(dh); return ok;
}

static int copy_local_dir(const char *src, const char *dst) {
    CreateDirectoryA(dst, NULL);
    char search[1200]; snprintf(search, sizeof(search), "%s\\*", src);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(search, &fd);
    if (h == INVALID_HANDLE_VALUE) return -1;
    int ok = 0;
    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
        char sc[1200], dc[1200];
        snprintf(sc, sizeof(sc), "%s\\%s", src, fd.cFileName);
        snprintf(dc, sizeof(dc), "%s\\%s", dst, fd.cFileName);
        ok |= (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            ? copy_local_dir(sc, dc)
            : (CopyFileA(sc, dc, FALSE) ? 0 : -1);
    } while (FindNextFileA(h, &fd));
    FindClose(h); return ok;
}

// ===== ファイラー描画 =========================================
static void draw_filer_entry(FilerPane *p, int idx, int is_active, int col, int w, int visible) {
    int r = idx - p->scroll;
    if (r < 0 || r >= visible) return;
    move_xy(r + 2, col);
    if (idx >= p->count) {
        char blank[512];
        int n = w < (int)sizeof(blank)-1 ? w : (int)sizeof(blank)-1;
        memset(blank, ' ', n); blank[n] = '\0'; wprint(blank); return;
    }
    FilerEntry *e = &p->entries[idx];
    int name_w = w - 23; if (name_w < 6) name_w = 6;
    char spart[12];
    if (e->is_dir) snprintf(spart, sizeof(spart), "%-9s", "<DIR>");
    else           fmt_size(e->size, spart, sizeof(spart));
    int is_sel    = (idx == p->selected);
    int is_marked = p->marked[idx];
    if      (is_sel && is_active) wprint(C_SEL);
    else if (is_sel)              wprint(C_DIM C_SEL);
    else if (is_marked)           wprint(C_YEL);
    else if (e->is_dir)           wprint(g_dir_color);
    // マーク中: {dir} / *file*、通常: [dir] /  file
    wprint(is_marked ? (e->is_dir ? "{" : "*") : (e->is_dir ? "[" : " "));
    wprint_w(e->name, name_w - 2);
    wprint(is_marked ? (e->is_dir ? "}" : "*") : (e->is_dir ? "]" : " "));
    wprintf2(" %9s %10s ", spart, e->date);
    wprint(RESET);
}

static void draw_filer_pane(FilerPane *p, int is_active, int col, int w, int visible) {
    move_xy(1, col);
    if (is_active) wprint(C_TITLE);
    char hdr[1200];
    snprintf(hdr, sizeof(hdr), "[%s] %s",
             p->is_remote ? "Remote" : "Local",
             p->path[0] ? p->path : "My Computer");
    wprint_w(hdr, w);
    wprint(RESET);
    for (int r = 0; r < visible; r++)
        draw_filer_entry(p, p->scroll + r, is_active, col, w, visible);
}

static void draw_filer(FilerPane panes[2], int active, int cols, int rows) {
    int w = (cols - 1) / 2, visible = rows - 3;
    wprint(ESC "[?25l" ESC "[H");
    draw_filer_pane(&panes[0], active == 0, 1,   w,        visible);
    draw_filer_pane(&panes[1], active == 1, w+2, cols-w-1, visible);
    for (int r = 1; r <= rows - 2; r++) { move_xy(r, w+1); wprint(C_DIM "|" RESET); }
    move_xy(rows-1, 1); wprint(C_DIM); draw_hline(cols); wprint(RESET);
    move_xy(rows, 1); clr_line();
    wprintf2(C_DIM " Space:Mark  Ctrl+A:全選択  Tab:Switch  Enter:Open  F5:Copy  F6:Move  F8:Delete  F12/Q/Esc:Close" RESET);
    wprint(ESC "[?25h");
}

static void update_selection(FilerPane panes[2], int active, int old_sel, int cols, int rows) {
    int w = (cols - 1) / 2, visible = rows - 3;
    int col = (active == 0) ? 1 : w + 2;
    int pw  = (active == 0) ? w : cols - w - 1;
    FilerPane *ap = &panes[active];
    wprint(ESC "[?25l");
    draw_filer_entry(ap, old_sel,      1, col, pw, visible);
    draw_filer_entry(ap, ap->selected, 1, col, pw, visible);
    wprint(ESC "[?25h");
}

static void filer_status(int rows, const char *color, const char *msg) {
    move_xy(rows, 1); clr_line(); wprint(color); wprint(msg); wprint(RESET);
}

// マーク数カウント
static int pane_marked_count(FilerPane *p) {
    int n = 0;
    for (int i = 0; i < p->count; i++) if (p->marked[i]) n++;
    return n;
}

// ===== LS_COLORS からフォルダ色を取得 ========================
static void detect_dir_color(LIBSSH2_SESSION *session) {
    LIBSSH2_CHANNEL *ch;
    while (!(ch = libssh2_channel_open_session(session))) {
        if (libssh2_session_last_error(session, NULL, NULL, 0) != LIBSSH2_ERROR_EAGAIN)
            return;
        Sleep(10);
    }
    int rc;
    while ((rc = libssh2_channel_exec(ch, "echo $LS_COLORS")) == LIBSSH2_ERROR_EAGAIN)
        Sleep(10);
    if (rc != 0) { libssh2_channel_free(ch); return; }
    char buf[4096] = {0}; int total = 0;
    while (total < (int)sizeof(buf) - 1) {
        int n;
        while ((n = libssh2_channel_read(ch, buf + total, sizeof(buf) - 1 - total))
               == LIBSSH2_ERROR_EAGAIN) Sleep(10);
        if (n <= 0) break;
        total += n;
    }
    libssh2_channel_send_eof(ch);
    libssh2_channel_wait_eof(ch);
    libssh2_channel_wait_closed(ch);
    libssh2_channel_free(ch);
    const char *p = strstr(buf, "di=");
    if (!p) return;
    p += 3;
    char code[36]; int i = 0;
    while (*p && *p != ':' && *p != '\n' && *p != '\r' && i < 34) code[i++] = *p++;
    code[i] = '\0';
    if (i > 0) snprintf(g_dir_color, sizeof(g_dir_color), ESC "[%sm", code);
}

// ===== ファイラーメインループ =================================
static void run_filer(LIBSSH2_SESSION *session, Connection *c) {
    detect_dir_color(session);

    LIBSSH2_SFTP *sftp;
    while (!(sftp = libssh2_sftp_init(session))) {
        if (libssh2_session_last_error(session, NULL, NULL, 0) != LIBSSH2_ERROR_EAGAIN)
            { wprint(C_ERR " SFTP init failed\r\n" RESET); Sleep(1500); return; }
        Sleep(10);
    }

    FilerPane panes[2]; memset(panes, 0, sizeof(panes));
    panes[0].is_remote = 0; GetCurrentDirectoryA(sizeof(panes[0].path), panes[0].path);
    panes[1].is_remote = 1; snprintf(panes[1].path, sizeof(panes[1].path), "/home/%s", c->user);
    list_local(&panes[0]);
    if (list_remote(&panes[1], session, sftp) < 0) {
        safe_copy(panes[1].path, sizeof(panes[1].path), "/");
        list_remote(&panes[1], session, sftp);
    }

    int cols, rows; get_console_size(&cols, &rows);
    int visible = rows - 3, active = 0;
    // vim 等が代替スクリーン未使用 → 代替スクリーンで元画面を保存・復元
    // vim 使用中（代替スクリーンをネストできない）→ 上書きし SIGWINCH で再描画
    int use_alt = !g_in_alt_screen;
    if (use_alt) wprint(ESC "[?1049h");
    wprint(ESC "[?25l" CLEAR ESC "[?25h");
    draw_filer(panes, active, cols, rows);

    while (1) {
        int key = read_key();
        FilerPane *ap = &panes[active];
        FilerPane *op = &panes[1 - active];
        int need_redraw = 1;

        switch (key) {
        case KEY_ESC: case 'q': case 'Q': case KEY_HOTKEY: goto filer_done;

        case KEY_RESIZE:
            get_console_size(&cols, &rows); visible = rows - 3; break;

        case KEY_TAB: active = 1 - active; break;

        case KEY_UP: {
            if (ap->selected > 0) {
                int old = ap->selected--;
                if (ap->selected < ap->scroll) ap->scroll--;
                else { update_selection(panes, active, old, cols, rows); need_redraw = 0; }
            } else need_redraw = 0;
            break;
        }
        case KEY_DOWN: {
            if (ap->selected < ap->count - 1) {
                int old = ap->selected++;
                if (ap->selected >= ap->scroll + visible) ap->scroll++;
                else { update_selection(panes, active, old, cols, rows); need_redraw = 0; }
            } else need_redraw = 0;
            break;
        }

        case KEY_ENTER: {
            if (ap->count == 0) break;
            FilerEntry *e = &ap->entries[ap->selected];
            if (!e->is_dir) break;
            if (strcmp(e->name, "..") == 0) pane_up(ap);
            else pane_enter(ap, e->name);
            ap->selected = ap->scroll = 0;
            pane_reload(ap, session, sftp);
            break;
        }

        case KEY_F5:
        case KEY_F6: {
            if (ap->count == 0) break;
            int mc = pane_marked_count(ap);
            int err = 0;
            for (int idx = 0; idx < ap->count; idx++) {
                if (mc ? !ap->marked[idx] : idx != ap->selected) continue;
                FilerEntry *e = &ap->entries[idx];
                if (strcmp(e->name, "..") == 0) continue;
                char smsg[280];
                snprintf(smsg, sizeof(smsg), " %s: %s ...", key==KEY_F5?"Copy":"Move", e->name);
                filer_status(rows, C_DIM, smsg);
                int ok = -1;
                char src[1200], dst[1200];
                if (!ap->is_remote && op->is_remote) {
                    snprintf(src, sizeof(src), "%s\\%s", ap->path, e->name);
                    snprintf(dst, sizeof(dst), "%s/%s",  op->path, e->name);
                    ok = e->is_dir ? upload_dir(src,dst,session,sftp)
                                   : upload_file(src,dst,session,sftp);
                    if (ok==0 && key==KEY_F6)
                        e->is_dir ? (void)delete_local_recursive(src) : (void)DeleteFileA(src);
                } else if (ap->is_remote && !op->is_remote) {
                    snprintf(src, sizeof(src), "%s/%s",  ap->path, e->name);
                    snprintf(dst, sizeof(dst), "%s\\%s", op->path, e->name);
                    ok = e->is_dir ? download_dir(src,dst,session,sftp)
                                   : download_file(src,dst,session,sftp);
                    if (ok==0 && key==KEY_F6) {
                        if (e->is_dir) delete_remote_recursive(src,session,sftp);
                        else { int rc; while ((rc=libssh2_sftp_unlink(sftp,src))==LIBSSH2_ERROR_EAGAIN) Sleep(10); }
                    }
                } else if (ap->is_remote && op->is_remote) {
                    snprintf(src, sizeof(src), "%s/%s", ap->path, e->name);
                    snprintf(dst, sizeof(dst), "%s/%s", op->path, e->name);
                    if (key==KEY_F6 && !e->is_dir) {
                        int rc;
                        while ((rc=libssh2_sftp_rename(sftp,src,dst))==LIBSSH2_ERROR_EAGAIN) Sleep(10);
                        ok = rc==0 ? 0 : -1;
                    } else {
                        ok = copy_remote_dir(src,dst,session,sftp);
                        if (ok==0 && key==KEY_F6) delete_remote_recursive(src,session,sftp);
                    }
                } else {
                    snprintf(src, sizeof(src), "%s\\%s", ap->path, e->name);
                    snprintf(dst, sizeof(dst), "%s\\%s", op->path, e->name);
                    ok = e->is_dir ? copy_local_dir(src,dst)
                                   : (CopyFileA(src,dst,FALSE) ? 0 : -1);
                    if (ok==0 && key==KEY_F6)
                        e->is_dir ? (void)delete_local_recursive(src) : (void)DeleteFileA(src);
                }
                if (ok != 0) err = 1;
            }
            memset(ap->marked, 0, sizeof(ap->marked));
            pane_reload(op, session, sftp);
            if (key == KEY_F6) pane_reload(ap, session, sftp);
            filer_status(rows, err ? C_ERR : C_OK, err ? " Error" : " Done");
            Sleep(700);
            break;
        }

        case KEY_F8: {
            if (ap->count == 0) break;
            int mc = pane_marked_count(ap);
            char cmsg[600];
            if (mc > 0)
                snprintf(cmsg, sizeof(cmsg), " Delete %d files  (Y to confirm)", mc);
            else {
                FilerEntry *e = &ap->entries[ap->selected];
                if (strcmp(e->name, "..") == 0) break;
                snprintf(cmsg, sizeof(cmsg), " Delete: %.200s  (Y to confirm)", e->name);
            }
            filer_status(rows, C_ERR, cmsg);
            int confirm = read_key();
            if (confirm != 'y' && confirm != 'Y') break;
            for (int idx = 0; idx < ap->count; idx++) {
                if (mc ? !ap->marked[idx] : idx != ap->selected) continue;
                FilerEntry *e = &ap->entries[idx];
                if (strcmp(e->name, "..") == 0) continue;
                char path[1200];
                if (!ap->is_remote) {
                    snprintf(path, sizeof(path), "%s\\%s", ap->path, e->name);
                    e->is_dir ? delete_local_recursive(path) : (void)DeleteFileA(path);
                } else {
                    snprintf(path, sizeof(path), "%s/%s", ap->path, e->name);
                    if (e->is_dir) delete_remote_recursive(path,session,sftp);
                    else { int rc; while ((rc=libssh2_sftp_unlink(sftp,path))==LIBSSH2_ERROR_EAGAIN) Sleep(10); }
                }
            }
            memset(ap->marked, 0, sizeof(ap->marked));
            pane_reload(ap, session, sftp);
            break;
        }

        case ' ': {
            if (ap->count == 0) { need_redraw = 0; break; }
            FilerEntry *e = &ap->entries[ap->selected];
            if (strcmp(e->name, "..") != 0)
                ap->marked[ap->selected] = !ap->marked[ap->selected];
            // マーク後に下へ移動
            if (ap->selected < ap->count - 1) ap->selected++;
            if (ap->selected >= ap->scroll + visible) ap->scroll++;
            break;
        }
        case 1: {  // Ctrl+A: 全ファイルマーク切り替え（.. を除く）
            int mc = pane_marked_count(ap);
            for (int i = 0; i < ap->count; i++) {
                if (strcmp(ap->entries[i].name, "..") == 0) continue;
                ap->marked[i] = (mc == 0) ? 1 : 0;
            }
            break;
        }
        default: need_redraw = 0; break;
        }
        if (need_redraw) draw_filer(panes, active, cols, rows);
    }
filer_done:
    libssh2_sftp_shutdown(sftp);
    if (use_alt) wprint(ESC "[?1049l");  // 通常シェル: 元画面を完全復元
    else         wprint(ESC "[?25h");    // vim 使用中: SIGWINCH で再描画
}

// ===== SSH スレッド ===========================================

// サーバー出力からカーソルモードと代替スクリーン使用状況を追跡
static void scan_cursor_mode(const char *buf, int n) {
    for (int i = 0; i < n - 7; i++) {  // ESC[?1049h は 8 バイト必要
        if ((unsigned char)buf[i] != 0x1b || buf[i+1] != '[' || buf[i+2] != '?') continue;
        // ESC[?1049h/l : 代替スクリーン切り替え（vim 等）
        if (buf[i+3]=='1' && buf[i+4]=='0' && buf[i+5]=='4' && buf[i+6]=='9') {
            if (buf[i+7] == 'h') { g_in_alt_screen = 1; continue; }
            if (buf[i+7] == 'l') { g_in_alt_screen = 0; continue; }
        }
    }
}

static void send_pty_size(LIBSSH2_CHANNEL*, int, int);  // forward

DWORD WINAPI recv_thread(LPVOID arg) {
    RecvArgs *a = arg;
    LIBSSH2_CHANNEL *ch = a->ch;
    char host[256]; safe_copy(host, sizeof(host), a->host);
    free(a);
    char buf[4096]; int n;
    while (g_running && !libssh2_channel_eof(ch)) {
        if (g_filer_active) {
            SetEvent(g_recv_paused);
            while (g_filer_active) Sleep(50);
            ResetEvent(g_recv_paused);
            continue;
        }
        EnterCriticalSection(&g_ssh_cs);
        n = libssh2_channel_read(ch, buf, sizeof(buf));
        LeaveCriticalSection(&g_ssh_cs);
        if (n > 0) {
            scan_cursor_mode(buf, n);
            DWORD w; WriteConsoleA(g_hOut, buf, n, &w, NULL);
        } else if (n == LIBSSH2_ERROR_EAGAIN) Sleep(10);
        else break;
    }
    g_running = 0;
    char msg[320];
    snprintf(msg, sizeof(msg), "\r\nConnection to %s closed.\r\n", host);
    DWORD w; WriteConsoleA(g_hOut, msg, (DWORD)strlen(msg), &w, NULL);
    return 0;
}

// リサイズポーリングスレッド（200ms）
DWORD WINAPI resize_thread(LPVOID arg) {
    LIBSSH2_CHANNEL *ch = arg;
    int pc = 0, pr = 0;
    get_console_size(&pc, &pr);
    while (g_running) {
        Sleep(200);
        if (g_filer_active) continue;
        int c, r; get_console_size(&c, &r);
        if (c != pc || r != pr) { pc = c; pr = r; send_pty_size(ch, c, r); }
    }
    return 0;
}

DWORD WINAPI send_thread(LPVOID arg) {
    LIBSSH2_CHANNEL *ch = arg;
    char buf[256]; DWORD nread;
    while (g_running) {
        if (!ReadFile(g_hIn, buf, sizeof(buf), &nread, NULL) || nread == 0) {
            if (g_running) continue;
            break;
        }
        // ファイラーホットキー（VT シーケンスで比較）
        if ((int)nread == g_filer_seq_len &&
            memcmp(buf, g_filer_seq, g_filer_seq_len) == 0) {
            g_filer_active = 1;
            SetEvent(g_filer_event);
            WaitForSingleObject(g_filer_done, INFINITE);
            continue;
        }
        EnterCriticalSection(&g_ssh_cs);
        int sent = 0, rc;
        while (sent < (int)nread) {
            while ((rc = libssh2_channel_write(ch, buf+sent, nread-sent))
                   == LIBSSH2_ERROR_EAGAIN) Sleep(10);
            if (rc < 0) { LeaveCriticalSection(&g_ssh_cs); g_running = 0; return 0; }
            sent += rc;
        }
        LeaveCriticalSection(&g_ssh_cs);
    }
    g_running = 0; return 0;
}

// ===== TCP 接続 ===============================================
static SOCKET connect_tcp(const char *host, int port) {
    struct addrinfo hints = {0}, *res, *rp;
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    char portstr[8]; snprintf(portstr, sizeof(portstr), "%d", port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return INVALID_SOCKET;
    SOCKET sock = INVALID_SOCKET;
    for (rp = res; rp; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock == INVALID_SOCKET) continue;
        if (connect(sock, rp->ai_addr, (int)rp->ai_addrlen) == 0) break;
        closesocket(sock); sock = INVALID_SOCKET;
    }
    freeaddrinfo(res); return sock;
}

// ===== SSH 接続メイン =========================================
// PTY サイズを送って SIGWINCH を発生させる
static void send_pty_size(LIBSSH2_CHANNEL *channel, int cols, int rows) {
    EnterCriticalSection(&g_ssh_cs);
    while (libssh2_channel_request_pty_size(channel, cols, rows)
           == LIBSSH2_ERROR_EAGAIN) Sleep(10);
    LeaveCriticalSection(&g_ssh_cs);
}

static int do_ssh(Connection *c) {
    wprintf2(CLEAR C_DIM " Connecting to %s@%s:%d [%s]...\r\n" RESET,
             c->user, c->host, c->port,
             c->auth_type == AUTH_PUBKEY ? "pubkey" : "password");

    SOCKET sock = connect_tcp(c->host, c->port);
    if (sock == INVALID_SOCKET) {
        wprint(C_ERR " TCP connect failed.\r\n" RESET); Sleep(1500); return -1;
    }

    LIBSSH2_SESSION *session = libssh2_session_init();
    libssh2_session_set_blocking(session, 0);

    int rc;
    while ((rc = libssh2_session_handshake(session, (libssh2_socket_t)sock))
           == LIBSSH2_ERROR_EAGAIN) Sleep(10);
    if (rc) { wprint(C_ERR " Handshake failed.\r\n" RESET); Sleep(1500); goto fail_session; }

    if (c->auth_type == AUTH_PUBKEY) {
        while ((rc = libssh2_userauth_publickey_fromfile(
                    session, c->user, NULL, c->keyfile,
                    c->passphrase[0] ? c->passphrase : NULL))
               == LIBSSH2_ERROR_EAGAIN) Sleep(10);
    } else {
        while ((rc = libssh2_userauth_password(session, c->user, c->pass))
               == LIBSSH2_ERROR_EAGAIN) Sleep(10);
    }
    if (rc) { wprint(C_ERR " Authentication failed.\r\n" RESET); Sleep(1500); goto fail_session; }

    LIBSSH2_CHANNEL *channel = NULL;
    while (!(channel = libssh2_channel_open_session(session))) {
        if (libssh2_session_last_error(session, NULL, NULL, 0) != LIBSSH2_ERROR_EAGAIN)
            goto fail_session;
        Sleep(10);
    }

    int cols, rows; get_console_size(&cols, &rows);
    while ((rc = libssh2_channel_request_pty_ex(channel, "xterm-256color", 14,
            NULL, 0, cols, rows, 0, 0)) == LIBSSH2_ERROR_EAGAIN) Sleep(10);
    if (rc) goto fail_channel;
    while ((rc = libssh2_channel_shell(channel)) == LIBSSH2_ERROR_EAGAIN) Sleep(10);
    if (rc) goto fail_channel;

    InitializeCriticalSection(&g_ssh_cs);
    g_filer_event = CreateEvent(NULL, TRUE,  FALSE, NULL);
    g_filer_done  = CreateEvent(NULL, FALSE, FALSE, NULL);
    g_recv_paused = CreateEvent(NULL, TRUE,  FALSE, NULL);

    g_running = 1;
    g_in_alt_screen = 0;  // 接続開始時にリセット
    console_raw();

    HANDLE threads[3];
    RecvArgs *ra = malloc(sizeof(RecvArgs));
    ra->ch = channel; safe_copy(ra->host, sizeof(ra->host), c->host);
    threads[0] = CreateThread(NULL, 0, recv_thread,   ra,      0, NULL);
    threads[1] = CreateThread(NULL, 0, send_thread,   channel, 0, NULL);
    threads[2] = CreateThread(NULL, 0, resize_thread, channel, 0, NULL);

    while (1) {
        HANDLE handles[3] = {threads[0], threads[1], g_filer_event};
        if (WaitForMultipleObjects(3, handles, FALSE, INFINITE) != WAIT_OBJECT_0 + 2) break;

        WaitForSingleObject(g_recv_paused, 500);
        console_unraw();
        SetConsoleMode(g_hIn, ENABLE_PROCESSED_INPUT | ENABLE_EXTENDED_FLAGS | ENABLE_WINDOW_INPUT);
        run_filer(session, c);
        g_filer_active = 0;
        g_in_alt_screen = 0;  // 再描画後はリセット（SIGWINCH でリモートが再設定する）
        // vim 等に再描画させる: +1 してすぐ戻すことで SIGWINCH を 2 回送る
        get_console_size(&cols, &rows);
        send_pty_size(channel, cols, rows + 1);
        Sleep(80);
        send_pty_size(channel, cols, rows);
        ResetEvent(g_filer_event);
        console_raw();
        SetEvent(g_filer_done);
    }

    g_running = 0;
    CancelIoEx(g_hIn, NULL);  // send_thread の ReadFile を解除
    WaitForSingleObject(threads[0], 3000);
    WaitForSingleObject(threads[1], 3000);
    WaitForSingleObject(threads[2], 1000);
    CloseHandle(threads[0]); CloseHandle(threads[1]); CloseHandle(threads[2]);
    CloseHandle(g_filer_event); CloseHandle(g_filer_done); CloseHandle(g_recv_paused);
    DeleteCriticalSection(&g_ssh_cs);
    console_unraw();

fail_channel:
    libssh2_channel_send_eof(channel);
    libssh2_channel_wait_closed(channel);
    libssh2_channel_free(channel);
fail_session:
    libssh2_session_disconnect(session, "Normal Shutdown");
    libssh2_session_free(session);
    closesocket(sock);
    return 0;
}

// ===== main ===================================================
static void usage(const char *prog) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s [--filer-key=KEY]                              # manager\n", prog);
    fprintf(stderr, "  %s [--filer-key=KEY] <host> <port> <user> <pass>\n", prog);
    fprintf(stderr, "  %s [--filer-key=KEY] <host> <port> <user> pubkey <keyfile> [pass]\n", prog);
    fprintf(stderr, "  KEY: f9, f10, f11, f12 (default), ctrl-g, ...\n");
}

int main(int argc, char *argv[]) {
    init_config_path();

    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--filer-key=", 12) == 0) {
            parse_hotkey(argv[i] + 12);
            for (int j = i; j < argc - 1; j++) argv[j] = argv[j+1];
            argc--; i--;
        }
    }

    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
    libssh2_init(0);
    tui_init();

    if (argc == 1) {
        load_connections();
        Connection *c = run_manager();
        if (c) { Connection copy = *c; do_ssh(&copy); }

    } else if (argc == 5) {
        Connection c = {0};
        safe_copy(c.name, sizeof(c.name), "direct");
        safe_copy(c.host, sizeof(c.host), argv[1]);
        c.port = atoi(argv[2]);
        safe_copy(c.user, sizeof(c.user), argv[3]);
        c.auth_type = AUTH_PASSWORD;
        safe_copy(c.pass, sizeof(c.pass), argv[4]);
        do_ssh(&c);

    } else if (argc >= 6 && strcmp(argv[4], "pubkey") == 0) {
        Connection c = {0};
        safe_copy(c.name,    sizeof(c.name),    "direct");
        safe_copy(c.host,    sizeof(c.host),    argv[1]);
        c.port = atoi(argv[2]);
        safe_copy(c.user,    sizeof(c.user),    argv[3]);
        c.auth_type = AUTH_PUBKEY;
        safe_copy(c.keyfile, sizeof(c.keyfile), argv[5]);
        if (argc == 7) safe_copy(c.passphrase, sizeof(c.passphrase), argv[6]);
        do_ssh(&c);

    } else {
        usage(argv[0]);
    }

    tui_restore();
    libssh2_exit();
    WSACleanup();
    return 0;
}