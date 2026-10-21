/*
 * admin_server.c - 壁垒WAF 管理平面后端
 *
 * 一个极简的 HTTP 后端：
 *   1. 静态站：产品介绍页(/)、管理控制台(/console)、演示站点(/demo)
 *   2. 演示 API：/demo/api/*（后端信息、攻击日志尾部）
 *   3. 管理 API：/api/admin/*（总览统计、站点管理、端口/参数配置、规则列表）
 *   4. 其余路径返回普通业务响应，用于演示"正常请求放行"
 *
 * 用法: bileiwaf-admin <port> [demo.html] [attack_log] [docroot]
 *   port        监听端口（默认 9000）
 *   demo.html   演示站点页（默认 web/demo.html）
 *   attack_log  WAF 攻击日志路径（默认 logs/waf-attack.log）
 *   docroot     静态站目录（默认 web）
 *
 * 配置/站点/规则目录通过 WAF_HOME 环境变量定位（默认当前目录）。
 * 所有请求应经由壁垒WAF 反向代理到达本服务，切勿直接访问后端端口。
 */

#define _GNU_SOURCE  /* strcasestr */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <stdint.h>
#include <ctype.h>
#include <signal.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <poll.h>
#include <sys/wait.h>

#include "../include/version.h"

#define RECV_BUF_SIZE   65536
#define MAX_RESPONSE    (8 * 1024 * 1024)
#define LOG_TAIL_BYTES  (64 * 1024)
#define DEFAULT_PORT    9000
#define MAX_POST_BODY   (256 * 1024)
/* 客户端 socket 读写超时（秒）：防止半开/静默连接把后端线程永久占死。
 * 后端由 WAF 的 64 个 worker 并发代理，单线程串行处理会让 worker 全部排队阻塞，
 * 因此改为 thread-per-connection 并发处理。 */
#define CLIENT_IO_TIMEOUT_SEC 10
/* 并发后端线程上限（防止异常情况下线程数失控） */
#define MAX_BACKEND_THREADS   256

static const char *g_showcase_path = "web/demo.html";
static const char *g_attack_log    = "logs/waf-attack.log";
static const char *g_docroot       = "web";
/* 管理界面目录：WAF_HOME 下与 web/ 平级的独立目录（默认 adminui），可经
 * config/admin.conf 的 admin_dir 键自定义；物理上独立于 web/ 之外，即使
 * web 静态服务出现穿越漏洞也读不到管理页面文件 */
static char g_admin_dir[96]        = "adminui";
static time_t g_start_time;

/* 后端并发连接计数与上限保护 */
static pthread_mutex_t g_thread_mutex = PTHREAD_MUTEX_INITIALIZER;
static int g_active_threads = 0;

/* 监听端口：后端平面（127.0.0.1，经 WAF 访问）与管理平面（独立端口，可直连） */
static int g_backend_port = DEFAULT_PORT;
static int g_admin_port   = 0; /* 0=未启用独立管理端口（WAF_ADMIN_PORT 环境变量） */

/* WAF_HOME：配置/规则/日志根目录 */
static const char *waf_home(void) {
    const char *h = getenv("WAF_HOME");
    return (h && h[0]) ? h : ".";
}

/* ---------------- 基础工具 ---------------- */

static void json_escape(const char *in, char *out, size_t outsz) {
    size_t oi = 0;
    for (size_t i = 0; in[i] && oi + 8 < outsz; i++) {
        unsigned char c = (unsigned char)in[i];
        switch (c) {
            case '"':  out[oi++] = '\\'; out[oi++] = '"';  break;
            case '\\': out[oi++] = '\\'; out[oi++] = '\\'; break;
            case '\n': out[oi++] = '\\'; out[oi++] = 'n';  break;
            case '\r': out[oi++] = '\\'; out[oi++] = 'r';  break;
            case '\t': out[oi++] = '\\'; out[oi++] = 't';  break;
            default:
                if (c < 0x20) {
                    oi += (size_t)snprintf(out + oi, outsz - oi, "\\u%04x", c);
                } else {
                    out[oi++] = (char)c;
                }
        }
    }
    out[oi] = '\0';
}

/* 读取整个文件到堆缓冲区（失败返回 NULL） */
static char *read_whole_file(const char *path, size_t *out_len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return NULL; }
    long sz = ftell(fp);
    if (sz < 0) { fclose(fp); return NULL; }
    rewind(fp);
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(fp); return NULL; }
    size_t rd = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);
    buf[rd] = '\0';
    if (out_len) *out_len = rd;
    return buf;
}

/* 取文本文件末尾 max_bytes 内容（用于日志尾部） */
static char *read_file_tail(const char *path, size_t max_bytes, size_t *out_len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return NULL; }
    long sz = ftell(fp);
    if (sz < 0) { fclose(fp); return NULL; }
    long off = (sz > (long)max_bytes) ? sz - (long)max_bytes : 0;
    rewind(fp);
    if (fseek(fp, off, SEEK_SET) != 0) { fclose(fp); return NULL; }
    char *buf = malloc((size_t)(sz - off) + 1);
    if (!buf) { fclose(fp); return NULL; }
    size_t rd = fread(buf, 1, (size_t)(sz - off), fp);
    fclose(fp);
    buf[rd] = '\0';
    if (out_len) *out_len = rd;
    return buf;
}

/* ---------------- HTTP 响应 ---------------- */

static void send_response(int fd, const char *status, const char *ctype,
                          const char *body, size_t blen) {
    char header[512];
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 %s\r\n"
        "Content-Type: %s; charset=utf-8\r\n"
        "Content-Length: %zu\r\n"
        "Cache-Control: no-store\r\n"
        "Connection: close\r\n"
        "\r\n",
        status, ctype, blen);
    if (hlen > 0) {
        ssize_t w = write(fd, header, (size_t)hlen);
        (void)w;
    }
    if (body && blen) {
        size_t off = 0;
        while (off < blen) {
            ssize_t w = write(fd, body + off, blen - off);
            if (w <= 0) break;
            off += (size_t)w;
        }
    }
}

static void send_json(int fd, const char *json) {
    send_response(fd, "200 OK", "application/json", json, strlen(json));
}

static void send_error(int fd, const char *status, const char *msg) {
    char body[256];
    int n = snprintf(body, sizeof(body), "{\"success\":false,\"error\":\"%s\"}", msg);
    send_response(fd, status, "application/json", body, (size_t)n);
}

/* 带附加响应头的发送（Set-Cookie 等需要） */
static void send_response_ex(int fd, const char *status, const char *ctype,
                             const char *body, size_t blen, const char *extra_hdr) {
    char header[768];
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 %s\r\n"
        "Content-Type: %s; charset=utf-8\r\n"
        "Content-Length: %zu\r\n"
        "Cache-Control: no-store\r\n"
        "%s"
        "Connection: close\r\n"
        "\r\n",
        status, ctype, blen, extra_hdr ? extra_hdr : "");
    if (hlen > 0) {
        ssize_t w = write(fd, header, (size_t)hlen);
        (void)w;
    }
    if (body && blen) {
        size_t off = 0;
        while (off < blen) {
            ssize_t w = write(fd, body + off, blen - off);
            if (w <= 0) break;
            off += (size_t)w;
        }
    }
}

/* ---------------- 认证与会话（管理后台登录） ---------------- */

/* 紧凑 SHA-256（管理平面保持零外部依赖；仅用于口令摘要） */
typedef struct { uint32_t st[8]; uint64_t bits; uint8_t buf[64]; size_t bl; } sha256_ctx;
static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
static uint32_t ror32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void sha256_transform(sha256_ctx *c, const uint8_t *p) {
    uint32_t w[64], a, b, cc, d, e, f, g, h;
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i*4] << 24) | ((uint32_t)p[i*4+1] << 16) |
               ((uint32_t)p[i*4+2] << 8) | (uint32_t)p[i*4+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ror32(w[i-15],7) ^ ror32(w[i-15],18) ^ (w[i-15] >> 3);
        uint32_t s1 = ror32(w[i-2],17) ^ ror32(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=c->st[0]; b=c->st[1]; cc=c->st[2]; d=c->st[3];
    e=c->st[4]; f=c->st[5]; g=c->st[6]; h=c->st[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ror32(e,6) ^ ror32(e,11) ^ ror32(e,25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + K256[i] + w[i];
        uint32_t S0 = ror32(a,2) ^ ror32(a,13) ^ ror32(a,22);
        uint32_t mj = (a & b) ^ (a & cc) ^ (b & cc);
        uint32_t t2 = S0 + mj;
        h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
    }
    c->st[0]+=a; c->st[1]+=b; c->st[2]+=cc; c->st[3]+=d;
    c->st[4]+=e; c->st[5]+=f; c->st[6]+=g; c->st[7]+=h;
}

static void sha256_hex(const char *in, char out[65]) {
    sha256_ctx c;
    c.st[0]=0x6a09e667; c.st[1]=0xbb67ae85; c.st[2]=0x3c6ef372; c.st[3]=0xa54ff53a;
    c.st[4]=0x510e527f; c.st[5]=0x9b05688c; c.st[6]=0x1f83d9ab; c.st[7]=0x5be0cd19;
    c.bits = 0; c.bl = 0;
    size_t len = strlen(in);
    c.bits = (uint64_t)len * 8;
    const uint8_t *p = (const uint8_t *)in;
    while (len >= 64) { sha256_transform(&c, p); p += 64; len -= 64; }
    memcpy(c.buf, p, len);
    c.bl = len;
    c.buf[c.bl++] = 0x80;
    if (c.bl > 56) {
        memset(c.buf + c.bl, 0, 64 - c.bl);
        sha256_transform(&c, c.buf);
        c.bl = 0;
    }
    memset(c.buf + c.bl, 0, 56 - c.bl);
    uint64_t bits = c.bits;
    for (int i = 0; i < 8; i++) c.buf[56+i] = (uint8_t)(bits >> (56 - 8*i));
    sha256_transform(&c, c.buf);
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 4; j++)
            out[i*8+j*2]   = hx[(c.st[i] >> (28 - j*8)) & 0xf],
            out[i*8+j*2+1] = hx[(c.st[i] >> (24 - j*8)) & 0xf];
    out[64] = '\0';
}

/* 管理账号配置：$WAF_HOME/config/admin.conf（缺失则初始化默认账号 admin/admin123）
 * 兼容两种写法：
 *   扁平键（历史格式，单管理员）：user/password_salt/password_hash
 *   [account] 分节（多账号）：节内 user/role/password_salt/password_hash
 * 角色 role：admin=管理员（后台全部功能）；monitor=监控人员（仅监控大屏）。
 * 扁平首账号 role 缺省 admin，[account] 分节账号缺省 monitor（最小权限）。 */
typedef struct { char user[64]; char role[16]; char salt[33]; char hash[65]; } acct_t;
#define MAX_ACCTS 16
static acct_t g_accts[MAX_ACCTS];
static int    g_nacct = 0;

static void acct_set(acct_t *a, const char *k, const char *v) {
    if      (!strcmp(k, "user"))          snprintf(a->user, sizeof(a->user), "%s", v);
    else if (!strcmp(k, "role"))          snprintf(a->role, sizeof(a->role), "%s", v);
    else if (!strcmp(k, "password_salt")) snprintf(a->salt, sizeof(a->salt), "%s", v);
    else if (!strcmp(k, "password_hash")) snprintf(a->hash, sizeof(a->hash), "%s", v);
}
/* 角色归一：缺省时首账号 admin、其余 monitor；未知值一律按 monitor 最小权限 */
static void acct_norm_role(char *role, int first) {
    if (!role[0]) { snprintf(role, 16, "%s", first ? "admin" : "monitor"); return; }
    if (strcmp(role, "admin") != 0) snprintf(role, 16, "monitor");
}
static acct_t *acct_find(const char *user) {
    for (int i = 0; i < g_nacct; i++)
        if (!strcmp(g_accts[i].user, user)) return &g_accts[i];
    return NULL;
}

/* 解析 admin.conf → g_accts[]；存在至少一个完整账号返回 1 */
static int load_admin_conf(void) {
    char path[600];
    snprintf(path, sizeof(path), "%s/config/admin.conf", waf_home());
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;
    char line[512];
    int cur = -1;                       /* -1=扁平区（账号 0） -2=超限丢弃 */
    memset(g_accts, 0, sizeof(g_accts));
    g_nacct = 0;
    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '[') {                /* [account] 分节：开启一个新账号 */
            if (g_nacct < MAX_ACCTS) {
                cur = g_nacct++;
                memset(&g_accts[cur], 0, sizeof(acct_t));
            } else cur = -2;
            continue;
        }
        char *eq = strchr(p, '=');
        if (!eq) continue;
        *eq = '\0';
        char *v = eq + 1;
        while (*v == ' ' || *v == '\t') v++;
        size_t vl = strlen(v);
        while (vl && (v[vl-1] == '\n' || v[vl-1] == '\r' || v[vl-1] == ' ' || v[vl-1] == '\t'))
            v[--vl] = '\0';
        char *k = p;
        size_t kl = strlen(k);
        while (kl && (k[kl-1] == ' ' || k[kl-1] == '\t')) k[--kl] = '\0';
        if (cur == -2) continue;
        if (!strcmp(k, "admin_dir")) {
            /* 目录名仅允许字母/数字/./-/_，禁止路径分隔与穿越成分 */
            int ok = v[0] && strlen(v) < sizeof(g_admin_dir);
            for (const char *q = v; ok && *q; q++) {
                if (!(*q >= 'a' && *q <= 'z') && !(*q >= 'A' && *q <= 'Z') &&
                    !(*q >= '0' && *q <= '9') && *q != '.' && *q != '-' && *q != '_')
                    ok = 0;
            }
            if (ok && !strstr(v, "..")) snprintf(g_admin_dir, sizeof(g_admin_dir), "%s", v);
            else fprintf(stderr, "[admin] admin_dir 非法，忽略: %s\n", v);
            continue;
        }
        if (cur < 0) {
            /* 扁平键归属账号 0（历史格式） */
            if (!strcmp(k, "user") || !strcmp(k, "role") ||
                !strcmp(k, "password_salt") || !strcmp(k, "password_hash")) {
                if (g_nacct == 0) { g_nacct = 1; memset(&g_accts[0], 0, sizeof(acct_t)); }
                acct_set(&g_accts[0], k, v);
            }
            continue;
        }
        acct_set(&g_accts[cur], k, v);
    }
    fclose(fp);
    /* 收缩：剔除缺用户名/盐/哈希的不完整账号 */
    int n = 0;
    for (int i = 0; i < g_nacct; i++) {
        if (g_accts[i].user[0] && g_accts[i].salt[0] && g_accts[i].hash[0]) {
            if (n != i) g_accts[n] = g_accts[i];
            n++;
        }
    }
    g_nacct = n;
    for (int i = 0; i < g_nacct; i++) acct_norm_role(g_accts[i].role, i == 0);
    return g_nacct > 0;
}

/* 写回 admin.conf：账号 0 保持扁平键（兼容历史工具），其余账号以 [account] 分节追加 */
static int save_admin_conf(void) {
    char path[600], tmp[640];
    snprintf(path, sizeof(path), "%s/config/admin.conf", waf_home());
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f) return -1;
    fprintf(f,
        "# 壁垒WAF 管理后台账号（password_hash = sha256(password_salt + password)）\n"
        "# 角色 role：admin=管理员（后台全部功能） monitor=监控人员（仅监控大屏）\n"
        "user = %s\n"
        "role = %s\n"
        "password_salt = %s\n"
        "password_hash = %s\n"
        "admin_dir = %s\n",
        g_accts[0].user, g_accts[0].role, g_accts[0].salt, g_accts[0].hash, g_admin_dir);
    for (int i = 1; i < g_nacct; i++) {
        fprintf(f,
            "\n[account]\n"
            "user = %s\n"
            "role = %s\n"
            "password_salt = %s\n"
            "password_hash = %s\n",
            g_accts[i].user, g_accts[i].role, g_accts[i].salt, g_accts[i].hash);
    }
    fclose(f);
    if (rename(tmp, path) != 0) { unlink(tmp); return -1; }
    return 0;
}

static void ensure_admin_conf(void) {
    if (load_admin_conf()) return;
    /* 初始化默认账号 */
    unsigned char rnd[16];
    FILE *ur = fopen("/dev/urandom", "rb");
    if (!ur || fread(rnd, 1, sizeof(rnd), ur) != sizeof(rnd)) {
        for (size_t i = 0; i < sizeof(rnd); i++) rnd[i] = (unsigned char)(rand() ^ time(NULL) >> (i % 7));
    }
    if (ur) fclose(ur);
    memset(&g_accts[0], 0, sizeof(acct_t));
    snprintf(g_accts[0].user, sizeof(g_accts[0].user), "admin");
    snprintf(g_accts[0].role, sizeof(g_accts[0].role), "admin");
    for (int i = 0; i < 16; i++) snprintf(g_accts[0].salt + 2*i, 3, "%02x", rnd[i]);
    char cat[160];
    snprintf(cat, sizeof(cat), "%s%s", g_accts[0].salt, "admin123");
    sha256_hex(cat, g_accts[0].hash);
    g_nacct = 1;
    save_admin_conf();
    printf("[admin] 已初始化管理后台账号: admin / admin123 （config/admin.conf，请尽快修改密码）\n");
    fflush(stdout);
}

/* 会话表（内存态，重启即失效；TTL 12h 滑动续期） */
#define MAX_SESSIONS 128
#define SESSION_TTL  43200
typedef struct { char token[65]; char user[64]; char role[16]; time_t expiry; } sess_t;
static sess_t g_sessions[MAX_SESSIONS];
static pthread_mutex_t g_sess_mutex = PTHREAD_MUTEX_INITIALIZER;

static void random_hex(char *out, int nbytes /* out 需要 2*nbytes+1 */) {
    unsigned char rnd[32];
    FILE *ur = fopen("/dev/urandom", "rb");
    if (!ur || fread(rnd, 1, (size_t)nbytes, ur) != (size_t)nbytes) {
        for (int i = 0; i < nbytes; i++) rnd[i] = (unsigned char)(rand() ^ (time(NULL) << (i % 5)));
    }
    if (ur) fclose(ur);
    for (int i = 0; i < nbytes; i++) snprintf(out + 2*i, 3, "%02x", rnd[i]);
    out[2*nbytes] = '\0';
}

static void session_create_ex(char tok[65], const char *user, const char *role) {
    random_hex(tok, 32);
    pthread_mutex_lock(&g_sess_mutex);
    time_t now = time(NULL);
    /* 淘汰过期项，腾不出位置则覆盖最旧 */
    int slot = -1, oldest = 0;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (g_sessions[i].token[0] && g_sessions[i].expiry < now) { g_sessions[i].token[0] = '\0'; }
        if (!g_sessions[i].token[0] && slot < 0) slot = i;
        if (g_sessions[i].expiry < g_sessions[oldest].expiry) oldest = i;
    }
    if (slot < 0) slot = oldest;
    snprintf(g_sessions[slot].token, sizeof(g_sessions[0].token), "%s", tok);
    snprintf(g_sessions[slot].user,  sizeof(g_sessions[0].user),  "%s", user ? user : "");
    snprintf(g_sessions[slot].role,  sizeof(g_sessions[0].role),  "%s", role ? role : "monitor");
    g_sessions[slot].expiry = now + SESSION_TTL;
    pthread_mutex_unlock(&g_sess_mutex);
}

/* 命中有效会话时输出 user/role（可为 NULL 跳过）；返回 1 有效、0 无效 */
static int session_lookup(const char *tok, char *user, size_t uc, char *role, size_t rc) {
    if (!tok || !tok[0]) return 0;
    pthread_mutex_lock(&g_sess_mutex);
    time_t now = time(NULL);
    int ok = 0;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (g_sessions[i].token[0] && !strcmp(g_sessions[i].token, tok)) {
            if (g_sessions[i].expiry > now) {
                g_sessions[i].expiry = now + SESSION_TTL; /* 滑动续期 */
                ok = 1;
                if (user && uc > 0) snprintf(user, uc, "%s", g_sessions[i].user);
                if (role && rc > 0) snprintf(role, rc, "%s", g_sessions[i].role);
            } else {
                g_sessions[i].token[0] = '\0';
            }
            break;
        }
    }
    pthread_mutex_unlock(&g_sess_mutex);
    return ok;
}

static int session_valid(const char *tok) {
    return session_lookup(tok, NULL, 0, NULL, 0);
}

static void session_drop(const char *tok) {
    if (!tok || !tok[0]) return;
    pthread_mutex_lock(&g_sess_mutex);
    for (int i = 0; i < MAX_SESSIONS; i++)
        if (g_sessions[i].token[0] && !strcmp(g_sessions[i].token, tok)) {
            g_sessions[i].token[0] = '\0';
            break;
        }
    pthread_mutex_unlock(&g_sess_mutex);
}

/* 登录失败锁定：同一来源 5 次失败锁 60s */
typedef struct { char ip[64]; int fails; time_t lock_until; } fail_t;
static fail_t g_fails[64];
static pthread_mutex_t g_fail_mutex = PTHREAD_MUTEX_INITIALIZER;

static int login_allowed(const char *ip) {
    pthread_mutex_lock(&g_fail_mutex);
    time_t now = time(NULL);
    int ok = 1;
    for (int i = 0; i < 64; i++) {
        if (g_fails[i].ip[0] && !strcmp(g_fails[i].ip, ip)) {
            if (g_fails[i].lock_until > now) ok = 0;
            break;
        }
    }
    pthread_mutex_unlock(&g_fail_mutex);
    return ok;
}

static void login_fail(const char *ip) {
    pthread_mutex_lock(&g_fail_mutex);
    time_t now = time(NULL);
    int slot = -1;
    for (int i = 0; i < 64; i++) {
        if (!g_fails[i].ip[0]) { slot = i; break; }
        if (!strcmp(g_fails[i].ip, ip)) { slot = i; break; }
    }
    if (slot < 0) slot = 0;
    snprintf(g_fails[slot].ip, sizeof(g_fails[0].ip), "%s", ip);
    g_fails[slot].fails++;
    if (g_fails[slot].fails >= 5) {
        g_fails[slot].lock_until = now + 60;
        g_fails[slot].fails = 0;
    }
    pthread_mutex_unlock(&g_fail_mutex);
}

static void login_ok(const char *ip) {
    pthread_mutex_lock(&g_fail_mutex);
    for (int i = 0; i < 64; i++)
        if (g_fails[i].ip[0] && !strcmp(g_fails[i].ip, ip)) {
            g_fails[i].fails = 0;
            g_fails[i].lock_until = 0;
            break;
        }
    pthread_mutex_unlock(&g_fail_mutex);
}

/* ---------------- 表单/Cookie 解析工具 ---------------- */

/* urlencoded 值解码：%XX 与 '+' */
static void url_decode(const char *in, char *out, size_t outsz) {
    size_t oi = 0;
    for (size_t i = 0; in[i] && oi + 1 < outsz; i++) {
        if (in[i] == '%' && in[i+1] && in[i+2]) {
            char hx[3] = { in[i+1], in[i+2], 0 };
            out[oi++] = (char)strtol(hx, NULL, 16);
            i += 2;
        } else if (in[i] == '+') {
            out[oi++] = ' ';
        } else {
            out[oi++] = in[i];
        }
    }
    out[oi] = '\0';
}

/* 从 "k=v&k2=v2" 表单取值（已 url 解码） */
static void form_val(const char *post, const char *key, char *out, size_t outsz) {
    out[0] = '\0';
    if (!post) return;
    char pat[80];
    snprintf(pat, sizeof(pat), "%s=", key);
    const char *p = strstr(post, pat);
    /* 命中需为字段起点（前导是 & 或起始） */
    while (p && p != post && p[-1] != '&') {
        p = strstr(p + 1, pat);
    }
    if (!p) return;
    p += strlen(pat);
    char raw[512];
    size_t ri = 0;
    while (p[ri] && p[ri] != '&' && ri + 1 < sizeof(raw)) { raw[ri] = p[ri]; ri++; }
    raw[ri] = '\0';
    url_decode(raw, out, outsz);
}

/* 从 Cookie 头取值 */
static void cookie_val(const char *cookie_hdr, const char *name, char *out, size_t outsz) {
    out[0] = '\0';
    if (!cookie_hdr || !cookie_hdr[0]) return;
    char pat[80];
    snprintf(pat, sizeof(pat), "%s=", name);
    const char *p = strcasestr(cookie_hdr, pat);
    if (!p) return;
    p += strlen(pat);
    size_t i = 0;
    while (p[i] && p[i] != ';' && p[i] != ' ' && i + 1 < outsz) { out[i] = p[i]; i++; }
    out[i] = '\0';
}

static int authed(const char *cookie_hdr) {
    char tok[80];
    cookie_val(cookie_hdr, "waf_admin_sess", tok, sizeof(tok));
    return session_valid(tok);
}

static int require_auth(int fd, const char *cookie_hdr) {
    if (authed(cookie_hdr)) return 1;
    send_error(fd, "401 Unauthorized", "登录已失效，请重新登录");
    return 0;
}

/* ---------------- API 处理 ---------------- */

static void handle_info(int fd) {
    char esc1[128], esc2[256];
    json_escape(g_showcase_path, esc1, sizeof(esc1));
    json_escape(g_attack_log, esc2, sizeof(esc2));
    char body[1024];
    snprintf(body, sizeof(body),
        "{"
        "\"success\":true,"
        "\"data\":{"
        "\"service\":\"waf-demo-backend\","
        "\"version\":\"1.0\","
        "\"uptime_sec\":%ld,"
        "\"showcase\":\"%s\","
        "\"attack_log\":\"%s\","
        "\"message\":\"你正在通过 WAF 反向代理访问受保护的后端业务\""
        "}}",
        (long)(time(NULL) - g_start_time), esc1, esc2);
    send_json(fd, body);
}

static void handle_logs(int fd) {
    size_t len = 0;
    char *tail = read_file_tail(g_attack_log, LOG_TAIL_BYTES, &len);
    if (!tail) {
        send_json(fd, "{\"success\":true,\"data\":{\"exists\":false,"
                      "\"content\":\"(暂无攻击日志 —— 尚未检测到攻击，点击上方按钮模拟攻击后刷新)\"}}");
        return;
    }
    char *esc = malloc(len * 6 + 16);
    if (!esc) { free(tail); send_error(fd, "500 Internal Server Error", "out of memory"); return; }
    json_escape(tail, esc, len * 6 + 16);
    char *body = malloc(len * 6 + 256);
    if (!body) { free(tail); free(esc); send_error(fd, "500 Internal Server Error", "out of memory"); return; }
    snprintf(body, len * 6 + 256,
        "{\"success\":true,\"data\":{\"exists\":true,\"bytes\":%zu,\"content\":\"%s\"}}",
        len, esc);
    send_json(fd, body);
    free(body);
    free(esc);
    free(tail);
}

/* ---------------- 静态文件 ---------------- */

static const char *mime_of(const char *path) {
    const char *e = strrchr(path, '.');
    if (!e) return "text/html";
    if (!strcmp(e, ".html")) return "text/html";
    if (!strcmp(e, ".css"))  return "text/css";
    if (!strcmp(e, ".js"))   return "application/javascript";
    if (!strcmp(e, ".json")) return "application/json";
    if (!strcmp(e, ".svg"))  return "image/svg+xml";
    if (!strcmp(e, ".png"))  return "image/png";
    if (!strcmp(e, ".ico"))  return "image/x-icon";
    return "application/octet-stream";
}

/* 提供 docroot 下的静态文件（拒绝 .. 防穿越；后端仅监听 127.0.0.1，仍双保险） */
static void serve_static(int fd, const char *rel) {
    if (strstr(rel, "..")) { send_error(fd, "403 Forbidden", "bad path"); return; }
    char full[1024];
    snprintf(full, sizeof(full), "%s/%s", g_docroot, rel);
    size_t len = 0;
    char *data = read_whole_file(full, &len);
    if (!data) { send_error(fd, "404 Not Found", "not found"); return; }
    send_response(fd, "200 OK", mime_of(full), data, len);
    free(data);
}

/* 302 重定向（后端平面引导到管理平面 / 大屏登录闸门共用） */
static void send_redirect(int fd, const char *location) {
    char extra[768];
    snprintf(extra, sizeof(extra), "Location: %s\r\n", location);
    send_response_ex(fd, "302 Found", "text/plain", "", 0, extra);
}

/* 管理界面静态资源：以 WAF_HOME/<admin_dir> 为根（独立于 web/ 之外） */
static void serve_admin_static(int fd, const char *rel) {
    if (!rel[0] || rel[0] == '/' || strstr(rel, "..")) {
        send_error(fd, "403 Forbidden", "bad path"); return;
    }
    char full[1024];
    snprintf(full, sizeof(full), "%s/%s/%s", waf_home(), g_admin_dir, rel);
    size_t len = 0;
    char *data = read_whole_file(full, &len);
    if (!data) { send_error(fd, "404 Not Found", "not found"); return; }
    send_response(fd, "200 OK", mime_of(full), data, len);
    free(data);
}

/* ---------------- 管理 API：统计（大屏 + 后台共用） ---------------- */

/* 解析 "[YYYY-MM-DD HH:MM:SS]" 为 time_t */
static time_t parse_log_ts(const char *s) {
    struct tm tmv;
    memset(&tmv, 0, sizeof(tmv));
    if (sscanf(s, "%d-%d-%d %d:%d:%d",
               &tmv.tm_year, &tmv.tm_mon, &tmv.tm_mday,
               &tmv.tm_hour, &tmv.tm_min, &tmv.tm_sec) != 6) return 0;
    tmv.tm_year -= 1900;
    tmv.tm_mon  -= 1;
    return mktime(&tmv);
}

#define NTYPE 10
static const char *g_type_names[NTYPE] = {
    "SQL_INJECTION", "XSS", "CMD_INJECTION", "PATH_TRAVERSAL",
    "XXE", "SSRF", "FILE_UPLOAD", "SCANNER", "CC", "UNKNOWN"
};

typedef struct { char key[160]; long count; } counter_t;

typedef struct {
    long atk_total, atk_blocked, atk_logged, atk_today;
    long req_total, req_ok, req_forbidden, req_other;
    long trend[24], trend_blk[24];
    long type_cnt[NTYPE];
    counter_t ips[256];   int nips;
    counter_t rules[256]; int nrules;
    counter_t paths[256]; int npaths;
    long sev_high, sev_mid, sev_low;
    long qps5_x10;   /* 近 5 分钟平均请求速率 ×10，避免浮点 */
    long uptime_sec;
} stats_data_t;

static stats_data_t g_stats_cache;
static time_t      g_stats_cache_at = 0;
static pthread_mutex_t g_stats_mutex = PTHREAD_MUTEX_INITIALIZER;

static void bump(counter_t *arr, int *n, int cap, const char *key) {
    for (int i = 0; i < *n; i++)
        if (!strcmp(arr[i].key, key)) { arr[i].count++; return; }
    if (*n < cap) {
        snprintf(arr[*n].key, sizeof(arr[0].key), "%s", key);
        arr[*n].count = 1;
        (*n)++;
    }
}

static int cmp_counter_desc(const void *a, const void *b) {
    const counter_t *x = (const counter_t *)a, *y = (const counter_t *)b;
    return (y->count > x->count) - (y->count < x->count);
}

/* 数据平面持续防护时长（秒）：logs/bileiwaf.pid → /proc/<pid>/stat 的 starttime
 * （第 22 字段，即最后一个 ')' 后第 20 个 token，单位为时钟滴答），
 * uptime = /proc/uptime - starttime/HZ。pid 无效或读取失败时回退 admin 进程启动时刻。 */
static long data_plane_uptime(void) {
    char p[300];
    snprintf(p, sizeof(p), "%s/logs/bileiwaf.pid", waf_home());
    FILE *pf = fopen(p, "r");
    if (!pf) return (long)(time(NULL) - g_start_time);
    int pid = 0;
    if (fscanf(pf, "%d", &pid) != 1 || pid <= 1) { fclose(pf); return (long)(time(NULL) - g_start_time); }
    fclose(pf);

    char sp[64];
    snprintf(sp, sizeof(sp), "/proc/%d/stat", pid);
    long starttick = 0;
    FILE *sf = fopen(sp, "r");
    if (sf) {
        char buf[4096];
        if (fgets(buf, sizeof(buf), sf)) {
            char *rp = strrchr(buf, ')');   /* comm 字段可能含空格，取最后一个 ')' */
            if (rp) {
                int field = 1;
                char *save = NULL;
                for (char *tok = strtok_r(rp + 1, " ", &save); tok;
                     tok = strtok_r(NULL, " ", &save), field++) {
                    if (field == 20) { starttick = atol(tok); break; }  /* 字段22 = ')'后第20个 */
                }
            }
        }
        fclose(sf);
    }
    if (starttick <= 0) return (long)(time(NULL) - g_start_time);

    double up = 0;
    FILE *uf = fopen("/proc/uptime", "r");
    if (uf) {
        if (fscanf(uf, "%lf", &up) != 1) up = 0;
        fclose(uf);
    }
    long hz = sysconf(_SC_CLK_TCK);
    if (hz > 0 && up > 0) {
        long r = (long)(up - (double)starttick / hz);
        if (r > 0) return r;
    }
    return (long)(time(NULL) - g_start_time);
}

static void collect_stats(stats_data_t *s) {
    memset(s, 0, sizeof(*s));
    time_t now = time(NULL);
    s->uptime_sec = data_plane_uptime();
    char today_str[16];
    strftime(today_str, sizeof(today_str), "%Y-%m-%d", localtime(&now));

    /* 攻击日志全量统计 */
    FILE *fp = fopen(g_attack_log, "r");
    if (fp) {
        char line[4096];
        char cur_type[64] = "UNKNOWN", cur_rule[80] = "-", cur_action[16] = "LOG", cur_ts[32] = "";
        int cur_sev = 0;
        time_t cur_epoch = 0;
        while (fgets(line, sizeof(line), fp)) {
            if (line[0] == '[' && strstr(line, " ATTACK |")) {
                sscanf(line + 1, "%31[^]]", cur_ts);
                cur_epoch = parse_log_ts(cur_ts);
                char *p, *b;
                if ((p = strstr(line, "Type: "))) {
                    sscanf(p + 6, "%63s", cur_type);
                    if ((b = strchr(cur_type, '|'))) *b = '\0';
                }
                if ((p = strstr(line, "Severity: "))) cur_sev = atoi(p + 10);
                if ((p = strstr(line, "Rule: "))) {
                    sscanf(p + 6, "%79s", cur_rule);
                    if ((b = strchr(cur_rule, '|'))) *b = '\0';
                }
                if ((p = strstr(line, "Action: "))) sscanf(p + 8, "%15s", cur_action);

                s->atk_total++;
                if (!strcmp(cur_action, "BLOCK")) s->atk_blocked++; else s->atk_logged++;
                if (!strncmp(cur_ts, today_str, 10)) s->atk_today++;
                if (cur_epoch > 0 && now - cur_epoch < 86400) {
                    int bucket = (int)((now - cur_epoch) / 3600);
                    if (bucket >= 0 && bucket < 24) {
                        s->trend[23 - bucket]++;
                        if (!strcmp(cur_action, "BLOCK")) s->trend_blk[23 - bucket]++;
                    }
                }
                int ti;
                for (ti = 0; ti < NTYPE; ti++)
                    if (!strcmp(cur_type, g_type_names[ti])) break;
                s->type_cnt[ti < NTYPE ? ti : NTYPE - 1]++;
                if (cur_sev >= 4) s->sev_high++;
                else if (cur_sev == 3) s->sev_mid++;
                else s->sev_low++;
                bump(s->rules, &s->nrules, 256, cur_rule);
            } else if (strstr(line, "| IP: ")) {
                char buf[600] = "";
                char *p = strstr(line, "| IP: ");
                sscanf(p + 6, "%63s", buf);
                char *b = strchr(buf, '|'); if (b) *b = '\0';
                if (buf[0]) bump(s->ips, &s->nips, 256, buf);
                if ((p = strstr(line, "| Path: "))) {
                    sscanf(p + 8, "%511s", buf);
                    if ((b = strchr(buf, '|'))) *b = '\0';
                    if (buf[0]) bump(s->paths, &s->npaths, 256, buf);
                }
            }
        }
        fclose(fp);
    }

    /* 访问日志：请求总量 + 状态分布（全量） */
    char access_path[600];
    snprintf(access_path, sizeof(access_path), "%s/logs/waf-access.log", waf_home());
    FILE *af = fopen(access_path, "r");
    if (af) {
        char line[1024];
        while (fgets(line, sizeof(line), af)) {
            int status = 0;
            char m[16], u[512];
            if (sscanf(line, "[%*[^]]] %*s %15s %511s %d", m, u, &status) == 3) {
                s->req_total++;
                if (status == 200) s->req_ok++;
                else if (status == 403) s->req_forbidden++;
                else s->req_other++;
            }
        }
        fclose(af);
        /* 近 5 分钟 QPS：访问日志尾部 2MB */
        size_t tl = 0;
        char *tail = read_file_tail(access_path, 2 * 1024 * 1024, &tl);
        if (tail) {
            long recent = 0;
            char *save = NULL;
            for (char *ln = strtok_r(tail, "\n", &save); ln; ln = strtok_r(NULL, "\n", &save)) {
                if (ln[0] != '[') continue;
                char tsbuf[32] = "";
                sscanf(ln + 1, "%31[^]]", tsbuf);
                time_t ts = parse_log_ts(tsbuf);
                if (ts > 0 && now - ts < 300) recent++;
            }
            s->qps5_x10 = recent * 10 / 300;
            free(tail);
        }
    }

    qsort(s->ips,   (size_t)s->nips,   sizeof(counter_t), cmp_counter_desc);
    qsort(s->rules, (size_t)s->nrules, sizeof(counter_t), cmp_counter_desc);
    qsort(s->paths, (size_t)s->npaths, sizeof(counter_t), cmp_counter_desc);
    /* WAF 拦截(403)仅写攻击日志不写访问日志，forbidden 以攻击日志拦截数为准 */
    s->req_forbidden = s->atk_blocked;
}

/* 5 秒缓存读取（拷贝快照，避免并发撕裂） */
static void get_stats_copy(stats_data_t *out) {
    pthread_mutex_lock(&g_stats_mutex);
    time_t now = time(NULL);
    if (g_stats_cache_at == 0 || now - g_stats_cache_at >= 5) {
        collect_stats(&g_stats_cache);
        g_stats_cache_at = now;
    }
    *out = g_stats_cache;
    pthread_mutex_unlock(&g_stats_mutex);
}

/* ---------------- GeoIP：IP 地理定位（libmaxminddb；City→Country 自动降级） ----------------
 * 数据文件解析顺序：
 *   1. waf.conf 的 geoip_db 键（绝对路径，或相对 WAF_HOME）
 *   2. $WAF_HOME/geoip/GeoLite2-City.mmdb
 *   3. $WAF_HOME/geoip/GeoLite2-Country.mmdb（仅国家，无城市/坐标）
 * 编译期未探测到 libmaxminddb 或数据文件缺失时整体降级：geo_lookup 返回 ok=0，
 * 调用方照常输出（来源字段为空串），不影响防护与管理功能。
 * MMDB 句柄在首次查询时懒加载并常驻（mmap 只读，查询线程安全）。 */
typedef struct {
    int    ok;             /* 1=查到有效归属 */
    char   country[96];    /* 国家名（优先 zh-CN，回退英文） */
    char   country_en[96]; /* 国家英文名（匹配 echarts world 地图 name） */
    char   code[8];        /* ISO 3166-1 alpha-2 国家代码 */
    char   city[96];       /* 城市名（City 库才有，Country 库为空） */
    double lat, lon;       /* 经纬度（City 库才有） */
    int    has_coord;
} geo_info_t;

#ifdef HAVE_MAXMINDDB
#include <maxminddb.h>
#include <dlfcn.h>

/* 运行期动态加载 libmaxminddb（不产生 DT_NEEDED）：
 * 目标机未安装该库时管理平面照常启动，仅 IP 地理定位降级为空。 */
typedef int  (*mmdb_open_fn)(const char *, int, MMDB_s *);
typedef MMDB_lookup_result_s (*mmdb_lookup_fn)(MMDB_s *, const char *, int *, int *);
typedef int  (*mmdb_aget_fn)(MMDB_entry_s *, MMDB_entry_data_s *, const char *const *);

static MMDB_s g_geo_mmdb;
static int g_geo_state = 0;   /* 0=未初始化 1=已加载 -1=不可用 */
static pthread_mutex_t g_geo_mutex = PTHREAD_MUTEX_INITIALIZER;
static void *g_geo_lib = NULL;
static mmdb_open_fn   p_mmdb_open = NULL;
static mmdb_lookup_fn p_mmdb_lookup = NULL;
static mmdb_aget_fn   p_mmdb_aget = NULL;

static int geo_load_lib(void) {
    if (g_geo_lib) return 0;
    static const char *names[] = { "libmaxminddb.so.0", "libmaxminddb.so", NULL };
    for (int i = 0; names[i]; i++) {
        g_geo_lib = dlopen(names[i], RTLD_NOW | RTLD_LOCAL);
        if (g_geo_lib) break;
    }
    if (!g_geo_lib) return -1;
    p_mmdb_open   = (mmdb_open_fn)dlsym(g_geo_lib, "MMDB_open");
    p_mmdb_lookup = (mmdb_lookup_fn)dlsym(g_geo_lib, "MMDB_lookup_string");
    p_mmdb_aget   = (mmdb_aget_fn)dlsym(g_geo_lib, "MMDB_aget_value");
    if (!p_mmdb_open || !p_mmdb_lookup || !p_mmdb_aget) {
        dlclose(g_geo_lib);
        g_geo_lib = NULL;
        p_mmdb_open = NULL; p_mmdb_lookup = NULL; p_mmdb_aget = NULL;
        return -1;
    }
    return 0;
}

/* 读取简单键值配置的首个匹配（忽略 # / [ 开头行；剥离行尾注释与空白） */
static void conf_get_val(const char *file, const char *key, char *out, size_t cap) {
    out[0] = '\0';
    FILE *fp = fopen(file, "r");
    if (!fp) return;
    char ln[1024];
    size_t klen = strlen(key);
    while (fgets(ln, sizeof(ln), fp)) {
        char *p = ln;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '[') continue;
        if (strncmp(p, key, klen) != 0) continue;
        p += klen;
        while (*p == ' ' || *p == '\t') p++;
        if (*p != '=') continue;
        p++;
        while (*p == ' ' || *p == '\t') p++;
        size_t n = strcspn(p, "\r\n#");
        while (n > 0 && (p[n - 1] == ' ' || p[n - 1] == '\t')) n--;
        if (n >= cap) n = cap - 1;
        memcpy(out, p, n);
        out[n] = '\0';
        break;
    }
    fclose(fp);
}

/* 定位并打开 MMDB（City 优先）；成功返回 1，失败 -1 */
static int geo_open_db(void) {
    if (geo_load_lib() != 0) return -1;
    char cand[3][800];
    int n = 0;
    char cfg[800] = "";
    char cpath[900];
    snprintf(cpath, sizeof(cpath), "%s/config/waf.conf", waf_home());
    conf_get_val(cpath, "geoip_db", cfg, sizeof(cfg));
    if (cfg[0]) {
        if (cfg[0] == '/') snprintf(cand[n], sizeof(cand[n]), "%s", cfg);
        else snprintf(cand[n], sizeof(cand[n]), "%s/%s", waf_home(), cfg);
        n++;
    }
    snprintf(cand[n], sizeof(cand[n]), "%s/geoip/GeoLite2-City.mmdb", waf_home()); n++;
    snprintf(cand[n], sizeof(cand[n]), "%s/geoip/GeoLite2-Country.mmdb", waf_home()); n++;
    for (int i = 0; i < n; i++) {
        if (access(cand[i], R_OK) != 0) continue;
        if (p_mmdb_open(cand[i], MMDB_MODE_MMAP, &g_geo_mmdb) != MMDB_SUCCESS) continue;
        return 1;
    }
    return -1;
}

/* 取 MMDB 路径上的 UTF-8 字符串；成功返回 0 */
static int mmdb_str(const MMDB_entry_s *e, const char *const *path, char *out, size_t cap) {
    out[0] = '\0';
    MMDB_entry_data_s d;
    if (p_mmdb_aget((MMDB_entry_s *)e, &d, path) != MMDB_SUCCESS) return -1;
    if (!d.has_data || d.type != MMDB_DATA_TYPE_UTF8_STRING) return -1;
    size_t n = d.data_size;
    if (n >= cap) n = cap - 1;
    memcpy(out, d.utf8_string, n);
    out[n] = '\0';
    return 0;
}

/* 取 MMDB 路径上的数值（double/float）；成功返回 0 */
static int mmdb_num(const MMDB_entry_s *e, const char *const *path, double *out) {
    MMDB_entry_data_s d;
    if (p_mmdb_aget((MMDB_entry_s *)e, &d, path) != MMDB_SUCCESS || !d.has_data) return -1;
    if (d.type == MMDB_DATA_TYPE_DOUBLE) { *out = d.double_value; return 0; }
    if (d.type == MMDB_DATA_TYPE_FLOAT)  { *out = (double)d.float_value; return 0; }
    return -1;
}

static void geo_lookup(const char *ip, geo_info_t *g) {
    memset(g, 0, sizeof(*g));
    if (!ip || !ip[0]) return;
    pthread_mutex_lock(&g_geo_mutex);
    if (g_geo_state == 0) g_geo_state = geo_open_db();
    if (g_geo_state != 1) { pthread_mutex_unlock(&g_geo_mutex); return; }

    int ec = 0, mmerr = 0;
    /* 注意：libmaxminddb 1.2.0 的 MMDB_lookup_string 会无条件写 *mmdb_error，
     * 传 NULL 会段错误——必须传有效指针（早期版本曾因此崩溃）。 */
    MMDB_lookup_result_s res = p_mmdb_lookup(&g_geo_mmdb, ip, &ec, &mmerr);
    if (ec != 0 || mmerr != 0 || !res.found_entry) { pthread_mutex_unlock(&g_geo_mutex); return; }

    static const char *P_CT_ZH[] = { "country", "names", "zh-CN", NULL };
    static const char *P_CT_EN[] = { "country", "names", "en", NULL };
    static const char *P_CODE[]  = { "country", "iso_code", NULL };
    static const char *P_CI_ZH[] = { "city", "names", "zh-CN", NULL };
    static const char *P_CI_EN[] = { "city", "names", "en", NULL };
    static const char *P_LAT[]   = { "location", "latitude", NULL };
    static const char *P_LON[]   = { "location", "longitude", NULL };

    char zh[96] = "", en[96] = "";
    mmdb_str(&res.entry, P_CT_ZH, zh, sizeof(zh));
    mmdb_str(&res.entry, P_CT_EN, en, sizeof(en));
    if (!zh[0]) snprintf(zh, sizeof(zh), "%s", en);
    snprintf(g->country, sizeof(g->country), "%s", zh);
    snprintf(g->country_en, sizeof(g->country_en), "%s", en);
    mmdb_str(&res.entry, P_CODE, g->code, sizeof(g->code));

    char cz[96] = "", ce[96] = "";
    mmdb_str(&res.entry, P_CI_ZH, cz, sizeof(cz));
    mmdb_str(&res.entry, P_CI_EN, ce, sizeof(ce));
    if (!cz[0]) snprintf(cz, sizeof(cz), "%s", ce);
    snprintf(g->city, sizeof(g->city), "%s", cz);

    double la = 0, lo = 0;
    if (mmdb_num(&res.entry, P_LAT, &la) == 0 && mmdb_num(&res.entry, P_LON, &lo) == 0) {
        g->lat = la; g->lon = lo; g->has_coord = 1;
    }
    g->ok = (g->country[0] || g->city[0]) ? 1 : 0;
    pthread_mutex_unlock(&g_geo_mutex);
}
#else
static void geo_lookup(const char *ip, geo_info_t *g) { (void)ip; memset(g, 0, sizeof(*g)); }
#endif /* HAVE_MAXMINDDB */

/* 输出 geo 字段到 JSON（ok 时输出归属；否则全部空/0，前端显示「—」） */
static int geo_json(const char *ip, char *out, size_t cap) {
    geo_info_t g;
    geo_lookup(ip, &g);
    char cz[200], czen[200], cc[200], ccity[200];
    json_escape(g.country, cz, sizeof(cz));
    json_escape(g.country_en, czen, sizeof(czen));
    json_escape(g.code, cc, sizeof(cc));
    json_escape(g.city, ccity, sizeof(ccity));
    return snprintf(out, cap,
        "\"country\":\"%s\",\"country_en\":\"%s\",\"country_code\":\"%s\",\"city\":\"%s\","
        "\"lat\":%.4f,\"lon\":%.4f",
        cz, czen, cc, ccity,
        g.has_coord ? g.lat : 0.0, g.has_coord ? g.lon : 0.0);
}

/* 统计 JSON 主体（调用方已输出 "data":{ 开括号，此处不再重复；也不闭合 top_paths 由各调用方续写） */
static void append_stats_json(const stats_data_t *s, char *body, size_t cap, size_t *off) {
    *off += snprintf(body + *off, cap - *off,
        "\"uptime_sec\":%ld,"
        "\"attacks\":{\"total\":%ld,\"blocked\":%ld,\"logged\":%ld,\"today\":%ld},"
        "\"requests\":{\"total\":%ld,\"ok\":%ld,\"forbidden\":%ld,\"other\":%ld},"
        "\"qps_5min\":%ld.%ld,"
        "\"severity\":{\"high\":%ld,\"mid\":%ld,\"low\":%ld},"
        "\"trend24h\":[",
        s->uptime_sec, s->atk_total, s->atk_blocked, s->atk_logged, s->atk_today,
        s->req_total, s->req_ok, s->req_forbidden, s->req_other,
        s->qps5_x10 / 10, s->qps5_x10 % 10,
        s->sev_high, s->sev_mid, s->sev_low);
    for (int i = 0; i < 24; i++)
        *off += snprintf(body + *off, cap - *off, "%s%ld", i ? "," : "", s->trend[i]);
    *off += snprintf(body + *off, cap - *off, "],\"trend24h_blocked\":[");
    for (int i = 0; i < 24; i++)
        *off += snprintf(body + *off, cap - *off, "%s%ld", i ? "," : "", s->trend_blk[i]);
    *off += snprintf(body + *off, cap - *off, "],\"types\":[");
    int first = 1;
    for (int i = 0; i < NTYPE; i++) {
        if (s->type_cnt[i] == 0) continue;
        *off += snprintf(body + *off, cap - *off, "%s{\"name\":\"%s\",\"count\":%ld}",
                         first ? "" : ",", g_type_names[i], s->type_cnt[i]);
        first = 0;
    }
    *off += snprintf(body + *off, cap - *off, "],\"top_ips\":[");
    for (int i = 0; i < s->nips && i < 5; i++) {
        char gj[520];
        geo_json(s->ips[i].key, gj, sizeof(gj));
        *off += snprintf(body + *off, cap - *off, "%s{\"ip\":\"%s\",\"count\":%ld,%s}",
                         i ? "," : "", s->ips[i].key, s->ips[i].count, gj);
    }
    *off += snprintf(body + *off, cap - *off, "],\"top_rules\":[");
    for (int i = 0; i < s->nrules && i < 5; i++) {
        char esc[400]; json_escape(s->rules[i].key, esc, sizeof(esc));
        *off += snprintf(body + *off, cap - *off, "%s{\"rule\":\"%s\",\"count\":%ld}",
                         i ? "," : "", esc, s->rules[i].count);
    }
    *off += snprintf(body + *off, cap - *off, "],\"top_paths\":[");
    for (int i = 0; i < s->npaths && i < 5; i++) {
        char esc[400]; json_escape(s->paths[i].key, esc, sizeof(esc));
        *off += snprintf(body + *off, cap - *off, "%s{\"path\":\"%s\",\"count\":%ld}",
                         i ? "," : "", esc, s->paths[i].count);
    }
    *off += snprintf(body + *off, cap - *off, "]");
}

/* 攻击日志条目（供总览「实时攻击流」与攻击日志明细共用） */
typedef struct {
    char ts[32]; long epoch;
    char type[64]; int sev;
    char rule[80]; char action[16];
    char ip[64]; char method[16];
    char path[512]; char query[512];
} atk_entry_t;

/* 大屏总览（公开接口，监控大屏免登录展示） */
static void handle_admin_overview(int fd) {
    stats_data_t s;
    get_stats_copy(&s);
    char *body = malloc(MAX_RESPONSE);
    if (!body) { send_error(fd, "500 Internal Server Error", "oom"); return; }
    size_t off = 0;
    off += snprintf(body + off, MAX_RESPONSE - off, "{\"success\":true,\"data\":{");
    append_stats_json(&s, body, MAX_RESPONSE, &off);

    /* 最近攻击条目（攻击日志尾部 256KB，解析为结构化对象，附 IP 地理归属） */
    size_t tl = 0;
    char *tail = read_file_tail(g_attack_log, 256 * 1024, &tl);
    off += snprintf(body + off, MAX_RESPONSE - off, ",\"recent\":[");
    if (tail) {
        atk_entry_t ring[24];
        int n = 0, head = 0;
        atk_entry_t cur; int have = 0;
        memset(&cur, 0, sizeof(cur));
        char *save = NULL;
        for (char *ln = strtok_r(tail, "\n", &save); ln; ln = strtok_r(NULL, "\n", &save)) {
            if (ln[0] == '[' && strstr(ln, " ATTACK |")) {
                if (have) { ring[head] = cur; head = (head + 1) % 24; if (n < 24) n++; }
                memset(&cur, 0, sizeof(cur));
                sscanf(ln + 1, "%31[^]]", cur.ts);
                cur.epoch = parse_log_ts(cur.ts);
                char *p, *b;
                if ((p = strstr(ln, "Type: "))) { sscanf(p + 6, "%63s", cur.type); if ((b = strchr(cur.type, '|'))) *b = '\0'; }
                if ((p = strstr(ln, "Severity: "))) cur.sev = atoi(p + 10);
                if ((p = strstr(ln, "Rule: "))) { sscanf(p + 6, "%79s", cur.rule); if ((b = strchr(cur.rule, '|'))) *b = '\0'; }
                if ((p = strstr(ln, "Action: "))) {
                    sscanf(p + 8, "%15s", cur.action);
                    for (char *c = cur.action; *c; c++) *c = (char)tolower((unsigned char)*c);
                }
                have = 1;
            } else if (have) {
                char *p, *b;
                if ((p = strstr(ln, "| IP: "))) { sscanf(p + 6, "%63s", cur.ip); if ((b = strchr(cur.ip, '|'))) *b = '\0'; }
                if ((p = strstr(ln, "| Method: "))) { sscanf(p + 10, "%15s", cur.method); if ((b = strchr(cur.method, '|'))) *b = '\0'; }
                if ((p = strstr(ln, "| Path: "))) { sscanf(p + 8, "%511s", cur.path); if ((b = strchr(cur.path, '|'))) *b = '\0'; }
                if ((p = strstr(ln, "| Query: "))) { sscanf(p + 9, "%511s", cur.query); if ((b = strchr(cur.query, '|'))) *b = '\0'; }
            }
        }
        if (have) { ring[head] = cur; head = (head + 1) % 24; if (n < 24) n++; }
        for (int i = 0; i < n; i++) {   /* 最新在前 */
            const atk_entry_t *e = &ring[(head - 1 - i + 24) % 24];
            char e_ts[96], e_type[200], e_rule[220], e_path[1200], gj[520];
            json_escape(e->ts,   e_ts,   sizeof(e_ts));
            json_escape(e->type, e_type, sizeof(e_type));
            json_escape(e->rule, e_rule, sizeof(e_rule));
            json_escape(e->path, e_path, sizeof(e_path));
            geo_json(e->ip, gj, sizeof(gj));
            off += snprintf(body + off, MAX_RESPONSE - off,
                "%s{\"time\":\"%s\",\"type\":\"%s\",\"sev\":%d,\"rule\":\"%s\","
                "\"action\":\"%s\",\"ip\":\"%s\",\"method\":\"%s\",\"path\":\"%s\",%s}",
                i ? "," : "", e_ts, e_type, e->sev, e_rule,
                e->action, e->ip, e->method, e_path, gj);
            if (off > MAX_RESPONSE - 8192) break;
        }
        free(tail);
    }
    off += snprintf(body + off, MAX_RESPONSE - off, "]}}");
    send_response(fd, "200 OK", "application/json", body, off);
    free(body);
}

/* 统计目录内文件数（跳过隐藏项；ext 为 NULL 计全部） */
static int count_files(const char *dir, const char *ext) {
    DIR *d = opendir(dir);
    if (!d) return 0;
    int n = 0;
    struct dirent *de;
    while ((de = readdir(d))) {
        if (de->d_name[0] == '.') continue;
        if (ext && !strstr(de->d_name, ext)) continue;
        n++;
    }
    closedir(d);
    return n;
}

/* 后台统计（需登录）：总览数据 + 站点/规则文件数 + 监听端口 */
static void handle_admin_stats(int fd) {
    stats_data_t s;
    get_stats_copy(&s);
    char sdir[600], rdir[600];
    snprintf(sdir, sizeof(sdir), "%s/config/sites", waf_home());
    snprintf(rdir, sizeof(rdir), "%s/rules", waf_home());
    char *body = malloc(MAX_RESPONSE);
    if (!body) { send_error(fd, "500 Internal Server Error", "oom"); return; }
    size_t off = 0;
    off += snprintf(body + off, MAX_RESPONSE - off, "{\"success\":true,\"data\":{");
    append_stats_json(&s, body, MAX_RESPONSE, &off);
    off += snprintf(body + off, MAX_RESPONSE - off,
        ",\"sites\":%d,\"rule_files\":%d,"
        "\"listen\":{\"backend_port\":%d,\"admin_port\":%d}}}",
        count_files(sdir, ".conf"), count_files(rdir, NULL),
        g_backend_port, g_admin_port);
    send_response(fd, "200 OK", "application/json", body, off);
    free(body);
}

/* ---------------- 管理 API：攻击日志明细（分页/筛选） ---------------- */

#define ATK_RING_CAP  20000
#define ATK_SCAN_BYTES (32L * 1024 * 1024)
static pthread_mutex_t g_atk_mutex = PTHREAD_MUTEX_INITIALIZER;

/* 解析攻击日志尾部 window 字节为按时间倒序的条目数组（malloc，调用方释放） */
static atk_entry_t *atk_collect(int *out_n, long window, long *scanned) {
    *out_n = 0;
    FILE *fp = fopen(g_attack_log, "rb");
    if (!fp) return NULL;
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    long off = sz > window ? sz - window : 0;
    *scanned = sz - off;
    fseek(fp, off, SEEK_SET);
    char *buf = malloc((size_t)(sz - off) + 1);
    if (!buf) { fclose(fp); return NULL; }
    size_t rd = fread(buf, 1, (size_t)(sz - off), fp);
    fclose(fp);
    buf[rd] = '\0';

    atk_entry_t *ring = malloc(sizeof(atk_entry_t) * ATK_RING_CAP);
    if (!ring) { free(buf); return NULL; }
    int head = 0, count = 0;
    atk_entry_t cur;
    int have = 0;
    memset(&cur, 0, sizeof(cur));
    char *save = NULL;
    for (char *ln = strtok_r(buf, "\n", &save); ln; ln = strtok_r(NULL, "\n", &save)) {
        if (ln[0] == '[' && strstr(ln, " ATTACK |")) {
            if (have) {
                ring[head] = cur;
                head = (head + 1) % ATK_RING_CAP;
                if (count < ATK_RING_CAP) count++;
            }
            memset(&cur, 0, sizeof(cur));
            sscanf(ln + 1, "%31[^]]", cur.ts);
            cur.epoch = parse_log_ts(cur.ts);
            char *p, *b;
            if ((p = strstr(ln, "Type: "))) {
                sscanf(p + 6, "%63s", cur.type);
                if ((b = strchr(cur.type, '|'))) *b = '\0';
            }
            if ((p = strstr(ln, "Severity: "))) cur.sev = atoi(p + 10);
            if ((p = strstr(ln, "Rule: "))) {
                sscanf(p + 6, "%79s", cur.rule);
                if ((b = strchr(cur.rule, '|'))) *b = '\0';
            }
            if ((p = strstr(ln, "Action: "))) {
                sscanf(p + 8, "%15s", cur.action);
                for (char *c = cur.action; *c; c++) *c = (char)tolower((unsigned char)*c); /* 日志为 BLOCK 大写，统一小写供筛选/展示 */
            }
            have = 1;
        } else if (have) {
            char *p, *b;
            if ((p = strstr(ln, "| IP: "))) {
                sscanf(p + 6, "%63s", cur.ip);
                if ((b = strchr(cur.ip, '|'))) *b = '\0';
            }
            if ((p = strstr(ln, "| Method: "))) {
                sscanf(p + 10, "%15s", cur.method);
                if ((b = strchr(cur.method, '|'))) *b = '\0';
            }
            if ((p = strstr(ln, "| Path: "))) {
                sscanf(p + 8, "%511s", cur.path);
                if ((b = strchr(cur.path, '|'))) *b = '\0';
            }
            if ((p = strstr(ln, "| Query: "))) {
                sscanf(p + 9, "%511s", cur.query);
                if ((b = strchr(cur.query, '|'))) *b = '\0';
            }
        }
    }
    if (have) {
        ring[head] = cur;
        head = (head + 1) % ATK_RING_CAP;
        if (count < ATK_RING_CAP) count++;
    }
    free(buf);

    atk_entry_t *out = malloc(sizeof(atk_entry_t) * (count ? count : 1));
    if (!out) { free(ring); return NULL; }
    for (int i = 0; i < count; i++)
        out[i] = ring[(head - 1 - i + ATK_RING_CAP) % ATK_RING_CAP]; /* 最新在前 */
    free(ring);
    *out_n = count;
    return out;
}

/* query string 取值（已 url 解码） */
static void qs_val(const char *qs, const char *key, char *out, size_t outsz) {
    out[0] = '\0';
    if (!qs || !qs[0]) return;
    char pat[80];
    snprintf(pat, sizeof(pat), "%s=", key);
    const char *p = strstr(qs, pat);
    while (p && p != qs && p[-1] != '&') p = strstr(p + 1, pat);
    if (!p) return;
    p += strlen(pat);
    size_t i = 0;
    while (p[i] && p[i] != '&' && i + 1 < outsz) { out[i] = p[i]; i++; }
    out[i] = '\0';
    url_decode(out, out, outsz); /* 输出索引恒不超前输入索引，可原位解码 */
}

/* 攻击日志明细：?page=&size=&type=&action=&ip=&q=&hours= （需登录） */
static void handle_admin_attack_logs(int fd, const char *qs) {
    char tmp[64];
    long page = 1, size = 20, hours = 0;
    qs_val(qs, "page",  tmp, sizeof(tmp)); if (tmp[0]) { long v = atol(tmp); if (v >= 1 && v <= 100000) page = v; }
    qs_val(qs, "size",  tmp, sizeof(tmp)); if (tmp[0]) { long v = atol(tmp); if (v >= 1 && v <= 100) size = v; }
    qs_val(qs, "hours", tmp, sizeof(tmp)); if (tmp[0]) { long v = atol(tmp); if (v >= 0 && v <= 8760) hours = v; }
    char ftype[64] = "", faction[16] = "", fip[128] = "", fq[256] = "";
    qs_val(qs, "type",   ftype,   sizeof(ftype));
    qs_val(qs, "action", faction, sizeof(faction));
    qs_val(qs, "ip",     fip,     sizeof(fip));
    qs_val(qs, "q",      fq,      sizeof(fq));

    long scanned = 0;
    int n = 0;
    pthread_mutex_lock(&g_atk_mutex);
    atk_entry_t *arr = atk_collect(&n, ATK_SCAN_BYTES, &scanned);
    pthread_mutex_unlock(&g_atk_mutex);
    if (!arr) { send_error(fd, "500 Internal Server Error", "cannot parse attack log"); return; }

    time_t now = time(NULL);
    long start = (page - 1) * size;
    long total = 0;
    for (int i = 0; i < n; i++) {
        const atk_entry_t *e = &arr[i];
        if (ftype[0] && strcmp(e->type, ftype)) continue;
        if (faction[0] && strcmp(e->action, faction)) continue;
        if (fip[0] && !strstr(e->ip, fip)) continue;
        if (hours > 0 && (e->epoch <= 0 || now - e->epoch > hours * 3600)) continue;
        if (fq[0] && !strstr(e->path, fq) && !strstr(e->query, fq) &&
            !strstr(e->rule, fq) && !strstr(e->ip, fq) && !strstr(e->type, fq)) continue;
        total++;
    }

    char *body = malloc(MAX_RESPONSE);
    if (!body) { free(arr); send_error(fd, "500 Internal Server Error", "oom"); return; }
    size_t off = 0;
    off += snprintf(body + off, MAX_RESPONSE - off,
        "{\"success\":true,\"data\":{\"total\":%ld,\"page\":%ld,\"size\":%ld,"
        "\"scanned_mb\":%ld,\"rows\":[",
        total, page, size, scanned / (1024 * 1024));
    long idx = 0, emitted = 0;
    for (int i = 0; i < n && idx < start + size; i++) {
        const atk_entry_t *e = &arr[i];
        if (ftype[0] && strcmp(e->type, ftype)) continue;
        if (faction[0] && strcmp(e->action, faction)) continue;
        if (fip[0] && !strstr(e->ip, fip)) continue;
        if (hours > 0 && (e->epoch <= 0 || now - e->epoch > hours * 3600)) continue;
        if (fq[0] && !strstr(e->path, fq) && !strstr(e->query, fq) &&
            !strstr(e->rule, fq) && !strstr(e->ip, fq) && !strstr(e->type, fq)) continue;
        if (idx >= start) {
            char e_ts[80], e_path[1100], e_query[1100], e_rule[200], e_ip[160], e_type[160], gj[520];
            json_escape(e->ts, e_ts, sizeof(e_ts));
            json_escape(e->path, e_path, sizeof(e_path));
            json_escape(e->query, e_query, sizeof(e_query));
            json_escape(e->rule, e_rule, sizeof(e_rule));
            json_escape(e->ip, e_ip, sizeof(e_ip));
            json_escape(e->type, e_type, sizeof(e_type));
            geo_json(e->ip, gj, sizeof(gj));
            off += snprintf(body + off, MAX_RESPONSE - off,
                "%s{\"time\":\"%s\",\"type\":\"%s\",\"sev\":%d,\"rule\":\"%s\","
                "\"action\":\"%s\",\"ip\":\"%s\",\"method\":\"%s\","
                "\"path\":\"%s\",\"query\":\"%s\",%s}",
                emitted ? "," : "", e_ts, e_type, e->sev, e_rule,
                e->action, e_ip, e->method, e_path, e_query, gj);
            emitted++;
            if (off > MAX_RESPONSE - 4096) break;
        }
        idx++;
    }
    off += snprintf(body + off, MAX_RESPONSE - off, "]}}");
    send_response(fd, "200 OK", "application/json", body, off);
    free(body);
    free(arr);
}

/* ---------------- 管理 API：全局配置读写 ---------------- */

static void handle_admin_config_get(int fd) {
    char path[600];
    snprintf(path, sizeof(path), "%s/config/waf.conf", waf_home());
    FILE *fp = fopen(path, "r");
    if (!fp) { send_error(fd, "404 Not Found", "waf.conf not found"); return; }
    char *body = malloc(65536);
    if (!body) { fclose(fp); send_error(fd, "500 Internal Server Error", "oom"); return; }
    size_t off = 0;
    off += snprintf(body + off, 65536 - off, "{\"success\":true,\"data\":{");
    char line[1024]; int first = 1;
    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '[' || *p == '\n' || !*p) continue;
        char key[128] = "", val[512] = "";
        if (sscanf(p, "%127[^= \t] = %511[^\n]", key, val) != 2 &&
            sscanf(p, "%127[^=]=%511[^\n]", key, val) != 2) continue;
        /* 去掉 val 尾部空白 */
        size_t vl = strlen(val);
        while (vl && (val[vl-1] == ' ' || val[vl-1] == '\t' || val[vl-1] == '\r')) val[--vl] = '\0';
        char esc[1100]; json_escape(val, esc, sizeof(esc));
        off += snprintf(body + off, 65536 - off, "%s\"%s\":\"%s\"", first ? "" : ",", key, esc);
        first = 0;
    }
    fclose(fp);
    off += snprintf(body + off, 65536 - off, "}}");
    send_response(fd, "200 OK", "application/json", body, off);
    free(body);
}

/* 允许修改的配置键白名单 */
static const char *g_editable_keys[] = {
    "http_port", "https_port", "worker_threads", "detection_mode",
    "mode", "backend_host", "backend_port", "log_level", NULL
};

/* body 为 urlencoded: key=value&key2=value2（值仅允许安全字符） */
static void handle_admin_config_post(int fd, const char *post) {
    char updates[16][2][128]; int nupd = 0;
    char tmp[2048];
    snprintf(tmp, sizeof(tmp), "%s", post ? post : "");
    for (char *tok = strtok(tmp, "&"); tok && nupd < 16; tok = strtok(NULL, "&")) {
        char *eq = strchr(tok, '=');
        if (!eq) continue;
        *eq = '\0';
        const char *k = tok, *v = eq + 1;
        int allowed = 0;
        for (int i = 0; g_editable_keys[i]; i++)
            if (!strcmp(k, g_editable_keys[i])) { allowed = 1; break; }
        if (!allowed) continue;
        /* 值安全校验：仅字母数字 . _ - : */
        int bad = 0;
        for (const char *c = v; *c; c++)
            if (!(*c >= 'a' && *c <= 'z') && !(*c >= 'A' && *c <= 'Z') &&
                !(*c >= '0' && *c <= '9') && *c != '.' && *c != '_' &&
                *c != '-' && *c != ':') { bad = 1; break; }
        if (bad || strlen(v) >= 120) continue;
        snprintf(updates[nupd][0], 128, "%s", k);
        snprintf(updates[nupd][1], 128, "%s", v);
        nupd++;
    }
    if (!nupd) { send_error(fd, "400 Bad Request", "no valid keys"); return; }

    char path[600], bak[620];
    snprintf(path, sizeof(path), "%s/config/waf.conf", waf_home());
    snprintf(bak, sizeof(bak), "%s.bak", path);
    FILE *in = fopen(path, "r");
    if (!in) { send_error(fd, "404 Not Found", "waf.conf not found"); return; }
    FILE *out = fopen(bak, "w");
    if (!out) { fclose(in); send_error(fd, "500 Internal Server Error", "cannot write"); return; }
    char line[1024];
    int done[16]; memset(done, 0, sizeof(done));
    while (fgets(line, sizeof(line), in)) {
        int replaced = 0;
        for (int i = 0; i < nupd; i++) {
            char prefix[140];
            snprintf(prefix, sizeof(prefix), "%s", updates[i][0]);
            size_t pl = strlen(prefix);
            /* 行首（可含前导空白）匹配 key 且其后为空白或= */
            const char *p = line;
            while (*p == ' ' || *p == '\t') p++;
            if (!strncmp(p, prefix, pl) && (p[pl] == ' ' || p[pl] == '\t' || p[pl] == '=')) {
                fprintf(out, "%s = %s\n", updates[i][0], updates[i][1]);
                done[i] = 1; replaced = 1;
                break;
            }
        }
        if (!replaced) fputs(line, out);
    }
    fclose(in); fclose(out);
    if (rename(bak, path) != 0) {
        send_error(fd, "500 Internal Server Error", "rename failed");
        return;
    }
    send_json(fd, "{\"success\":true,\"message\":\"配置已保存，重启 WAF 后生效\",\"need_restart\":true}");
}

/* ---------------- 管理 API：站点管理 ---------------- */

/* 列出 config/sites/ 下所有站点 ini */
static void handle_admin_sites_get(int fd) {
    char dir[600];
    snprintf(dir, sizeof(dir), "%s/config/sites", waf_home());
    DIR *d = opendir(dir);
    if (!d) { send_error(fd, "404 Not Found", "sites dir not found"); return; }
    char *body = malloc(65536);
    if (!body) { closedir(d); send_error(fd, "500 Internal Server Error", "oom"); return; }
    size_t off = 0;
    off += snprintf(body + off, 65536 - off, "{\"success\":true,\"data\":[");
    struct dirent *de; int first = 1;
    while ((de = readdir(d))) {
        if (!strstr(de->d_name, ".conf")) continue;
        char fp_path[768];
        snprintf(fp_path, sizeof(fp_path), "%s/%s", dir, de->d_name);
        FILE *sf = fopen(fp_path, "r");
        if (!sf) continue;
        char domain[256] = "", bhost[128] = "", bport[16] = "", enabled[8] = "1";
        char line[512];
        while (fgets(line, sizeof(line), sf)) {
            char *p = line;
            while (*p == ' ' || *p == '\t') p++;
            if (!strncmp(p, "domain", 6) && strchr(p, '=') && !domain[0])
                sscanf(strchr(p, '=') + 1, " %255[^\n]", domain);
            else if (!strncmp(p, "backend_host", 12))
                sscanf(strchr(p, '=') + 1, " %127[^\n]", bhost);
            else if (!strncmp(p, "backend_port", 12))
                sscanf(strchr(p, '=') + 1, " %15[^\n]", bport);
            else if (!strncmp(p, "enabled", 7))
                sscanf(strchr(p, '=') + 1, " %7[^\n]", enabled);
        }
        fclose(sf);
        /* 清尾部空白 */
        for (char *s = domain; *s; s++) if (*s == '\r') *s = '\0';
        char esc1[600], esc2[300], esc3[300];
        json_escape(de->d_name, esc1, sizeof(esc1));
        json_escape(domain, esc2, sizeof(esc2));
        json_escape(bhost, esc3, sizeof(esc3));
        off += snprintf(body + off, 65536 - off,
            "%s{\"file\":\"%s\",\"domain\":\"%s\",\"backend_host\":\"%s\","
            "\"backend_port\":\"%s\",\"enabled\":\"%s\"}",
            first ? "" : ",", esc1, esc2, esc3, bport, enabled);
        first = 0;
    }
    closedir(d);
    off += snprintf(body + off, 65536 - off, "]}");
    send_response(fd, "200 OK", "application/json", body, off);
    free(body);
}

/* 重建 config/sites.conf 索引（保留 [global]，重写 [sites] 列表） */
static int rebuild_sites_index(void) {
    char dir[600], idx[600], tmp[620];
    snprintf(dir, sizeof(dir), "%s/config/sites", waf_home());
    snprintf(idx, sizeof(idx), "%s/config/sites.conf", waf_home());
    snprintf(tmp, sizeof(tmp), "%s.tmp", idx);

    FILE *in = fopen(idx, "r");
    FILE *out = fopen(tmp, "w");
    if (!out) { if (in) fclose(in); return -1; }

    /* 拷贝 [sites] 之前的全部内容 */
    int in_sites = 0;
    if (in) {
        char line[512];
        while (fgets(line, sizeof(line), in)) {
            if (!strncmp(line, "[sites]", 7)) { in_sites = 1; break; }
            fputs(line, out);
        }
        fclose(in);
    }
    if (!in_sites) fprintf(out, "\n");
    fprintf(out, "[sites]\n");

    DIR *d = opendir(dir);
    if (d) {
        struct dirent *de;
        while ((de = readdir(d)))
            if (strstr(de->d_name, ".conf"))
                fprintf(out, "site = %s\n", de->d_name);
        closedir(d);
    }
    fclose(out);
    return rename(tmp, idx);
}

/* 站点文件名安全化：仅保留字母数字 . - */
static void sanitize_filename(const char *in, char *out, size_t outsz) {
    size_t o = 0;
    for (size_t i = 0; in[i] && o + 1 < outsz; i++) {
        char c = in[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '.' || c == '-') out[o++] = c;
    }
    out[o] = '\0';
}

/* 下方证书辅助函数（定义见证书管理区，供站点创建复用） */
static int run_capture(const char *cmd, char *out, size_t outsz);
static int safe_fs_path(const char *p);

/* 生成自签证书（含 SAN）：certs/<domain>/{fullchain.pem,privkey.pem}
 * 用独立 openssl 配置文件写扩展，兼容 OpenSSL 1.0.2（无 -addext）与 1.1/3.x。
 * 成功返回 0，并回填 cpath/kpath。 */
static int selfsign_cert_files(const char *domain, int days,
                               char *cpath, size_t cc, char *kpath, size_t kk) {
    char dir[700];
    snprintf(dir, sizeof(dir), "%s/certs/%s", waf_home(), domain);
    char cmd[1600];
    snprintf(cmd, sizeof(cmd), "mkdir -p '%s' && chmod 700 '%s'", dir, dir);
    if (!safe_fs_path(dir) || system(cmd) != 0) return -1;

    snprintf(cpath, cc, "%s/fullchain.pem", dir);
    snprintf(kpath, kk, "%s/privkey.pem", dir);
    if (!safe_fs_path(cpath) || !safe_fs_path(kpath)) return -1;

    char cfg[900];
    snprintf(cfg, sizeof(cfg), "%s/.openssl-req.cnf", dir);
    FILE *f = fopen(cfg, "w");
    if (!f) return -1;
    fprintf(f,
        "[req]\n"
        "distinguished_name = dn\n"
        "x509_extensions = v3\n"
        "prompt = no\n"
        "[dn]\n"
        "CN = %s\n"
        "[v3]\n"
        "subjectAltName = DNS:%s\n"
        "basicConstraints = CA:FALSE\n"
        "keyUsage = digitalSignature, keyEncipherment\n"
        "extendedKeyUsage = serverAuth\n",
        domain, domain);
    fclose(f);

    snprintf(cmd, sizeof(cmd),
        "openssl req -x509 -newkey rsa:2048 -nodes -sha256 "
        "-keyout '%s' -out '%s' -days %d -config '%s' 2>/dev/null",
        kpath, cpath, days, cfg);
    char err[128];
    int rc = run_capture(cmd, err, sizeof(err));
    unlink(cfg);
    if (rc != 0) return -1;
    chmod(cpath, 0644);
    chmod(kpath, 0600);
    return 0;
}

/* POST 新增/更新站点:
 * domain=xx&backend_host=xx&backend_port=xx
 * [&document_root=xx][&ssl=0|1][&cert_days=365]
 * 生成完整站点模板（site/ssl/logging/gzip/cache/security），
 * ssl=1 时自动签发自签证书并写入 [ssl] 段。 */
static void handle_admin_sites_post(int fd, const char *post) {
    char domain[256] = "", bhost[128] = "127.0.0.1", bport[16] = "9000";
    char docroot[512] = "share", ssl[8] = "1", days[16] = "365";
    char tmp[2048];
    snprintf(tmp, sizeof(tmp), "%s", post ? post : "");
    for (char *tok = strtok(tmp, "&"); tok; tok = strtok(NULL, "&")) {
        char *eq = strchr(tok, '=');
        if (!eq) continue;
        *eq = '\0';
        if (!strcmp(tok, "domain"))            snprintf(domain, sizeof(domain), "%s", eq + 1);
        else if (!strcmp(tok, "backend_host")) snprintf(bhost, sizeof(bhost), "%s", eq + 1);
        else if (!strcmp(tok, "backend_port")) snprintf(bport, sizeof(bport), "%s", eq + 1);
        else if (!strcmp(tok, "document_root")) snprintf(docroot, sizeof(docroot), "%s", eq + 1);
        else if (!strcmp(tok, "ssl"))          snprintf(ssl, sizeof(ssl), "%s", eq + 1);
        else if (!strcmp(tok, "cert_days"))    snprintf(days, sizeof(days), "%s", eq + 1);
    }
    /* 校验：域名与主机仅允许安全字符，端口为数字 */
    for (const char *c = domain; *c; c++)
        if (!(*c >= 'a' && *c <= 'z') && !(*c >= '0' && *c <= '9') &&
            *c != '.' && *c != '-') {
            send_error(fd, "400 Bad Request", "invalid domain"); return;
        }
    for (const char *c = bhost; *c; c++)
        if (!(*c >= '0' && *c <= '9') && !(*c >= 'a' && *c <= 'z') &&
            !(*c >= 'A' && *c <= 'Z') && *c != '.' && *c != '-') {
            send_error(fd, "400 Bad Request", "invalid backend_host"); return;
        }
    for (const char *c = bport; *c; c++)
        if (!(*c >= '0' && *c <= '9')) {
            send_error(fd, "400 Bad Request", "invalid backend_port"); return;
        }
    for (const char *c = days; *c; c++)
        if (!(*c >= '0' && *c <= '9')) {
            send_error(fd, "400 Bad Request", "invalid cert_days"); return;
        }
    /* 文档根只允许路径字符，禁止换行/引号等会破坏 INI 的字符 */
    for (const char *c = docroot; *c; c++)
        if (!(*c >= 'a' && *c <= 'z') && !(*c >= 'A' && *c <= 'Z') &&
            !(*c >= '0' && *c <= '9') && !strchr("._/-:@", *c)) {
            send_error(fd, "400 Bad Request", "invalid document_root"); return;
        }
    if (!domain[0]) { send_error(fd, "400 Bad Request", "domain required"); return; }
    if (!docroot[0]) snprintf(docroot, sizeof(docroot), "%s", "share");

    int dnum = atoi(days);
    if (dnum < 1 || dnum > 3650) dnum = 365;
    int want_ssl = !(ssl[0] == '0' || !strcasecmp(ssl, "off") || !strcasecmp(ssl, "false"));

    char fname[300];
    sanitize_filename(domain, fname, sizeof(fname) - 6);
    if (!fname[0]) { send_error(fd, "400 Bad Request", "invalid domain"); return; }
    char fpath[800];
    snprintf(fpath, sizeof(fpath), "%s/config/sites/%s.conf", waf_home(), fname);
    /* 首次部署时 config/sites 可能尚未创建 */
    {
        char sdir[800];
        snprintf(sdir, sizeof(sdir), "%s/config/sites", waf_home());
        mkdir(sdir, 0755);
    }

    /* 证书路径：cert_file/key_file 用 WAF_HOME 绝对路径，避免 CWD 漂移 */
    char cpath[900] = "", kpath[900] = "";
    int cert_ok = 0;
    if (want_ssl) {
        snprintf(cpath, sizeof(cpath), "%s/certs/%s/fullchain.pem", waf_home(), domain);
        snprintf(kpath, sizeof(kpath), "%s/certs/%s/privkey.pem", waf_home(), domain);
        /* 已有可用证书则复用（更新站点不覆盖证书） */
        if (access(cpath, R_OK) == 0 && access(kpath, R_OK) == 0) {
            cert_ok = 1;
        } else if (selfsign_cert_files(domain, dnum, cpath, sizeof(cpath),
                                       kpath, sizeof(kpath)) == 0) {
            cert_ok = 1;
        }
    }

    FILE *f = fopen(fpath, "w");
    if (!f) { send_error(fd, "500 Internal Server Error", "cannot write site file"); return; }
    fprintf(f,
        "# 壁垒WAF 站点配置（由管理控制台创建 %s）\n"
        "# 修改后执行 `./waf check` 校验，再 reload/restart 生效\n"
        "\n"
        "[site]\n"
        "domain = %s\n"
        "domains = %s\n"
        "document_root = %s\n"
        "backend_host = %s\n"
        "backend_port = %s\n"
        "enabled = 1\n"
        "cc_captcha = 1\n"
        "\n"
        "[ssl]\n"
        "enabled = %d\n"
        "cert_file = %s\n"
        "key_file = %s\n"
        "\n"
        "[logging]\n"
        "enabled = 1\n"
        "level = info\n"
        "access_log = logs/%s/access.log\n"
        "error_log = logs/%s/error.log\n"
        "format = combined\n"
        "max_file_size = 100\n"
        "max_files = 7\n"
        "\n"
        "[optimization]\n"
        "worker_threads = 8\n"
        "max_connections = 2000\n"
        "connection_timeout = 60\n"
        "keepalive_timeout = 120\n"
        "\n"
        "[gzip]\n"
        "enabled = 1\n"
        "min_length = 20\n"
        "\n"
        "[cache]\n"
        "enabled = 0\n"
        "type = memory\n"
        "max_size = 256\n"
        "expire_time = 7200\n"
        "\n"
        "[security]\n"
        "csrf_protection = 1\n"
        "xss_protection = 1\n"
        "clickjacking_protection = 1\n",
        domain, domain, domain, docroot, bhost, bport,
        cert_ok ? 1 : 0, cert_ok ? cpath : "", cert_ok ? kpath : "",
        domain, domain);
    fclose(f);

    if (rebuild_sites_index() != 0) {
        send_error(fd, "500 Internal Server Error", "index update failed"); return;
    }

    char msg[700];
    if (want_ssl && !cert_ok)
        snprintf(msg, sizeof(msg),
                 "站点已保存，但自签证书生成失败（请检查 openssl）；可稍后在证书管理中手动生成。重启 WAF 后生效");
    else if (cert_ok)
        snprintf(msg, sizeof(msg),
                 "站点已保存，自签证书已生成并写入 [ssl]：%s。重启 WAF 后生效", cpath);
    else
        snprintf(msg, sizeof(msg), "站点已保存（未启用 HTTPS）。重启 WAF 后生效");
    char esc[900]; json_escape(msg, esc, sizeof(esc));
    char body[1000];
    int bl = snprintf(body, sizeof(body), "{\"success\":true,\"message\":\"%s\"}", esc);
    send_response(fd, "200 OK", "application/json", body, (size_t)bl);
}

/* POST 删除站点: file=xx.conf */
static void handle_admin_sites_delete(int fd, const char *post) {
    char file[300] = "";
    const char *p = post ? strstr(post, "file=") : NULL;
    if (p) sscanf(p + 5, "%299s", file);
    char *amp = strchr(file, '&'); if (amp) *amp = '\0';
    char safe[300];
    sanitize_filename(file, safe, sizeof(safe));
    if (!safe[0] || !strstr(safe, ".conf")) {
        send_error(fd, "400 Bad Request", "invalid file"); return;
    }
    char fpath[800];
    snprintf(fpath, sizeof(fpath), "%s/config/sites/%s", waf_home(), safe);
    if (unlink(fpath) != 0) {
        send_error(fd, "404 Not Found", "site file not found"); return;
    }
    rebuild_sites_index();
    send_json(fd, "{\"success\":true,\"message\":\"站点已删除，重载或重启 WAF 后生效\"}");
}

/* ---------------- 管理 API：规则列表 ---------------- */

static void handle_admin_rules_get(int fd) {
    char dir[600];
    snprintf(dir, sizeof(dir), "%s/rules", waf_home());
    DIR *d = opendir(dir);
    if (!d) { send_error(fd, "404 Not Found", "rules dir not found"); return; }
    char *body = malloc(65536);
    if (!body) { closedir(d); send_error(fd, "500 Internal Server Error", "oom"); return; }
    size_t off = 0;
    off += snprintf(body + off, 65536 - off, "{\"success\":true,\"data\":[");
    struct dirent *de; int first = 1;
    while ((de = readdir(d))) {
        if (!strstr(de->d_name, ".rules") && !strstr(de->d_name, ".ip")) continue;
        char fp_path[768];
        snprintf(fp_path, sizeof(fp_path), "%s/%s", dir, de->d_name);
        FILE *sf = fopen(fp_path, "r");
        if (!sf) continue;
        long count = 0;
        char line[1024];
        while (fgets(line, sizeof(line), sf)) {
            char *p = line;
            while (*p == ' ' || *p == '\t') p++;
            if (*p == '#' || *p == '\n' || !*p) continue;
            count++;
        }
        fclose(sf);
        char esc[300]; json_escape(de->d_name, esc, sizeof(esc));
        off += snprintf(body + off, 65536 - off,
            "%s{\"file\":\"%s\",\"entries\":%ld}", first ? "" : ",", esc, count);
        first = 0;
    }
    closedir(d);
    off += snprintf(body + off, 65536 - off, "]}");
    send_response(fd, "200 OK", "application/json", body, off);
    free(body);
}

/* ---------------- 管理 API：证书管理 ----------------
 * 证书根目录 WAF_HOME/certs/<域名>/{fullchain.pem,privkey.pem}；
 * 列表 = 已接入站点 cert_file 动态解析（openssl x509）+ 证书根目录物理枚举；
 * 上传/自签通过后写盘。全部用 popen 白名单参数，拒绝任何 shell 注入面。 */

/* 解析 X.509 notBefore/notAfter（"MMM DD HH:MM:SS YYYY GMT"）为 epoch */
static time_t asn1_time_to_epoch(const char *s) {
    static const char *mons[] = {"Jan","Feb","Mar","Apr","May","Jun",
                                 "Jul","Aug","Sep","Oct","Nov","Dec"};
    struct tm tmv; memset(&tmv, 0, sizeof(tmv));
    char mon[8] = "";
    if (sscanf(s, "%7s %d %d:%d:%d %d", mon, &tmv.tm_mday,
               &tmv.tm_hour, &tmv.tm_min, &tmv.tm_sec, &tmv.tm_year) != 6) return 0;
    int m = -1;
    for (int i = 0; i < 12; i++) if (!strncmp(mon, mons[i], 3)) { m = i; break; }
    if (m < 0) return 0;
    tmv.tm_mon = m; tmv.tm_year -= 1900; tmv.tm_isdst = 0;
    return timegm(&tmv);
}

/* 执行 openssl 并捕获输出（args 预校验仅安全字符，杜绝注入） */
static int run_capture(const char *cmd, char *out, size_t outsz) {
    FILE *pp = popen(cmd, "r");
    if (!pp) return -1;
    size_t n = fread(out, 1, outsz - 1, pp);
    out[n] = '\0';
    int rc = pclose(pp);
    return (WIFEXITED(rc) && WEXITSTATUS(rc) == 0) ? 0 : -1;
}

/* 校验证书/密钥路径：拒绝任何 shell 元字符 */
static int safe_fs_path(const char *p) {
    if (!p || !p[0]) return 0;
    for (const char *c = p; *c; c++) {
        if (!isalnum((unsigned char)*c) && *c != '/' && *c != '.' &&
            *c != '-' && *c != '_') return 0;
    }
    return !strstr(p, "..");
}

/* 从单个证书文件解析元数据；成功返回 0 并填充 JSON 片段（不含外层 {}） */
static int cert_meta_json(const char *cert_path, const char *site, const char *source,
                          char *jbuf, size_t jcap) {
    char cmd[1200], out[8192];
    snprintf(cmd, sizeof(cmd),
        "openssl x509 -in '%s' -noout -subject -issuer -enddate -startdate 2>/dev/null",
        cert_path);
    if (run_capture(cmd, out, sizeof(out)) != 0) return -1;

    char subject[256] = "", issuer[256] = "", nb[64] = "", na[64] = "";
    char *save = NULL;
    for (char *ln = strtok_r(out, "\n", &save); ln; ln = strtok_r(NULL, "\n", &save)) {
        if (!strncmp(ln, "subject=", 8))      snprintf(subject, sizeof(subject), "%s", ln + 8);
        else if (!strncmp(ln, "issuer=", 7))  snprintf(issuer, sizeof(issuer), "%s", ln + 7);
        else if (!strncmp(ln, "notBefore=", 10)) snprintf(nb, sizeof(nb), "%s", ln + 10);
        else if (!strncmp(ln, "notAfter=", 9))   snprintf(na, sizeof(na), "%s", ln + 9);
    }
    time_t now = time(NULL), exp = asn1_time_to_epoch(na);
    long days = exp ? (long)((exp - now) / 86400) : -9999;

    /* 提取 CN：subject 形如 "CN = example.com" 或老式 "/CN=example.com" */
    char cn[128] = "";
    char *p = strstr(subject, "CN");
    if (p) {
        p = strchr(p, '=');
        if (p) { p++; while (*p == ' ') p++; snprintf(cn, sizeof(cn), "%s", p);
                 char *e = strchr(cn, '/'); if (e) *e = '\0'; }
    }

    /* 指纹 */
    char fp[160] = "";
    snprintf(cmd, sizeof(cmd), "openssl x509 -in '%s' -noout -fingerprint -sha256 2>/dev/null", cert_path);
    char fpout[256] = "";
    if (run_capture(cmd, fpout, sizeof(fpout)) == 0) {
        char *q = strchr(fpout, '=');
        if (q) snprintf(fp, sizeof(fp), "%s", q + 1);
        char *nl = strchr(fp, '\n'); if (nl) *nl = '\0';
    }

    char esc_cert[700], esc_cn[200], esc_iss[300], esc_fp[200], esc_site[300];
    json_escape(cert_path, esc_cert, sizeof(esc_cert));
    json_escape(cn, esc_cn, sizeof(esc_cn));
    json_escape(issuer, esc_iss, sizeof(esc_iss));
    json_escape(fp, esc_fp, sizeof(esc_fp));
    json_escape(site ? site : "", esc_site, sizeof(esc_site));

    const char *status = (days < 0) ? "expired" : (days <= 30 ? "warning" : "ok");
    snprintf(jbuf, jcap,
        "\"site\":\"%s\",\"cert\":\"%s\",\"cn\":\"%s\",\"issuer\":\"%s\","
        "\"not_before\":\"%s\",\"not_after\":\"%s\",\"days_left\":%ld,"
        "\"fingerprint\":\"%s\",\"status\":\"%s\",\"source\":\"%s\"",
        esc_site, esc_cert, esc_cn, esc_iss, nb, na, days, esc_fp, status,
        source ? source : "");
    return 0;
}

/* GET /api/admin/certs —— 站点引用证书（动态）+ 证书根目录物理文件 */
static void handle_admin_certs_get(int fd) {
    size_t cap = 262144;
    char *body = malloc(cap);
    if (!body) { send_error(fd, "500 Internal Server Error", "oom"); return; }
    size_t off = 0;
    off += snprintf(body + off, cap - off, "{\"success\":true,\"data\":[");

    int first = 1;
    /* 1) 站点引用的证书：config/sites 下 conf 的 cert_file */
    char sdir[600];
    snprintf(sdir, sizeof(sdir), "%s/config/sites", waf_home());
    DIR *sd = opendir(sdir);
    if (sd) {
        struct dirent *de;
        while ((de = readdir(sd))) {
            if (!strstr(de->d_name, ".conf")) continue;
            char fp[900];
            snprintf(fp, sizeof(fp), "%s/%s", sdir, de->d_name);
            FILE *sf = fopen(fp, "r");
            if (!sf) continue;
            char domain[256] = "", cert[700] = "";
            char ln[1024];
            while (fgets(ln, sizeof(ln), sf)) {
                if (!strncmp(ln, "domain", 6))
                    sscanf(strchr(ln, '=') ? strchr(ln, '=') + 1 : ln, " %255[^\n]", domain);
                else if (!strncmp(ln, "cert_file", 9))
                    sscanf(strchr(ln, '=') ? strchr(ln, '=') + 1 : ln, " %699[^\n]", cert);
            }
            fclose(sf);
            if (!cert[0] || !safe_fs_path(cert)) continue;
            if (access(cert, R_OK) != 0) continue;   /* 文件缺失：由 2) 物理枚举体现 */
            char item[4096];
            if (cert_meta_json(cert, domain, "site", item, sizeof(item)) == 0) {
                off += snprintf(body + off, cap - off, "%s{%s}", first ? "" : ",", item);
                first = 0;
            }
        }
        closedir(sd);
    }

    /* 2) 物理证书：<WAF_HOME>/certs/<域>/fullchain.pem（未被站点引用的也列出） */
    char croot[600];
    snprintf(croot, sizeof(croot), "%s/certs", waf_home());
    DIR *cd = opendir(croot);
    if (cd) {
        struct dirent *de;
        while ((de = readdir(cd))) {
            if (de->d_name[0] == '.') continue;
            char cp[900];
            snprintf(cp, sizeof(cp), "%s/%s/fullchain.pem", croot, de->d_name);
            if (access(cp, R_OK) != 0) continue;
            /* 已在站点列表出现则跳过（避免重复） */
            if (strstr(body, cp)) continue;
            char item[4096];
            if (cert_meta_json(cp, de->d_name, "store", item, sizeof(item)) == 0) {
                off += snprintf(body + off, cap - off, "%s{%s}", first ? "" : ",", item);
                first = 0;
            }
        }
        closedir(cd);
    }
    off += snprintf(body + off, cap - off, "]}");
    send_response(fd, "200 OK", "application/json", body, off);
    free(body);
}

/* 从表单取大字段（PEM 可能很长，form_val 的 raw 缓冲仅 512，不够用） */
static void form_val_large(const char *post, const char *key, char *out, size_t outsz) {
    out[0] = '\0';
    if (!post) return;
    char pat[80];
    snprintf(pat, sizeof(pat), "%s=", key);
    const char *p = strstr(post, pat);
    while (p && p != post && p[-1] != '&') p = strstr(p + 1, pat);
    if (!p) return;
    p += strlen(pat);
    size_t ri = 0;
    while (p[ri] && p[ri] != '&' && ri + 1 < outsz) { out[ri] = p[ri]; ri++; }
    out[ri] = '\0';
    url_decode(out, out, outsz);
}

/* 将证书写入站点 conf 的 [ssl] 段（section 感知）：
 * - 已有 [ssl]：替换 cert_file/key_file 行并强制 enabled = 1（行内重写，落在原 section 内）
 * - 无 [ssl]：文件尾部追加完整 [ssl] 段
 * 解析器（waf_sites.c）只认 [ssl] 段内的 cert_file 且要求 enabled = 1 */
static int apply_cert_to_site_conf(const char *spath, const char *cpath, const char *kpath) {
    FILE *sf = fopen(spath, "r");
    if (!sf) return -1;
    char whole[16384] = "";
    size_t rn = fread(whole, 1, sizeof(whole) - 1, sf);
    whole[rn] = '\0';
    fclose(sf);

    FILE *wf = fopen(spath, "w");
    if (!wf) return -1;
    int in_ssl = 0, seen_ssl = 0, wrote_ck = 0, ssl_enabled_set = 0;
    char *save = NULL;
    for (char *ln = strtok_r(whole, "\n", &save); ln; ln = strtok_r(NULL, "\n", &save)) {
        char t[1024]; snprintf(t, sizeof(t), "%s", ln);
        const char *p = t; while (*p == ' ' || *p == '\t') p++;
        if (*p == '[') {
            if (in_ssl && !wrote_ck) {
                if (!ssl_enabled_set) fprintf(wf, "enabled = 1\n");
                fprintf(wf, "cert_file = %s\nkey_file = %s\n", cpath, kpath);
                wrote_ck = 1;
            }
            in_ssl = !strncmp(p, "[ssl]", 5);
            if (in_ssl) seen_ssl = 1;
            fprintf(wf, "%s\n", ln);
            continue;
        }
        if (in_ssl && (!strncmp(p, "cert_file", 9) || !strncmp(p, "key_file", 8)))
            continue;   /* 旧证书行丢弃，统一重写 */
        if (in_ssl && !strncmp(p, "enabled", 7)) {
            fprintf(wf, "enabled = 1\n");
            ssl_enabled_set = 1;
            continue;
        }
        fprintf(wf, "%s\n", ln);
    }
    if (in_ssl && !wrote_ck) {   /* [ssl] 是最后一个 section */
        if (!ssl_enabled_set) fprintf(wf, "enabled = 1\n");
        fprintf(wf, "cert_file = %s\nkey_file = %s\n", cpath, kpath);
        wrote_ck = 1;
    }
    if (!seen_ssl)
        fprintf(wf, "\n[ssl]\nenabled = 1\ncert_file = %s\nkey_file = %s\n", cpath, kpath);
    fclose(wf);
    return 0;
}

/* POST /api/admin/certs/upload —— domain=xx&cert=PEM&key=PEM[&apply=1]
 * apply=1 时同步写入 config/sites/<domain>.conf 的 [ssl] 段（站点须已存在） */
static void handle_admin_certs_upload(int fd, const char *post) {
    char domain[256] = "", apply[8] = "";
    static char cert_pem[65536], key_pem[65536];
    form_val(post, "domain", domain, sizeof(domain));
    form_val(post, "apply", apply, sizeof(apply));
    form_val_large(post, "cert", cert_pem, sizeof(cert_pem));
    form_val_large(post, "key", key_pem, sizeof(key_pem));

    for (const char *c = domain; *c; c++)
        if (!isalnum((unsigned char)*c) && *c != '.' && *c != '-') {
            send_error(fd, "400 Bad Request", "invalid domain"); return;
        }
    if (!domain[0]) { send_error(fd, "400 Bad Request", "domain required"); return; }
    if (!strstr(cert_pem, "BEGIN CERTIFICATE")) {
        send_error(fd, "400 Bad Request", "cert 需为 PEM 格式"); return;
    }
    if (!strstr(key_pem, "PRIVATE KEY")) {
        send_error(fd, "400 Bad Request", "key 需为 PEM 格式私钥"); return;
    }

    /* 落盘前先验证书与私钥匹配（modulus md5 比对） */
    char dir[700];
    snprintf(dir, sizeof(dir), "%s/certs/%s", waf_home(), domain);
    char cmd[1400];
    snprintf(cmd, sizeof(cmd), "mkdir -p '%s' && chmod 700 '%s'", dir, dir);
    if (!safe_fs_path(dir) || system(cmd) != 0) {
        send_error(fd, "500 Internal Server Error", "cannot create cert dir"); return;
    }

    char cpath[900], kpath[900];
    snprintf(cpath, sizeof(cpath), "%s/fullchain.pem", dir);
    snprintf(kpath, sizeof(kpath), "%s/privkey.pem", dir);

    /* 写临时文件做配对验证（写完即删） */
    char tc[900], tk[900];
    snprintf(tc, sizeof(tc), "%s/.up_c.pem", dir);
    snprintf(tk, sizeof(tk), "%s/.up_k.pem", dir);
    FILE *f = fopen(tc, "w"); if (f) { fputs(cert_pem, f); fclose(f); }
    f = fopen(tk, "w"); if (f) { fputs(key_pem, f); fclose(f); }

    char out1[128], out2[128];
    snprintf(cmd, sizeof(cmd), "openssl x509 -in '%s' -noout -modulus 2>/dev/null | openssl md5", tc);
    int okc = (run_capture(cmd, out1, sizeof(out1)) == 0 && strstr(out1, "="));
    snprintf(cmd, sizeof(cmd), "openssl rsa -in '%s' -noout -modulus 2>/dev/null | openssl md5", tk);
    int okk = (run_capture(cmd, out2, sizeof(out2)) == 0 && strstr(out2, "="));
    int match = (okc && okk && !strcmp(out1, out2));

    if (!match) { unlink(tc); unlink(tk);
        send_error(fd, "400 Bad Request", "证书与私钥不匹配或格式错误"); return; }

    rename(tc, cpath); rename(tk, kpath);
    chmod(cpath, 0644); chmod(kpath, 0600);

    /* apply=1：写入已存在站点的 [ssl] 段 */
    if (!strcmp(apply, "1")) {
        char spath[900];
        snprintf(spath, sizeof(spath), "%s/config/sites/%s.conf", waf_home(), domain);
        if (!safe_fs_path(spath) || access(spath, W_OK) != 0) {
            send_error(fd, "400 Bad Request", "站点配置不存在，请先在站点管理中创建该站点");
            return;
        }
        if (apply_cert_to_site_conf(spath, cpath, kpath) != 0) {
            send_error(fd, "500 Internal Server Error", "站点配置写入失败");
            return;
        }
    }
    char msg[300];
    snprintf(msg, sizeof(msg), "证书已上传至 %s%s", dir,
             !strcmp(apply, "1") ? "，已写入站点配置（重启 WAF 生效）" : "");
    char esc[400]; json_escape(msg, esc, sizeof(esc));
    char body[600];
    int bl = snprintf(body, sizeof(body), "{\"success\":true,\"message\":\"%s\"}", esc);
    send_response(fd, "200 OK", "application/json", body, (size_t)bl);
}

/* POST /api/admin/certs/selfsign —— domain=xx&days=365[&apply=1] */
static void handle_admin_certs_selfsign(int fd, const char *post) {
    char domain[256] = "", days[16] = "365", apply[8] = "";
    form_val(post, "domain", domain, sizeof(domain));
    form_val(post, "days", days, sizeof(days));
    form_val(post, "apply", apply, sizeof(apply));
    for (const char *c = domain; *c; c++)
        if (!isalnum((unsigned char)*c) && *c != '.' && *c != '-') {
            send_error(fd, "400 Bad Request", "invalid domain"); return;
        }
    for (const char *c = days; *c; c++)
        if (!isdigit((unsigned char)*c)) {
            send_error(fd, "400 Bad Request", "invalid days"); return;
        }
    if (!domain[0]) { send_error(fd, "400 Bad Request", "domain required"); return; }
    int dnum = atoi(days);
    if (dnum < 1 || dnum > 3650) { send_error(fd, "400 Bad Request", "days 1-3650"); return; }

    char cpath[900], kpath[900];
    if (selfsign_cert_files(domain, dnum, cpath, sizeof(cpath),
                            kpath, sizeof(kpath)) != 0) {
        send_error(fd, "500 Internal Server Error", "openssl 生成失败"); return;
    }

    if (!strcmp(apply, "1")) {
        char spath[900];
        snprintf(spath, sizeof(spath), "%s/config/sites/%s.conf", waf_home(), domain);
        if (!safe_fs_path(spath) || access(spath, W_OK) != 0) {
            send_error(fd, "400 Bad Request", "站点配置不存在，请先在站点管理中创建该站点");
            return;
        }
        if (apply_cert_to_site_conf(spath, cpath, kpath) != 0) {
            send_error(fd, "500 Internal Server Error", "站点配置写入失败");
            return;
        }
    }
    char body[512];
    int bl = snprintf(body, sizeof(body),
        "{\"success\":true,\"message\":\"自签证书已生成：%s（%d 天%s）\"}",
        cpath, dnum, !strcmp(apply, "1") ? "，已写入站点配置" : "");
    send_response(fd, "200 OK", "application/json", body, (size_t)bl);
}

/* ---------------- 证书续期（手动「立即续期」+ 后台每日自动） ----------------
 * Let's Encrypt 证书：certbot renew（webroot 模式，-w 取站点 document_root；
 *   --no-random-sleep-on-renew 规避非交互随机延迟）→ 成功后从 /etc/letsencrypt/live/
 *   <证书名>/ 回填到站点 cert_file/key_file。
 * 自签证书：用原 CN 重新签发（openssl req -x509，365 天）。
 * 续期成功后向数据平面发 SIGHUP → SSL 上下文热加载（无需重启即生效）。 */

static pthread_mutex_t g_renew_lock = PTHREAD_MUTEX_INITIALIZER;

/* 取证书 CN（subject 的 CN 值）；失败返回空串 */
static void ssl_cert_cn_of(const char *cert, char *out, size_t outsz) {
    out[0] = '\0';
    if (!safe_fs_path(cert)) return;
    char cmd[600], buf[1024];
    snprintf(cmd, sizeof(cmd), "openssl x509 -in '%s' -noout -subject 2>/dev/null", cert);
    if (run_capture(cmd, buf, sizeof(buf)) != 0) return;
    char *p = strstr(buf, "CN");
    if (!p) return;
    p = strchr(p, '=');
    if (!p) return;
    p++; while (*p == ' ') p++;
    size_t i = 0;
    while (p[i] && p[i] != '\n' && p[i] != ',' && p[i] != '/' && i + 1 < outsz) { out[i] = p[i]; i++; }
    while (i > 0 && out[i-1] == ' ') i--;
    out[i] = '\0';
}

/* 是否 Let's Encrypt 签发（issuer 含 "Let's Encrypt"） */
static int ssl_cert_is_le(const char *cert) {
    if (!safe_fs_path(cert)) return 0;
    char cmd[600], buf[1024];
    snprintf(cmd, sizeof(cmd), "openssl x509 -in '%s' -noout -issuer 2>/dev/null", cert);
    if (run_capture(cmd, buf, sizeof(buf)) != 0) return 0;
    return strstr(buf, "Let's Encrypt") != NULL;
}

/* certbot 是否可用（续期 Let's Encrypt 证书的前提） */
static int certbot_available(void) {
    return system("command -v certbot >/dev/null 2>&1") == 0;
}

/* LE 证书名 = cert_file 父目录名（.../letsencrypt/dbask.cn/fullchain.pem → dbask.cn） */
static void cert_le_name(const char *cert, char *out, size_t outsz) {
    out[0] = '\0';
    const char *slash = strrchr(cert, '/');
    if (!slash) return;
    size_t dlen = (size_t)(slash - cert);
    char dir[700];
    if (dlen >= sizeof(dir)) dlen = sizeof(dir) - 1;
    memcpy(dir, cert, dlen); dir[dlen] = '\0';
    const char *s2 = strrchr(dir, '/');
    snprintf(out, outsz, "%s", s2 ? s2 + 1 : dir);
}

/* 读取站点 conf 的首个 domain/document_root/cert_file/key_file */
static void read_site_cert_conf(const char *spath, char *domain, size_t dsz,
                                char *docroot, size_t rsz, char *cert, size_t csz,
                                char *key, size_t ksz) {
    domain[0] = docroot[0] = cert[0] = key[0] = '\0';
    FILE *f = fopen(spath, "r");
    if (!f) return;
    char ln[1024];
    while (fgets(ln, sizeof(ln), f)) {
        char *eq = strchr(ln, '=');
        if (!eq) continue;
        *eq = '\0';
        char *k = ln; while (*k == ' ' || *k == '\t') k++;
        size_t kl = strlen(k); while (kl && (k[kl-1] == ' ' || k[kl-1] == '\t')) k[--kl] = '\0';
        char *v = eq + 1; while (*v == ' ' || *v == '\t') v++;
        size_t vl = strlen(v);
        while (vl && (v[vl-1] == '\n' || v[vl-1] == '\r' || v[vl-1] == ' ' || v[vl-1] == '\t')) v[--vl] = '\0';
        if (!strcmp(k, "domain") && !domain[0]) snprintf(domain, dsz, "%s", v);
        else if (!strcmp(k, "document_root") && !docroot[0]) snprintf(docroot, rsz, "%s", v);
        else if (!strcmp(k, "cert_file") && !cert[0]) snprintf(cert, csz, "%s", v);
        else if (!strcmp(k, "key_file") && !key[0]) snprintf(key, ksz, "%s", v);
    }
    fclose(f);
}

static void last_nonempty_line(const char *s, char *out, size_t outsz) {
    out[0] = '\0';
    const char *p = s, *last = s;
    while (*p) { if (*p == '\n') last = p + 1; p++; }
    while (*last == ' ' || *last == '\t' || *last == '\r') last++;
    size_t i = 0;
    while (last[i] && last[i] != '\n' && last[i] != '\r' && i + 1 < outsz) { out[i] = last[i]; i++; }
    out[i] = '\0';
}

/* 续期单张站点证书。force=1：LE 强制续期（手动）；自签始终重签。
 * 返回 0=已续期 1=跳过（未到期） -1=失败；msg 写结果描述 */
static int renew_one_cert(const char *domain, const char *docroot,
                          const char *cert, const char *key, int force,
                          char *msg, size_t msgsz) {
    if (!cert[0] || !safe_fs_path(cert) || !key[0] || !safe_fs_path(key)) {
        snprintf(msg, msgsz, "证书/私钥路径无效"); return -1;
    }
    if (access(cert, R_OK) != 0) { snprintf(msg, msgsz, "证书文件缺失"); return -1; }

    if (ssl_cert_is_le(cert)) {
        char name[256]; cert_le_name(cert, name, sizeof(name));
        if (!name[0] || !safe_fs_path(name)) { snprintf(msg, msgsz, "无法解析证书名"); return -1; }
        if (!certbot_available()) {
            snprintf(msg, msgsz, "certbot 未安装，无法续期 Let's Encrypt 证书（yum install certbot）");
            return -1;
        }
        /* 固定 webroot：数据平面本机响应 /.well-known/acme-challenge/，
         * 不依赖业务站点 document_root（反代站点通常没有可用的该目录） */
        char acme[900], mkd[1000];
        snprintf(acme, sizeof(acme), "%s/web/acme", waf_home());
        snprintf(mkd, sizeof(mkd), "mkdir -p '%s/.well-known/acme-challenge'", acme);
        const char *wr = acme;
        if (system(mkd) != 0) {
            if (docroot[0] && safe_fs_path(docroot)) wr = docroot;
            else { snprintf(msg, msgsz, "无法创建 ACME webroot：%s", acme); return -1; }
        }
        char cmd[1400], out[8192];
        snprintf(cmd, sizeof(cmd),
            "certbot renew --cert-name '%s' -a webroot -w '%s' --no-random-sleep-on-renew %s 2>&1",
            name, wr, force ? "--force-renewal" : "");
        if (run_capture(cmd, out, sizeof(out)) != 0) {
            char el[400]; last_nonempty_line(out, el, sizeof(el));
            snprintf(msg, msgsz, "certbot 续期失败：%s", el);
            return -1;
        }
        /* certbot 在证书未临近到期时不执行续期（exit 0）。但 certbot 自身 timer
         * 可能已先行续期，此时 live 目录产物比站点副本新，需要回填。 */
        char livec[700], livek[700];
        snprintf(livec, sizeof(livec), "/etc/letsencrypt/live/%s/fullchain.pem", name);
        snprintf(livek, sizeof(livek), "/etc/letsencrypt/live/%s/privkey.pem", name);
        int not_due = strstr(out, "No renewals were attempted") ||
                      strstr(out, "not yet due for renewal");
        if (not_due) {
            if (!safe_fs_path(livec) || access(livec, R_OK) != 0) {
                snprintf(msg, msgsz, "Let's Encrypt 证书未临近到期，跳过");
                return 1;
            }
            char cmp[1500];
            snprintf(cmp, sizeof(cmp), "cmp -s '%s' '%s'", livec, cert);
            if (system(cmp) == 0) {
                snprintf(msg, msgsz, "Let's Encrypt 证书未临近到期，跳过");
                return 1;
            }
            /* 外部续期产物与站点副本不一致：继续走回填 */
        }
        if (!safe_fs_path(livec) || access(livec, R_OK) != 0 ||
            !safe_fs_path(livek) || access(livek, R_OK) != 0) {
            snprintf(msg, msgsz, not_due ? "证书未变化，跳过" : "续期成功但未找到签发产物");
            return not_due ? 1 : -1;
        }
        char cp[1600];
        snprintf(cp, sizeof(cp),
            "cp -f '%s' '%s' && cp -f '%s' '%s' && chmod 644 '%s' && chmod 600 '%s'",
            livec, cert, livek, key, cert, key);
        if (system(cp) != 0) { snprintf(msg, msgsz, "续期成功但证书回填失败"); return -1; }
        snprintf(msg, msgsz, not_due ? "已同步 certbot 最新证书（外部续期）"
                                     : "Let's Encrypt 证书已续期并回填");
        return 0;
    }

    /* 自签：非强制时仅在临近到期（≤30 天）才重签 */
    if (!force) {
        char cb[600], dummy[64];
        snprintf(cb, sizeof(cb), "openssl x509 -in '%s' -noout -checkend 2592000 2>/dev/null", cert);
        if (run_capture(cb, dummy, sizeof(dummy)) == 0) {
            snprintf(msg, msgsz, "未临近到期，跳过"); return 1;
        }
    }
    char cn[160]; ssl_cert_cn_of(cert, cn, sizeof(cn));
    if (!cn[0]) snprintf(cn, sizeof(cn), "%s", domain);
    if (!cn[0] || !safe_fs_path(cn)) { snprintf(msg, msgsz, "无法确定 CN"); return -1; }
    char gcmd[1600], dummy2[64];
    /* 用临时 openssl 配置文件写入 SAN：兼容 el7 的 OpenSSL 1.0.2
     * （该版本不支持 req 的 -addext 选项） */
    char cnf[256], cnf_body[1024];
    snprintf(cnf, sizeof(cnf), "/tmp/waf-selfsign-%d.cnf", (int)getpid());
    FILE *cf = fopen(cnf, "w");
    if (!cf) { snprintf(msg, msgsz, "无法创建自签配置文件"); return -1; }
    snprintf(cnf_body, sizeof(cnf_body),
        "[req]\nprompt = no\ndistinguished_name = dn\nx509_extensions = v3_req\n\n"
        "[dn]\nCN = %s\n\n"
        "[v3_req]\nsubjectAltName = DNS:%s\nbasicConstraints = CA:FALSE\n"
        "keyUsage = digitalSignature, keyEncipherment\nextendedKeyUsage = serverAuth\n",
        cn, cn);
    fputs(cnf_body, cf);
    fclose(cf);
    snprintf(gcmd, sizeof(gcmd),
        "openssl req -x509 -newkey rsa:2048 -nodes -keyout '%s' -out '%s' -days 365 "
        "-config '%s' -extensions v3_req 2>/dev/null",
        key, cert, cnf);
    int rc = run_capture(gcmd, dummy2, sizeof(dummy2));
    unlink(cnf);
    if (rc != 0) {
        snprintf(msg, msgsz, "自签重签失败"); return -1;
    }
    chmod(cert, 0644); chmod(key, 0600);
    snprintf(msg, msgsz, "自签证书已重签（CN=%s，365 天）", cn);
    return 0;
}

/* 向数据平面发 SIGHUP（证书热加载）；返回 1=已发送 */
static int signal_data_plane_reload(void) {
    char p[700];
    snprintf(p, sizeof(p), "%s/logs/bileiwaf.pid", waf_home());
    FILE *f = fopen(p, "r");
    if (!f) return 0;
    long pid = 0;
    if (fscanf(f, "%ld", &pid) != 1) pid = 0;
    fclose(f);
    if (pid <= 0) return 0;
    return kill((pid_t)pid, SIGHUP) == 0 ? 1 : 0;
}

/* 续期所有站点证书；only_domain 非空则仅该域名。结果 JSON 写 out，
 * 返回续期成功数，*failed 写失败数 */
static int renew_all_sites(const char *only_domain, int force, int log_detail,
                           char *out, size_t outsz, int *failed, int *skipped) {
    char sdir[600];
    snprintf(sdir, sizeof(sdir), "%s/config/sites", waf_home());
    DIR *d = opendir(sdir);
    size_t off = 0;
    int ok = 0, nf = 0, nsk = 0, first = 1;
    char seen[32][700];   /* 已处理证书路径：多站点共用一个证书时避免重复续期 */
    int seen_n = 0;
    off += snprintf(out + off, outsz - off, "[");
    if (d) {
        struct dirent *de;
        while ((de = readdir(d))) {
            if (!strstr(de->d_name, ".conf")) continue;
            char sp[900];
            snprintf(sp, sizeof(sp), "%s/%s", sdir, de->d_name);
            char domain[256], docroot[600], cert[700], key[700];
            read_site_cert_conf(sp, domain, sizeof(domain), docroot, sizeof(docroot),
                                cert, sizeof(cert), key, sizeof(key));
            if (!domain[0] || !cert[0]) continue;
            if (only_domain && only_domain[0] && strcmp(only_domain, domain)) continue;
            int dup = 0;
            for (int i = 0; i < seen_n; i++)
                if (strcmp(seen[i], cert) == 0) { dup = 1; break; }
            if (dup) continue;
            if (seen_n < 32) snprintf(seen[seen_n++], sizeof(seen[0]), "%s", cert);
            char msg[600];
            int rc = renew_one_cert(domain, docroot, cert, key, force, msg, sizeof(msg));
            if (rc == 0) ok++; else if (rc < 0) nf++; else nsk++;
            if (log_detail) {
                char lp[700];
                snprintf(lp, sizeof(lp), "%s/logs/admin.log", waf_home());
                FILE *lg = fopen(lp, "a");
                if (lg) {
                    char ts[32]; time_t now = time(NULL);
                    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));
                    fprintf(lg, "[%s] [auto-renew] %s: %s - %s\n", ts, domain,
                            rc == 0 ? "renewed" : (rc == 1 ? "skipped" : "failed"), msg);
                    fclose(lg);
                }
            }
            char escd[300], escm[900];
            json_escape(domain, escd, sizeof(escd));
            json_escape(msg, escm, sizeof(escm));
            off += snprintf(out + off, outsz - off,
                "%s{\"domain\":\"%s\",\"result\":\"%s\",\"message\":\"%s\"}",
                first ? "" : ",", escd,
                rc == 0 ? "renewed" : (rc == 1 ? "skipped" : "failed"), escm);
            first = 0;
        }
        closedir(d);
    }
    off += snprintf(out + off, outsz - off, "]");
    if (failed) *failed = nf;
    if (skipped) *skipped = nsk;
    return ok;
}

/* POST /api/admin/certs/renew —— domain=可选（缺省=续期全部站点证书） */
static void handle_admin_certs_renew(int fd, const char *post) {
    char domain[256] = "";
    form_val(post, "domain", domain, sizeof(domain));
    if (domain[0]) {
        for (const char *c = domain; *c; c++)
            if (!isalnum((unsigned char)*c) && *c != '.' && *c != '-') {
                send_error(fd, "400 Bad Request", "invalid domain"); return;
            }
    }
    if (pthread_mutex_trylock(&g_renew_lock) != 0) {
        send_error(fd, "409 Conflict", "续期任务正在进行，请稍后重试"); return;
    }
    char *out = malloc(65536), *body = malloc(65536);
    if (!out || !body) {
        free(out); free(body);
        pthread_mutex_unlock(&g_renew_lock);
        send_error(fd, "500 Internal Server Error", "oom"); return;
    }
    int failed = 0, skipped = 0;
    int ok = renew_all_sites(domain, 1, 0, out, 65536, &failed, &skipped);
    int signaled = (ok > 0) ? signal_data_plane_reload() : 0;
    int bl = snprintf(body, 65536,
        "{\"success\":true,\"renewed\":%d,\"skipped\":%d,\"failed\":%d,\"ssl_reloaded\":%s,\"results\":%s}",
        ok, skipped, failed, signaled ? "true" : "false", out);
    send_response(fd, "200 OK", "application/json", body, (size_t)bl);
    free(out); free(body);
    pthread_mutex_unlock(&g_renew_lock);
}

/* 后台维护线程：启动 3 分钟后首检，之后每 24 小时检查一次，仅续期临近到期（≤30 天）的证书 */
static void *cert_autorenew_thread(void *arg) {
    (void)arg;
    sleep(180);
    for (;;) {
        if (pthread_mutex_trylock(&g_renew_lock) == 0) {
            char *out = malloc(65536);
            if (out) {
                int failed = 0, skipped = 0;
                int ok = renew_all_sites(NULL, 0, 1, out, 65536, &failed, &skipped);
                int signaled = 0;
                if (ok > 0) signaled = signal_data_plane_reload();
                /* 无论成功、跳过还是失败都记录，便于排查自动续期是否真正运行 */
                char lp[700];
                snprintf(lp, sizeof(lp), "%s/logs/admin.log", waf_home());
                FILE *lg = fopen(lp, "a");
                if (lg) {
                    char ts[32]; time_t now = time(NULL);
                    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));
                    fprintf(lg, "[%s] [auto-renew] summary: renewed=%d skipped=%d failed=%d ssl_reload=%d certbot=%d\n",
                            ts, ok, skipped, failed, signaled, certbot_available());
                    fclose(lg);
                }
                free(out);
            }
            pthread_mutex_unlock(&g_renew_lock);
        }
        sleep(24 * 3600);
    }
    return NULL;
}

/* ---------------- 管理 API：登录/登出/会话/改密 ---------------- */

static void handle_admin_login(int fd, const char *post, const char *client_ip) {
    if (!login_allowed(client_ip)) {
        send_error(fd, "429 Too Many Requests", "失败次数过多，请 60 秒后重试");
        return;
    }
    char user[128] = "", pass[128] = "";
    form_val(post, "user", user, sizeof(user));
    form_val(post, "pass", pass, sizeof(pass));
    /* 对任意输入都计算哈希：无论用户是否存在，避免时序侧信道探测账号名 */
    char cat[160], hash[65], dummy[65];
    acct_t *a = acct_find(user);
    snprintf(cat, sizeof(cat), "%s%s", a ? a->salt : "00000000000000000000000000000000", pass);
    sha256_hex(cat, hash);
    if (!a) { snprintf(cat, sizeof(cat), "%s%s", "00000000000000000000000000000000", pass);
              sha256_hex(cat, dummy); }
    if (a && a->user[0] && !strcmp(hash, a->hash)) {
        login_ok(client_ip);
        char tok[65];
        session_create_ex(tok, a->user, a->role);
        char extra[192];
        snprintf(extra, sizeof(extra),
            "Set-Cookie: waf_admin_sess=%s; Path=/; HttpOnly; SameSite=Lax; Max-Age=%d\r\n",
            tok, SESSION_TTL);
        char uesc[300]; json_escape(a->user, uesc, sizeof(uesc));
        char body[512];
        snprintf(body, sizeof(body),
            "{\"success\":true,\"user\":\"%s\",\"role\":\"%s\"}", uesc, a->role);
        send_response_ex(fd, "200 OK", "application/json", body, strlen(body), extra);
    } else {
        login_fail(client_ip);
        send_error(fd, "401 Unauthorized", "用户名或密码错误");
    }
}

static void handle_admin_logout(int fd, const char *cookie_hdr) {
    char tok[80];
    cookie_val(cookie_hdr, "waf_admin_sess", tok, sizeof(tok));
    session_drop(tok);
    /* 长度用 strlen 计算：此前的手数长度 15 漏掉收尾 '}'，导致 JSON 被截断 */
    send_response_ex(fd, "200 OK", "application/json",
        "{\"success\":true}", strlen("{\"success\":true}"),
        "Set-Cookie: waf_admin_sess=; Path=/; HttpOnly; Max-Age=0\r\n");
}

static void handle_admin_version(int fd) {
    char body[256];
    snprintf(body, sizeof(body),
        "{\"success\":true,\"version\":\"%s\",\"build\":\"%s\"}",
        WAF_VERSION, WAF_BUILD_DATE);
    send_json(fd, body);
}

static void handle_admin_session(int fd, const char *cookie_hdr) {
    char tok[80];
    cookie_val(cookie_hdr, "waf_admin_sess", tok, sizeof(tok));
    char body[512];
    char suser[64], srole[16];
    if (session_lookup(tok, suser, sizeof(suser), srole, sizeof(srole))) {
        char uesc[300]; json_escape(suser, uesc, sizeof(uesc));
        snprintf(body, sizeof(body),
            "{\"success\":true,\"authenticated\":true,\"user\":\"%s\",\"role\":\"%s\","
            "\"version\":\"%s\",\"build\":\"%s\","
            "\"listen\":{\"backend_port\":%d,\"admin_port\":%d}}",
            uesc, srole, WAF_VERSION, WAF_BUILD_DATE, g_backend_port, g_admin_port);
    } else {
        snprintf(body, sizeof(body),
            "{\"success\":true,\"authenticated\":false,"
            "\"version\":\"%s\",\"build\":\"%s\","
            "\"listen\":{\"backend_port\":%d,\"admin_port\":%d}}",
            WAF_VERSION, WAF_BUILD_DATE, g_backend_port, g_admin_port);
    }
    send_json(fd, body);
}

static void handle_admin_password(int fd, const char *cookie_hdr, const char *post) {
    if (!require_auth(fd, cookie_hdr)) return;
    /* 定位当前会话账号：按会话身份改密，不得影响其他账号 */
    char tok[80];
    cookie_val(cookie_hdr, "waf_admin_sess", tok, sizeof(tok));
    char suser[64];
    if (!session_lookup(tok, suser, sizeof(suser), NULL, 0)) {
        send_error(fd, "401 Unauthorized", "会话失效，请重新登录");
        return;
    }
    acct_t *a = acct_find(suser);
    if (!a) {
        send_error(fd, "401 Unauthorized", "账号不存在，请重新登录");
        return;
    }
    char oldp[128] = "", newp[128] = "";
    form_val(post, "old", oldp, sizeof(oldp));
    form_val(post, "new", newp, sizeof(newp));
    char cat[160], hash[65];
    snprintf(cat, sizeof(cat), "%s%s", a->salt, oldp);
    sha256_hex(cat, hash);
    if (strcmp(hash, a->hash) != 0) {
        send_error(fd, "400 Bad Request", "旧密码错误");
        return;
    }
    size_t nl = strlen(newp);
    if (nl < 6 || nl >= 100) {
        send_error(fd, "400 Bad Request", "新密码长度需为 6-99 位");
        return;
    }
    /* 计算新口令哈希（旧哈希仅用于校验，不得复用落盘）；换新盐防彩虹表 */
    random_hex(a->salt, 16);
    char ncat[160];
    snprintf(ncat, sizeof(ncat), "%s%s", a->salt, newp);
    sha256_hex(ncat, a->hash);
    /* 全量写回：保留所有账号（含 [account] 分节），仅更新当前账号凭据 */
    if (save_admin_conf() != 0) {
        send_error(fd, "500 Internal Server Error", "cannot write admin.conf");
        return;
    }
    send_json(fd, "{\"success\":true,\"message\":\"密码已修改，当前会话仍然有效\"}");
}

/* ---------------- 请求处理 ---------------- */

/* 完整读取一个 HTTP 请求：TCP 是字节流，浏览器/代理常把请求头拆成多个报文
 * （大 Cookie、UA 或 TLS 分片时尤其明显）。旧实现只 recv 一次，头部被截断时
 * 解析不到 Cookie → 已登录用户刷新/切换页面被判定未登录而跳回登录页。
 * 这里循环读到 "\r\n\r\n" 为止，再按 Content-Length 补齐 body。 */
static ssize_t read_http_request(int fd, char *buf, size_t cap) {
    size_t used = 0;
    char *hdr_end = NULL;

    while (used + 1 < cap) {
        ssize_t r = recv(fd, buf + used, cap - 1 - used, 0);
        if (r <= 0) break;
        used += (size_t)r;
        buf[used] = '\0';
        hdr_end = strstr(buf, "\r\n\r\n");
        if (hdr_end) break;
    }
    if (used == 0) return -1;
    if (!hdr_end) return (ssize_t)used;   /* 头部不完整（超时/超长）：交给调用方拒绝 */

    /* POST：按 Content-Length 补读 body（管理 API 需要完整表单） */
    char *cl = strcasestr(buf, "Content-Length:");
    if (cl && cl < hdr_end) {
        long want = strtol(cl + 15, NULL, 10);
        if (want > 0 && want < MAX_POST_BODY) {
            size_t hdr_len = (size_t)(hdr_end + 4 - buf);
            size_t total = hdr_len + (size_t)want;
            if (total > cap - 1) total = cap - 1;
            while (used < total) {
                ssize_t r = recv(fd, buf + used, cap - 1 - used, 0);
                if (r <= 0) break;
                used += (size_t)r;
            }
            buf[used] = '\0';
        }
    }
    return (ssize_t)used;
}

static void handle_client(int fd, const char *client_ip, int on_admin_plane) {
    char buf[RECV_BUF_SIZE];
    ssize_t n = read_http_request(fd, buf, sizeof(buf));
    if (n <= 0) return;

    /* 解析请求行: METHOD SP PATH SP VERSION */
    char method[16] = "", path[2048] = "";
    if (sscanf(buf, "%15s %2047s", method, path) != 2) return;

    /* POST body 指针 */
    char *body = strstr(buf, "\r\n\r\n");
    body = body ? body + 4 : (char *)"";

    /* Cookie 头（复制出来，不破坏 buf 中 body 位置） */
    char cookie_hdr[2048] = "";
    char *ck = strcasestr(buf, "\r\nCookie:");
    if (ck) {
        ck += 9;
        char *e = strstr(ck, "\r\n");
        size_t cl2 = e ? (size_t)(e - ck) : strlen(ck);
        if (cl2 >= sizeof(cookie_hdr)) cl2 = sizeof(cookie_hdr) - 1;
        memcpy(cookie_hdr, ck, cl2);
        cookie_hdr[cl2] = '\0';
    }

    /* 拆出 query string */
    char qs[1024] = "";
    char *qm = strchr(path, '?');
    if (qm) { *qm = '\0'; snprintf(qs, sizeof(qs), "%s", qm + 1); }

    time_t now = time(NULL);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));
    fprintf(stderr, "[%s] %s %s (%s)\n", ts, method, path, client_ip);

    /* ---- 演示 API（公开，兼容原接口） ---- */
    if (strcmp(path, "/demo/api/info") == 0) { handle_info(fd); return; }
    if (strcmp(path, "/demo/api/logs") == 0) { handle_logs(fd); return; }

    /* ---- 管理平面隔离 ----
     * 启用独立管理端口（g_admin_port>0）时，后端平面（数据面反代目标）不再提供
     * 管理后台/监控大屏/管理 API：一律 404，不产生任何跳转，管理端口号不下发。
     * 未启用独立管理端口时保持单端口旧行为（兼容存量部署）。 */
    if (!on_admin_plane && g_admin_port > 0) {
        if (strncmp(path, "/api/admin/", 11) == 0) {
            send_error(fd, "404 Not Found", "not found");
            return;
        }
        if (!strcmp(path, "/admin") || !strcmp(path, "/admin/") ||
            !strncmp(path, "/admin/", 7) || !strcmp(path, "/admin.html") ||
            !strcmp(path, "/console") || !strcmp(path, "/console/") ||
            !strcmp(path, "/console.html")) {
            send_error(fd, "404 Not Found", "not found");
            return;
        }
    }

    /* ---- 管理 API ---- */
    /* 公开：登录、会话探测（监控大屏与总览数据均需登录后访问） */
    if (strcmp(path, "/api/admin/login") == 0 && !strcmp(method, "POST")) {
        handle_admin_login(fd, body, client_ip);
        return;
    }
    if (strcmp(path, "/api/admin/session") == 0) { handle_admin_session(fd, cookie_hdr); return; }
    if (strcmp(path, "/api/admin/version") == 0) { handle_admin_version(fd); return; }

    /* 其余 /api/admin/ 下的路径一律需要登录 */
    if (strncmp(path, "/api/admin/", 11) == 0) {
        if (!require_auth(fd, cookie_hdr)) return;
        /* 角色闸门：monitor（监控人员）仅放行监控大屏只读接口与登出，
         * 站点/规则/证书/配置/日志/改密等管理功能一律 403 */
        {
            char srole[16] = ""; char gtok[80];
            cookie_val(cookie_hdr, "waf_admin_sess", gtok, sizeof(gtok));
            if (session_lookup(gtok, NULL, 0, srole, sizeof(srole)) &&
                strcmp(srole, "admin") != 0) {
                int allow = !strcmp(path, "/api/admin/overview") ||
                            !strcmp(path, "/api/admin/stats") ||
                            (!strcmp(path, "/api/admin/logout") && !strcmp(method, "POST"));
                if (!allow) {
                    send_error(fd, "403 Forbidden", "权限不足：监控人员仅可访问监控大屏");
                    return;
                }
            }
        }
        if (strcmp(path, "/api/admin/overview") == 0) { handle_admin_overview(fd); return; }
        if (strcmp(path, "/api/admin/logout") == 0 && !strcmp(method, "POST")) {
            handle_admin_logout(fd, cookie_hdr);
            return;
        }
        if (strcmp(path, "/api/admin/password") == 0 && !strcmp(method, "POST")) {
            handle_admin_password(fd, cookie_hdr, body);
            return;
        }
        if (strcmp(path, "/api/admin/stats") == 0) { handle_admin_stats(fd); return; }
        if (strcmp(path, "/api/admin/logs/attacks") == 0) { handle_admin_attack_logs(fd, qs); return; }
        if (strcmp(path, "/api/admin/config") == 0) {
            if (!strcmp(method, "POST")) handle_admin_config_post(fd, body);
            else handle_admin_config_get(fd);
            return;
        }
        if (strcmp(path, "/api/admin/sites") == 0) {
            if (!strcmp(method, "POST")) handle_admin_sites_post(fd, body);
            else handle_admin_sites_get(fd);
            return;
        }
        if (strcmp(path, "/api/admin/sites/delete") == 0 && !strcmp(method, "POST")) {
            handle_admin_sites_delete(fd, body);
            return;
        }
        if (strcmp(path, "/api/admin/rules") == 0) { handle_admin_rules_get(fd); return; }
        if (strcmp(path, "/api/admin/certs") == 0) { handle_admin_certs_get(fd); return; }
        if (strcmp(path, "/api/admin/certs/upload") == 0 && !strcmp(method, "POST")) {
            handle_admin_certs_upload(fd, body); return;
        }
        if (strcmp(path, "/api/admin/certs/selfsign") == 0 && !strcmp(method, "POST")) {
            handle_admin_certs_selfsign(fd, body); return;
        }
        if (strcmp(path, "/api/admin/certs/renew") == 0 && !strcmp(method, "POST")) {
            handle_admin_certs_renew(fd, body); return;
        }
        if (strcmp(path, "/api/admin/logs") == 0) { handle_logs(fd); return; }
        send_error(fd, "404 Not Found", "unknown admin api");
        return;
    }

    /* ---- 静态站 ---- */
    /* 产品介绍页：根路径 */
    if (strcmp(path, "/") == 0 || strcmp(path, "/index.html") == 0) {
        serve_static(fd, "index.html");
        return;
    }
    /* 管理后台入口（独立目录 $WAF_HOME/<admin_dir>/，默认 adminui，物理上
     * 位于 web/ 之外）：
     * 未登录 → 登录页 login.html；已登录 → 302 到监控大屏 dashboard */
    if (strcmp(path, "/admin") == 0 || strcmp(path, "/admin/") == 0) {
        if (!authed(cookie_hdr)) serve_admin_static(fd, "login.html");
        else send_redirect(fd, "/admin/dashboard");
        return;
    }
    /* 管理功能壳（日志/站点/证书/规则/端口，需登录） */
    if (strcmp(path, "/admin/index.html") == 0) {
        if (!authed(cookie_hdr)) { send_redirect(fd, "/admin"); return; }
        serve_admin_static(fd, "index.html");
        return;
    }
    /* 监控大屏（管理后台总览页，需登录） */
    if (!strcmp(path, "/admin/dashboard") || !strcmp(path, "/admin/dashboard.html")) {
        if (!authed(cookie_hdr)) { send_redirect(fd, "/admin"); return; }
        serve_admin_static(fd, "dashboard.html");
        return;
    }
    /* admin 界面专属静态资源（/admin/xxx → <admin_dir>/xxx；登录页自身资源放行） */
    if (!strncmp(path, "/admin/", 7)) {
        serve_admin_static(fd, path + 7);
        return;
    }
    /* 旧入口 /console 一律 302 到管理后台监控大屏 */
    if (strcmp(path, "/console") == 0 || strcmp(path, "/console/") == 0 ||
        strcmp(path, "/console.html") == 0) {
        send_redirect(fd, "/admin/dashboard");
        return;
    }
    /* 演示站点（WAF 功能攻防演示） */
    if (strcmp(path, "/demo") == 0 || strcmp(path, "/demo/") == 0) {
        size_t len = 0;
        char *html = read_whole_file(g_showcase_path, &len);
        if (html) {
            send_response(fd, "200 OK", "text/html", html, len);
            free(html);
        } else {
            send_error(fd, "404 Not Found", "showcase not found");
        }
        return;
    }
    /* 大屏演示页 / 测试报告页（docroot 静态，免登录演示） */
    if (strcmp(path, "/screen") == 0 || strcmp(path, "/screen.html") == 0) {
        serve_static(fd, "screen.html");
        return;
    }
    if (strcmp(path, "/report") == 0 || strcmp(path, "/report.html") == 0) {
        serve_static(fd, "report.html");
        return;
    }
    /* docroot 下的其他静态资源 */
    if (!strncmp(path, "/assets/", 8) || !strncmp(path, "/images/", 8)) {
        serve_static(fd, path + 1);
        return;
    }

    /* 其他路径：普通业务响应 */
    char rbody[256];
    int blen = snprintf(rbody, sizeof(rbody),
        "{\"success\":true,\"backend\":\"waf-demo-backend\",\"path\":\"%s\","
        "\"message\":\"Hello! 该请求已通过 WAF 转发到受保护的业务后端\"}", path);
    send_response(fd, "200 OK", "application/json", rbody, (size_t)blen);
}

/* 每个客户端连接一个线程：并发处理，避免单个慢连接阻塞全局 */
typedef struct { int fd; char ip[64]; int on_admin_plane; } client_arg_t;

static void *client_thread_main(void *arg) {
    client_arg_t *c = (client_arg_t *)arg;
    handle_client(c->fd, c->ip, c->on_admin_plane);
    close(c->fd);
    free(c);

    pthread_mutex_lock(&g_thread_mutex);
    g_active_threads--;
    pthread_mutex_unlock(&g_thread_mutex);
    return NULL;
}

/* 设置客户端 socket 读写超时，防止半开/静默连接永久占用线程 */
static void set_client_timeout(int fd) {
    struct timeval tv = {CLIENT_IO_TIMEOUT_SEC, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

/* 创建监听 socket（失败返回 -1） */
static int make_listener(int port, uint32_t net_addr, const char *tag) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(net_addr);
    addr.sin_port = htons((uint16_t)port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "bind %s:%d: %s\n", tag, port, strerror(errno));
        close(fd);
        return -1;
    }
    if (listen(fd, 64) < 0) { perror("listen"); close(fd); return -1; }
    printf("壁垒WAF 管理平面 [%s] 已监听端口 %d\n", tag, port);
    fflush(stdout);
    return fd;
}

int main(int argc, char *argv[]) {
    int port = DEFAULT_PORT;
    if (argc > 1) port = atoi(argv[1]);
    if (argc > 2) g_showcase_path = argv[2];
    if (argc > 3) g_attack_log = argv[3];
    if (argc > 4) g_docroot = argv[4];
    g_backend_port = port;

    /* 独立管理平面端口：WAF_ADMIN_PORT 环境变量（监听 0.0.0.0，供管理后台直连，登录保护）。
     * 不设置则仅后端平面监听 127.0.0.1，管理后台经 WAF 反向代理 /admin 访问。 */
    const char *apenv = getenv("WAF_ADMIN_PORT");
    if (apenv && atoi(apenv) > 0 && atoi(apenv) != port) g_admin_port = atoi(apenv);

    signal(SIGPIPE, SIG_IGN);
    g_start_time = time(NULL);
    ensure_admin_conf();

    int server_fd = make_listener(port, INADDR_LOOPBACK, "后端平面 127.0.0.1");
    if (server_fd < 0) return 1;
    int admin_fd = -1;
    if (g_admin_port > 0) {
        admin_fd = make_listener(g_admin_port, INADDR_ANY, "管理平面 0.0.0.0");
        if (admin_fd < 0) g_admin_port = 0;
    }

    struct pollfd pfds[2];
    int npfd = 0;
    pfds[npfd].fd = server_fd; pfds[npfd].events = POLLIN; pfds[npfd].revents = 0; npfd++;
    if (admin_fd >= 0) {
        pfds[npfd].fd = admin_fd; pfds[npfd].events = POLLIN; pfds[npfd].revents = 0; npfd++;
    }

    printf("壁垒WAF 管理后台入口: /admin （账号见 config/admin.conf）\n");
    fflush(stdout);

    /* 证书后台自动续期线程：每日检查临近到期（≤30 天）证书并续期，成功后 SIGHUP
     * 通知数据平面热加载 SSL 上下文。与手动续期共用 g_renew_lock 互斥。 */
    {
        pthread_t ctid;
        if (pthread_create(&ctid, NULL, cert_autorenew_thread, NULL) == 0)
            pthread_detach(ctid);
        else
            perror("pthread_create(cert_autorenew)");
    }

    while (1) {
        int rc = poll(pfds, (nfds_t)npfd, -1);
        if (rc < 0) {
            if (errno == EINTR) continue;
            perror("poll");
            continue;
        }
        for (int i = 0; i < npfd; i++) {
            if (!(pfds[i].revents & POLLIN)) continue;
            struct sockaddr_in cli;
            socklen_t clen = sizeof(cli);
            int client_fd = accept(pfds[i].fd, (struct sockaddr *)&cli, &clen);
            if (client_fd < 0) {
                if (errno == EINTR) continue;
                perror("accept");
                continue;
            }

            set_client_timeout(client_fd);

            pthread_mutex_lock(&g_thread_mutex);
            int over_limit = (g_active_threads >= MAX_BACKEND_THREADS);
            if (!over_limit) g_active_threads++;
            pthread_mutex_unlock(&g_thread_mutex);

            if (over_limit) {
                /* 并发已到上限：直接关闭，避免线程数失控 */
                close(client_fd);
                continue;
            }

            client_arg_t *carg = malloc(sizeof(client_arg_t));
            if (!carg) {
                close(client_fd);
                pthread_mutex_lock(&g_thread_mutex);
                g_active_threads--;
                pthread_mutex_unlock(&g_thread_mutex);
                continue;
            }
            carg->fd = client_fd;
            carg->on_admin_plane = (pfds[i].fd == admin_fd);
            snprintf(carg->ip, sizeof(carg->ip), "%s", inet_ntoa(cli.sin_addr));

            pthread_t tid;
            if (pthread_create(&tid, NULL, client_thread_main, carg) != 0) {
                free(carg);
                close(client_fd);
                pthread_mutex_lock(&g_thread_mutex);
                g_active_threads--;
                pthread_mutex_unlock(&g_thread_mutex);
                continue;
            }
            pthread_detach(tid);
        }
    }
    return 0;
}
