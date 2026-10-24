/* ============================================================
 * CC 触发人机验证（站点级 cc_captcha）
 *
 * 流程：CC 刚超阈值(ccr==2) 且站点开启 cc_captcha →
 *   无放行 cookie → 302 /waf-captcha?to=<原URL> →
 *   GET 出 SVG 图形验证码 → POST 判卷 →
 *   通过：Set-Cookie waf_cap=<expiry>.<hmac> + 302 回原 URL + cc_reset_ip
 *   失败：换新码重试，同 IP 累计 5 次失败 → cc_block_ip 转 CC 封禁
 *
 * 反自动化：码仅存 SHA256（比较大小写不敏感）；sid/码一次性（提交即作废）；
 * 渲染逐字符随机旋转/字号/字体/颜色 + 干扰曲线 + 噪点；挑战绑定发起 IP；
 * TTL 300s；放行 cookie 为 HMAC-SHA256 签名，密钥仅存内存。
 * ============================================================ */

#include "../include/waf_captcha.h"
#include "../include/waf_cc.h"
#include "../include/waf_http.h"
#include "../include/waf_ssl.h"
#include "../include/waf_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#define CAP_MAX_SESSIONS 4096
#define CAP_SESSION_TTL  300
#define CAP_MAX_FAILS    5
#define CAP_CODE_LEN     4
#define CAP_COOKIE_NAME  "waf_cap"

typedef struct {
    char sid[33];                /* 16 字节随机数的 hex */
    char ip[MAX_IP_LENGTH];
    unsigned char code_sha[32];  /* SHA256(小写码) */
    time_t expires;
    int fails;
    int used;                    /* sid 一次性：提交即作废 */
} cap_session_t;

static cap_session_t cap_sessions[CAP_MAX_SESSIONS];
static int cap_sessions_count = 0;
static pthread_mutex_t cap_mutex = PTHREAD_MUTEX_INITIALIZER;

static unsigned char cap_hmac_key[32];
static unsigned int cap_rng = 0;
static int cap_initialized = 0;

/* 去混淆字符集：无 0/O/1/l/I 等 */
static const char *CAP_CHARS = "23456789abcdefghjkmnpqrstuvwxyz";
/* 验证码字符暗色调色板（与浅色页面背景对比，不利 OCR 二值化） */
static const char *CAP_COLORS[8] = {
    "#2f4f4f", "#556b2f", "#8b4513", "#483d8b",
    "#6b3fa0", "#365e7d", "#7d5a3c", "#3d6b4f"
};

int captcha_init(void) {
    if (RAND_bytes(cap_hmac_key, sizeof(cap_hmac_key)) != 1) {
        /* 极端回退：/dev/urandom 直读 */
        FILE *fp = fopen("/dev/urandom", "rb");
        if (!fp || fread(cap_hmac_key, 1, sizeof(cap_hmac_key), fp) != sizeof(cap_hmac_key)) {
            waf_log(LOG_LEVEL_ERROR, "captcha: failed to seed HMAC key");
            if (fp) fclose(fp);
            return -1;
        }
        if (fp) fclose(fp);
    }
    unsigned int seed;
    RAND_bytes((unsigned char *)&seed, sizeof(seed));
    cap_rng = seed;
    cap_initialized = 1;
    waf_log(LOG_LEVEL_INFO, "Captcha module initialized (challenge ttl=%ds, max_fails=%d)",
            CAP_SESSION_TTL, CAP_MAX_FAILS);
    return 0;
}

/* ---- 基础工具 ---- */

static int cap_rand(int lo, int hi) {  /* [lo, hi] */
    if (hi <= lo) return lo;
    return lo + (int)(rand_r(&cap_rng) % (unsigned int)(hi - lo + 1));
}

static void cap_sha256(const unsigned char *data, size_t len, unsigned char out[32]) {
    unsigned int olen = 0;
    EVP_Digest(data, len, out, &olen, EVP_sha256(), NULL);
}

static void cap_hex(const unsigned char *in, size_t n, char *out) {
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i * 2] = hx[in[i] >> 4];
        out[i * 2 + 1] = hx[in[i] & 0x0f];
    }
    out[n * 2] = '\0';
}

/* application/x-www-form-urlencoded 值解码：%xx 与 '+'→空格 */
static void cap_form_decode(char *dst, size_t dstsz, const char *src, size_t srclen) {
    size_t j = 0;
    for (size_t i = 0; i < srclen && j + 1 < dstsz; i++) {
        if (src[i] == '%' && i + 2 < srclen) {
            int hi = src[i + 1], lo = src[i + 2];
            int hv = (hi >= '0' && hi <= '9') ? hi - '0' :
                     ((hi >= 'a' && hi <= 'f') ? hi - 'a' + 10 :
                     ((hi >= 'A' && hi <= 'F') ? hi - 'A' + 10 : -1));
            int lv = (lo >= '0' && lo <= '9') ? lo - '0' :
                     ((lo >= 'a' && lo <= 'f') ? lo - 'a' + 10 :
                     ((lo >= 'A' && lo <= 'F') ? lo - 'A' + 10 : -1));
            if (hv >= 0 && lv >= 0) {
                dst[j++] = (char)((hv << 4) | lv);
                i += 2;
                continue;
            }
        }
        dst[j++] = (src[i] == '+') ? ' ' : src[i];
    }
    dst[j] = '\0';
}

/* 回跳 URL 编码（置于 query 参数） */
static void cap_urlencode(const char *src, char *dst, size_t dstsz) {
    static const char hx[] = "0123456789ABCDEF";
    size_t j = 0;
    for (const char *p = src; *p && j + 4 < dstsz; p++) {
        unsigned char c = (unsigned char)*p;
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' ||
            c == '~' || c == '/') {
            dst[j++] = (char)c;
        } else {
            dst[j++] = '%';
            dst[j++] = hx[c >> 4];
            dst[j++] = hx[c & 0x0f];
        }
    }
    dst[j] = '\0';
}

/* 回跳地址安全校验：仅站内相对路径，防 open redirect。
 * 带长度版：len 个字符内做同样判断（Referer 路径截取用） */
static int cap_safe_return_len(const char *s, size_t len) {
    if (!s || len == 0 || s[0] != '/') return 0;
    if (len >= 2 && (s[1] == '/' || s[1] == '\\')) return 0;
    return 1;
}

static int cap_safe_return(const char *to) {
    return to ? cap_safe_return_len(to, strlen(to)) : 0;
}

/* HMAC(ip|expiry) hex。msg = "waf_cap|" ip "|" expiry */
static void cap_clearance_hmac(const char *ip, long expiry, char *hex_out /*65*/) {
    char msg[128];
    int mlen = snprintf(msg, sizeof(msg), "%s|%s|%ld", CAP_COOKIE_NAME, ip, expiry);
    unsigned char mac[32];
    unsigned int olen = 0;
    HMAC(EVP_sha256(), cap_hmac_key, sizeof(cap_hmac_key),
         (const unsigned char *)msg, (size_t)mlen, mac, &olen);
    cap_hex(mac, 32, hex_out);
}

/* ---- session 表 ---- */

/* 生成新挑战：sid/code 明文双出（明文仅用于本请求渲染，表内只存 hash）；
 * 同 IP 旧挑战全部作废（一个 IP 同时只有一个活跃挑战） */
static int cap_session_create(const char *ip, char *sid_out /*33*/,
                              char *code_out /*CAP_CODE_LEN+1*/) {
    unsigned char raw[16];
    if (RAND_bytes(raw, sizeof(raw)) != 1) return -1;
    cap_hex(raw, 16, sid_out);

    char code[CAP_CODE_LEN + 1];
    for (int i = 0; i < CAP_CODE_LEN; i++)
        code[i] = CAP_CHARS[cap_rand(0, (int)strlen(CAP_CHARS) - 1)];
    code[CAP_CODE_LEN] = '\0';
    /* 码统一小写存储（比较大小写不敏感） */
    for (int i = 0; i < CAP_CODE_LEN; i++)
        if (code[i] >= 'A' && code[i] <= 'Z') code[i] += 32;
    unsigned char sha[32];
    cap_sha256((const unsigned char *)code, CAP_CODE_LEN, sha);

    pthread_mutex_lock(&cap_mutex);
    for (int i = 0; i < cap_sessions_count; i++) {
        if (strcmp(cap_sessions[i].ip, ip) == 0) cap_sessions[i].used = 1;
    }
    int slot = -1;
    if (cap_sessions_count < CAP_MAX_SESSIONS) {
        slot = cap_sessions_count++;
    } else {
        /* 表满：回收一个过期/已用槽位 */
        time_t now = time(NULL);
        for (int i = 0; i < cap_sessions_count; i++) {
            if (cap_sessions[i].used || cap_sessions[i].expires < now) { slot = i; break; }
        }
        if (slot < 0) { pthread_mutex_unlock(&cap_mutex); return -1; }
    }
    cap_session_t *s = &cap_sessions[slot];
    strncpy(s->sid, sid_out, sizeof(s->sid) - 1);
    s->sid[sizeof(s->sid) - 1] = '\0';
    strncpy(s->ip, ip, sizeof(s->ip) - 1);
    memcpy(s->code_sha, sha, 32);
    s->expires = time(NULL) + CAP_SESSION_TTL;
    s->fails = 0;
    s->used = 0;
    pthread_mutex_unlock(&cap_mutex);

    if (code_out) memcpy(code_out, code, CAP_CODE_LEN + 1);
    waf_log(LOG_LEVEL_DEBUG, "captcha: new challenge ip=%s sid=%s", ip, sid_out);
    return 0;
}

/* 判卷：命中有效未用挑战返回 0 并将 sid 标记 used（一次性） */
static int cap_session_take(const char *ip, const char *sid, unsigned char sha_out[32]) {
    pthread_mutex_lock(&cap_mutex);
    time_t now = time(NULL);
    for (int i = 0; i < cap_sessions_count; i++) {
        cap_session_t *s = &cap_sessions[i];
        if (!s->used && s->expires >= now &&
            strcmp(s->sid, sid) == 0 && strcmp(s->ip, ip) == 0) {
            s->used = 1;  /* 一次性：无论对错 */
            memcpy(sha_out, s->code_sha, 32);
            pthread_mutex_unlock(&cap_mutex);
            return 0;
        }
    }
    pthread_mutex_unlock(&cap_mutex);
    return -1;
}

static int cap_session_fails(const char *ip) {
    pthread_mutex_lock(&cap_mutex);
    int f = 0;
    for (int i = 0; i < cap_sessions_count; i++) {
        if (strcmp(cap_sessions[i].ip, ip) == 0) { f = cap_sessions[i].fails; break; }
    }
    pthread_mutex_unlock(&cap_mutex);
    return f;
}

static void cap_session_fail(const char *ip) {
    pthread_mutex_lock(&cap_mutex);
    for (int i = 0; i < cap_sessions_count; i++) {
        if (strcmp(cap_sessions[i].ip, ip) == 0) {
            cap_sessions[i].fails++;
            break;
        }
    }
    pthread_mutex_unlock(&cap_mutex);
}

void captcha_cleanup(void) {
    pthread_mutex_lock(&cap_mutex);
    time_t now = time(NULL);
    int w = 0;
    for (int i = 0; i < cap_sessions_count; i++) {
        if (!cap_sessions[i].used && cap_sessions[i].expires >= now) {
            if (w != i) cap_sessions[w] = cap_sessions[i];
            w++;
        }
    }
    cap_sessions_count = w;
    pthread_mutex_unlock(&cap_mutex);
}

/* ---- 响应发送 ---- */

static int cap_send(int client_fd, SSL *ssl, int is_https,
                    int status, const char *status_msg,
                    const char *h1name, const char *h1val,
                    const char *h2name, const char *h2val,
                    const char *body, size_t body_len, int keep_alive) {
    http_response_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.status_code = status;
    snprintf(resp.status_message, sizeof(resp.status_message), "%s", status_msg);
    http_set_header(&resp, "Content-Type", "text/html; charset=utf-8");
    http_set_header(&resp, "Cache-Control", "no-store");
    if (h1name && h1val) http_set_header(&resp, h1name, h1val);
    if (h2name && h2val) http_set_header(&resp, h2name, h2val);
    http_set_connection_header(&resp, keep_alive);
    if (body && body_len) http_set_body(&resp, body, body_len);

    if (is_https) {
        char buf[MAX_REQUEST_SIZE];
        int len = http_build_response(&resp, buf, sizeof(buf));
        if (len < 0) return -1;
        waf_ssl_send(ssl, buf, len);
    } else {
        http_send_response(client_fd, &resp);
    }
    return 1;
}

/* ---- SVG 验证码渲染（反 OCR：逐字符随机形变 + 干扰曲线 + 噪点） ---- */

static int cap_render_svg(char *svg, size_t sz, const char *code) {
    size_t off = 0;
    off += snprintf(svg + off, sz - off,
        "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 180 60' width='180' height='60'>"
        "<rect width='180' height='60' fill='#f2f4f3'/>");
    for (int i = 0; i < 4; i++) {
        off += snprintf(svg + off, sz - off,
            "<path d='M%d %d Q %d %d, %d %d T %d %d' fill='none' stroke='%s' "
            "stroke-width='%d.%d' opacity='0.55'/>",
            cap_rand(-5, 20), cap_rand(5, 55), cap_rand(40, 90), cap_rand(-10, 70),
            cap_rand(80, 120), cap_rand(-10, 70), cap_rand(150, 190), cap_rand(5, 55),
            CAP_COLORS[cap_rand(0, 7)], cap_rand(1, 1), cap_rand(2, 8));
    }
    for (int i = 0; i < 30; i++) {
        off += snprintf(svg + off, sz - off,
            "<circle cx='%d' cy='%d' r='%d' fill='%s' opacity='0.5'/>",
            cap_rand(0, 179), cap_rand(0, 59), cap_rand(1, 2),
            CAP_COLORS[cap_rand(0, 7)]);
    }
    static const char *fonts[3] = { "serif", "sans-serif", "monospace" };
    for (int i = 0; i < CAP_CODE_LEN; i++) {
        off += snprintf(svg + off, sz - off,
            "<text x='0' y='0' transform='translate(%d %d) rotate(%d)' "
            "font-family='%s' font-size='%d' font-weight='bold' fill='%s'>%c</text>",
            22 + i * 38 + cap_rand(-3, 3), 42 + cap_rand(-4, 3), cap_rand(-35, 35),
            fonts[cap_rand(0, 2)], cap_rand(26, 34),
            CAP_COLORS[cap_rand(0, 7)], code[i]);
    }
    off += snprintf(svg + off, sz - off, "</svg>");
    return (int)off;
}

static size_t cap_b64(const char *in, size_t len, char *out, size_t outsz) {
    static const char tb[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t j = 0;
    for (size_t i = 0; i < len && j + 4 < outsz; i += 3) {
        unsigned b0 = (unsigned char)in[i];
        unsigned b1 = (i + 1 < len) ? (unsigned char)in[i + 1] : 0;
        unsigned b2 = (i + 2 < len) ? (unsigned char)in[i + 2] : 0;
        out[j++] = tb[b0 >> 2];
        out[j++] = tb[((b0 & 3) << 4) | (b1 >> 4)];
        out[j++] = (i + 1 < len) ? tb[((b1 & 15) << 2) | (b2 >> 6)] : '=';
        out[j++] = (i + 2 < len) ? tb[b2 & 63] : '=';
    }
    out[j] = '\0';
    return j;
}

/* ---- 页面模板 ---- */

static int cap_render_page(char *html, size_t sz, const char *sid,
                           const char *to_enc, const char *img_b64,
                           const char *msg) {
    return snprintf(html, sz,
"<!DOCTYPE html><html><head><meta charset='utf-8'>"
"<meta name='viewport' content='width=device-width,initial-scale=1'>"
"<title>人机验证</title><style>"
"body{font-family:system-ui,'PingFang SC','Microsoft YaHei',sans-serif;"
"background:#eef1f0;display:flex;align-items:center;justify-content:center;"
"min-height:100vh;margin:0}"
".card{background:#fff;border:1px solid #dde3e1;border-radius:12px;"
"padding:32px;max-width:360px;width:90%%;box-sizing:border-box}"
"h2{margin:0 0 6px;font-size:18px;color:#1a1f36}"
"p{margin:0 0 18px;font-size:13px;color:#6b7280}"
".row{display:flex;gap:10px;align-items:center;margin-bottom:14px}"
"img{border:1px solid #e4e8e6;border-radius:8px}"
"a.refresh{font-size:12px;color:#2f7d4f;text-decoration:none;white-space:nowrap}"
"input[type=text]{width:100%%;box-sizing:border-box;padding:10px;font-size:16px;"
"border:1px solid #cfd6d3;border-radius:8px;letter-spacing:3px;text-transform:uppercase}"
"button{width:100%%;padding:10px;font-size:15px;color:#fff;background:#2f7d4f;"
"border:0;border-radius:8px;cursor:pointer}"
"button:hover{background:#276940}"
".msg{color:#b3541e;font-size:13px;margin:0 0 12px}"
"</style></head><body><div class='card'>"
"<h2>访问验证</h2>"
"<p>检测到异常高频访问，请输入下图字符以继续</p>"
"%s"
"<form method='POST' action='/waf-captcha'>"
"<input type='hidden' name='sid' value='%s'>"
"<input type='hidden' name='to' value='%s'>"
"<div class='row'>"
"<img src=\"data:image/svg+xml;base64,%s\" alt='captcha'>"
"<a class='refresh' href='/waf-captcha?to=%s'>换一张</a>"
"</div>"
"<input type='text' name='code' maxlength='8' autocomplete='off' "
"placeholder='输入验证码' autofocus required>"
"<div style='height:12px'></div>"
"<button type='submit'>提交验证</button>"
"</form></div></body></html>",
        msg ? msg : "", sid, to_enc, img_b64 ? img_b64 : "", to_enc);
}

/* ---- 端点处理 ---- */

int captcha_is_endpoint(const char *url) {
    if (!url) return 0;
    /* 只比较路径部分：302 跳转来的 GET 带 ?to= 查询串，
     * 整 URL strcmp 会匹配失败导致请求落入 CC 分支形成 302 循环 */
    static const char ep[] = "/waf-captcha";
    const char *q = strchr(url, '?');
    size_t n = q ? (size_t)(q - url) : strlen(url);
    return n == sizeof(ep) - 1 && strncmp(url, ep, sizeof(ep) - 1) == 0;
}

int captcha_send_challenge(int client_fd, http_request_t *req,
                           SSL *ssl, int is_https, int keep_alive) {
    char to_enc[MAX_URL_LENGTH + 8];
    cap_urlencode(req->url, to_enc, sizeof(to_enc));
    char loc[MAX_URL_LENGTH + 64];
    snprintf(loc, sizeof(loc), "/waf-captcha?to=%s", to_enc);
    return cap_send(client_fd, ssl, is_https, 302, "Found",
                    "Location", loc, NULL, NULL,
                    "<html><body>Redirecting...</body></html>", 40, keep_alive);
}

/* 出题并发送（GET 或判卷失败重试共用） */
static int cap_send_challenge_page(int client_fd, http_request_t *req,
                                   SSL *ssl, int is_https, int keep_alive,
                                   const char *to, const char *msg) {
    char sid[33], plain[CAP_CODE_LEN + 1];
    if (cap_session_create(req->client_ip, sid, plain) != 0) return 0;

    char svg[8192];
    cap_render_svg(svg, sizeof(svg), plain);
    char b64[16384];
    cap_b64(svg, strlen(svg), b64, sizeof(b64));

    char to_enc[MAX_URL_LENGTH + 8];
    cap_urlencode(to, to_enc, sizeof(to_enc));

    char html[32768];
    cap_render_page(html, sizeof(html), sid, to_enc, b64, msg);
    return cap_send(client_fd, ssl, is_https, 200, "OK",
                    NULL, NULL, NULL, NULL, html, strlen(html), keep_alive);
}

int captcha_handle(int client_fd, http_request_t *req,
                   SSL *ssl, int is_https, int keep_alive) {
    if (!req || !cap_initialized) return 0;
    const char *ip = req->client_ip;

    /* 封禁态不出题：落回原 403 路径 */
    if (cc_is_blocked(ip)) return 0;

    /* 回跳地址：POST 表单 to= 优先，其次 GET query to=，再次 Referer 路径，默认 / */
    char to[MAX_URL_LENGTH] = "/";

    if (strcmp(req->method, "POST") == 0) {
        /* ---- 判卷 ---- */
        char sid[64] = "", code[64] = "", toraw[MAX_URL_LENGTH] = "";
        char pair[512];
        const char *p = req->body;
        size_t rem = req->body_len;
        while (rem > 0) {
            size_t pl = 0;
            while (pl < rem && p[pl] != '&') pl++;
            if (pl < sizeof(pair)) {
                memcpy(pair, p, pl);
                pair[pl] = '\0';
                char *eq = strchr(pair, '=');
                if (eq) {
                    *eq = '\0';
                    const char *v = eq + 1;
                    if (strcmp(pair, "sid") == 0)
                        cap_form_decode(sid, sizeof(sid), v, strlen(v));
                    else if (strcmp(pair, "code") == 0)
                        cap_form_decode(code, sizeof(code), v, strlen(v));
                    else if (strcmp(pair, "to") == 0)
                        cap_form_decode(toraw, sizeof(toraw), v, strlen(v));
                }
            }
            p += pl;
            if (pl < rem) p++;  /* skip '&' */
            rem -= pl;
        }
        if (toraw[0] && cap_safe_return(toraw)) snprintf(to, sizeof(to), "%s", toraw);

        /* 输入规范化：去空白 + 转小写 */
        char norm[16];
        size_t nj = 0;
        for (const char *c = code; *c && nj < sizeof(norm) - 1; c++) {
            if (*c == ' ' || *c == '\t' || *c == '\r' || *c == '\n') continue;
            norm[nj++] = (*c >= 'A' && *c <= 'Z') ? *c + 32 : *c;
        }
        norm[nj] = '\0';

        unsigned char want_sha[32], got_sha[32];
        int sid_ok = (cap_session_take(ip, sid, want_sha) == 0);
        if (!sid_ok || nj != CAP_CODE_LEN ||
            (cap_sha256((const unsigned char *)norm, nj, got_sha),
             memcmp(want_sha, got_sha, 32) != 0)) {
            /* sid 无效/过期/非本 IP 或答案错误：计失败 + 重出题 */
            cap_session_fail(ip);
            int fails = cap_session_fails(ip);
            waf_log(LOG_LEVEL_WARN, "captcha: wrong code ip=%s fails=%d", ip, fails);
            if (fails >= CAP_MAX_FAILS) {
                int dur = cc_block_duration();
                cc_block_ip(ip, dur);
                waf_log(LOG_LEVEL_WARN, "captcha: too many failures, block ip=%s for %ds",
                        ip, dur);
                char msg[160];
                snprintf(msg, sizeof(msg),
                         "<p class='msg'>验证失败次数过多，访问已被封禁 %d 秒。</p>", dur);
                return cap_send_challenge_page(client_fd, req, ssl, is_https,
                                               0, to, msg);
            }
            char msg[128];
            snprintf(msg, sizeof(msg),
                     "<p class='msg'>验证码错误，还可尝试 %d 次</p>",
                     CAP_MAX_FAILS - fails);
            return cap_send_challenge_page(client_fd, req, ssl, is_https,
                                           keep_alive, to, msg);
        }

        /* 验证通过：发放放行 cookie + 回跳 */
        {
            /* 放行有效期下限 5 分钟：CC 封禁时长可能配置得很短（如 60s），
             * 不足以让误报用户完成一次正常浏览，验证完立刻又被拦下 */
            int dur = cc_block_duration();
            if (dur < 300) dur = 300;
            long expiry = (long)time(NULL) + dur;
            char mac[65];
            cap_clearance_hmac(ip, expiry, mac);
            char cookie[160];
            snprintf(cookie, sizeof(cookie),
                     "%s=%ld.%s; Path=/; HttpOnly; SameSite=Lax; Max-Age=%d",
                     CAP_COOKIE_NAME, expiry, mac, dur);
            cc_reset_ip(ip);
            waf_log(LOG_LEVEL_INFO, "captcha: passed ip=%s, clearance %ds", ip, dur);
            return cap_send(client_fd, ssl, is_https, 302, "Found",
                            "Set-Cookie", cookie, "Location", to,
                            "<html><body>Redirecting...</body></html>", 40, keep_alive);
        }
    }

    /* ---- GET 出题：回跳地址取 query to= 或 Referer 路径 ---- */
    {
        char qto[MAX_URL_LENGTH + 8];
        if (req->query[0] &&
            sscanf(req->query, "to=%2557s", qto) == 1) {
            char dec[MAX_URL_LENGTH];
            cap_form_decode(dec, sizeof(dec), qto, strlen(qto));
            if (cap_safe_return(dec)) snprintf(to, sizeof(to), "%s", dec);
        } else if (http_get_header_value(req->headers, "Referer",
                                         qto, sizeof(qto)) >= 0) {
            char *sp = strchr(qto, '/');
            if (sp) {
                char *qp = strchr(sp, '?');
                size_t pl = qp ? (size_t)(qp - sp) : strlen(sp);
                if (pl > 0 && pl < sizeof(to) && cap_safe_return_len(sp, pl)) {
                    memcpy(to, sp, pl);
                    to[pl] = '\0';
                }
            }
        }
        return cap_send_challenge_page(client_fd, req, ssl, is_https,
                                       keep_alive, to, NULL);
    }
}

int captcha_check_clearance(const char *ip, const char *headers) {
    if (!ip || !headers || !cap_initialized) return 0;
    char cookie_hdr[2048];
    if (http_get_header_value(headers, "Cookie", cookie_hdr, sizeof(cookie_hdr)) < 0)
        return 0;

    /* 找 waf_cap=<expiry>.<mac> */
    const char *p = cookie_hdr;
    char val[256] = "";
    while (*p) {
        while (*p == ' ' || *p == ';') p++;
        const char *semi = strchr(p, ';');
        size_t len = semi ? (size_t)(semi - p) : strlen(p);
        if (len < sizeof(val)) {
            char item[256];
            memcpy(item, p, len);
            item[len] = '\0';
            char *eq = strchr(item, '=');
            if (eq) {
                *eq = '\0';
                char *k = item;
                while (*k == ' ') k++;
                if (strcmp(k, CAP_COOKIE_NAME) == 0) {
                    snprintf(val, sizeof(val), "%s", eq + 1);
                    break;
                }
            }
        }
        if (!semi) break;
        p = semi + 1;
    }
    if (!val[0]) return 0;

    char *dot = strchr(val, '.');
    if (!dot) return 0;
    *dot = '\0';
    long expiry = atol(val);
    const char *mac_hex = dot + 1;
    if (strlen(mac_hex) != 64) return 0;

    if (expiry <= (long)time(NULL)) return 0;

    char want[65];
    cap_clearance_hmac(ip, expiry, want);
    /* 常数时间比较 */
    unsigned char diff = 0;
    for (int i = 0; i < 64; i++) diff |= (unsigned char)(want[i] ^ mac_hex[i]);
    return diff == 0;
}
