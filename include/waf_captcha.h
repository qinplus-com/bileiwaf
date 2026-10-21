#ifndef WAF_CAPTCHA_H
#define WAF_CAPTCHA_H

#include "waf_common.h"
#include <openssl/ssl.h>

/* CC 触发人机验证（站点级 cc_captcha）：
 * 非白名单 IP 触发 CC 阈值时，站点若开启 cc_captcha 则先发 SVG 图形验证码
 * 挑战（/waf-captcha 端点），真人验证通过后发放 HMAC 签名放行 cookie
 * （有效期 = CC block_duration），脚本/AI 难以自动化通过。
 * 反自动化：码仅存 SHA256、sid/码一次性、渲染逐字符随机化、
 * 绑定发起 IP、TTL 300s、失败 5 次转 CC 封禁。 */

/* 启动初始化：生成 HMAC 密钥（/dev/urandom）。在 cc_init 之后调用一次 */
int captcha_init(void);

/* 过期挑战回收：挂 waf.c 维护循环（300s 周期） */
void captcha_cleanup(void);

/* URL 是否为验证码端点（/waf-captcha） */
int captcha_is_endpoint(const char *url);

/* 处理验证码端点 GET（出题）/POST（判卷）。已发送响应返回 1；
 * 该 IP 处于 CC 封禁态时不出题，返回 0（调用方落到原 403 路径） */
int captcha_handle(int client_fd, http_request_t *req,
                   SSL *ssl, int is_https, int keep_alive);

/* CC 刚触发时的挑战跳转：302 → /waf-captcha?to=<原URL>。恒返回 1 */
int captcha_send_challenge(int client_fd, http_request_t *req,
                           SSL *ssl, int is_https, int keep_alive);

/* 校验放行 cookie（waf_cap=expiry.hmac）：签名匹配且未过期返回 1 */
int captcha_check_clearance(const char *ip, const char *headers);

#endif
