#define _GNU_SOURCE
#include "../include/waf.h"
#include "../include/waf_ai.h"
#include "../include/waf_ai_cnn.h"
#include "../include/waf_ai_ae.h"
#include "../include/waf_log.h"
#include "../include/waf_http.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <ctype.h>
#include <sys/stat.h>

/* ============================================================
 * 解码与统计工具
 * ============================================================ */

const char* ai_ensemble_type_str(ai_ensemble_type_t type) {
    switch (type) {
        case AI_ENSEMBLE_NONE: return "None";
        case AI_ENSEMBLE_VOTING: return "Voting";
        case AI_ENSEMBLE_CASCADE: return "Cascade";
        case AI_ENSEMBLE_BLENDING: return "Blending";
        default: return "Unknown";
    }
}

const char* ai_detection_result_str(ai_detection_result_t result) {
    switch (result) {
        case AI_DETECTION_NORMAL:    return "NORMAL";
        case AI_DETECTION_SUSPICIOUS: return "SUSPICIOUS";
        case AI_DETECTION_MALICIOUS:  return "MALICIOUS";
        default: return "UNKNOWN";
    }
}

const char* ai_model_type_str(ai_model_type_t type) {
    switch (type) {
        case AI_MODEL_TYPE_ISOLATION_FOREST: return "Isolation Forest (0day)";
        case AI_MODEL_TYPE_RANDOM_FOREST:    return "Distilled Logistic (Known)";
        case AI_MODEL_TYPE_AUTOENCODER:      return "Autoencoder (Anomaly)";
        case AI_MODEL_TYPE_SQLI_DETECTOR:    return "SQLi Detector";
        case AI_MODEL_TYPE_XSS_DETECTOR:     return "XSS Detector";
        default: return "Unknown";
    }
}

static double compute_entropy(const char *str) {
    if (!str) return 0.0;
    int counts[256] = {0};
    int len = (int)strlen(str);
    if (len == 0) return 0.0;
    for (int i = 0; i < len; i++) counts[(unsigned char)str[i]]++;
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            double p = (double)counts[i] / len;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

int ai_url_decode(char *dst, const char *src, int dst_size) {
    if (!dst || !src || dst_size <= 0) return 0;
    int i = 0, j = 0;
    while (src[i] && j < dst_size - 1) {
        if (src[i] == '%' && src[i+1] && src[i+2]) {
            int hex1 = src[i+1], hex2 = src[i+2];
            int v1 = (hex1 >= '0' && hex1 <= '9') ? hex1 - '0' :
                     ((hex1 >= 'a' && hex1 <= 'f') ? hex1 - 'a' + 10 :
                     ((hex1 >= 'A' && hex1 <= 'F') ? hex1 - 'A' + 10 : -1));
            int v2 = (hex2 >= '0' && hex2 <= '9') ? hex2 - '0' :
                     ((hex2 >= 'a' && hex2 <= 'f') ? hex2 - 'a' + 10 :
                     ((hex2 >= 'A' && hex2 <= 'F') ? hex2 - 'A' + 10 : -1));
            if (v1 >= 0 && v2 >= 0) {
                dst[j++] = (char)((v1 << 4) | v2);
                i += 3;
                continue;
            }
        } else if (src[i] == '+') {
            dst[j++] = ' ';
            i++;
            continue;
        }
        dst[j++] = src[i++];
    }
    dst[j] = '\0';
    return j;
}

static int unicode_decode(char *dst, const char *src, int dst_size) {
    if (!dst || !src || dst_size <= 0) return 0;
    int i = 0, j = 0;
    while (src[i] && j < dst_size - 1) {
        if (src[i] == '\\' && src[i+1] == 'u' && src[i+2] && src[i+3] && src[i+4] && src[i+5]) {
            int code = 0, ok = 1;
            for (int k = 2; k < 6; k++) {
                char c = src[i + k];
                if (c >= '0' && c <= '9') code = (code << 4) | (c - '0');
                else if (c >= 'a' && c <= 'f') code = (code << 4) | (c - 'a' + 10);
                else if (c >= 'A' && c <= 'F') code = (code << 4) | (c - 'A' + 10);
                else { ok = 0; break; }
            }
            if (ok) {
                if (code >= 0x20 && code <= 0x7E) {
                    dst[j++] = (char)code;
                } else if (code >= 0x80 && code <= 0xFFFF && j + 3 < dst_size) {
                    if (code < 0x800) {
                        dst[j++] = (char)(0xC0 | ((code >> 6) & 0x1F));
                        dst[j++] = (char)(0x80 | (code & 0x3F));
                    } else {
                        dst[j++] = (char)(0xE0 | ((code >> 12) & 0x0F));
                        dst[j++] = (char)(0x80 | ((code >> 6) & 0x3F));
                        dst[j++] = (char)(0x80 | (code & 0x3F));
                    }
                }
                i += 6;
                continue;
            }
        }
        dst[j++] = src[i++];
    }
    dst[j] = '\0';
    return j;
}

static int html_entity_decode(char *dst, const char *src, int dst_size) {
    if (!dst || !src || dst_size <= 0) return 0;
    int i = 0, j = 0;
    while (src[i] && j < dst_size - 1) {
        if (src[i] == '&' && src[i+1]) {
            const char *end = strchr(src + i, ';');
            if (end) {
                int len = (int)(end - src - i);
                if (len > 1 && len < 32) {
                    char entity[40];
                    strncpy(entity, src + i, len + 1);
                    entity[len + 1] = '\0';
                    if (strcmp(entity, "&lt;") == 0) { dst[j++] = '<'; i += 4; continue; }
                    if (strcmp(entity, "&gt;") == 0) { dst[j++] = '>'; i += 4; continue; }
                    if (strcmp(entity, "&amp;") == 0) { dst[j++] = '&'; i += 5; continue; }
                    if (strcmp(entity, "&quot;") == 0) { dst[j++] = '"'; i += 6; continue; }
                    if (strcmp(entity, "&apos;") == 0) { dst[j++] = '\''; i += 6; continue; }
                    if (strcmp(entity, "&nbsp;") == 0) { dst[j++] = ' '; i += 6; continue; }
                    if (strncmp(entity, "&#x", 3) == 0 || strncmp(entity, "&#X", 3) == 0) {
                        int code = 0, ok = 1;
                        for (int k = 3; k < len; k++) {
                            char c = entity[k];
                            if (c >= '0' && c <= '9') code = (code << 4) | (c - '0');
                            else if (c >= 'a' && c <= 'f') code = (code << 4) | (c - 'a' + 10);
                            else if (c >= 'A' && c <= 'F') code = (code << 4) | (c - 'A' + 10);
                            else { ok = 0; break; }
                        }
                        if (ok && code >= 0x20 && code <= 0x7E) { dst[j++] = (char)code; i += len + 1; continue; }
                    }
                    if (strncmp(entity, "&#", 2) == 0) {
                        int code = 0, ok = 1;
                        for (int k = 2; k < len; k++) {
                            char c = entity[k];
                            if (c >= '0' && c <= '9') code = code * 10 + (c - '0');
                            else { ok = 0; break; }
                        }
                        if (ok && code >= 0x20 && code <= 0x7E) { dst[j++] = (char)code; i += len + 1; continue; }
                    }
                }
            }
        }
        dst[j++] = src[i++];
    }
    dst[j] = '\0';
    return j;
}

static int count_encoded_chars(const char *str) {
    if (!str) return 0;
    int count = 0;
    int len = (int)strlen(str);
    for (int i = 0; i < len; i++) {
        if (str[i] == '%' && i + 2 < len) {
            if (isxdigit((unsigned char)str[i+1]) && isxdigit((unsigned char)str[i+2])) count++;
        } else if (str[i] == '\\' && i + 5 < len && str[i+1] == 'u') {
            int valid = 1;
            for (int j = 2; j < 6 && valid; j++)
                if (!isxdigit((unsigned char)str[i+j])) valid = 0;
            if (valid) count++;
        } else if (str[i] == '&') {
            const char *end = strchr(str + i, ';');
            if (end && (end - str - i) > 1 && (end - str - i) < 32) count++;
        }
    }
    return count;
}

static int count_special_chars(const char *str) {
    if (!str) return 0;
    int count = 0;
    const char *special = "!@#$%^&*()_+-=[]{}|;:,.<>?";
    while (*str) { if (strchr(special, *str)) count++; str++; }
    return count;
}

/* ============================================================
 * 攻击指示器（仅用于特征提取，不做判定）
 * 注意：已移除裸 "--" / "#"（FP 炸弹）
 * ============================================================ */

static int contains_sql_pattern(const char *str) {
    if (!str) return 0;
    static const char *patterns[] = {
        "union select", "union all select",
        "insert into", "update set", "delete from", "drop table",
        "exec(", "execute(", "sleep(", "benchmark(", "waitfor delay", "pg_sleep",
        "information_schema", "sys.tables", "syscolumns",
        "cast(", "convert(", "substring(", "mid(", "left(", "right(", "char(", "ascii(",
        "from users", "where 1=1", "or 1=1", "and 1=1", "' or '", "' and '",
        ";--", ";#", "like '%", "rlike ", "regexp ",
        NULL
    };
    for (int i = 0; patterns[i]; i++)
        if (strcasestr(str, patterns[i])) return 1;
    return 0;
}

static int contains_xss_pattern(const char *str) {
    if (!str) return 0;
    static const char *patterns[] = {
        "<script", "</script>", "javascript:", "vbscript:",
        "alert(", "confirm(", "prompt(",
        "document.cookie", "document.write", "innerhtml", "outerhtml",
        "onload=", "onclick=", "onmouseover=", "onerror=", "onfocus=", "onblur=",
        "onchange=", "onsubmit=", "onunload=", "onresize=",
        "<iframe", "<object", "<embed", "<applet", "<svg", "<canvas",
        "string.fromcharcode", "atob(", "btoa(", "unescape(",
        "settimeout(", "setinterval(", "xmlhttprequest",
        "<img src=x", "srcdoc=", "expression(",
        /* 括号取下标调用形态（混淆 XSS 常见）：["alert"](..)、['eval'](..) */
        "\"alert\"", "'alert'", "\"eval\"", "'eval'",
        "\"atob\"", "'atob'", "\"fromcharcode\"", "'fromcharcode'",
        "\"confirm\"", "'confirm'", "\"prompt\"", "'prompt'",
        NULL
    };
    for (int i = 0; patterns[i]; i++)
        if (strcasestr(str, patterns[i])) return 1;
    return 0;
}

static int contains_cmd_pattern(const char *str) {
    if (!str) return 0;
    static const char *patterns[] = {
        "$(", "`", "system(", "shell_exec(", "passthru(",
        "popen(", "proc_open(", "pcntl_exec(",
        "bash -c", "sh -c", "cmd /c", "cmd.exe", "powershell",
        "wget ", "curl ", "ncat ", "traceroute", "nslookup",
        "rm -rf", "/etc/passwd", "/etc/shadow",
        "whoami", "uname -a",
        "${jndi:", "com.sun.rowset.jdbcrowsetimpl",
        "%24%7bjndi",
        NULL
    };
    for (int i = 0; patterns[i]; i++)
        if (strcasestr(str, patterns[i])) return 1;
    return 0;
}

static int contains_path_traversal(const char *str) {
    if (!str) return 0;
    static const char *patterns[] = {
        "../", "..\\", "..%2f", "..%5c", "%2e%2e/", "%2e%2e\\",
        "/etc/passwd", "/etc/shadow", "/etc/group",
        "proc/self/environ", "proc/version", "web-inf", "\\..\\",
        NULL
    };
    for (int i = 0; patterns[i]; i++)
        if (strcasestr(str, patterns[i])) return 1;
    return 0;
}

static int contains_xxe_pattern(const char *str) {
    if (!str) return 0;
    static const char *patterns[] = {
        "<!doctype", "<!entity", "[cdata[",
        "system \"", "system '", "public \"", "public '",
        "php://", "expect:", "gopher://",
        "%3c!entity", "%25%3c!entity",
        NULL
    };
    for (int i = 0; patterns[i]; i++)
        if (strcasestr(str, patterns[i])) return 1;
    return 0;
}

static int contains_deserialization_pattern(const char *str) {
    if (!str) return 0;
    static const char *patterns[] = {
        "readobject", "readresolve", "writeobject",
        "java.io.objectinputstream",
        "com.sun.rowset.jdbcrowsetimpl",
        "org.apache.commons.collections",
        "org.codehaus.groovy.runtime",
        "com.thoughtworks.xstream",
        "fastjson", "serialversionuid",
        NULL
    };
    for (int i = 0; patterns[i]; i++)
        if (strcasestr(str, patterns[i])) return 1;
    return 0;
}

/* ============================================================
 * 定长特征提取（64 槽，固定下标，缺失补零）
 * ============================================================ */

static double clamp01(double v) { return v < 0.0 ? 0.0 : (v > 1.0 ? 1.0 : v); }

static void fill_source_features(double *features, int src, const char *s) {
    if (!s || !s[0]) return;
    size_t len = strlen(s);
    features[AI_FEAT(src, AI_F_LEN)]     = clamp01((double)len / 255.0);
    features[AI_FEAT(src, AI_F_ENTROPY)] = clamp01(compute_entropy(s) / 8.0);
    features[AI_FEAT(src, AI_F_ENC)]     = clamp01((double)count_encoded_chars(s) / 20.0);
    features[AI_FEAT(src, AI_F_SPECIAL)] = clamp01((double)count_special_chars(s) / (double)(len + 1));
    features[AI_FEAT(src, AI_F_SQL)]     = contains_sql_pattern(s) ? 1.0 : 0.0;
    features[AI_FEAT(src, AI_F_XSS)]     = contains_xss_pattern(s) ? 1.0 : 0.0;
    features[AI_FEAT(src, AI_F_CMD)]     = contains_cmd_pattern(s) ? 1.0 : 0.0;
    features[AI_FEAT(src, AI_F_PATH)]    = contains_path_traversal(s) ? 1.0 : 0.0;
}

/* 折叠空反引号：`` → 空（与引擎解码管线一致） */
static void fold_empty_backticks(char *s) {
    char *w = s;
    for (char *r = s; *r; ) {
        if (r[0] == '`' && r[1] == '`') { r += 2; continue; }
        *w++ = *r++;
    }
    *w = '\0';
}

/* \xNN 反转义 */
static int hex_backslash_decode(char *dst, const char *src, int dst_size) {
    int i = 0, j = 0;
    while (src[i] && j < dst_size - 1) {
        if (src[i] == '\\' && (src[i+1] == 'x' || src[i+1] == 'X') &&
            isxdigit((unsigned char)src[i+2]) && isxdigit((unsigned char)src[i+3])) {
            int hi = isdigit((unsigned char)src[i+2]) ? src[i+2] - '0' :
                     (tolower((unsigned char)src[i+2]) - 'a' + 10);
            int lo = isdigit((unsigned char)src[i+3]) ? src[i+3] - '0' :
                     (tolower((unsigned char)src[i+3]) - 'a' + 10);
            dst[j++] = (char)((hi << 4) | lo);
            i += 4;
            continue;
        }
        dst[j++] = src[i++];
    }
    dst[j] = '\0';
    return j;
}

/* 深度解码（对齐引擎多层解码管线）：
 * URL 解码 → 空反引号折叠 → unicode 反转义 → \xNN 反转义 → 二次 URL 解码 → HTML 实体解码 → 再次 unicode */
static void deep_decode(const char *in, char *out, int outsz) {
    char a[4096], b[4096], c[4096], d[4096];
    out[0] = '\0';
    if (!in || !in[0]) return;
    ai_url_decode(a, in, (int)sizeof(a));
    fold_empty_backticks(a);
    unicode_decode(b, a, (int)sizeof(b));
    hex_backslash_decode(c, b, (int)sizeof(c));
    ai_url_decode(d, c, (int)sizeof(d));
    html_entity_decode(b, d, (int)sizeof(b));
    unicode_decode(out, b, outsz);
}

int ai_extract_features(http_request_t *req, double *features, int *feature_count) {
    if (!req || !features || !feature_count) return -1;

    memset(features, 0, sizeof(double) * AI_FEAT_DIM);
    *feature_count = AI_FEAT_DIM;

    char decoded[4096];

    fill_source_features(features, AI_SRC_URL, req->url);
    deep_decode(req->url, decoded, (int)sizeof(decoded));
    fill_source_features(features, AI_SRC_URLDEC, decoded);

    fill_source_features(features, AI_SRC_QUERY, req->query);
    deep_decode(req->query, decoded, (int)sizeof(decoded));
    fill_source_features(features, AI_SRC_QUERYDEC, decoded);

    fill_source_features(features, AI_SRC_BODY, req->body);
    deep_decode(req->body, decoded, (int)sizeof(decoded));
    fill_source_features(features, AI_SRC_BODYDEC, decoded);

    /* 头特征（hdrs.*, 槽 48-55）不参与：黑/白语料的头部熵与特殊字符比存在
     * 采样性差异（攻击样本多用简易 UA、字段少），属语料泄漏而非真实判别信号，
     * 会导致正常请求被误判为高分。保留槽位但恒置 0。 */
    (void)0;

    /* 聚合/交叉特征 */
    int fam_sql = 0, fam_xss = 0, fam_cmd = 0, fam_path = 0, fam_other = 0;
    double total_enc = 0.0;
    for (int s = 0; s < AI_SRC_COUNT; s++) {
        if (features[AI_FEAT(s, AI_F_SQL)]  > 0) fam_sql = 1;
        if (features[AI_FEAT(s, AI_F_XSS)]  > 0) fam_xss = 1;
        if (features[AI_FEAT(s, AI_F_CMD)]  > 0) fam_cmd = 1;
        if (features[AI_FEAT(s, AI_F_PATH)] > 0) fam_path = 1;
        total_enc += features[AI_FEAT(s, AI_F_ENC)];
        if (features[AI_FEAT(s, AI_F_ENTROPY)] > 0) {
            /* 每来源的 XXE/反序列化另算（不占来源槽位，仅参与聚合） */
        }
    }
    fam_other = (contains_xxe_pattern(req->url) || contains_deserialization_pattern(req->url) ||
                 contains_xxe_pattern(req->query) || contains_deserialization_pattern(req->query) ||
                 contains_xxe_pattern(req->body) || contains_deserialization_pattern(req->body) ||
                 contains_xxe_pattern(req->headers) || contains_deserialization_pattern(req->headers)) ? 1 : 0;

    features[AI_X_ANY_SQL]  = fam_sql;
    features[AI_X_ANY_XSS]  = fam_xss;
    features[AI_X_ANY_CMD]  = fam_cmd;
    features[AI_X_ANY_PATH] = fam_path;
    features[AI_X_ANY_OTHER] = fam_other;
    features[AI_X_FAMILIES] = (fam_sql + fam_xss + fam_cmd + fam_path + fam_other) / 5.0;
    features[AI_X_TOTAL_ENC] = clamp01(total_enc);

    /* 槽位 63：非常规方法指示 */
    if (req->method && req->method[0]) {
        int common = (strcmp(req->method, "GET") == 0 || strcmp(req->method, "POST") == 0 ||
                      strcmp(req->method, "HEAD") == 0 || strcmp(req->method, "OPTIONS") == 0);
        features[AI_X_EXTRA] = common ? 0.0 : 1.0;
    }

    return 0;
}

/* ============================================================
 * 逻辑回归评分（统一形式，无按类型硬编码下标）
 * ============================================================ */

double ai_calculate_anomaly_score(ai_config_t *config, double *features, int feature_count, int model_index) {
    if (!config || !features || model_index < 0 || model_index >= MAX_MODELS) return 0.0;
    if (model_index >= config->model_count) return 0.0;

    ai_model_t *model = &config->models[model_index];
    if (!model->trained) return 0.0;

    double z = model->bias;
    int n = feature_count < MAX_FEATURES ? feature_count : MAX_FEATURES;
    for (int i = 0; i < n; i++) {
        double sd = model->std[i];
        if (sd < 0.05) sd = 0.05;   /* 与训练一致的 std 下限，防止近常量特征放大 */
        z += model->weights[i] * ((features[i] - model->mean[i]) / sd);
    }
    if (z > 60.0) z = 60.0;
    if (z < -60.0) z = -60.0;
    return 1.0 / (1.0 + exp(-z));
}

double ai_score_request(ai_config_t *config, http_request_t *req) {
    if (!config || !req) return 0.0;
    /* v3.0：在线检测仅使用 CNN+AE 双通道融合（64 槽 LR 弃用） */
    if (config->fusion_ready)
        return ai_fusion_score(config, req, NULL, NULL);
    return 0.0;
}

ai_detection_result_t ai_detect_single(ai_config_t *config, http_request_t *req, int model_index) {
    if (!config || !req || !config->enabled || model_index < 0 || model_index >= config->model_count)
        return AI_DETECTION_NORMAL;
    ai_model_t *model = &config->models[model_index];
    if (!model->trained) return AI_DETECTION_NORMAL;

    double features[MAX_FEATURES];
    int fc = 0;
    ai_extract_features(req, features, &fc);
    double score = ai_calculate_anomaly_score(config, features, fc, model_index);

    if (score >= model->threshold) return AI_DETECTION_MALICIOUS;
    if (score >= model->threshold * 0.7) return AI_DETECTION_SUSPICIOUS;
    return AI_DETECTION_NORMAL;
}

ai_detection_result_t ai_ensemble_voting(ai_config_t *config, double *features, int feature_count) {
    if (!config || config->model_count == 0) return AI_DETECTION_NORMAL;

    double total_weight = 0.0, malicious_weight = 0.0;
    for (int i = 0; i < config->model_count; i++) {
        ai_model_t *model = &config->models[i];
        if (!model->trained) continue;
        double score = ai_calculate_anomaly_score(config, features, feature_count, i);
        total_weight += model->weight;
        if (score >= model->threshold) malicious_weight += model->weight;
    }
    if (total_weight > 0) {
        double ratio = malicious_weight / total_weight;
        if (ratio >= config->ensemble_threshold) return AI_DETECTION_MALICIOUS;
        if (ratio >= config->ensemble_threshold * 0.5) return AI_DETECTION_SUSPICIOUS;
    }
    return AI_DETECTION_NORMAL;
}

ai_detection_result_t ai_ensemble_cascade(ai_config_t *config, double *features, int feature_count) {
    if (!config || config->model_count == 0) return AI_DETECTION_NORMAL;
    for (int i = 0; i < config->model_count; i++) {
        ai_model_t *model = &config->models[i];
        if (!model->trained) continue;
        double score = ai_calculate_anomaly_score(config, features, feature_count, i);
        if (score >= model->threshold) return AI_DETECTION_MALICIOUS;
        if (score >= model->threshold * 0.7) return AI_DETECTION_SUSPICIOUS;
    }
    return AI_DETECTION_NORMAL;
}

ai_detection_result_t ai_ensemble_blending(ai_config_t *config, double *features, int feature_count) {
    if (!config || !features) return AI_DETECTION_NORMAL;
    if (config->model_count <= 0 || config->model_count > MAX_MODELS) return AI_DETECTION_NORMAL;

    double blended = 0.0, total_weight = 0.0;
    for (int i = 0; i < config->model_count && i < MAX_MODELS; i++) {
        ai_model_t *model = &config->models[i];
        if (!model->trained) continue;
        blended += ai_calculate_anomaly_score(config, features, feature_count, i) * model->weight;
        total_weight += model->weight;
    }
    if (total_weight > 0) {
        blended /= total_weight;
        if (blended >= config->ensemble_threshold) return AI_DETECTION_MALICIOUS;
        if (blended >= config->ensemble_threshold * 0.7) return AI_DETECTION_SUSPICIOUS;
    }
    return AI_DETECTION_NORMAL;
}

/* 纯打分入口：只返回置信度，不做任何拦截决策、不做任何 URL 白名单旁路 */
ai_detection_result_t ai_detect(ai_config_t *config, http_request_t *req) {
    if (!config || !req || !config->enabled) return AI_DETECTION_NORMAL;

    /* v3.0：双通道融合判定（CNN+AE）；无融合模型时 AI 不可用 */
    if (config->fusion_ready) {
        pthread_mutex_lock(&config->mutex);
        config->detection_count++;
        pthread_mutex_unlock(&config->mutex);

        double score = ai_fusion_score(config, req, NULL, NULL);
        if (score >= config->fusion_threshold) return AI_DETECTION_MALICIOUS;
        if (score >= config->fusion_threshold * 0.7) return AI_DETECTION_SUSPICIOUS;
        return AI_DETECTION_NORMAL;
    }

    /* 旧 LR 路径（仅离线工具链使用；在线 detection 不再依赖） */
    if (config->model_count <= 0 || config->model_count > MAX_MODELS) return AI_DETECTION_NORMAL;

    double features[MAX_FEATURES];
    int fc = 0;
    ai_extract_features(req, features, &fc);

    switch (config->ensemble_type) {
        case AI_ENSEMBLE_VOTING:   return ai_ensemble_voting(config, features, fc);
        case AI_ENSEMBLE_CASCADE:  return ai_ensemble_cascade(config, features, fc);
        case AI_ENSEMBLE_BLENDING: return ai_ensemble_blending(config, features, fc);
        case AI_ENSEMBLE_NONE:
        default:
            return ai_detect_single(config, req, 0);
    }
}

/* ============================================================
 * 模型管理
 * ============================================================ */

int ai_add_model(ai_config_t *config, ai_model_type_t type, const char *name, double weight) {
    if (!config || config->model_count >= MAX_MODELS) return -1;
    ai_model_t *model = &config->models[config->model_count];
    memset(model, 0, sizeof(ai_model_t));
    model->type = type;
    if (name) strncpy(model->name, name, sizeof(model->name) - 1);
    else snprintf(model->name, sizeof(model->name), "Model_%d", config->model_count);
    model->weight = weight;
    model->threshold = 0.5;
    model->trained = 0;
    for (int i = 0; i < MAX_FEATURES; i++) {
        model->weights[i] = 0.0;
        model->mean[i] = 0.0;
        model->std[i] = 1.0;
    }
    config->model_count++;
    return config->model_count - 1;
}

int ai_remove_model(ai_config_t *config, int index) {
    if (!config || index < 0 || index >= config->model_count) return -1;
    for (int i = index; i < config->model_count - 1; i++)
        config->models[i] = config->models[i + 1];
    config->model_count--;
    return 0;
}

static ai_config_t default_config;

int ai_init(ai_config_t *config, void *waf_cfg_ptr) {
    if (!config) config = &default_config;

    memset(config, 0, sizeof(ai_config_t));
    pthread_mutex_init(&config->mutex, NULL);

    config->enabled = 1;
    config->shadow_mode = 0;
    config->auto_learning = 0;
    config->auto_update_rules = 0;
    config->retrain_interval = 3600;
    config->min_samples_for_retrain = 200;
    config->model_count = 0;
    config->ensemble_type = AI_ENSEMBLE_BLENDING;
    config->ensemble_threshold = 0.5;

    /* 自主学习护栏默认值（deny-by-default 的保守值） */
    config->guard.enabled = 0;
    config->guard.shadow_mode = 1;
    config->guard.min_occurrences = 5;
    config->guard.min_confidence_pct = 90;
    config->guard.max_rules = 200;
    config->guard.max_white_fp = 0;
    /* 0 = 评估白名单全量样本。评估只取前 N 个样本会让「未采样区间」的匹配漏检，
     * 使 max_white_fp=0 的零误报承诺形同虚设（实测：采样 2000/33219 时，
     * 由白样本铸出的规则在被采样子集里 fp=0 通过，全量回放却产生误报）。 */
    config->guard.white_sample_size = 0;
    strcpy(config->guard.learned_rules_path, "rules/ai_learned.rules");
    strcpy(config->guard.white_list_path, "/tmp/white_all.txt");

    /* 相对路径：守护进程 cwd=WAF_HOME（start.sh cd），CLI 从实例目录运行，
     * 各自解析到本实例目录，杜绝跨实例/跨环境读写生产模型（v1.1.0 曾硬编码
     * 绝对路径，发行包在他机误读本机生产模型） */
    strcpy(config->model_path, "models/ai_model.dat");
    strcpy(config->data_path, "data/ai_samples.dat");
    mkdir("models", 0755);
    mkdir("data", 0755);

    waf_config_t *waf_cfg = (waf_config_t *)waf_cfg_ptr;
    if (waf_cfg) {
        config->ensemble_type = waf_cfg->ai_ensemble;
        config->ensemble_threshold = waf_cfg->ai_ensemble_threshold;
        config->shadow_mode = waf_cfg->ai_shadow_mode;
        config->guard.enabled = waf_cfg->ai_guard_enabled;
        config->guard.shadow_mode = waf_cfg->ai_shadow_mode;
        if (waf_cfg->ai_guard_min_occ > 0) config->guard.min_occurrences = waf_cfg->ai_guard_min_occ;
        if (waf_cfg->ai_guard_min_conf > 0) config->guard.min_confidence_pct = waf_cfg->ai_guard_min_conf;
        if (waf_cfg->ai_guard_max_rules > 0) config->guard.max_rules = waf_cfg->ai_guard_max_rules;
        config->guard.max_white_fp = waf_cfg->ai_guard_max_white_fp;
        if (waf_cfg->ai_white_list[0]) 
            strncpy(config->guard.white_list_path, waf_cfg->ai_white_list,
                    sizeof(config->guard.white_list_path) - 1);
        if (waf_cfg->ai_learned_rules[0]) {
            strncpy(config->guard.learned_rules_path, waf_cfg->ai_learned_rules,
                    sizeof(config->guard.learned_rules_path) - 1);
        } else if (waf_cfg->rules_dir[0]) {
            snprintf(config->guard.learned_rules_path, sizeof(config->guard.learned_rules_path),
                     "%s/ai_learned.rules", waf_cfg->rules_dir);
        }
        if (waf_cfg->ai_auto_learn) config->auto_learning = 1;

        if (waf_cfg->detection_mode == DETECTION_MODE_RULES) {
            /* 纯规则模式：默认不启用 AI 判定；影子模式仅打分不拦截 */
            config->enabled = config->shadow_mode ? 1 : 0;
            waf_log(LOG_LEVEL_INFO, "Detection mode: RULES (AI %s)",
                    config->enabled ? "shadow-scoring enabled" : "disabled");
        } else if (waf_cfg->detection_mode == DETECTION_MODE_AI) {
            config->enabled = 1;
            waf_log(LOG_LEVEL_INFO, "Detection mode: AI");
        } else {
            config->enabled = 1;
            waf_log(LOG_LEVEL_INFO, "Detection mode: AUTO");
        }
    }

    double weights[MAX_MODELS] = {0.40, 0.20, 0.15, 0.125, 0.125};
    if (waf_cfg) {
        for (int i = 0; i < MAX_MODELS; i++)
            if (waf_cfg->ai_model_weights[i] > 0) weights[i] = waf_cfg->ai_model_weights[i];
    }

    ai_add_model(config, AI_MODEL_TYPE_ISOLATION_FOREST, "Isolation_Forest", weights[0]);
    ai_add_model(config, AI_MODEL_TYPE_RANDOM_FOREST,    "Distilled_Logistic", weights[1]);
    ai_add_model(config, AI_MODEL_TYPE_AUTOENCODER,      "Autoencoder", weights[2]);
    ai_add_model(config, AI_MODEL_TYPE_SQLI_DETECTOR,    "SQLi_Detector", weights[3]);
    ai_add_model(config, AI_MODEL_TYPE_XSS_DETECTOR,     "XSS_Detector", weights[4]);

    if (waf_cfg) {
        for (int i = 0; i < config->model_count; i++)
            config->models[i].threshold = waf_cfg->ai_threshold;
    }

    /* v3.0：在线检测仅加载 CNN+AE 双通道（64 槽 LR 弃用，不再在线加载）。
     * 模型缺失 → fusion_ready=0 → AI 不可用 → 检测回退规则引擎兜底。 */
    ai_fusion_load(config);

    /* waf.conf 显式配置的 ai_ensemble_threshold 优先于模型文件内保存的校准值，
     * 使用户可在不重训的情况下调整 AI 判定工作点（0 = 未配置，沿用模型校准值） */
    if (waf_cfg && waf_cfg->ai_ensemble_threshold > 0.0) {
        config->ensemble_threshold = waf_cfg->ai_ensemble_threshold;
        if (config->fusion_ready) config->fusion_threshold = waf_cfg->ai_ensemble_threshold;
    }
    /* ai_cnn_weight 显式配置（0..1）覆盖融合校准的 w_cnn（0 = 沿用校准值） */
    if (waf_cfg && waf_cfg->ai_cnn_weight > 0.0 && config->fusion_ready) {
        config->fusion_w_cnn = waf_cfg->ai_cnn_weight;
    }

    waf_log(LOG_LEVEL_INFO, "AI module init: ensemble=%s models=%d enabled=%d shadow=%d guard=%d",
            ai_ensemble_type_str(config->ensemble_type), config->model_count,
            config->enabled, config->shadow_mode, config->guard.enabled);
    return 0;
}

void ai_cleanup(ai_config_t *config) {
    if (!config) return;
    if (config->cnn_model) { ai_cnn_destroy((ai_cnn_t *)config->cnn_model); config->cnn_model = NULL; }
    if (config->ae_model)  { ai_ae_destroy((ai_ae_t *)config->ae_model);   config->ae_model = NULL; }
    config->fusion_ready = 0;
    pthread_mutex_destroy(&config->mutex);
    waf_log(LOG_LEVEL_INFO, "AI module cleaned up");
}

int ai_load_model(ai_config_t *config, const char *path) {
    if (!config || !path || config->model_count == 0) return -1;
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    size_t rd = fread(&config->models[0], sizeof(ai_model_t), 1, fp);
    fclose(fp);
    return rd == 1 ? 0 : -1;
}

int ai_save_model(ai_config_t *config, const char *path) {
    if (!config || !path || config->model_count == 0) return -1;
    FILE *fp = fopen(path, "wb");
    if (!fp) return -1;
    fwrite(&config->models[0], sizeof(ai_model_t), 1, fp);
    fclose(fp);
    return 0;
}

int ai_load_ensemble(ai_config_t *config, const char *base_path) {
    if (!config || !base_path) return -1;
    char index_path[512];
    snprintf(index_path, sizeof(index_path), "%s.index", base_path);
    FILE *fp = fopen(index_path, "rb");
    if (!fp) return -1;

    int saved_model_count = 0;
    ai_ensemble_type_t saved_type = AI_ENSEMBLE_NONE;
    double saved_threshold = 0.5;
    if (fread(&saved_model_count, sizeof(int), 1, fp) != 1 ||
        fread(&saved_type, sizeof(ai_ensemble_type_t), 1, fp) != 1 ||
        fread(&saved_threshold, sizeof(double), 1, fp) != 1) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    if (saved_model_count <= 0 || saved_model_count > MAX_MODELS) return -1;
    if (saved_type < AI_ENSEMBLE_NONE || saved_type > AI_ENSEMBLE_BLENDING) saved_type = AI_ENSEMBLE_BLENDING;

    int loaded = 0;
    for (int i = 0; i < saved_model_count && i < MAX_MODELS; i++) {
        char mp[512];
        snprintf(mp, sizeof(mp), "%s.%d", base_path, i);
        FILE *mf = fopen(mp, "rb");
        if (mf) {
            if (fread(&config->models[i], sizeof(ai_model_t), 1, mf) == 1 && config->models[i].trained)
                loaded++;
            fclose(mf);
        }
    }
    if (loaded == 0) return -1;

    config->model_count = saved_model_count;
    config->ensemble_type = saved_type;
    config->ensemble_threshold = saved_threshold;
    waf_log(LOG_LEVEL_INFO, "Ensemble loaded from %s (%d models trained)", base_path, loaded);
    return 0;
}

int ai_save_ensemble(ai_config_t *config, const char *base_path) {
    if (!config || !base_path) return -1;
    char index_path[512];
    snprintf(index_path, sizeof(index_path), "%s.index", base_path);
    FILE *fp = fopen(index_path, "wb");
    if (!fp) return -1;
    fwrite(&config->model_count, sizeof(int), 1, fp);
    fwrite(&config->ensemble_type, sizeof(ai_ensemble_type_t), 1, fp);
    fwrite(&config->ensemble_threshold, sizeof(double), 1, fp);
    for (int i = 0; i < config->model_count; i++) {
        char mp[512];
        snprintf(mp, sizeof(mp), "%s.%d", base_path, i);
        FILE *mf = fopen(mp, "wb");
        if (mf) {
            fwrite(&config->models[i], sizeof(ai_model_t), 1, mf);
            fclose(mf);
        }
    }
    fclose(fp);
    return 0;
}

/* ============================================================
 * 样本池（环形缓冲）与训练
 * ============================================================ */

int ai_add_sample(ai_config_t *config, double *features, int feature_count, int is_malicious) {
    if (!config || !features || feature_count <= 0) return -1;

    pthread_mutex_lock(&config->mutex);
    ai_sample_t *sample = &config->samples[config->sample_head];
    memset(sample, 0, sizeof(ai_sample_t));
    int n = feature_count < MAX_FEATURES ? feature_count : MAX_FEATURES;
    for (int i = 0; i < n; i++) sample->features[i] = features[i];
    sample->feature_count = n;
    sample->is_malicious = is_malicious;
    config->sample_head = (config->sample_head + 1) % MAX_SAMPLES;
    if (config->sample_count < MAX_SAMPLES) config->sample_count++;
    pthread_mutex_unlock(&config->mutex);
    return 0;
}

/* 逻辑回归拟合：标准化 + 梯度下降（带 L2），类别不平衡按频率反比加权 */
int ai_fit_logistic(ai_model_t *model, const ai_sample_t *samples, int count,
                    int epochs, double lr) {
    if (!model || !samples || count < 2) return -1;

    double mean[MAX_FEATURES] = {0}, std[MAX_FEATURES] = {0};
    long pos = 0, neg = 0;
    for (int i = 0; i < count; i++) {
        const ai_sample_t *s = &samples[i];
        if (s->is_malicious) pos++; else neg++;
        for (int j = 0; j < AI_FEAT_DIM; j++) mean[j] += s->features[j];
    }
    if (pos == 0 || neg == 0) return -1; /* 单类语料无法蒸馏 */
    for (int j = 0; j < AI_FEAT_DIM; j++) mean[j] /= count;
    for (int i = 0; i < count; i++) {
        const ai_sample_t *s = &samples[i];
        for (int j = 0; j < AI_FEAT_DIM; j++) {
            double d = s->features[j] - mean[j];
            std[j] += d * d;
        }
    }
    /* std 下限 0.05（归一化特征量程的 5%）：近常量特征若按极小 std 标准化，
     * 会被放大成主导 logit 的伪信号（实测 hdrs.ent std=0.013 导致 GET / 被判 100 分）。
     * 训练与推理使用同一 std，保证一致。 */
    for (int j = 0; j < AI_FEAT_DIM; j++) {
        std[j] = sqrt(std[j] / count);
        if (std[j] < 0.05) std[j] = 0.05;
        model->mean[j] = mean[j];
        model->std[j] = std[j];
    }

    double wclass_pos = (double)count / (2.0 * (double)pos);
    double wclass_neg = (double)count / (2.0 * (double)neg);

    double w[MAX_FEATURES] = {0};
    double b = 0.0;
    const double l2 = 1e-4;

    for (int epoch = 0; epoch < epochs; epoch++) {
        double gw[MAX_FEATURES] = {0};
        double gb = 0.0;
        for (int i = 0; i < count; i++) {
            const ai_sample_t *s = &samples[i];
            double z = b;
            for (int j = 0; j < AI_FEAT_DIM; j++)
                z += w[j] * ((s->features[j] - mean[j]) / std[j]);
            if (z > 60.0) z = 60.0; if (z < -60.0) z = -60.0;
            double p = 1.0 / (1.0 + exp(-z));
            double cw = s->is_malicious ? wclass_pos : wclass_neg;
            double err = (p - (s->is_malicious ? 1.0 : 0.0)) * cw;
            gb += err;
            for (int j = 0; j < AI_FEAT_DIM; j++)
                gw[j] += err * ((s->features[j] - mean[j]) / std[j]);
        }
        for (int j = 0; j < AI_FEAT_DIM; j++) {
            w[j] -= lr * (gw[j] / count + l2 * w[j]);
        }
        b -= lr * (gb / count);
    }

    for (int j = 0; j < AI_FEAT_DIM; j++) model->weights[j] = w[j];
    model->bias = b;
    model->trained = 1;
    model->sample_count = count;
    return 0;
}

int ai_train_ensemble(ai_config_t *config) {
    if (!config || config->sample_count < 20 || config->model_count == 0) return -1;

    pthread_mutex_lock(&config->mutex);
    int rc = ai_fit_logistic(&config->models[0], config->samples, config->sample_count, 300, 0.5);
    if (rc == 0) {
        config->models[0].type = AI_MODEL_TYPE_RANDOM_FOREST;
        strncpy(config->models[0].name, "Distilled_Logistic", sizeof(config->models[0].name) - 1);
    }
    pthread_mutex_unlock(&config->mutex);

    if (rc != 0) return -1;
    ai_save_ensemble(config, config->model_path);
    waf_log(LOG_LEVEL_INFO, "Online ensemble trained on %d samples", config->sample_count);
    return 0;
}

int ai_train_model(ai_config_t *config) { return ai_train_ensemble(config); }

int ai_update_model(ai_config_t *config) {
    if (!config) return -1;
    int need = 0;
    pthread_mutex_lock(&config->mutex);
    need = (config->sample_count >= config->min_samples_for_retrain);
    pthread_mutex_unlock(&config->mutex);
    if (need) return ai_train_ensemble(config);
    return 0;
}

int ai_auto_learn(ai_config_t *config, http_request_t *req, int attack_detected) {
    if (!config || !req || !config->auto_learning) return -1;
    double features[MAX_FEATURES];
    int fc = 0;
    if (ai_extract_features(req, features, &fc) != 0) return -1;
    ai_add_sample(config, features, fc, attack_detected ? 1 : 0);
    if (config->sample_count >= config->min_samples_for_retrain) ai_train_ensemble(config);
    return 0;
}

/* ============================================================
 * AI → 引擎原生规则（护栏写盘由 waf_ai_guard.c 编排）
 * 仅负责"消毒 + 语法校验 + 去重追加"，不做热加载决策。
 * ============================================================ */

int ai_adapt_rules(ai_config_t *config, const char *pattern, int confidence) {
    if (!config || !pattern) return -1;
    if (!config->guard.enabled) return -1;

    /* pattern 消毒：拒绝逗号（strtok 会截断）、换行、以及退化的空串 */
    if (!pattern[0] || strlen(pattern) > 512) return -1;
    if (strchr(pattern, ',') || strchr(pattern, '\n') || strchr(pattern, '\r')) return -1;

    /* regcomp 语法校验（POSIX ERE，与引擎一致） */
    regex_t re;
    if (regcomp(&re, pattern, REG_EXTENDED | REG_ICASE) != 0) return -1;
    regfree(&re);

    const char *path = config->guard.learned_rules_path;

    /* 读入现有内容（含去重与计数） */
    static char existing[262144];
    size_t used = 0;
    existing[0] = '\0';
    int cnt = 0;
    FILE *fp = fopen(path, "r");
    if (fp) {
        char line[1024];
        while (fgets(line, sizeof(line), fp)) {
            size_t ll = strlen(line);
            if (used + ll < sizeof(existing) - 1) {
                memcpy(existing + used, line, ll);
                used += ll;
                existing[used] = '\0';
            }
            /* 去重：同 pattern 已存在则跳过 */
            if (strncmp(line, AI_RULE_TYPE_STR ",", strlen(AI_RULE_TYPE_STR) + 1) == 0) {
                char *p1 = strchr(line, ',');
                char *p2 = p1 ? strchr(p1 + 1, ',') : NULL;
                if (p1 && p2 && (size_t)(p2 - p1 - 1) == strlen(pattern) &&
                    strncmp(p1 + 1, pattern, strlen(pattern)) == 0) {
                    fclose(fp);
                    return -1;
                }
                if (p2) cnt++;
            }
        }
        fclose(fp);
    }
    if (cnt >= config->guard.max_rules) return -1;

    char newline[1200];
    int nl = snprintf(newline, sizeof(newline), "%s,%s,5,block,AI-LEARNED confidence=%d%%\n",
                      AI_RULE_TYPE_STR, pattern, confidence);

    /* 原子落盘：.bak 备份 → 临时文件 → rename 覆盖 */
    char bak[600], tmp[600];
    snprintf(bak, sizeof(bak), "%s.bak", path);
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *bf = fopen(bak, "w");
    if (bf) { if (used) fwrite(existing, 1, used, bf); fclose(bf); }

    FILE *tf = fopen(tmp, "w");
    if (!tf) return -1;
    if (used) fwrite(existing, 1, used, tf);
    fwrite(newline, 1, (size_t)nl, tf);
    fflush(tf);
    fclose(tf);
    if (rename(tmp, path) != 0) { remove(tmp); return -1; }
    return 0;
}

/* ============================================================
 * 从日志训练（保留兼容：把攻击日志当黑样本、访问日志当白样本）
 * ============================================================ */

int ai_train_from_logs(ai_config_t *config, const char *log_dir) {
    if (!config || !log_dir) return -1;
    char path[512];
    char line[2048];
    int trained = 0;
    http_request_t fake;

    snprintf(path, sizeof(path), "%s/waf-attack.log", log_dir);
    FILE *fp = fopen(path, "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            char *p = strstr(line, "Path: ");
            if (p) {
                p += 6;
                char *e = strchr(p, '\n'); if (e) *e = '\0';
                memset(&fake, 0, sizeof(fake));
                strncpy(fake.url, p, sizeof(fake.url) - 1);
                strncpy(fake.path, p, sizeof(fake.path) - 1);
                char *q = strstr(line, "Query: ");
                if (q) { q += 7; char *qe = strchr(q, '\n'); if (qe) *qe = '\0';
                         strncpy(fake.query, q, sizeof(fake.query) - 1); }
                double f[MAX_FEATURES]; int fc = 0;
                if (ai_extract_features(&fake, f, &fc) == 0) { ai_add_sample(config, f, fc, 1); trained++; }
            }
        }
        fclose(fp);
    }

    snprintf(path, sizeof(path), "%s/waf-access.log", log_dir);
    fp = fopen(path, "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            char *sp = strchr(line, ' ');
            if (!sp) continue;
            char *method = line;
            char *url = sp + 1;
            char *http = strstr(url, " HTTP/");
            if (!http) continue;
            *http = '\0';
            memset(&fake, 0, sizeof(fake));
            size_t mlen = (size_t)(sp - line);
            if (mlen >= sizeof(fake.method)) mlen = sizeof(fake.method) - 1;
            memcpy(fake.method, method, mlen);
            strncpy(fake.url, url, sizeof(fake.url) - 1);
            strncpy(fake.path, url, sizeof(fake.path) - 1);
            double f[MAX_FEATURES]; int fc = 0;
            if (ai_extract_features(&fake, f, &fc) == 0) { ai_add_sample(config, f, fc, 0); trained++; }
        }
        fclose(fp);
    }

    if (trained > 0) ai_train_model(config);
    waf_log(LOG_LEVEL_INFO, "AI trained from logs: %d samples", trained);
    return trained;
}

int ai_get_model_status(ai_config_t *config, ai_model_status_t *status) {
    if (!config || !status) return -1;
    pthread_mutex_lock(&config->mutex);
    memset(status, 0, sizeof(ai_model_status_t));
    if (config->model_count > 0) {
        strncpy(status->model_type, ai_model_type_str(config->models[0].type), sizeof(status->model_type) - 1);
        status->trained = config->models[0].trained;
        status->sample_count = config->sample_count;
        status->threshold = config->models[0].threshold;
        status->detection_count = config->detection_count;
        status->auto_learning_enabled = config->auto_learning;
        for (int i = 0; i < MAX_FEATURES; i++)
            if (config->models[0].std[i] != 0.0) status->feature_count++;
    }
    pthread_mutex_unlock(&config->mutex);
    return 0;
}

int ai_get_ensemble_status(ai_config_t *config, ai_ensemble_status_t *status) {
    if (!config || !status) return -1;
    pthread_mutex_lock(&config->mutex);
    memset(status, 0, sizeof(ai_ensemble_status_t));
    strncpy(status->ensemble_type, ai_ensemble_type_str(config->ensemble_type),
            sizeof(status->ensemble_type) - 1);
    status->model_count = config->model_count;
    status->ensemble_threshold = config->ensemble_threshold;
    for (int i = 0; i < config->model_count && i < MAX_MODELS; i++) {
        strncpy(status->model_type[i], ai_model_type_str(config->models[i].type), 31);
        status->trained[i] = config->models[i].trained;
    }
    pthread_mutex_unlock(&config->mutex);
    return 0;
}

/* ============================================================
 * v3.0 双通道融合（char-CNN 监督 + autoencoder 自监督）
 * ============================================================ */

#define AI_FUSION_MAGIC   "WAFU"
#define AI_FUSION_VERSION 1

/* 在 model_path 同目录加载 ai_cnn.dat / ai_ae.dat / ai_fusion.dat */
int ai_fusion_load(ai_config_t *config) {
    if (!config) return -1;
    config->fusion_ready = 0;
    config->cnn_model = NULL;
    config->ae_model = NULL;

    char dir[512];
    snprintf(dir, sizeof(dir), "%s", config->model_path);
    char *slash = strrchr(dir, '/');
    if (slash) *slash = '\0';
    else snprintf(dir, sizeof(dir), ".");

    char p_cnn[600], p_ae[600], p_fu[600];
    snprintf(p_cnn, sizeof(p_cnn), "%s/ai_cnn.dat", dir);
    snprintf(p_ae,  sizeof(p_ae),  "%s/ai_ae.dat", dir);
    snprintf(p_fu,  sizeof(p_fu),  "%s/ai_fusion.dat", dir);

    ai_cnn_t *cnn = ai_cnn_load(p_cnn);
    if (!cnn || !ai_cnn_is_trained(cnn)) {
        if (cnn) ai_cnn_destroy(cnn);
        waf_log(LOG_LEVEL_INFO, "AI fusion: no trained char-CNN model (%s); AI inert", p_cnn);
        return -1;
    }

    /* AE 缺失/未训练 → 单通道 CNN（w_ae=0），不算致命 */
    ai_ae_t *ae = ai_ae_load(p_ae);
    int have_ae = (ae && ai_ae_is_trained(ae));
    if (ae && !have_ae) { ai_ae_destroy(ae); ae = NULL; }

    FILE *fp = fopen(p_fu, "rb");
    if (!fp) {
        ai_cnn_destroy(cnn);
        if (ae) ai_ae_destroy(ae);
        waf_log(LOG_LEVEL_INFO, "AI fusion: no calibration file (%s); AI inert", p_fu);
        return -1;
    }
    char magic[4];
    uint32_t ver;
    double w_cnn = 1.0, w_ae = 0.0, thr = 0.98;
    if (fread(magic, 1, 4, fp) != 4 || memcmp(magic, AI_FUSION_MAGIC, 4) != 0 ||
        fread(&ver, sizeof(uint32_t), 1, fp) != 1 || ver != AI_FUSION_VERSION ||
        fread(&w_cnn, sizeof(double), 1, fp) != 1 ||
        fread(&w_ae, sizeof(double), 1, fp) != 1 ||
        fread(&thr, sizeof(double), 1, fp) != 1) {
        fclose(fp);
        ai_cnn_destroy(cnn);
        if (ae) ai_ae_destroy(ae);
        return -1;
    }
    fclose(fp);

    if (!have_ae) w_ae = 0.0;
    config->cnn_model = cnn;
    config->ae_model = ae;
    config->fusion_w_cnn = w_cnn;
    config->fusion_w_ae = w_ae;
    config->fusion_threshold = thr;
    config->fusion_ready = 1;
    waf_log(LOG_LEVEL_INFO, "AI fusion loaded: cnn=1 ae=%d w_cnn=%.3f w_ae=%.3f thr=%.4f",
            have_ae, w_cnn, w_ae, thr);
    return 0;
}

double ai_fusion_score(ai_config_t *config, http_request_t *req,
                       double *pcnn, double *pae) {
    if (!config || !req || !config->fusion_ready) return 0.0;
    double c = ai_cnn_score((const ai_cnn_t *)config->cnn_model, req);
    double a = config->ae_model
               ? ai_ae_score((const ai_ae_t *)config->ae_model, req) : 0.0;
    if (pcnn) *pcnn = c;
    if (pae) *pae = a;
    double f = config->fusion_w_cnn * c + config->fusion_w_ae * a;
    return f > 1.0 ? 1.0 : f;
}

/* ---- 离线校准 ---- */

typedef struct { double fs; int label; } fusion_pt_t;

static int fusion_pt_cmp(const void *a, const void *b) {
    double d = ((const fusion_pt_t *)a)->fs - ((const fusion_pt_t *)b)->fs;
    return d < 0 ? -1 : (d > 0 ? 1 : 0);
}

int ai_calibrate_fusion(ai_config_t *config, const char *black_list,
                        const char *white_list, const char *out_path) {
    if (!config || !black_list || !white_list || !out_path) return -1;
    if (!config->cnn_model) {
        waf_log(LOG_LEVEL_ERROR, "Calibrate: no CNN model in memory (train or load first)");
        return -1;
    }

    long cap = 40000;
    double *cs = malloc(sizeof(double) * cap);
    double *as = malloc(sizeof(double) * cap);
    int *lb = malloc(sizeof(int) * cap);
    if (!cs || !as || !lb) { free(cs); free(as); free(lb); return -1; }

    /* 语料逐样本算双通道分数 */
    static char raw[MAX_REQUEST_SIZE];
    char line[1024];
    long nb = 0, nw = 0;
    for (int pass = 0; pass < 2; pass++) {
        const char *list = pass == 0 ? black_list : white_list;
        int label = pass == 0 ? 1 : 0;
        FILE *fp = fopen(list, "r");
        if (!fp) { free(cs); free(as); free(lb); return -1; }
        while (fgets(line, sizeof(line), fp) && (nb + nw) < cap) {
            size_t ll = strlen(line);
            while (ll > 0 && (line[ll-1] == '\n' || line[ll-1] == '\r')) line[--ll] = '\0';
            if (ll == 0) continue;
            FILE *rf = fopen(line, "rb");
            if (!rf) continue;
            size_t rd = fread(raw, 1, sizeof(raw) - 1, rf);
            fclose(rf);
            raw[rd] = '\0';
            http_request_t rq;
            memset(&rq, 0, sizeof(rq));
            if (http_parse_request(raw, rd, &rq) != 0) continue;
            long i = nb + nw;
            cs[i] = ai_cnn_score((const ai_cnn_t *)config->cnn_model, &rq);
            as[i] = config->ae_model
                    ? ai_ae_score((const ai_ae_t *)config->ae_model, &rq) : 0.0;
            lb[i] = label;
            if (label) nb++; else nw++;
            if (((nb + nw) % 5000) == 0) { printf("  scoring %ld...\r", nb + nw); fflush(stdout); }
        }
        fclose(fp);
    }
    long n = nb + nw;
    printf("Calibrate corpus: black=%ld white=%ld\n", nb, nw);
    if (nb == 0 || nw == 0) { free(cs); free(as); free(lb); return -1; }

    /* 权重网格 × 排序扫阈值；目标 err = FN + 3×FP（FP 罚项），
     * 阈值下限 = 白样本融合分 99.9% 分位（限制 FP 上限 ~0.1%） */
    double best_err = 1e18, best_wc = 1.0, best_wa = 0.0, best_thr = 0.98;
    long best_fn = nb, best_fp = 0;
    fusion_pt_t *pts = malloc(sizeof(fusion_pt_t) * n);
    if (!pts) { free(cs); free(as); free(lb); return -1; }

    for (int wi = 10; wi >= 5; wi--) {
        double wc = wi / 10.0;
        for (int wj = 0; wj <= 10; wj++) {
            double wa = wj / 20.0;   /* 0 .. 0.5 */
            for (long i = 0; i < n; i++) {
                pts[i].fs = wc * cs[i] + wa * as[i];
                pts[i].label = lb[i];
            }
            qsort(pts, n, sizeof(fusion_pt_t), fusion_pt_cmp);
            /* 白样本 99.9% 分位 */
            long white_seen = 0, pos = 0;
            double thr_floor = 1.1;
            for (long i = 0; i < n; i++) {
                if (pts[i].label == 0) white_seen++;
                if (white_seen >= (long)((double)nw * 0.999)) { thr_floor = pts[i].fs; break; }
            }
            /* 从低到高扫描；t 取每个唯一分数点，判定规则 fs >= t → 拦截。
             * 双指针维护 below 计数：FN=black_below, FP=nw-white_below（O(n)）。 */
            long black_below = 0, white_below = 0;
            long i = 0;
            while (i < n) {
                long j = i;
                while (j < n && pts[j].fs == pts[i].fs) j++;
                double t = pts[i].fs;
                if (t >= thr_floor && t > 0.0) {
                    long fn = black_below;
                    long fp = nw - white_below;
                    double err = (double)fn + 3.0 * (double)fp;
                    if (err < best_err) {
                        best_err = err;
                        best_wc = wc; best_wa = wa; best_thr = t;
                        best_fn = fn; best_fp = fp;
                    }
                }
                for (long k = i; k < j; k++) {
                    if (pts[k].label == 1) black_below++; else white_below++;
                }
                i = j;
            }
            (void)pos;
        }
    }

    waf_log(LOG_LEVEL_INFO, "Fusion calibrated: w_cnn=%.2f w_ae=%.2f thr=%.4f FN=%ld FP=%ld (penalized err=%.0f)",
            best_wc, best_wa, best_thr, best_fn, best_fp, best_err);
    printf("Calibrated: w_cnn=%.2f w_ae=%.2f thr=%.4f\n", best_wc, best_wa, best_thr);
    printf("  corpus FN=%ld FP=%ld (total err=%ld, penalized=%.0f)\n",
           best_fn, best_fp, best_fn + best_fp, best_err);

    /* 更新内存配置并写盘 */
    config->fusion_w_cnn = best_wc;
    config->fusion_w_ae = best_wa;
    config->fusion_threshold = best_thr;

    FILE *fp = fopen(out_path, "wb");
    if (!fp) { free(pts); free(cs); free(as); free(lb); return -1; }
    char magic[4] = AI_FUSION_MAGIC;
    uint32_t ver = AI_FUSION_VERSION;
    int ok = fwrite(magic, 1, 4, fp) == 4 &&
             fwrite(&ver, sizeof(uint32_t), 1, fp) == 1 &&
             fwrite(&best_wc, sizeof(double), 1, fp) == 1 &&
             fwrite(&best_wa, sizeof(double), 1, fp) == 1 &&
             fwrite(&best_thr, sizeof(double), 1, fp) == 1;
    fclose(fp);
    free(pts); free(cs); free(as); free(lb);
    return ok ? 0 : -1;
}
