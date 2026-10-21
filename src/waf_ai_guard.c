#define _GNU_SOURCE
#include "../include/waf_ai_guard.h"
#include "../include/waf_log.h"
#include "../include/waf_http.h"
#include "../include/waf_rules.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <regex.h>
#include <pthread.h>
#include <unistd.h>

#define GUARD_MAX_CANDIDATES 4096
#define GUARD_FRAG_MAX 128

/* 日志路径按 WAF_HOME（缺省取 cwd）解析，避免硬编码——保证 demo 实例与生产隔离 */
static char g_shadow_log[600] = {0};
static char g_audit_log[600] = {0};
static void guard_paths(void) {
    if (g_shadow_log[0]) return;
    char base[512];
    const char *home = getenv("WAF_HOME");
    if (home && home[0]) {
        snprintf(base, sizeof(base), "%s", home);
    } else if (!getcwd(base, sizeof(base))) {
        snprintf(base, sizeof(base), ".");
    }
    snprintf(g_shadow_log, sizeof(g_shadow_log), "%s/logs/ai-shadow.log", base);
    snprintf(g_audit_log, sizeof(g_audit_log), "%s/logs/ai-learn-audit.log", base);
}

typedef struct {
    char frag[GUARD_FRAG_MAX];   /* 已转义的 ERE 片段（聚类键） */
    char literal[GUARD_FRAG_MAX];/* 原始可读片段（用于日志） */
    int count;
    int best_conf;               /* 最高置信度百分比 */
    time_t first_seen;
    int promoted;                /* 已铸成规则 */
} guard_cand_t;

static guard_cand_t g_cands[GUARD_MAX_CANDIDATES];
static int g_cand_count = 0;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
/* tick 串行锁：多个工作线程并发进入铸造流程会导致重复铸规则、写入交错，
 * 并共用 ai_guard_white_eval 内的 static 缓冲。铸造本身极低频，串行无碍。 */
static pthread_mutex_t g_tick_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile int g_tick_running = 0;
/* 后台铸造线程 */
static pthread_t g_worker;
static volatile int g_worker_run = 0;
static ai_config_t *g_worker_cfg = NULL;
static void *guard_worker_main(void *arg);
static unsigned long g_minted = 0;
static unsigned long g_rejected = 0;
static unsigned long g_events = 0;
static time_t g_last_tick = 0;

/* 强攻击关键词（用于从高分未拦截事件中定位可疑片段） */
static const char *g_needles[] = {
    "union select", "information_schema", "or 1=1", "and 1=1", "sleep(", "benchmark(",
    "waitfor", "pg_sleep", "char(", "0x", "<script", "javascript:", "onerror=", "srcdoc=",
    "document.cookie", "${jndi:", "exec(", "system(", "whoami", "/etc/passwd", "/etc/shadow",
    "../", "..\\", "php://", "expect:", "<!entity", "cmd.exe", "powershell", "nslookup",
    "%00", "eval(", "assert(", "passthru(",
    NULL
};

static void guard_ere_escape(const char *in, char *out, size_t outsz) {
    static const char *meta = ".^$*+?()[]{}|\\";
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 2 < outsz; i++) {
        if (strchr(meta, in[i])) out[j++] = '\\';
        out[j++] = in[i];
    }
    out[j] = '\0';
}

/* 从载荷中提取可疑片段：命中强关键词后取其邻域，去噪、转义 */
static int guard_extract(const char *payload, char out[][GUARD_FRAG_MAX],
                         char lit[][GUARD_FRAG_MAX], int max_out) {
    if (!payload || !payload[0]) return 0;
    int n = 0;
    for (int k = 0; g_needles[k] && n < max_out; k++) {
        const char *hit = strcasestr(payload, g_needles[k]);
        if (!hit) continue;

        char buf[GUARD_FRAG_MAX];
        size_t cap = strlen(g_needles[k]) + 16;
        if (cap > 40) cap = 40;
        if (cap > strlen(hit)) cap = strlen(hit);
        if (cap >= sizeof(buf)) cap = sizeof(buf) - 1;
        memcpy(buf, hit, cap);
        buf[cap] = '\0';

        /* 去噪：截断尾部的引号/尖括号/分号及空白 */
        size_t L = strlen(buf);
        while (L > 0 && (buf[L-1] == '"' || buf[L-1] == '\'' || buf[L-1] == '>' ||
                         buf[L-1] == '<' || buf[L-1] == ';' || buf[L-1] == ' ' ||
                         buf[L-1] == '\t')) {
            buf[--L] = '\0';
        }
        if (L < 6) continue;                     /* 片段过短 → 泛化风险高，丢弃 */
        if (strchr(buf, ',')) continue;          /* 逗号会截断规则行，丢弃 */

        /* 去重输出 */
        int dup = 0;
        for (int i = 0; i < n; i++)
            if (strncmp(lit[i], buf, GUARD_FRAG_MAX) == 0) { dup = 1; break; }
        if (dup) continue;

        strncpy(lit[n], buf, GUARD_FRAG_MAX - 1);
        lit[n][GUARD_FRAG_MAX - 1] = '\0';
        guard_ere_escape(buf, out[n], GUARD_FRAG_MAX);
        n++;
    }
    return n;
}

static guard_cand_t *guard_cand_find_or_add(const char *frag) {
    for (int i = 0; i < g_cand_count; i++)
        if (strcmp(g_cands[i].frag, frag) == 0) return &g_cands[i];
    if (g_cand_count >= GUARD_MAX_CANDIDATES) return NULL;
    guard_cand_t *c = &g_cands[g_cand_count++];
    memset(c, 0, sizeof(*c));
    strncpy(c->frag, frag, GUARD_FRAG_MAX - 1);
    c->first_seen = time(NULL);
    return c;
}

int ai_guard_init(ai_config_t *config) {
    pthread_mutex_lock(&g_lock);
    memset(g_cands, 0, sizeof(g_cands));
    g_cand_count = 0;
    g_minted = g_rejected = g_events = 0;
    g_last_tick = time(NULL);
    pthread_mutex_unlock(&g_lock);
    waf_log(LOG_LEVEL_INFO, "AI guard initialized");

    /* 后台维护线程：铸造(含白样本全量评估)在独立线程执行，避免占用请求线程。
     * 实测：候选累积后单次 tick 可阻塞发起它的请求数秒至数十秒。 */
    if (!g_worker_run && config) {
        g_worker_cfg = config;
        g_worker_run = 1;
        if (pthread_create(&g_worker, NULL, guard_worker_main, NULL) == 0)
            pthread_detach(g_worker);
        else
            g_worker_run = 0;
    }
    return 0;
}

static void guard_log_line(const char *path, const char *line) {
    guard_paths();
    FILE *fp = fopen(path, "a");
    if (!fp) return;
    fputs(line, fp);
    fputc('\n', fp);
    fclose(fp);
}

int ai_guard_shadow(ai_config_t *config, http_request_t *req, int rules_blocked) {
    if (!config || !req) return 0;
    if (!config->enabled) return 0;

    /* v3.0：影子打分使用 CNN+AE 双通道融合；无融合模型则不产生影子数据 */
    if (!config->fusion_ready) return 0;

    double cnn_sc = 0.0, ae_sc = 0.0;
    double blended = ai_fusion_score(config, req, &cnn_sc, &ae_sc);
    int conf = (int)(blended * 100.0 + 0.5);

    pthread_mutex_lock(&config->mutex);
    config->shadow_total++;
    if (blended >= config->fusion_threshold) config->shadow_hits++;
    unsigned long total = config->shadow_total, hits = config->shadow_hits;
    pthread_mutex_unlock(&config->mutex);

    /* 高置信度未拦截事件 → 候选 */
    if (config->guard.enabled && !rules_blocked && conf >= config->guard.min_confidence_pct) {
        char frags[12][GUARD_FRAG_MAX], lits[12][GUARD_FRAG_MAX];
        int n = 0;
        n += guard_extract(req->url, frags + n, lits + n, 3);
        n += guard_extract(req->query, frags + n, lits + n, 3);
        n += guard_extract(req->body, frags + n, lits + n, 4);
        if (n > 0) {
            pthread_mutex_lock(&g_lock);
            for (int i = 0; i < n; i++) {
                guard_cand_t *c = guard_cand_find_or_add(frags[i]);
                if (!c) continue;
                c->count++;
                if (conf > c->best_conf) {
                    c->best_conf = conf;
                    strncpy(c->literal, lits[i], GUARD_FRAG_MAX - 1);
                }
            }
            pthread_mutex_unlock(&g_lock);
        }
    }

    /* 影子日志（节流：每 200 条或命中时记录，避免日志爆炸）；
     * v3.0 追加 cnn/ae 通道分（百分制），保持既有字段前缀兼容 */
    if (blended >= config->fusion_threshold || (total % 200) == 0) {
        char line[1400];
        time_t now = time(NULL);
        struct tm tmv;
        localtime_r(&now, &tmv);
        snprintf(line, sizeof(line),
                 "{\"t\":\"%04d-%02d-%02d %02d:%02d:%02d\",\"ip\":\"%s\",\"m\":\"%s\","
                 "\"u\":\"%.300s\",\"score\":%d,\"cnn\":%d,\"ae\":%d,\"verdict\":\"%s\",\"rules_blocked\":%d,"
                 "\"total\":%lu,\"hits\":%lu}",
                 tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
                 tmv.tm_hour, tmv.tm_min, tmv.tm_sec,
                 req->client_ip, req->method, req->url, conf,
                 (int)(cnn_sc * 100.0 + 0.5), (int)(ae_sc * 100.0 + 0.5),
                 blended >= config->fusion_threshold ? "MALICIOUS" : "NORMAL",
                 rules_blocked, total, hits);
        guard_log_line(g_shadow_log, line);
    }

    return conf;
}

int ai_guard_white_eval(const char *pattern, const char *white_list_path, int sample_limit) {
    if (!pattern || !white_list_path) return -1;

    regex_t re;
    if (regcomp(&re, pattern, REG_EXTENDED | REG_ICASE) != 0) return -1;

    FILE *fp = fopen(white_list_path, "r");
    if (!fp) { regfree(&re); return -1; }

    int hits = 0;
    int checked = 0;
    char line[1024];
    static char raw[MAX_REQUEST_SIZE];

    while (fgets(line, sizeof(line), fp) && (sample_limit <= 0 || checked < sample_limit)) {
        size_t ll = strlen(line);
        while (ll > 0 && (line[ll-1] == '\n' || line[ll-1] == '\r')) line[--ll] = '\0';
        if (ll == 0) continue;

        FILE *rf = fopen(line, "rb");
        if (!rf) continue;
        size_t rd = fread(raw, 1, sizeof(raw) - 1, rf);
        fclose(rf);
        raw[rd] = '\0';
        checked++;

        http_request_t rq;
        memset(&rq, 0, sizeof(rq));
        if (http_parse_request(raw, rd, &rq) != 0) continue;

        /* 引擎按参数值分别扫描：这里对 url/query/body 分别判定，任一命中即计为命中 */
        int matched = 0;
        if (rq.url[0] && regexec(&re, rq.url, 0, NULL, 0) == 0) matched = 1;
        if (!matched && rq.query[0] && regexec(&re, rq.query, 0, NULL, 0) == 0) matched = 1;
        if (!matched && rq.body[0] && regexec(&re, rq.body, 0, NULL, 0) == 0) matched = 1;
        if (matched) {
            hits++;
            if (hits > 5) break; /* 早停：已验证为不安全 */
        }
    }
    fclose(fp);
    regfree(&re);
    return hits;
}

static int guard_write_audit(const char *path, const char *pattern, const char *literal,
                             int conf, int white_fp, const char *action) {
    char line[1400];
    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv);
    snprintf(line, sizeof(line),
             "{\"t\":\"%04d-%02d-%02d %02d:%02d:%02d\",\"pattern\":\"%s\",\"literal\":\"%s\","
             "\"confidence\":%d,\"white_fp\":%d,\"action\":\"%s\"}",
             tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
             tmv.tm_hour, tmv.tm_min, tmv.tm_sec,
             pattern, literal, conf, white_fp, action);
    guard_log_line(path, line);
    return 0;
}

/* 后台铸造线程主体：每 2s 唤醒一次（ai_guard_tick 内部另有 5s 节流） */
static void *guard_worker_main(void *arg) {
    (void)arg;
    while (g_worker_run) {
        struct timespec ts = {2, 0};
        nanosleep(&ts, NULL);
        if (g_worker_cfg) ai_guard_tick(g_worker_cfg);
    }
    return NULL;
}

int ai_guard_tick(ai_config_t *config) {
    if (!config || !config->guard.enabled) return 0;
    if (config->model_count <= 0) return 0;
    /* 已在铸造中：立即返回，绝不让请求线程阻塞在一次长维护任务上
     * （白样本全量评估可能耗时较久）。 */
    if (g_tick_running) return 0;

    time_t now = time(NULL);
    if (config->guard.min_occurrences > 0 && now - g_last_tick < 5) return 0;

    pthread_mutex_lock(&g_tick_lock);
    if (g_tick_running || (config->guard.min_occurrences > 0 && now - g_last_tick < 5)) {
        pthread_mutex_unlock(&g_tick_lock);
        return 0;
    }
    g_tick_running = 1;
    g_last_tick = now;
    int minted = 0;

    /* 候选快照在 g_lock 下取得；白样本全量评估等重活放在锁外，
     * 避免阻塞请求线程的 ai_guard_shadow（其也需 g_lock 记录候选）。 */
    int snap;
    pthread_mutex_lock(&g_lock);
    snap = g_cand_count;
    pthread_mutex_unlock(&g_lock);

    for (int i = 0; i < snap && i < GUARD_MAX_CANDIDATES; i++) {
        char frag[GUARD_FRAG_MAX], lit[GUARD_FRAG_MAX];
        int conf;

        pthread_mutex_lock(&g_lock);
        guard_cand_t *c = &g_cands[i];
        if (c->promoted || c->count < config->guard.min_occurrences ||
            c->best_conf < config->guard.min_confidence_pct) {
            pthread_mutex_unlock(&g_lock);
            continue;
        }
        strncpy(frag, c->frag, GUARD_FRAG_MAX - 1); frag[GUARD_FRAG_MAX-1] = '\0';
        strncpy(lit, c->literal[0] ? c->literal : c->frag, GUARD_FRAG_MAX - 1);
        lit[GUARD_FRAG_MAX-1] = '\0';
        conf = c->best_conf;
        c->promoted = 1;   /* 先标记：本轮不再重复评估同一候选 */
        pthread_mutex_unlock(&g_lock);

        /* 护栏 1：白样本影子评估（新增误报不得超过上限；0 表示评估全量样本） */
        int fp = ai_guard_white_eval(frag, config->guard.white_list_path,
                                     config->guard.white_sample_size);
        if (fp < 0) fp = 1 << 20; /* 无法评估 → 视为不安全 */
        if (fp > config->guard.max_white_fp) {
            g_rejected++;
            guard_write_audit(g_audit_log, frag, lit, conf, fp, "REJECTED_WHITE_FP");
            continue;
        }

        /* 护栏 2：消毒 + regcomp + 去重 + 上限（在 ai_adapt_rules 内完成） */
        if (ai_adapt_rules(config, frag, conf) != 0) {
            g_rejected++;
            guard_write_audit(g_audit_log, frag, lit, conf, fp, "REJECTED_DUP_OR_LIMIT");
            continue;
        }

        /* 护栏 3：热加载（失败则回滚） */
        if (rules_reload() != 0) {
            ai_guard_rollback(config);
            guard_write_audit(g_audit_log, frag, lit, conf, fp, "RELOAD_FAILED_ROLLBACK");
        } else {
            minted++;
            g_minted++;
            guard_write_audit(g_audit_log, frag, lit, conf, fp, "PROMOTED");
        }
    }
    g_last_tick = now;
    g_tick_running = 0;
    pthread_mutex_unlock(&g_tick_lock);

    if (minted > 0)
        waf_log(LOG_LEVEL_INFO, "AI guard promoted %d rule(s) into %s",
                minted, config->guard.learned_rules_path);
    return minted;
}

int ai_guard_rollback(ai_config_t *config) {
    if (!config) return -1;
    char bak[600];
    snprintf(bak, sizeof(bak), "%s.bak", config->guard.learned_rules_path);
    if (access(bak, F_OK) != 0) return -1;
    if (rename(bak, config->guard.learned_rules_path) != 0) return -1;
    rules_reload();
    guard_write_audit(g_audit_log, "-", "-", 0, 0, "ROLLBACK");
    waf_log(LOG_LEVEL_WARN, "AI learned rules rolled back to previous snapshot");
    return 0;
}

void ai_guard_stats(ai_config_t *config, unsigned long *total, unsigned long *hits,
                    unsigned long *minted, unsigned long *rejected) {
    if (config) {
        pthread_mutex_lock(&config->mutex);
        if (total) *total = config->shadow_total;
        if (hits) *hits = config->shadow_hits;
        pthread_mutex_unlock(&config->mutex);
    }
    if (minted) *minted = g_minted;
    if (rejected) *rejected = g_rejected;
    (void)g_events;
}
