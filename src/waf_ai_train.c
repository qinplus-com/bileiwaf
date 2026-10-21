#define _GNU_SOURCE
#include "../include/waf.h"
#include "../include/waf_ai.h"
#include "../include/waf_log.h"
#include "../include/waf_http.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

/*
 * C 内置离线蒸馏训练器
 *
 * 语料：blazehttp 原始 HTTP 请求文件清单（每行一个路径）
 *   black_list → 标注为恶意（监督标签来自规则引擎的拦截判定，即"规则蒸馏"）
 *   white_list → 标注为良性
 *
 * 模型：64 维定长特征的逻辑回归（标准化 + 类别频率反比加权），
 *       与在线学习共用 ai_fit_logistic()，权重落在 models[0]。
 *
 * 校准：在语料上扫描阈值，最小化 (FN+FP)，写入 model->threshold 与 ensemble_threshold。
 * 自包含、无外部依赖，产物格式为 ai_save_ensemble() 的 .index/.0/.1...
 */

typedef struct {
    ai_sample_t *v;
    long n;
    long cap;
} sample_vec;

static int vec_push(sample_vec *sv, const ai_sample_t *s) {
    if (sv->n >= sv->cap) {
        long ncap = sv->cap ? sv->cap * 2 : 4096;
        ai_sample_t *nv = realloc(sv->v, (size_t)ncap * sizeof(ai_sample_t));
        if (!nv) return -1;
        sv->v = nv;
        sv->cap = ncap;
    }
    sv->v[sv->n++] = *s;
    return 0;
}

static long load_list(sample_vec *sv, const char *list_path, int label, long limit,
                      long *parse_fail, long *total) {
    FILE *fp = fopen(list_path, "r");
    if (!fp) return -1;

    static char raw[MAX_REQUEST_SIZE];
    char line[1024];
    long loaded = 0, fail = 0, seen = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (limit > 0 && loaded >= limit) break;
        size_t ll = strlen(line);
        while (ll > 0 && (line[ll-1] == '\n' || line[ll-1] == '\r')) line[--ll] = '\0';
        if (ll == 0) continue;

        FILE *rf = fopen(line, "rb");
        if (!rf) { fail++; continue; }
        size_t rd = fread(raw, 1, sizeof(raw) - 1, rf);
        fclose(rf);
        raw[rd] = '\0';
        seen++;

        http_request_t rq;
        memset(&rq, 0, sizeof(rq));
        if (http_parse_request(raw, rd, &rq) != 0) { fail++; continue; }

        ai_sample_t s;
        memset(&s, 0, sizeof(s));
        int fc = 0;
        if (ai_extract_features(&rq, s.features, &fc) != 0) { fail++; continue; }
        s.feature_count = fc;
        s.is_malicious = label;
        if (vec_push(sv, &s) != 0) break;
        loaded++;
    }
    fclose(fp);
    if (parse_fail) *parse_fail += fail;
    if (total) *total += seen;
    return loaded;
}

/* 直接按模型参数打分（标准化空间），供校准/评估使用 */
static double score_of(const ai_model_t *m, const double *x) {
    double z = m->bias;
    for (int j = 0; j < AI_FEAT_DIM; j++) {
        double sd = m->std[j];
        if (sd < 1e-9) sd = 1.0;
        z += m->weights[j] * ((x[j] - m->mean[j]) / sd);
    }
    if (z > 60.0) z = 60.0;
    if (z < -60.0) z = -60.0;
    return 1.0 / (1.0 + exp(-z));
}

int ai_distill_train(ai_config_t *config,
                     const char *black_list, const char *white_list,
                     const char *out_base_path,
                     const ai_guard_config_t *guard,
                     int epochs, double lr,
                     ai_train_report_t *report) {
    if (!config || !black_list || !white_list) return -1;
    if (epochs <= 0) epochs = 400;
    if (lr <= 0) lr = 0.5;

    ai_train_report_t rep;
    memset(&rep, 0, sizeof(rep));
    rep.epochs = epochs;

    sample_vec sv;
    memset(&sv, 0, sizeof(sv));

    long pf = 0, tot = 0;
    long nb = load_list(&sv, black_list, 1, -1, &pf, &tot);
    rep.black_files = tot;
    rep.black_sampled = nb < 0 ? 0 : nb;

    long pf2 = 0, tot2 = 0;
    long nw = load_list(&sv, white_list, 0, -1, &pf2, &tot2);
    rep.white_files = tot2;
    rep.white_sampled = nw < 0 ? 0 : nw;
    rep.parse_fail = pf + pf2;

    if (report) *report = rep;
    if (sv.n < 20 || rep.black_sampled == 0 || rep.white_sampled == 0) {
        free(sv.v);
        waf_log(LOG_LEVEL_ERROR, "Distill: insufficient corpus (black=%ld white=%ld)",
                rep.black_sampled, rep.white_sampled);
        return -1;
    }

    ai_model_t *model = &config->models[0];
    if (ai_fit_logistic(model, sv.v, (int)sv.n, epochs, lr) != 0) {
        free(sv.v);
        waf_log(LOG_LEVEL_ERROR, "Distill: logistic fit failed");
        return -1;
    }

    /* 阈值校准：最小化 FN+FP */
    double best_t = 0.5;
    long best_err = -1;
    for (int ti = 2; ti <= 98; ti++) {
        double t = ti / 100.0;
        long fn = 0, fp = 0;
        for (long i = 0; i < sv.n; i++) {
            double sc = score_of(model, sv.v[i].features);
            if (sv.v[i].is_malicious) { if (sc < t) fn++; }
            else { if (sc >= t) fp++; }
        }
        long err = fn + fp;
        if (best_err < 0 || err < best_err) { best_err = err; best_t = t; }
    }

    long fn = 0, fp = 0, pos_below = 0, neg_above = 0;
    double pos_sum = 0, neg_sum = 0, pos_min = 1e9, neg_max = -1e9;
    for (long i = 0; i < sv.n; i++) {
        double sc = score_of(model, sv.v[i].features);
        if (sv.v[i].is_malicious) {
            pos_sum += sc;
            if (sc < pos_min) pos_min = sc;
            if (sc < best_t) { fn++; pos_below++; }
        } else {
            neg_sum += sc;
            if (sc > neg_max) neg_max = sc;
            if (sc >= best_t) { fp++; neg_above++; }
        }
    }

    model->threshold = best_t;
    model->type = AI_MODEL_TYPE_RANDOM_FOREST;
    strncpy(model->name, "Distilled_Logistic", sizeof(model->name) - 1);
    model->weight = 1.0;

    /* 其余模型保持未训练：融合只使用蒸馏主模型 */
    for (int i = 1; i < config->model_count; i++) config->models[i].trained = 0;

    config->ensemble_type = AI_ENSEMBLE_BLENDING;
    config->ensemble_threshold = best_t;
    if (guard) config->guard = *guard;

    const char *out = out_base_path ? out_base_path : config->model_path;
    if (ai_save_ensemble(config, out) != 0) {
        free(sv.v);
        waf_log(LOG_LEVEL_ERROR, "Distill: failed to save ensemble to %s", out);
        return -1;
    }

    rep.final_loss = (double)(fn + fp);
    rep.pos_mean = pos_sum / (double)rep.black_sampled;
    rep.neg_mean = neg_sum / (double)rep.white_sampled;
    rep.pos_min = pos_min;
    rep.neg_max = neg_max;
    rep.pos_below_thr = pos_below;
    rep.neg_above_thr = neg_above;
    rep.best_threshold = best_t;
    if (report) *report = rep;

    waf_log(LOG_LEVEL_INFO,
            "Distill done: black=%ld white=%ld thr=%.2f FN=%ld FP=%ld pos_mean=%.3f neg_mean=%.3f",
            rep.black_sampled, rep.white_sampled, best_t, fn, fp, rep.pos_mean, rep.neg_mean);
    free(sv.v);
    return 0;
}

int ai_eval_corpus(ai_config_t *config, const char *black_list, const char *white_list,
                   double threshold, long *fn, long *fp, long *black_total, long *white_total,
                   long sample_limit) {
    if (!config || config->model_count == 0) return -1;
    ai_model_t *model = &config->models[0];
    if (!model->trained) return -1;

    sample_vec sv;
    memset(&sv, 0, sizeof(sv));
    long pf = 0, tot = 0;

    long nb = load_list(&sv, black_list, 1, sample_limit, &pf, &tot);
    long pf2 = 0, tot2 = 0;
    long nw = load_list(&sv, white_list, 0, sample_limit, &pf2, &tot2);

    long n_fn = 0, n_fp = 0;
    for (long i = 0; i < sv.n; i++) {
        double sc = score_of(model, sv.v[i].features);
        if (sv.v[i].is_malicious) { if (sc < threshold) n_fn++; }
        else { if (sc >= threshold) n_fp++; }
    }
    if (fn) *fn = n_fn;
    if (fp) *fp = n_fp;
    if (black_total) *black_total = nb;
    if (white_total) *white_total = nw;

    free(sv.v);
    return 0;
}
