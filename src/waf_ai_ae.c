#define _GNU_SOURCE
#include "../include/waf.h"
#include "../include/waf_ai.h"
#include "../include/waf_ai_ae.h"
#include "../include/waf_log.h"
#include "../include/waf_http.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <stdint.h>

/* 参数布局（连续 float 数组）：
 * w1[H1][IN] b1[H1] | w2[H2][H1] b2[H2] | w3[H1][H2] b3[H1] | w4[IN][H1] b4[IN] */
#define AE_N_W1 (AI_AE_H1 * AI_AE_IN)
#define AE_N_B1 (AI_AE_H1)
#define AE_N_W2 (AI_AE_H2 * AI_AE_H1)
#define AE_N_B2 (AI_AE_H2)
#define AE_N_W3 (AI_AE_H1 * AI_AE_H2)
#define AE_N_B3 (AI_AE_H1)
#define AE_N_W4 (AI_AE_IN * AI_AE_H1)
#define AE_N_B4 (AI_AE_IN)

#define AE_OFF_W1 0
#define AE_OFF_B1 (AE_OFF_W1 + AE_N_W1)
#define AE_OFF_W2 (AE_OFF_B1 + AE_N_B1)
#define AE_OFF_B2 (AE_OFF_W2 + AE_N_W2)
#define AE_OFF_W3 (AE_OFF_B2 + AE_N_B2)
#define AE_OFF_B3 (AE_OFF_W3 + AE_N_W3)
#define AE_OFF_W4 (AE_OFF_B3 + AE_N_B3)
#define AE_OFF_B4 (AE_OFF_W4 + AE_N_W4)
#define AI_AE_NPARAM (AE_OFF_B4 + AE_N_B4)

struct ai_ae {
    float p[AI_AE_NPARAM];
    float err_mean;
    float err_std;
    int trained;
};

/* ---------------- 前向：返回重建误差（MSE），可选写激活 ---------------- */

static float ae_forward_err(const ai_ae_t *m, const double *xd,
                            float *h1o, float *h2o, float *xhat) {
    const float *w1 = m->p + AE_OFF_W1;
    const float *b1 = m->p + AE_OFF_B1;
    const float *w2 = m->p + AE_OFF_W2;
    const float *b2 = m->p + AE_OFF_B2;
    const float *w3 = m->p + AE_OFF_W3;
    const float *b3 = m->p + AE_OFF_B3;
    const float *w4 = m->p + AE_OFF_W4;
    const float *b4 = m->p + AE_OFF_B4;

    float x[AI_AE_IN];
    for (int i = 0; i < AI_AE_IN; i++) x[i] = (float)xd[i];

    float h1[AI_AE_H1], h2[AI_AE_H2], xr[AI_AE_IN];
    for (int j = 0; j < AI_AE_H1; j++) {
        float acc = b1[j];
        const float *wj = w1 + j * AI_AE_IN;
        for (int i = 0; i < AI_AE_IN; i++) acc += wj[i] * x[i];
        h1[j] = acc > 0.0f ? acc : 0.0f;
    }
    for (int k = 0; k < AI_AE_H2; k++) {
        float acc = b2[k];
        const float *wk = w2 + k * AI_AE_H1;
        for (int j = 0; j < AI_AE_H1; j++) acc += wk[j] * h1[j];
        h2[k] = acc > 0.0f ? acc : 0.0f;
    }
    for (int j = 0; j < AI_AE_H1; j++) {
        float acc = b3[j];
        const float *wj = w3 + j * AI_AE_H2;
        for (int k = 0; k < AI_AE_H2; k++) acc += wj[k] * h2[k];
        xr[j] = acc > 0.0f ? acc : 0.0f;   /* 解码隐层复用 h1 缓冲名 xr */
    }
    float err = 0.0f;
    for (int i = 0; i < AI_AE_IN; i++) {
        float acc = b4[i];
        const float *wi = w4 + i * AI_AE_H1;
        for (int j = 0; j < AI_AE_H1; j++) acc += wi[j] * xr[j];
        xhat[i] = acc;
        float d = acc - x[i];
        err += d * d;
    }
    err /= (float)AI_AE_IN;
    if (h1o) memcpy(h1o, h1, sizeof(h1));
    if (h2o) memcpy(h2, h2, sizeof(h2));
    /* 解码隐层 xr 通过 xhat 前的最后一层复用：调用方需要时重新前向 */
    return err;
}

/* ---------------- 输入构建 ---------------- */

void ai_ae_build_input(const http_request_t *req, double *x) {
    memset(x, 0, sizeof(double) * AI_AE_IN);
    if (!req) return;

    /* 前 64 维：复用 64 槽特征 */
    http_request_t tmp = *req;
    int fc = 0;
    ai_extract_features(&tmp, x, &fc);

    /* 后 64 维：query+body 单次解码后的相邻字节对 bigram 哈希 */
    char dq[4096], db[4096];
    ai_url_decode(dq, req->query, (int)sizeof(dq));
    ai_url_decode(db, req->body, (int)sizeof(db));

    double cnt[AI_AE_BG];
    memset(cnt, 0, sizeof(cnt));
    long npairs = 0;
    const char *parts[2] = { dq, db };
    for (int pi = 0; pi < 2; pi++) {
        const char *s = parts[pi];
        if (!s || !s[0] || !s[1]) continue;
        for (size_t i = 0; s[i] && s[i+1]; i++) {
            unsigned a = (unsigned char)s[i];
            unsigned b = (unsigned char)s[i+1];
            cnt[(a * 131u + b) & (AI_AE_BG - 1)] += 1.0;
            npairs++;
        }
    }
    double norm = (double)(npairs + 1);
    for (int i = 0; i < AI_AE_BG; i++) x[64 + i] = cnt[i] / norm;
}

/* ---------------- 评分 ---------------- */

double ai_ae_score_x(const ai_ae_t *m, const double *x) {
    if (!m || !m->trained || !x) return 0.0;
    float xhat[AI_AE_IN];
    float err = ae_forward_err(m, x, NULL, NULL, xhat);
    float std = m->err_std;
    if (std < 1e-6f) std = 1e-6f;
    double z = ((double)err - (double)m->err_mean) / (double)std;
    /* z=4 → 0.5；z<2 趋近 0，z>6 趋近 1 */
    double s = z - 4.0;
    if (s > 30.0) return 1.0;
    if (s < -30.0) return 0.0;
    return 1.0 / (1.0 + exp(-s));
}

double ai_ae_score(const ai_ae_t *m, const http_request_t *req) {
    if (!m || !m->trained || !req) return 0.0;
    double x[AI_AE_IN];
    ai_ae_build_input(req, x);
    return ai_ae_score_x(m, x);
}

/* ---------------- 模型管理 ---------------- */

static float ae_randn(void) {
    double u1 = ((double)rand() + 1.0) / ((double)RAND_MAX + 2.0);
    double u2 = (double)rand() / ((double)RAND_MAX + 1.0);
    return (float)(sqrt(-2.0 * log(u1)) * cos(2.0 * M_PI * u2));
}

ai_ae_t *ai_ae_create(void) {
    ai_ae_t *m = calloc(1, sizeof(ai_ae_t));
    if (!m) return NULL;
    srand(20261018);
    struct { int off; int n; int fan; } layers[] = {
        { AE_OFF_W1, AE_N_W1, AI_AE_IN },
        { AE_OFF_W2, AE_N_W2, AI_AE_H1 },
        { AE_OFF_W3, AE_N_W3, AI_AE_H2 },
        { AE_OFF_W4, AE_N_W4, AI_AE_H1 },
    };
    for (int li = 0; li < 4; li++) {
        float sc = sqrtf(2.0f / (float)layers[li].fan);
        for (int i = 0; i < layers[li].n; i++)
            m->p[layers[li].off + i] = ae_randn() * sc;
    }
    m->err_mean = 0.0f;
    m->err_std = 1.0f;
    m->trained = 0;
    return m;
}

void ai_ae_destroy(ai_ae_t *m) { free(m); }

int ai_ae_is_trained(const ai_ae_t *m) { return m ? m->trained : 0; }

int ai_ae_save(const ai_ae_t *m, const char *path) {
    if (!m || !path) return -1;
    FILE *fp = fopen(path, "wb");
    if (!fp) return -1;
    char magic[4] = AI_AE_MAGIC;
    uint32_t hdr[5] = { AI_AE_VERSION, AI_AE_NPARAM, AI_AE_IN, AI_AE_H1, AI_AE_H2 };
    uint32_t trained = (uint32_t)m->trained;
    int ok = fwrite(magic, 1, 4, fp) == 4 &&
             fwrite(hdr, sizeof(uint32_t), 5, fp) == 5 &&
             fwrite(&trained, sizeof(uint32_t), 1, fp) == 1 &&
             fwrite(&m->err_mean, sizeof(float), 1, fp) == 1 &&
             fwrite(&m->err_std, sizeof(float), 1, fp) == 1 &&
             fwrite(m->p, sizeof(float), AI_AE_NPARAM, fp) == AI_AE_NPARAM;
    fclose(fp);
    return ok ? 0 : -1;
}

ai_ae_t *ai_ae_load(const char *path) {
    if (!path) return NULL;
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    char magic[4];
    uint32_t hdr[5], trained;
    if (fread(magic, 1, 4, fp) != 4 || memcmp(magic, AI_AE_MAGIC, 4) != 0 ||
        fread(hdr, sizeof(uint32_t), 5, fp) != 5 ||
        hdr[0] != AI_AE_VERSION || hdr[1] != AI_AE_NPARAM ||
        hdr[2] != AI_AE_IN || hdr[3] != AI_AE_H1 || hdr[4] != AI_AE_H2 ||
        fread(&trained, sizeof(uint32_t), 1, fp) != 1) {
        fclose(fp);
        return NULL;
    }
    ai_ae_t *m = calloc(1, sizeof(ai_ae_t));
    if (!m) { fclose(fp); return NULL; }
    if (fread(&m->err_mean, sizeof(float), 1, fp) != 1 ||
        fread(&m->err_std, sizeof(float), 1, fp) != 1 ||
        fread(m->p, sizeof(float), AI_AE_NPARAM, fp) != AI_AE_NPARAM) {
        free(m);
        fclose(fp);
        return NULL;
    }
    fclose(fp);
    m->trained = trained ? 1 : 0;
    return m;
}

/* ---------------- 训练（仅白样本，Adam + MSE） ---------------- */

int ai_ae_train(ai_ae_t *m, const char *white_list, int epochs, double lr) {
    if (!m || !white_list) return -1;
    if (epochs <= 0) epochs = 30;
    if (lr <= 0) lr = 1e-3;

    long cap = 40000;
    double *xs = malloc((size_t)cap * AI_AE_IN * sizeof(double));
    if (!xs) return -1;

    FILE *fp = fopen(white_list, "r");
    if (!fp) { free(xs); return -1; }
    static char raw[MAX_REQUEST_SIZE];
    char line[1024];
    long n = 0, fail = 0;
    while (fgets(line, sizeof(line), fp) && n < cap) {
        size_t ll = strlen(line);
        while (ll > 0 && (line[ll-1] == '\n' || line[ll-1] == '\r')) line[--ll] = '\0';
        if (ll == 0) continue;
        FILE *rf = fopen(line, "rb");
        if (!rf) { fail++; continue; }
        size_t rd = fread(raw, 1, sizeof(raw) - 1, rf);
        fclose(rf);
        raw[rd] = '\0';
        http_request_t rq;
        memset(&rq, 0, sizeof(rq));
        if (http_parse_request(raw, rd, &rq) != 0) { fail++; continue; }
        ai_ae_build_input(&rq, xs + n * AI_AE_IN);
        n++;
    }
    fclose(fp);
    if (n < 100) {
        waf_log(LOG_LEVEL_ERROR, "AE train: insufficient white corpus n=%ld", n);
        free(xs);
        return -1;
    }
    printf("AE corpus: white=%ld (parse_fail=%ld)\n", n, fail);
    waf_log(LOG_LEVEL_INFO, "AE train: white=%ld epochs=%d lr=%g", n, epochs, lr);

    float *g  = calloc(AI_AE_NPARAM, sizeof(float));
    float *m1 = calloc(AI_AE_NPARAM, sizeof(float));
    float *m2 = calloc(AI_AE_NPARAM, sizeof(float));
    long *order = malloc(sizeof(long) * n);
    if (!g || !m1 || !m2 || !order) {
        free(g); free(m1); free(m2); free(order); free(xs);
        return -1;
    }
    for (long i = 0; i < n; i++) order[i] = i;

    const float b1a = 0.9f, b2a = 0.999f, aeps = 1e-8f;
    const int bs = 128;
    long step = 0;
    srand(20261018);
    time_t t0 = time(NULL);

    for (int ep = 0; ep < epochs; ep++) {
        for (long i = n - 1; i > 0; i--) {
            long j = (long)((double)rand() / ((double)RAND_MAX + 1.0) * (i + 1));
            long tmp = order[i]; order[i] = order[j]; order[j] = tmp;
        }
        double ep_loss = 0.0;
        long nb = 0;
        for (long off = 0; off + bs <= n; off += bs) {
            memset(g, 0, sizeof(float) * AI_AE_NPARAM);
            double bl = 0.0;
            for (int b = 0; b < bs; b++) {
                const double *xd = xs + order[off + b] * AI_AE_IN;
                float h1[AI_AE_H1], h2[AI_AE_H2], xhat[AI_AE_IN];
                float err = ae_forward_err(m, xd, h1, h2, xhat);
                bl += err;

                /* 反向：dL/dxhat = 2*(xhat-x)/IN */
                float x[AI_AE_IN];
                for (int i = 0; i < AI_AE_IN; i++) x[i] = (float)xd[i];
                /* 先累加 dxr（经 w4）与 b4 梯度；w4 梯度需解码隐层激活 xr，
                 * ae_forward_err 未导出 xr，在下方块中重新计算后累加 */
                float dxr[AI_AE_H1];
                memset(dxr, 0, sizeof(dxr));
                float *g_w4 = g + AE_OFF_W4;
                const float *w4 = m->p + AE_OFF_W4;
                for (int i = 0; i < AI_AE_IN; i++) {
                    float d = 2.0f * (xhat[i] - x[i]) / (float)AI_AE_IN;
                    const float *wi = w4 + i * AI_AE_H1;
                    g[AE_OFF_B4 + i] += d;
                    for (int j = 0; j < AI_AE_H1; j++) dxr[j] += d * wi[j];
                }
                {
                    const float *w3 = m->p + AE_OFF_W3;
                    const float *b3 = m->p + AE_OFF_B3;
                    float xr[AI_AE_H1];
                    for (int j = 0; j < AI_AE_H1; j++) {
                        float acc = b3[j];
                        const float *wj = w3 + j * AI_AE_H2;
                        for (int k = 0; k < AI_AE_H2; k++) acc += wj[k] * h2[k];
                        xr[j] = acc > 0.0f ? acc : 0.0f;
                    }
                    for (int i = 0; i < AI_AE_IN; i++) {
                        float d = 2.0f * (xhat[i] - x[i]) / (float)AI_AE_IN;
                        float *gw = g_w4 + i * AI_AE_H1;
                        for (int j = 0; j < AI_AE_H1; j++) gw[j] += d * xr[j];
                    }
                    /* 解码隐层 ReLU mask */
                    float dh2[AI_AE_H2];
                    memset(dh2, 0, sizeof(dh2));
                    const float *w3c = m->p + AE_OFF_W3;
                    for (int j = 0; j < AI_AE_H1; j++) {
                        float gj = (xr[j] > 0.0f) ? dxr[j] : 0.0f;
                        float *gw3 = g + AE_OFF_W3 + j * AI_AE_H2;
                        for (int k = 0; k < AI_AE_H2; k++) {
                            gw3[k] += gj * h2[k];
                            dh2[k] += gj * w3c[j * AI_AE_H2 + k];
                        }
                        g[AE_OFF_B3 + j] += gj;
                    }
                    /* h2 ReLU mask → dh1 */
                    float dh1[AI_AE_H1];
                    memset(dh1, 0, sizeof(dh1));
                    const float *w2 = m->p + AE_OFF_W2;
                    for (int k = 0; k < AI_AE_H2; k++) {
                        float gk = (h2[k] > 0.0f) ? dh2[k] : 0.0f;
                        float *gw2 = g + AE_OFF_W2 + k * AI_AE_H1;
                        for (int j = 0; j < AI_AE_H1; j++) {
                            gw2[j] += gk * h1[j];
                            dh1[j] += gk * w2[k * AI_AE_H1 + j];
                        }
                        g[AE_OFF_B2 + k] += gk;
                    }
                    /* h1 ReLU mask → w1 */
                    for (int j = 0; j < AI_AE_H1; j++) {
                        float gj = (h1[j] > 0.0f) ? dh1[j] : 0.0f;
                        float *gw1 = g + AE_OFF_W1 + j * AI_AE_IN;
                        for (int i = 0; i < AI_AE_IN; i++) gw1[i] += gj * x[i];
                        g[AE_OFF_B1 + j] += gj;
                    }
                }
            }
            ep_loss += bl;
            nb++;
            step++;
            float bc1 = 1.0f - powf(b1a, (float)step);
            float bc2 = 1.0f - powf(b2a, (float)step);
            for (int i = 0; i < AI_AE_NPARAM; i++) {
                float gi = g[i] / (float)bs;
                m1[i] = b1a * m1[i] + (1.0f - b1a) * gi;
                m2[i] = b2a * m2[i] + (1.0f - b2a) * gi * gi;
                m->p[i] -= (float)lr * (m1[i] / bc1) / (sqrtf(m2[i] / bc2) + aeps);
            }
        }
        printf("epoch %2d/%d  mse=%.6f  elapsed=%lds\n",
               ep + 1, epochs, ep_loss / (double)(nb * bs), (long)(time(NULL) - t0));
        fflush(stdout);
    }

    /* 训练集重建误差分布 → err_mean/err_std */
    double sum = 0.0, sq = 0.0;
    for (long i = 0; i < n; i++) {
        float xhat[AI_AE_IN];
        float err = ae_forward_err(m, xs + i * AI_AE_IN, NULL, NULL, xhat);
        sum += err;
        sq += (double)err * err;
    }
    double mean = sum / (double)n;
    double var = sq / (double)n - mean * mean;
    if (var < 1e-12) var = 1e-12;
    m->err_mean = (float)mean;
    m->err_std = (float)sqrt(var);
    m->trained = 1;
    printf("AE err distribution: mean=%.6f std=%.6f\n", m->err_mean, m->err_std);
    waf_log(LOG_LEVEL_INFO, "AE trained: n=%ld err_mean=%.6f err_std=%.6f",
            n, m->err_mean, m->err_std);

    free(g); free(m1); free(m2); free(order); free(xs);
    return 0;
}
