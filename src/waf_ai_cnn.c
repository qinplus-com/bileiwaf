#define _GNU_SOURCE
#include "../include/waf.h"
#include "../include/waf_ai.h"
#include "../include/waf_ai_cnn.h"
#include "../include/waf_log.h"
#include "../include/waf_http.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <stdint.h>

/* ============================================================
 * 参数布局：单一连续 float 数组 + 偏移视图（便于 gradcheck 统一遍历）
 * ============================================================ */

#define CNN_N_EMB  (256 * AI_CNN_EMB)                    /* 4096 */
#define CNN_N_W1   (AI_CNN_F1 * AI_CNN_EMB * AI_CNN_K1)  /* 2560 */
#define CNN_N_B1   (AI_CNN_F1)
#define CNN_N_W2   (AI_CNN_F2 * AI_CNN_F1 * AI_CNN_K2)   /* 3072 */
#define CNN_N_B2   (AI_CNN_F2)
#define CNN_N_WFC1 (AI_CNN_FC * AI_CNN_F2)               /* 1024 */
#define CNN_N_BFC1 (AI_CNN_FC)
#define CNN_N_WFC2 (AI_CNN_FC)
#define CNN_N_BFC2 1

#define CNN_OFF_EMB  0
#define CNN_OFF_W1   (CNN_OFF_EMB + CNN_N_EMB)
#define CNN_OFF_B1   (CNN_OFF_W1 + CNN_N_W1)
#define CNN_OFF_W2   (CNN_OFF_B1 + CNN_N_B1)
#define CNN_OFF_B2   (CNN_OFF_W2 + CNN_N_W2)
#define CNN_OFF_WFC1 (CNN_OFF_B2 + CNN_N_B2)
#define CNN_OFF_BFC1 (CNN_OFF_WFC1 + CNN_N_WFC1)
#define CNN_OFF_WFC2 (CNN_OFF_BFC1 + CNN_N_BFC1)
#define CNN_OFF_BFC2 (CNN_OFF_WFC2 + CNN_N_WFC2)
#define AI_CNN_NPARAM (CNN_OFF_BFC2 + CNN_N_BFC2)

#define CNN_T1  (AI_CNN_L / AI_CNN_POOL)        /* 192 */
#define CNN_T2  (CNN_T1 / AI_CNN_POOL)          /* 48  */

struct ai_cnn {
    float p[AI_CNN_NPARAM];
    int trained;
};

/* ============================================================
 * 前向激活 / 反向梯度 scratch（每请求独立，线程安全）
 * ============================================================ */

typedef struct {
    float *a1;    /* [L][F1]   conv1+ReLU */
    float *p1;    /* [T1][F1]  pool1 */
    float *a2;    /* [T1][F2]  conv2+ReLU */
    float *p2;    /* [T2][F2]  pool2 */
    float *gap;   /* [F2] */
    float *h1;    /* [FC] */
    unsigned char *am1;  /* [T1][F1] pool1 argmax 偏移 0..3 */
    unsigned char *am2;  /* [T2][F2] pool2 argmax 偏移 0..3 */
    unsigned char *agap; /* [F2]     GAP argmax 时间下标 0..T2-1 */
    /* 反向缓冲（仅训练用，可为 NULL） */
    float *dp1;   /* [T1][F1] */
    float *da2;   /* [T1][F2] */
    float *dp2;   /* [T2][F2] */
    float *dgap;  /* [F2] */
    float *dh1;   /* [FC] */
} cnn_scratch;

static int scratch_alloc(cnn_scratch *s, int for_train) {
    memset(s, 0, sizeof(*s));
    s->a1  = malloc(sizeof(float) * AI_CNN_L * AI_CNN_F1);
    s->p1  = malloc(sizeof(float) * CNN_T1 * AI_CNN_F1);
    s->a2  = malloc(sizeof(float) * CNN_T1 * AI_CNN_F2);
    s->p2  = malloc(sizeof(float) * CNN_T2 * AI_CNN_F2);
    s->gap = malloc(sizeof(float) * AI_CNN_F2);
    s->h1  = malloc(sizeof(float) * AI_CNN_FC);
    s->am1 = malloc(CNN_T1 * AI_CNN_F1);
    s->am2 = malloc(CNN_T2 * AI_CNN_F2);
    s->agap = malloc(AI_CNN_F2);
    if (!s->a1 || !s->p1 || !s->a2 || !s->p2 || !s->gap || !s->h1 ||
        !s->am1 || !s->am2 || !s->agap) goto fail;
    if (for_train) {
        s->dp1  = calloc(CNN_T1 * AI_CNN_F1, sizeof(float));
        s->da2  = calloc(CNN_T1 * AI_CNN_F2, sizeof(float));
        s->dp2  = calloc(CNN_T2 * AI_CNN_F2, sizeof(float));
        s->dgap = calloc(AI_CNN_F2, sizeof(float));
        s->dh1  = calloc(AI_CNN_FC, sizeof(float));
        if (!s->dp1 || !s->da2 || !s->dp2 || !s->dgap || !s->dh1) goto fail;
    }
    return 0;
fail:
    free(s->a1); free(s->p1); free(s->a2); free(s->p2); free(s->gap);
    free(s->h1); free(s->am1); free(s->am2); free(s->agap);
    free(s->dp1); free(s->da2); free(s->dp2); free(s->dgap); free(s->dh1);
    memset(s, 0, sizeof(*s));
    return -1;
}

static void scratch_free(cnn_scratch *s) {
    if (!s) return;
    free(s->a1); free(s->p1); free(s->a2); free(s->p2); free(s->gap);
    free(s->h1); free(s->am1); free(s->am2); free(s->agap);
    free(s->dp1); free(s->da2); free(s->dp2); free(s->dgap); free(s->dh1);
    memset(s, 0, sizeof(*s));
}

/* ============================================================
 * 前向传播（写满 scratch 激活与 argmax），返回 logit
 * ============================================================ */

static float cnn_forward(const ai_cnn_t *m, const unsigned char *seq, cnn_scratch *s) {
    const float *emb  = m->p + CNN_OFF_EMB;
    const float *w1   = m->p + CNN_OFF_W1;
    const float *b1   = m->p + CNN_OFF_B1;
    const float *w2   = m->p + CNN_OFF_W2;
    const float *b2   = m->p + CNN_OFF_B2;
    const float *wfc1 = m->p + CNN_OFF_WFC1;
    const float *bfc1 = m->p + CNN_OFF_BFC1;
    const float *wfc2 = m->p + CNN_OFF_WFC2;
    const float  bfc2 = m->p[CNN_OFF_BFC2];

    /* conv1(pad=same) + ReLU；输入直接查 emb 表，不物化嵌入层输出 */
    for (int t = 0; t < AI_CNN_L; t++) {
        for (int f = 0; f < AI_CNN_F1; f++) {
            float acc = b1[f];
            const float *wf = w1 + f * AI_CNN_EMB * AI_CNN_K1;
            for (int kk = 0; kk < AI_CNN_K1; kk++) {
                int tt = t + kk - AI_CNN_K1 / 2;
                if (tt < 0 || tt >= AI_CNN_L) continue;
                const float *xe = emb + seq[tt] * AI_CNN_EMB;
                const float *wk = wf + kk;
                for (int e = 0; e < AI_CNN_EMB; e++)
                    acc += xe[e] * wk[e * AI_CNN_K1];
            }
            s->a1[t * AI_CNN_F1 + f] = acc > 0.0f ? acc : 0.0f;
        }
    }

    /* pool1: 窗口/步长 = POOL */
    for (int u = 0; u < CNN_T1; u++) {
        for (int f = 0; f < AI_CNN_F1; f++) {
            int bi = 0;
            float bv = s->a1[(u * AI_CNN_POOL) * AI_CNN_F1 + f];
            for (int j = 1; j < AI_CNN_POOL; j++) {
                float v = s->a1[(u * AI_CNN_POOL + j) * AI_CNN_F1 + f];
                if (v > bv) { bv = v; bi = j; }
            }
            s->p1[u * AI_CNN_F1 + f] = bv;
            s->am1[u * AI_CNN_F1 + f] = (unsigned char)bi;
        }
    }

    /* conv2(pad=same) + ReLU，输入 p1 [T1][F1] */
    for (int t = 0; t < CNN_T1; t++) {
        for (int f = 0; f < AI_CNN_F2; f++) {
            float acc = b2[f];
            const float *wf = w2 + f * AI_CNN_F1 * AI_CNN_K2;
            for (int kk = 0; kk < AI_CNN_K2; kk++) {
                int tt = t + kk - AI_CNN_K2 / 2;
                if (tt < 0 || tt >= CNN_T1) continue;
                const float *xc = s->p1 + tt * AI_CNN_F1;
                const float *wk = wf + kk;
                for (int c = 0; c < AI_CNN_F1; c++)
                    acc += xc[c] * wk[c * AI_CNN_K2];
            }
            s->a2[t * AI_CNN_F2 + f] = acc > 0.0f ? acc : 0.0f;
        }
    }

    /* pool2 */
    for (int u = 0; u < CNN_T2; u++) {
        for (int f = 0; f < AI_CNN_F2; f++) {
            int bi = 0;
            float bv = s->a2[(u * AI_CNN_POOL) * AI_CNN_F2 + f];
            for (int j = 1; j < AI_CNN_POOL; j++) {
                float v = s->a2[(u * AI_CNN_POOL + j) * AI_CNN_F2 + f];
                if (v > bv) { bv = v; bi = j; }
            }
            s->p2[u * AI_CNN_F2 + f] = bv;
            s->am2[u * AI_CNN_F2 + f] = (unsigned char)bi;
        }
    }

    /* global max pool over time */
    for (int f = 0; f < AI_CNN_F2; f++) {
        int bi = 0;
        float bv = s->p2[f];
        for (int t = 1; t < CNN_T2; t++) {
            float v = s->p2[t * AI_CNN_F2 + f];
            if (v > bv) { bv = v; bi = t; }
        }
        s->gap[f] = bv;
        s->agap[f] = (unsigned char)bi;
    }

    /* fc1 + ReLU */
    for (int i = 0; i < AI_CNN_FC; i++) {
        float acc = bfc1[i];
        const float *wi = wfc1 + i * AI_CNN_F2;
        for (int f = 0; f < AI_CNN_F2; f++) acc += wi[f] * s->gap[f];
        s->h1[i] = acc > 0.0f ? acc : 0.0f;
    }

    /* fc2 logit */
    float logit = bfc2;
    for (int i = 0; i < AI_CNN_FC; i++) logit += wfc2[i] * s->h1[i];
    return logit;
}

static float sigmoidf(float z) {
    if (z > 30.0f) return 1.0f;
    if (z < -30.0f) return 0.0f;
    return 1.0f / (1.0f + expf(-z));
}

/* 数值稳定 BCE（logit 域） */
static double bce_loss(float logit, int y) {
    double z = logit;
    double a = z > 0 ? z : 0.0;
    double az = z > 0 ? z : -z;
    return (a - z * y + log(1.0 + exp(-az)));
}

/* ============================================================
 * 反向传播（单样本），梯度累加进 g[AI_CNN_NPARAM]
 * 要求 scratch 已含前向激活；反向缓冲由调用者清零
 * ============================================================ */

static void cnn_backward(const ai_cnn_t *m, const unsigned char *seq,
                         cnn_scratch *s, float dz, float *g) {
    const float *emb  = m->p + CNN_OFF_EMB;
    const float *w1   = m->p + CNN_OFF_W1;
    const float *w2   = m->p + CNN_OFF_W2;
    const float *wfc1 = m->p + CNN_OFF_WFC1;
    const float *wfc2 = m->p + CNN_OFF_WFC2;

    float *g_emb  = g + CNN_OFF_EMB;
    float *g_w1   = g + CNN_OFF_W1;
    float *g_b1   = g + CNN_OFF_B1;
    float *g_w2   = g + CNN_OFF_W2;
    float *g_b2   = g + CNN_OFF_B2;
    float *g_wfc1 = g + CNN_OFF_WFC1;
    float *g_bfc1 = g + CNN_OFF_BFC1;
    float *g_wfc2 = g + CNN_OFF_WFC2;

    /* fc2 */
    for (int i = 0; i < AI_CNN_FC; i++) {
        g_wfc2[i] += dz * s->h1[i];
        s->dh1[i] = dz * wfc2[i];
    }
    g[CNN_OFF_BFC2] += dz;

    /* fc1（ReLU 反向：前向输出为 0 处梯度为 0） */
    for (int i = 0; i < AI_CNN_FC; i++) {
        float gi = (s->h1[i] > 0.0f) ? s->dh1[i] : 0.0f;
        float *gw = g_wfc1 + i * AI_CNN_F2;
        for (int f = 0; f < AI_CNN_F2; f++) gw[f] += gi * s->gap[f];
        g_bfc1[i] += gi;
        s->dh1[i] = gi;
    }
    for (int f = 0; f < AI_CNN_F2; f++) {
        float acc = 0.0f;
        for (int i = 0; i < AI_CNN_FC; i++) acc += s->dh1[i] * wfc1[i * AI_CNN_F2 + f];
        s->dgap[f] = acc;
    }

    /* GAP 反向 → dp2 */
    for (int f = 0; f < AI_CNN_F2; f++)
        s->dp2[s->agap[f] * AI_CNN_F2 + f] += s->dgap[f];

    /* pool2 反向 → da2（经 ReLU mask 在 conv2 反向中施加） */
    for (int u = 0; u < CNN_T2; u++)
        for (int f = 0; f < AI_CNN_F2; f++)
            s->da2[(u * AI_CNN_POOL + s->am2[u * AI_CNN_F2 + f]) * AI_CNN_F2 + f] +=
                s->dp2[u * AI_CNN_F2 + f];

    /* conv2 反向 */
    for (int t = 0; t < CNN_T1; t++) {
        for (int f = 0; f < AI_CNN_F2; f++) {
            float gv = s->da2[t * AI_CNN_F2 + f];
            if (gv == 0.0f) continue;
            if (s->a2[t * AI_CNN_F2 + f] <= 0.0f) continue;  /* ReLU mask */
            g_b2[f] += gv;
            float *gw = g_w2 + f * AI_CNN_F1 * AI_CNN_K2;
            const float *wf = w2 + f * AI_CNN_F1 * AI_CNN_K2;
            for (int kk = 0; kk < AI_CNN_K2; kk++) {
                int tt = t + kk - AI_CNN_K2 / 2;
                if (tt < 0 || tt >= CNN_T1) continue;
                const float *xc = s->p1 + tt * AI_CNN_F1;
                float *dxc = s->dp1 + tt * AI_CNN_F1;
                for (int c = 0; c < AI_CNN_F1; c++) {
                    gw[c * AI_CNN_K2 + kk] += gv * xc[c];
                    dxc[c] += gv * wf[c * AI_CNN_K2 + kk];
                }
            }
        }
    }

    /* pool1 反向 → da1（直接写 a1 梯度，复用 da2 尺寸不足，用临时全零区 a1 自身大小缓冲） */
    /* 为省内存，pool1 反向直接散到 conv1 反向循环中按 (t,f) 读取：
     * 先构造 da1 = 0，再散播 */
    float *da1 = s->a1;  /* 注意：a1 激活在 conv1 反向 ReLU mask 仍需用，不能覆盖 */
    /* 因 a1 仍被需要，改用独立缓冲：复用 p1 区域不够大。这里显式分配一次静态线程缓冲。 */
    (void)da1;
    float *da1_buf = (float *)calloc((size_t)AI_CNN_L * AI_CNN_F1, sizeof(float));
    if (!da1_buf) return;
    for (int u = 0; u < CNN_T1; u++)
        for (int f = 0; f < AI_CNN_F1; f++)
            da1_buf[(u * AI_CNN_POOL + s->am1[u * AI_CNN_F1 + f]) * AI_CNN_F1 + f] +=
                s->dp1[u * AI_CNN_F1 + f];

    /* conv1 反向 */
    for (int t = 0; t < AI_CNN_L; t++) {
        for (int f = 0; f < AI_CNN_F1; f++) {
            float gv = da1_buf[t * AI_CNN_F1 + f];
            if (gv == 0.0f) continue;
            if (s->a1[t * AI_CNN_F1 + f] <= 0.0f) continue;  /* ReLU mask */
            g_b1[f] += gv;
            float *gw = g_w1 + f * AI_CNN_EMB * AI_CNN_K1;
            const float *wf = w1 + f * AI_CNN_EMB * AI_CNN_K1;
            for (int kk = 0; kk < AI_CNN_K1; kk++) {
                int tt = t + kk - AI_CNN_K1 / 2;
                if (tt < 0 || tt >= AI_CNN_L) continue;
                const float *xe = emb + seq[tt] * AI_CNN_EMB;
                float *dxe = g_emb + seq[tt] * AI_CNN_EMB;
                for (int e = 0; e < AI_CNN_EMB; e++) {
                    gw[e * AI_CNN_K1 + kk] += gv * xe[e];
                    dxe[e] += gv * wf[e * AI_CNN_K1 + kk];
                }
            }
        }
    }
    free(da1_buf);
}

/* ============================================================
 * 对外：评分
 * ============================================================ */

double ai_cnn_score_seq(const ai_cnn_t *m, const unsigned char *seq) {
    if (!m || !m->trained || !seq) return 0.0;
    cnn_scratch s;
    if (scratch_alloc(&s, 0) != 0) return 0.0;
    float logit = cnn_forward(m, seq, &s);
    scratch_free(&s);
    return (double)sigmoidf(logit);
}

double ai_cnn_score(const ai_cnn_t *m, const http_request_t *req) {
    if (!m || !m->trained || !req) return 0.0;
    unsigned char seq[AI_CNN_L];
    ai_cnn_build_seq(req, seq);
    return ai_cnn_score_seq(m, seq);
}

/* ============================================================
 * 输入序列构建（训练/推理共用）：url \x01 url_dec \x01 body \x01 body_dec
 * ============================================================ */

void ai_cnn_build_seq(const http_request_t *req, unsigned char *seq) {
    memset(seq, 0, AI_CNN_L);
    if (!req) return;
    int pos = 0;
    const char *parts[2] = { req->url, req->body };
    for (int pi = 0; pi < 2 && pos < AI_CNN_L; pi++) {
        const char *raw = parts[pi];
        if (!raw || !raw[0]) continue;
        for (const char *p = raw; *p && pos < AI_CNN_L; p++)
            seq[pos++] = (unsigned char)*p;
        if (pos >= AI_CNN_L) break;
        seq[pos++] = 0x01;
        char dec[4096];
        ai_url_decode(dec, raw, (int)sizeof(dec));
        for (const char *p = dec; *p && pos < AI_CNN_L; p++)
            seq[pos++] = (unsigned char)*p;
        if (pos < AI_CNN_L) seq[pos++] = 0x02;
    }
}

/* ============================================================
 * 模型管理
 * ============================================================ */

static float randn_box_muller(void) {
    double u1 = ((double)rand() + 1.0) / ((double)RAND_MAX + 2.0);
    double u2 = (double)rand() / ((double)RAND_MAX + 1.0);
    return (float)(sqrt(-2.0 * log(u1)) * cos(2.0 * M_PI * u2));
}

ai_cnn_t *ai_cnn_create(void) {
    ai_cnn_t *m = calloc(1, sizeof(ai_cnn_t));
    if (!m) return NULL;
    /* He 初始化 */
    srand(20261018);
    float *emb = m->p + CNN_OFF_EMB;
    for (int i = 0; i < CNN_N_EMB; i++) emb[i] = randn_box_muller() * 0.1f;
    float *w1 = m->p + CNN_OFF_W1;
    float s1 = sqrtf(2.0f / (AI_CNN_EMB * AI_CNN_K1));
    for (int i = 0; i < CNN_N_W1; i++) w1[i] = randn_box_muller() * s1;
    float *w2 = m->p + CNN_OFF_W2;
    float s2 = sqrtf(2.0f / (AI_CNN_F1 * AI_CNN_K2));
    for (int i = 0; i < CNN_N_W2; i++) w2[i] = randn_box_muller() * s2;
    float *wfc1 = m->p + CNN_OFF_WFC1;
    float s3 = sqrtf(2.0f / AI_CNN_F2);
    for (int i = 0; i < CNN_N_WFC1; i++) wfc1[i] = randn_box_muller() * s3;
    float *wfc2 = m->p + CNN_OFF_WFC2;
    for (int i = 0; i < CNN_N_WFC2; i++) wfc2[i] = randn_box_muller() * 0.1f;
    m->trained = 0;
    return m;
}

void ai_cnn_destroy(ai_cnn_t *m) { free(m); }

int ai_cnn_is_trained(const ai_cnn_t *m) { return m ? m->trained : 0; }

int ai_cnn_save(const ai_cnn_t *m, const char *path) {
    if (!m || !path) return -1;
    FILE *fp = fopen(path, "wb");
    if (!fp) return -1;
    char magic[4] = AI_CNN_MAGIC;
    uint32_t hdr[9] = { AI_CNN_VERSION, AI_CNN_NPARAM, AI_CNN_L, AI_CNN_EMB,
                        AI_CNN_F1, AI_CNN_K1, AI_CNN_F2, AI_CNN_K2, AI_CNN_FC };
    uint32_t trained = (uint32_t)m->trained;
    int ok = fwrite(magic, 1, 4, fp) == 4 &&
             fwrite(hdr, sizeof(uint32_t), 9, fp) == 9 &&
             fwrite(&trained, sizeof(uint32_t), 1, fp) == 1 &&
             fwrite(m->p, sizeof(float), AI_CNN_NPARAM, fp) == AI_CNN_NPARAM;
    fclose(fp);
    return ok ? 0 : -1;
}

ai_cnn_t *ai_cnn_load(const char *path) {
    if (!path) return NULL;
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    char magic[4];
    uint32_t hdr[9], trained;
    if (fread(magic, 1, 4, fp) != 4 || memcmp(magic, AI_CNN_MAGIC, 4) != 0 ||
        fread(hdr, sizeof(uint32_t), 9, fp) != 9 ||
        hdr[0] != AI_CNN_VERSION || hdr[1] != AI_CNN_NPARAM ||
        hdr[2] != AI_CNN_L || hdr[3] != AI_CNN_EMB ||
        hdr[4] != AI_CNN_F1 || hdr[5] != AI_CNN_K1 ||
        hdr[6] != AI_CNN_F2 || hdr[7] != AI_CNN_K2 || hdr[8] != AI_CNN_FC ||
        fread(&trained, sizeof(uint32_t), 1, fp) != 1) {
        fclose(fp);
        return NULL;
    }
    ai_cnn_t *m = calloc(1, sizeof(ai_cnn_t));
    if (!m) { fclose(fp); return NULL; }
    if (fread(m->p, sizeof(float), AI_CNN_NPARAM, fp) != AI_CNN_NPARAM) {
        free(m);
        fclose(fp);
        return NULL;
    }
    fclose(fp);
    m->trained = trained ? 1 : 0;
    return m;
}

/* ============================================================
 * 训练：语料加载 → gradcheck（可选） → Adam mini-batch
 * ============================================================ */

typedef struct {
    unsigned char *seqs;   /* n × AI_CNN_L */
    int *labels;
    long n;
} cnn_corpus;

static void corpus_free(cnn_corpus *c) {
    if (!c) return;
    free(c->seqs);
    free(c->labels);
    memset(c, 0, sizeof(*c));
}

static long corpus_load_list(cnn_corpus *c, const char *list_path, int label,
                             long *fail_out) {
    FILE *fp = fopen(list_path, "r");
    if (!fp) return -1;
    static char raw[MAX_REQUEST_SIZE];
    char line[1024];
    long loaded = 0, fail = 0;
    while (fgets(line, sizeof(line), fp)) {
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

        unsigned char *dst = c->seqs + c->n * AI_CNN_L;
        ai_cnn_build_seq(&rq, dst);
        c->labels[c->n] = label;
        c->n++;
        loaded++;
    }
    fclose(fp);
    if (fail_out) *fail_out += fail;
    return loaded;
}

/* 单 batch 损失+梯度（g 累加前由调用者清零；返回加权损失和） */
static double batch_loss_grad(const ai_cnn_t *m, const cnn_corpus *c,
                              const long *idx, int bs, float pos_w,
                              float *g, cnn_scratch *s) {
    double loss = 0.0;
    for (int b = 0; b < bs; b++) {
        const unsigned char *seq = c->seqs + idx[b] * AI_CNN_L;
        int y = c->labels[idx[b]];
        memset(s->dp1, 0, sizeof(float) * CNN_T1 * AI_CNN_F1);
        memset(s->da2, 0, sizeof(float) * CNN_T1 * AI_CNN_F2);
        memset(s->dp2, 0, sizeof(float) * CNN_T2 * AI_CNN_F2);
        float logit = cnn_forward(m, seq, s);
        float cw = y ? pos_w : 1.0f;
        loss += bce_loss(logit, y) * cw;
        float dz = (sigmoidf(logit) - (float)y) * cw;
        cnn_backward(m, seq, s, dz, g);
    }
    return loss;
}

static double batch_loss_only(const ai_cnn_t *m, const cnn_corpus *c,
                              const long *idx, int bs, float pos_w) {
    double loss = 0.0;
    cnn_scratch s;
    if (scratch_alloc(&s, 0) != 0) return 0.0;
    for (int b = 0; b < bs; b++) {
        const unsigned char *seq = c->seqs + idx[b] * AI_CNN_L;
        int y = c->labels[idx[b]];
        float logit = cnn_forward(m, seq, &s);
        loss += bce_loss(logit, y) * (y ? pos_w : 1.0f);
    }
    scratch_free(&s);
    return loss;
}

/* 数值梯度自检：随机抽样 200 个参数做中心差分对比解析梯度。
 * float32 参数下差分误差底 ~1e-4 量级；max-pool argmax 在 eps 扰动下
 * 翻转会让数值梯度含"跳变"分量而解析次梯度不含，表现为浅层(emb/w1)
 * 小梯度参数上 |diff|≤1e-3 的相对误差假阳性。判定因此要求
 * 相对误差>2% 且 绝对差>1e-3 才算 bad（真实反向 bug 产生 O(1) 级偏差）。
 * 打印最差 5 个参数便于诊断。返回 0 通过。 */
static int cnn_gradcheck(ai_cnn_t *m, const cnn_corpus *c, float pos_w) {
    long idx[16];
    srand(4242);
    for (int i = 0; i < 16; i++) idx[i] = (long)((double)rand() / RAND_MAX * (c->n - 1));

    float *g = calloc(AI_CNN_NPARAM, sizeof(float));
    if (!g) return -1;
    cnn_scratch s;
    if (scratch_alloc(&s, 1) != 0) { free(g); return -1; }
    batch_loss_grad(m, c, idx, 16, pos_w, g, &s);
    scratch_free(&s);

    const float eps = 1e-3f;
    double worst = 0.0;
    double worst_rel[5] = {0};
    int bad = 0, checked = 0;
    struct { int pi; double num, ana, rel; } bads[12];
    int nbad_rec = 0;
    srand(777);
    for (int t = 0; t < 200; t++) {
        int pi = rand() % AI_CNN_NPARAM;
        float orig = m->p[pi];
        m->p[pi] = orig + eps;
        double lp = batch_loss_only(m, c, idx, 16, pos_w);
        m->p[pi] = orig - eps;
        double lm = batch_loss_only(m, c, idx, 16, pos_w);
        m->p[pi] = orig;
        double num = (lp - lm) / (2.0 * eps);
        double ana = g[pi];
        double denom = fabs(num) + fabs(ana);
        if (denom < 1e-6) continue;  /* 双侧零梯度，无判别意义 */
        double rel = fabs(num - ana) / denom;
        checked++;
        if (rel > worst) worst = rel;
        for (int k = 0; k < 5; k++) {
            if (rel > worst_rel[k]) {
                for (int q = 4; q > k; q--) worst_rel[q] = worst_rel[q-1];
                worst_rel[k] = rel;
                break;
            }
        }
        if (rel > 0.02 && fabs(num - ana) > 1e-3) {
            bad++;
            if (nbad_rec < 12) {
                bads[nbad_rec].pi = pi;
                bads[nbad_rec].num = num;
                bads[nbad_rec].ana = ana;
                bads[nbad_rec].rel = rel;
                nbad_rec++;
            }
        }
    }
    free(g);
    /* 层归属名（按参数偏移区间） */
    static const struct { int off, n; const char *name; } layers[] = {
        { CNN_OFF_EMB,  CNN_N_EMB,  "emb"  },
        { CNN_OFF_W1,   CNN_N_W1,   "w1"   },
        { CNN_OFF_B1,   CNN_N_B1,   "b1"   },
        { CNN_OFF_W2,   CNN_N_W2,   "w2"   },
        { CNN_OFF_B2,   CNN_N_B2,   "b2"   },
        { CNN_OFF_WFC1, CNN_N_WFC1, "wfc1" },
        { CNN_OFF_BFC1, CNN_N_BFC1, "bfc1" },
        { CNN_OFF_WFC2, CNN_N_WFC2, "wfc2" },
        { CNN_OFF_BFC2, CNN_N_BFC2, "bfc2" },
    };
    for (int i = 0; i < nbad_rec; i++) {
        const char *ln = "?";
        for (size_t k = 0; k < sizeof(layers)/sizeof(layers[0]); k++)
            if (bads[i].pi >= layers[k].off && bads[i].pi < layers[k].off + layers[k].n) {
                ln = layers[k].name; break;
            }
        printf("  bad#%d pi=%d layer=%s num=%.6g ana=%.6g rel=%.4f\n",
               i, bads[i].pi, ln, bads[i].num, bads[i].ana, bads[i].rel);
    }
    waf_log(LOG_LEVEL_INFO, "CNN gradcheck: checked=%d worst_rel=%.6f bad(>2%%)=%d "
            "top5=%.5f/%.5f/%.5f/%.5f/%.5f",
            checked, worst, bad,
            worst_rel[0], worst_rel[1], worst_rel[2], worst_rel[3], worst_rel[4]);
    printf("CNN gradcheck: checked=%d worst_rel=%.6f bad(>2%%)=%d\n", checked, worst, bad);
    if (bad > 0 || checked == 0) return -2;
    return 0;
}

int ai_cnn_train(ai_cnn_t *m, const char *black_list, const char *white_list,
                 int epochs, double lr, int gradcheck) {
    if (!m || !black_list || !white_list) return -1;
    if (epochs <= 0) epochs = 20;
    if (lr <= 0) lr = 1e-3;

    /* 预估语料规模：按行数 */
    long cap = 40000;
    cnn_corpus c;
    memset(&c, 0, sizeof(c));
    c.seqs = malloc((size_t)cap * AI_CNN_L);
    c.labels = malloc((size_t)cap * sizeof(int));
    if (!c.seqs || !c.labels) { corpus_free(&c); return -1; }

    long fail = 0;
    long nb = corpus_load_list(&c, black_list, 1, &fail);
    long nw = corpus_load_list(&c, white_list, 0, &fail);
    if (nb <= 0 || nw <= 0 || c.n < 100) {
        waf_log(LOG_LEVEL_ERROR, "CNN train: insufficient corpus black=%ld white=%ld", nb, nw);
        corpus_free(&c);
        return -1;
    }
    float pos_w = (float)nw / (float)nb;
    if (pos_w > 20.0f) pos_w = 20.0f;
    waf_log(LOG_LEVEL_INFO, "CNN train: black=%ld white=%ld pos_w=%.1f epochs=%d lr=%g",
            nb, nw, pos_w, epochs, lr);
    printf("CNN corpus: black=%ld white=%ld (parse_fail=%ld) pos_w=%.1f\n", nb, nw, fail, pos_w);

    if (gradcheck) {
        if (cnn_gradcheck(m, &c, pos_w) != 0) {
            printf("CNN gradcheck FAILED; training aborted\n");
            corpus_free(&c);
            return -2;
        }
        printf("CNN gradcheck OK\n");
    }

    /* Adam */
    float *g  = calloc(AI_CNN_NPARAM, sizeof(float));
    float *m1 = calloc(AI_CNN_NPARAM, sizeof(float));
    float *m2 = calloc(AI_CNN_NPARAM, sizeof(float));
    if (!g || !m1 || !m2) { free(g); free(m1); free(m2); corpus_free(&c); return -1; }
    const float b1 = 0.9f, b2 = 0.999f, aeps = 1e-8f;
    const int bs = 64;
    long *order = malloc(sizeof(long) * c.n);
    if (!order) { free(g); free(m1); free(m2); corpus_free(&c); return -1; }
    for (long i = 0; i < c.n; i++) order[i] = i;

    cnn_scratch s;
    if (scratch_alloc(&s, 1) != 0) {
        free(g); free(m1); free(m2); free(order); corpus_free(&c); return -1;
    }

    srand(20261018);
    long step = 0;
    time_t t0 = time(NULL);
    for (int ep = 0; ep < epochs; ep++) {
        /* Fisher-Yates shuffle */
        for (long i = c.n - 1; i > 0; i--) {
            long j = (long)((double)rand() / ((double)RAND_MAX + 1.0) * (i + 1));
            long tmp = order[i]; order[i] = order[j]; order[j] = tmp;
        }
        double ep_loss = 0.0;
        long nb_batches = 0;
        for (long off = 0; off + bs <= c.n; off += bs) {
            memset(g, 0, sizeof(float) * AI_CNN_NPARAM);
            ep_loss += batch_loss_grad(m, &c, order + off, bs, pos_w, g, &s);
            nb_batches++;
            step++;
            float bc1 = 1.0f - powf(b1, (float)step);
            float bc2 = 1.0f - powf(b2, (float)step);
            for (int i = 0; i < AI_CNN_NPARAM; i++) {
                float gi = g[i] / (float)bs;
                m1[i] = b1 * m1[i] + (1.0f - b1) * gi;
                m2[i] = b2 * m2[i] + (1.0f - b2) * gi * gi;
                m->p[i] -= (float)lr * (m1[i] / bc1) / (sqrtf(m2[i] / bc2) + aeps);
            }
        }
        /* 每 epoch 末全量训练集 FN/FP @0.5（推理批量小，秒级） */
        long fn = 0, fp = 0;
        for (long i = 0; i < c.n; i++) {
            const unsigned char *seq = c.seqs + i * AI_CNN_L;
            cnn_scratch se;
            if (scratch_alloc(&se, 0) != 0) break;
            float logit = cnn_forward(m, seq, &se);
            scratch_free(&se);
            double sc = (double)sigmoidf(logit);
            if (c.labels[i] == 1 && sc < 0.5) fn++;
            if (c.labels[i] == 0 && sc >= 0.5) fp++;
        }
        waf_log(LOG_LEVEL_INFO, "CNN epoch %d/%d loss=%.4f trainFN=%ld trainFP=%ld",
                ep + 1, epochs, ep_loss / (double)(nb_batches * bs), fn, fp);
        printf("epoch %2d/%d  loss=%.4f  trainFN=%ld trainFP=%ld  elapsed=%lds\n",
               ep + 1, epochs, ep_loss / (double)(nb_batches * bs), fn, fp,
               (long)(time(NULL) - t0));
        fflush(stdout);
    }

    m->trained = 1;
    scratch_free(&s);
    free(g); free(m1); free(m2); free(order);
    corpus_free(&c);
    return 0;
}
