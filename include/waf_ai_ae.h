#ifndef WAF_AI_AE_H
#define WAF_AI_AE_H

#include "waf_common.h"

/*
 * 白流量自监督异常检测通道（0day 主动发现）：
 * MLP autoencoder 仅用白样本训练，重建误差即异常分。
 *
 * 输入 128 维 = 64 槽手工特征（ai_extract_features）+ 64 维字符 bigram 哈希；
 * 结构 128→48→12→48→128（ReLU，输出层线性，MSE loss）。
 * 异常分 = 重建误差 z-score（按训练集 err_mean/err_std）经 sigmoid 映射。
 */

#define AI_AE_MAGIC   "WAAE"
#define AI_AE_VERSION 1

#define AI_AE_IN  128   /* 64 槽特征 + 64 维 bigram */
#define AI_AE_BG  64    /* bigram 哈希桶数（输入后 64 维） */
#define AI_AE_H1  48
#define AI_AE_H2  12

typedef struct ai_ae ai_ae_t;

ai_ae_t *ai_ae_create(void);
void     ai_ae_destroy(ai_ae_t *m);
int      ai_ae_is_trained(const ai_ae_t *m);

int      ai_ae_save(const ai_ae_t *m, const char *path);
ai_ae_t *ai_ae_load(const char *path);   /* 失败返回 NULL */

/* 输入向量构建（训练/推理共用）：前 64 维 = ai_extract_features，
 * 后 64 维 = query+body 单次 URL 解码后的相邻字节对哈希计数（归一化）。 */
void ai_ae_build_input(const http_request_t *req, double *x /*[AI_AE_IN]*/);

double ai_ae_score_x(const ai_ae_t *m, const double *x);
double ai_ae_score(const ai_ae_t *m, const http_request_t *req);

/* 仅用白样本自监督训练（Adam + MSE）；训练集重建误差 mean/std 随模型保存。 */
int ai_ae_train(ai_ae_t *m, const char *white_list, int epochs, double lr);

#endif
