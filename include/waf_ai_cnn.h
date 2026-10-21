#ifndef WAF_AI_CNN_H
#define WAF_AI_CNN_H

#include "waf_common.h"

/*
 * char-CNN 通道：字符级卷积网络，监督学习已知攻击模式
 * （ground-truth 标签，可学会规则引擎漏检样本；--labels rules 可退化为纯蒸馏）
 *
 * 结构：emb(256→16) → conv1d(k=5,f=32,pad=same)+ReLU+maxpool(4)
 *      → conv1d(k=3,f=32,pad=same)+ReLU+maxpool(4) → global-max-pool
 *      → FC(32)+ReLU → FC(1)+sigmoid
 * 前向约 1.6M 乘加（<1ms），参数量 ~9.8K。
 */

#define AI_CNN_MAGIC   "WACN"
#define AI_CNN_VERSION 1

#define AI_CNN_L    768   /* 输入序列定长（截断/零填充） */
#define AI_CNN_EMB  16    /* 字节 embedding 维度 */
#define AI_CNN_F1   32    /* conv1 输出通道 */
#define AI_CNN_K1   5     /* conv1 核宽 */
#define AI_CNN_F2   32    /* conv2 输出通道 */
#define AI_CNN_K2   3     /* conv2 核宽 */
#define AI_CNN_POOL 4     /* 两级 maxpool 窗口 */
#define AI_CNN_FC   32    /* 全连接隐层 */

typedef struct ai_cnn ai_cnn_t;

ai_cnn_t *ai_cnn_create(void);
void      ai_cnn_destroy(ai_cnn_t *m);
int       ai_cnn_is_trained(const ai_cnn_t *m);

int       ai_cnn_save(const ai_cnn_t *m, const char *path);
ai_cnn_t *ai_cnn_load(const char *path);   /* 失败返回 NULL */

/* 输入序列构建：url + \x01 + url解码 + \x01 + body + \x01 + body解码，
 * 逐字节写入 seq[AI_CNN_L]（截断/零填充）。训练与推理共用同一构建器，
 * 保证线上线下分布一致。 */
void ai_cnn_build_seq(const http_request_t *req, unsigned char *seq);

double ai_cnn_score_seq(const ai_cnn_t *m, const unsigned char *seq);
double ai_cnn_score(const ai_cnn_t *m, const http_request_t *req);

/*
 * 离线训练（纯 C，Adam + BCE，正类加权）：
 *   black_list/white_list：语料清单（每行一个原始 HTTP 请求文件路径）
 *   labels_gt != 0 用清单标签（黑=1/白=0）；否则保留扩展位（当前实现恒用清单标签）
 *   gradcheck != 0：训练前做数值梯度自检（随机 200 参数，相对误差 >1e-4 返回 -2）
 * 返回 0 成功；训练结束后模型已在内存中，调用 ai_cnn_save 持久化。
 */
int ai_cnn_train(ai_cnn_t *m, const char *black_list, const char *white_list,
                 int epochs, double lr, int gradcheck);

#endif
