#ifndef WAF_AI_H
#define WAF_AI_H

#include "waf_common.h"

#define AI_MODEL_VERSION "3.0"
#define MAX_FEATURES 64
#define MAX_SAMPLES 20000
#define ANOMALY_THRESHOLD 0.99
#define MAX_MODELS 5

/*
 * 特征布局（定长 64 槽，固定下标，缺失补零，绝不漂移）
 *
 *   7 个来源 × 8 个特征 = 56，另加 8 个聚合/交叉特征 = 64
 *      来源 S: 0=url 1=url深度解码 2=query 3=query深度解码 4=body 5=body深度解码 6=headers
 *      特征 f: 0=归一化长度 1=熵 2=编码密度 3=特殊字符比
 *              4=SQL 指示 5=XSS 指示 6=CMD 指示 7=路径穿越指示
 *   聚合槽位:
 *      56=任一来源命中 SQL  57=任一来源命中 XSS  58=任一来源命中 CMD
 *      59=任一来源命中 路径穿越  60=任一来源命中 XXE/反序列化
 *      61=命中的指示器家族数/5  62=总编码字符数/20  63=非常规方法
 */
#define AI_SRC_URL       0
#define AI_SRC_URLDEC    1
#define AI_SRC_QUERY     2
#define AI_SRC_QUERYDEC  3
#define AI_SRC_BODY      4
#define AI_SRC_BODYDEC   5
#define AI_SRC_HEADERS   6
#define AI_SRC_COUNT     7

#define AI_F_LEN         0
#define AI_F_ENTROPY     1
#define AI_F_ENC         2
#define AI_F_SPECIAL     3
#define AI_F_SQL         4
#define AI_F_XSS         5
#define AI_F_CMD         6
#define AI_F_PATH        7
#define AI_F_PER_SRC     8

#define AI_FEAT(src, f)  ((src) * AI_F_PER_SRC + (f))

#define AI_X_ANY_SQL     56
#define AI_X_ANY_XSS     57
#define AI_X_ANY_CMD     58
#define AI_X_ANY_PATH    59
#define AI_X_ANY_OTHER   60
#define AI_X_FAMILIES    61
#define AI_X_TOTAL_ENC   62
#define AI_X_EXTRA       63

#define AI_FEAT_DIM      64
#define AI_FEAT_EXTRA    AI_X_EXTRA

/* 引擎原生规则类型前缀（与 rules 目录下 .rules 的 TYPE 字段一致） */
#define AI_RULE_TYPE_STR "AILEARN"

typedef enum {
    AI_DETECTION_NORMAL = 0,
    AI_DETECTION_SUSPICIOUS,
    AI_DETECTION_MALICIOUS
} ai_detection_result_t;

typedef enum {
    AI_MODEL_TYPE_ISOLATION_FOREST,  /* 未知攻击/异常 */
    AI_MODEL_TYPE_RANDOM_FOREST,     /* 已知攻击模式（蒸馏主模型） */
    AI_MODEL_TYPE_AUTOENCODER,       /* 异常请求 */
    AI_MODEL_TYPE_SQLI_DETECTOR,     /* SQL 注入专门模型 */
    AI_MODEL_TYPE_XSS_DETECTOR       /* XSS 专门模型 */
} ai_model_type_t;

typedef enum {
    AI_ENSEMBLE_NONE = 0,
    AI_ENSEMBLE_VOTING,
    AI_ENSEMBLE_CASCADE,
    AI_ENSEMBLE_BLENDING
} ai_ensemble_type_t;

typedef struct {
    double features[MAX_FEATURES];
    int feature_count;
    double score;
    int is_malicious;
} ai_sample_t;

typedef struct {
    ai_model_type_t type;
    char name[64];
    int trained;
    int sample_count;
    double weights[MAX_FEATURES];   /* 逻辑回归权重（标准化空间） */
    double bias;
    double threshold;
    double weight;

    double mean[MAX_FEATURES];      /* 特征均值（标准化） */
    double std[MAX_FEATURES];       /* 特征标准差（标准化） */
} ai_model_t;

/* 自主学习护栏配置（可被 waf.conf 覆盖） */
typedef struct {
    int enabled;                    /* 是否启用自动生成规则 */
    int shadow_mode;                /* 影子模式：AI 只打分不拦截 */
    int min_occurrences;            /* 候选片段最少复现次数 */
    int min_confidence_pct;         /* 最低置信度百分比 */
    int max_rules;                  /* ai_learned.rules 最大规则数 */
    int max_white_fp;               /* 白样本影子评估允许的新增命中上限 */
    int white_sample_size;          /* 白样本评估采样数量 */
    char learned_rules_path[512];   /* 自动规则文件路径 */
    char white_list_path[512];      /* 白样本清单（影子评估用） */
} ai_guard_config_t;

typedef struct {
    int enabled;
    int shadow_mode;
    ai_model_t models[MAX_MODELS];
    int model_count;
    ai_ensemble_type_t ensemble_type;
    double ensemble_threshold;
    int auto_learning;
    int auto_update_rules;
    int retrain_interval;
    int min_samples_for_retrain;

    ai_sample_t samples[MAX_SAMPLES];
    int sample_count;
    int sample_head;                 /* 环形缓冲写入位置 */

    char model_path[512];
    char data_path[512];

    int detection_count;
    int false_positives;
    int true_positives;

    /* 影子模式统计 */
    unsigned long shadow_total;
    unsigned long shadow_hits;

    ai_guard_config_t guard;

    /* v3.0 双通道模型（char-CNN 监督 + autoencoder 自监督），
     * 不透明指针，实际类型为 ai_cnn_t / ai_ae_t（见 waf_ai_cnn.h/waf_ai_ae.h）。
     * fusion_ready=1 时在线检测仅用 CNN+AE 融合（64 槽 LR 不再参与在线判定）。 */
    void *cnn_model;
    void *ae_model;
    double fusion_w_cnn;
    double fusion_w_ae;
    double fusion_threshold;
    int fusion_ready;

    pthread_mutex_t mutex;
} ai_config_t;

typedef struct {
    char model_type[32];
    int trained;
    int sample_count;
    int feature_count;
    double threshold;
    int detection_count;
    int auto_learning_enabled;
} ai_model_status_t;

typedef struct {
    char model_type[MAX_MODELS][32];
    int trained[MAX_MODELS];
    int model_count;
    char ensemble_type[32];
    double ensemble_threshold;
} ai_ensemble_status_t;

int ai_init(ai_config_t *config, void *waf_cfg);
void ai_cleanup(ai_config_t *config);

int ai_add_model(ai_config_t *config, ai_model_type_t type, const char *name, double weight);
int ai_remove_model(ai_config_t *config, int index);

int ai_load_model(ai_config_t *config, const char *path);
int ai_save_model(ai_config_t *config, const char *path);
int ai_load_ensemble(ai_config_t *config, const char *base_path);
int ai_save_ensemble(ai_config_t *config, const char *base_path);

int ai_extract_features(http_request_t *req, double *features, int *feature_count);
ai_detection_result_t ai_detect(ai_config_t *config, http_request_t *req);
ai_detection_result_t ai_detect_single(ai_config_t *config, http_request_t *req, int model_index);
double ai_calculate_anomaly_score(ai_config_t *config, double *features, int feature_count, int model_index);
double ai_score_request(ai_config_t *config, http_request_t *req);

ai_detection_result_t ai_ensemble_voting(ai_config_t *config, double *features, int feature_count);
ai_detection_result_t ai_ensemble_cascade(ai_config_t *config, double *features, int feature_count);
ai_detection_result_t ai_ensemble_blending(ai_config_t *config, double *features, int feature_count);

int ai_add_sample(ai_config_t *config, double *features, int feature_count, int is_malicious);
int ai_train_model(ai_config_t *config);
int ai_train_ensemble(ai_config_t *config);
int ai_update_model(ai_config_t *config);

int ai_auto_learn(ai_config_t *config, http_request_t *req, int attack_detected);
int ai_adapt_rules(ai_config_t *config, const char *pattern, int confidence);

const char* ai_detection_result_str(ai_detection_result_t result);
const char* ai_model_type_str(ai_model_type_t type);
const char* ai_ensemble_type_str(ai_ensemble_type_t type);

int ai_train_from_logs(ai_config_t *config, const char *log_dir);
int ai_get_model_status(ai_config_t *config, ai_model_status_t *status);
int ai_get_ensemble_status(ai_config_t *config, ai_ensemble_status_t *status);

/* ---- 离线蒸馏训练器（C 内置，自包含，无外部依赖） ---- */
/* 读取 blazehttp 语料清单（每行一个原始 HTTP 请求文件路径），
 * 用规则引擎的判定作为监督标签，训练逻辑回归模型并写入 base_path。 */
typedef struct {
    long black_files;
    long white_files;
    long black_sampled;
    long white_sampled;
    long parse_fail;
    int  epochs;
    double final_loss;
    double pos_mean;
    double neg_mean;
    double pos_min;
    double neg_max;
    long pos_below_thr;
    long neg_above_thr;
    double best_threshold;
} ai_train_report_t;

int ai_distill_train(ai_config_t *config,
                     const char *black_list, const char *white_list,
                     const char *out_base_path,
                     const ai_guard_config_t *guard,
                     int epochs, double lr,
                     ai_train_report_t *report);

/* 逻辑回归拟合核心（训练器与在线学习共用）：
 * 输入已标注样本，内部完成标准化（写入 model->mean/std），
 * 梯度下降拟合 model->weights/bias。返回 0 成功。 */
int ai_fit_logistic(ai_model_t *model, const ai_sample_t *samples, int count,
                    int epochs, double lr);

/* 用给定阈值在语料上评估当前模型（AI-only 模式） */
int ai_eval_corpus(ai_config_t *config, const char *black_list, const char *white_list,
                   double threshold, long *fn, long *fp, long *black_total, long *white_total,
                   long sample_limit);

/* ---- v3.0 双通道（CNN + AE）融合接口 ---- */

/* URL 单次解码（%XX / +），训练器与 AE/CNN 序列构建共用 */
int ai_url_decode(char *dst, const char *src, int dst_size);

/* 在 model_path 同目录加载 ai_cnn.dat / ai_ae.dat / ai_fusion.dat；
 * 任一缺失或校验失败 → fusion_ready=0（AI 不可用，检测回退规则兜底）。 */
int  ai_fusion_load(ai_config_t *config);

/* 双通道融合打分：fusion = w_cnn*cnn + w_ae*ae；
 * pcnn/pae 可传 NULL。fusion_ready=0 时返回 0。 */
double ai_fusion_score(ai_config_t *config, http_request_t *req,
                       double *pcnn, double *pae);

/* 离线校准：在语料上扫描 (w_cnn, w_ae, thr) 最小化 FN+FP（FP 罚项 ×3），
 * 写 out_path（magic WAFU）。返回 0 成功。 */
int ai_calibrate_fusion(ai_config_t *config, const char *black_list,
                        const char *white_list, const char *out_path);

#endif
