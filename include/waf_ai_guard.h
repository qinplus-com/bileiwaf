#ifndef WAF_AI_GUARD_H
#define WAF_AI_GUARD_H

#include "waf_common.h"
#include "waf_ai.h"

/*
 * AI 驱动 WAF —— 影子模式 + 护栏自主学习
 *
 * 设计要点（保持规则引擎为第一级权威判定，永不破坏既有准确率）：
 *   1. 影子模式：AI 只打分并写日志，绝不拦截。规则命中作为监督标签（规则蒸馏）。
 *   2. 护栏学习：对"AI 高分但未被规则拦截"的事件做聚类去重、复现次数与置信度双门槛。
 *   3. 铸规则：生成引擎原生格式（TYPE,pattern,score,action,desc），pattern 消毒并过 regcomp。
 *   4. 影子评估：在全量白样本上回放候选规则，要求新增命中 ≤ max_white_fp（默认 0）。
 *   5. 原子热加载：临时文件 + rename 落盘，随后 rules_reload()；审计日志 + 一键回滚。
 *   6. 防投毒：绝不把未验证的在线流量当"良性"标签；规则生成速率与总量受上限约束；
 *      AI 生成规则独立文件，与人工规则物理隔离。
 */

int ai_guard_init(ai_config_t *config);

/* 影子模式入口：在规则判定之后调用。
 * rules_blocked：规则引擎是否已拦截（1/0，作为监督标签来源）。
 * 返回 AI 置信度百分比（0-100）。 */
int ai_guard_shadow(ai_config_t *config, http_request_t *req, int rules_blocked);

/* 定时/节流触发：处理待定候选、铸规则并热加载。返回本次新增规则数。 */
int ai_guard_tick(ai_config_t *config);

/* 一键回滚：从 .bak 恢复自动规则文件并热加载。 */
int ai_guard_rollback(ai_config_t *config);

/* 影子/审计统计快照 */
void ai_guard_stats(ai_config_t *config, unsigned long *total, unsigned long *hits,
                    unsigned long *minted, unsigned long *rejected);

/* 白样本影子评估：返回候选 pattern 在白样本上命中的数量（-1 表示无法评估）。 */
int ai_guard_white_eval(const char *pattern, const char *white_list_path, int sample_limit);

#endif
