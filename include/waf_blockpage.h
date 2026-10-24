#ifndef WAF_BLOCKPAGE_H
#define WAF_BLOCKPAGE_H

#include <stddef.h>

/* 403 拦截页（可配置广告位）
 *
 * 配置：$WAF_HOME/config/blockpage.conf，缺失或 enabled=0 时保持原有极简页。
 * 支持自定义模板（{{ip}} / {{rule}} / {{url}} / {{time}} / {{ad}} 占位符），
 * 广告位支持 banner 图片、iframe 广告位、第三方 JS 片段三种形式。
 */

/* 读取配置并缓存模板/广告片段；进程启动时调用一次 */
int blockpage_init(void);

/* 重新加载（SIGHUP 热更新广告配置，不必重启进程） */
int blockpage_reload(void);

/* 渲染拦截页；返回写入 out 的字节数，返回 0 表示不可用（调用方回退内置页）。
 * ip / rule / url 允许为 NULL，内部统一 HTML 转义，防止把攻击者可控的 URL
 * 反射进页面造成 XSS。 */
size_t blockpage_render(char *out, size_t outsz,
                        const char *ip, const char *rule, const char *url);

#endif
