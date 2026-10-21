# 变更日志

本项目遵循语义化版本。格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。

## [1.0.0] - 2026-10-21

首个正式发布版本。

### 新增

- 管理后台 RBAC：`admin` 角色拥有全部功能，`monitor` 角色仅可访问监控大屏；
  未授权接口返回 403，登录响应与会话查询均返回角色信息。
- 多账号支持：`config/admin.conf` 支持 `[account]` 分节追加账号，扁平首账号缺省为管理员，
  分节账号缺省为最小权限（monitor）。
- 自定义 404 页面：新增 `error_404_page` 配置项，支持替换为任意品牌页面；
  文件不可读时自动回退内置页面并告警。
- 日志治理：按大小自动轮转（`log_rotate_size`，默认 50 MB）与归档保留期自动清理
  （`log_retention_days`，默认 30 天）；清理改为原生目录遍历，不再依赖外部 `find`。

### 改进

- 账号密码改为按会话账号修改并换新随机盐，写回配置文件时保留全部账号。
- 登录校验对不存在的用户执行等价哈希计算，降低时序侧信道风险。
- 站点静态资源 404 响应统一走可配置错误页。

### 构建与发行

- 提供三种发行形态：源码包（`./configure && make && make install`）、
  预编译二进制包（el7 / el8 两种平台）、RPM 包（含 systemd 单元与 `%config(noreplace)` 配置保护）。
- RPM 文件清单补齐 `adminui/`、`waf` 启动脚本与 `config/admin.conf`。
- 管理平面的 IP 地理定位改为运行期 `dlopen` 加载 libmaxminddb：目标机未安装该库时
  管理后台照常启动（仅地理来源降级），不再因缺少 `libmaxminddb.so.0` 启动失败。
- 新增 OpenSSL 1.0.2 兼容层，同一份源码可在 el7（1.0.2）与 el8+（1.1/3.x）编译。

### 许可

- 项目以 Apache License 2.0 发布。
