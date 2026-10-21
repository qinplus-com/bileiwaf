# 壁垒WAF（BileiWAF）

壁垒WAF 是一款用 C 语言实现的一体化 **Web 应用防火墙**，采用反向代理架构前置在业务系统之前：
所有流量先经 WAF 检测再转发到后端，攻击请求在到达业务之前即被阻断。

- 检测引擎：**1,100+ 条规则**（SQL 注入 / XSS / 命令注入 / 路径穿越 / XXE / SSRF / 反序列化 / 扫描器识别等）
  + **AI 双通道模型**（CNN 载荷分类 + 自编码器异常检测 + 融合决策），规则与 AI 可组合工作
- 管理平面：独立管理进程，提供 Web 管理后台与**实时监控大屏**
- 单二进制、零运行时依赖（除 OpenSSL / libcurl / json-c 等基础库），可直接替换 nginx 前置层

## 核心特性

| 分类 | 能力 |
|---|---|
| 攻击检测 | SQL 注入、XSS、命令注入、路径穿越、文件包含/上传、XXE、SSRF、反序列化、扫描器指纹、恶意 Bot |
| AI 检测 | `rules` / `ai` / `auto` 三种模式；AI 未就绪时自动回退规则引擎（fail-safe）；AI 影子评分与护栏自动学习 |
| 访问控制 | IP 黑白名单、地域/IP 画像、CC 防护（阈值 + 人机验证）、API 防护 |
| 站点管理 | 多站点虚拟主机、按站点独立后端/证书/日志，Web 后台在线增删改 |
| HTTPS | 证书上传、自签证书生成、证书续期与到期提醒 |
| 管理后台 | 管理员（admin，全部功能）/ 监控人员（monitor，仅监控大屏）双角色 RBAC |
| 可观测 | 攻击日志、访问日志、错误日志、审计日志；监控大屏实时攻击流/地图/趋势 |
| 错误页 | 自定义 404 页面（`error_404_page` 配置项，替换为任意品牌页） |
| 日志治理 | 按大小自动轮转 + 保留期自动清理（`log_rotate_size` / `log_retention_days`） |

## 架构

```
                     ┌──────────────────────────────────────────┐
   Client ────► :80  │  数据平面 bin/bileiwaf                     │
             :443  │   ├─ 解析 → 规则引擎 → AI 检测 → 动作裁决   │──► 业务后端
                     │   ├─ CC 防护 / 人机验证 / 黑白名单          │    (127.0.0.1:9000 等)
                     │   └─ 日志（轮转/保留期）                    │
                     └───────────────┬──────────────────────────┘
                                     │ 攻击/访问数据
                     ┌───────────────▼──────────────────────────┐
   管理员 ───► :19000 │  管理平面 bin/bileiwaf-admin              │
   监控员 ───►         │   ├─ Web 管理后台（站点/证书/规则/配置）   │
                     │   ├─ 监控大屏（实时攻击态势）              │
                     │   └─ RBAC：admin / monitor               │
                     └──────────────────────────────────────────┘
```

## 快速开始

### 依赖

- 编译：`gcc`、`make`
- 必需库：`openssl-devel`、`libcurl-devel`、`json-c-devel`
- 可选：`libmaxminddb-devel`（监控大屏 IP 地理定位，缺失则来源信息降级）

RHEL / CentOS / openEuler：

```bash
sudo dnf install -y gcc make openssl-devel libcurl-devel json-c-devel libmaxminddb-devel
```

### 发行包选择

| 目标系统 | 预编译包 | RPM |
|---|---|---|
| el7 系（CentOS 7 / RHEL 7，glibc 2.17、OpenSSL 1.0.2） | `bileiwaf-1.0.1-bin-el7-x86_64.tar.gz` | `bileiwaf-1.0.1-1.el7.x86_64.rpm` |
| el8 系（CentOS 8 / Rocky 8 / openEuler，glibc 2.28、OpenSSL 1.1） | `bileiwaf-1.0.1-bin-el8-x86_64.tar.gz` | `bileiwaf-1.0.1-1.<dist>.x86_64.rpm` |

预编译包解压到 `/` 即可（内含 `opt/bileiwaf/` 与 systemd 单元）。libmaxminddb 为运行期可选：
未安装时管理后台与监控大屏正常工作，仅 IP 地理来源显示为「—」。

### 编译安装

```bash
./configure --prefix=/opt/bileiwaf
make -j"$(nproc)"
sudo make install
```

### 启动

```bash
/opt/bileiwaf/waf start          # 默认监听 80/443，首次启动自动生成自签证书
/opt/bileiwaf/waf status
/opt/bileiwaf/waf stop
```

管理后台：`http://<服务器IP>:19000/admin`，初始账号 **admin / admin123**（首次登录后请立即修改）。
监控大屏：`http://<服务器IP>:19000/admin/dashboard`。

### 接入业务

编辑 `config/sites/demo.local.conf`（或复制为 `<域名>.conf`），修改 `domain` 与 `backend_host/backend_port`，
然后在 `config/sites.conf` 的 `[sites]` 中追加 `site = <域名>.conf`，重启即可。

## 配置说明

主配置 `config/waf.conf`（完整注释见文件本身）：

| 配置项 | 说明 | 默认 |
|---|---|---|
| `http_port` / `https_port` | 数据平面监听端口 | 80 / 443 |
| `admin_port` | 管理平面监听端口 | 19000 |
| `backend_host` / `backend_port` | 默认业务后端 | 127.0.0.1 / 9000 |
| `detection_mode` | `rules` / `ai` / `auto` | auto |
| `worker_threads` | 工作线程数 | 8 |
| `log_rotate_size` | 单日志文件轮转阈值（MB），0 关闭 | 50 |
| `log_retention_days` | 轮转归档保留天数，0 永久 | 30 |
| `error_404_page` | 自定义 404 页面文件路径 | 空（内置演示页） |

账号配置 `config/admin.conf`：扁平首账号为管理员，`[account]` 分节可追加监控账号：

```ini
user = admin
role = admin              # admin=全部功能  monitor=仅监控大屏
password_salt = <16字节随机盐 hex>
password_hash = sha256(salt + password)

# [account]
# user = monitor
# role = monitor
# password_salt = ...
# password_hash = ...
```

> 密码以加盐 SHA-256 存储，明文不落盘；修改密码请使用管理后台「修改密码」，系统会换新盐重算。

## 实测数据

基于 blazehttp 流量回放（同一硬件、同一规则集）：

| 模式 | 检出率 | 误报率 | 准确率 |
|---|---|---|---|
| rules（纯规则） | 98.02% | 0.09% | 99.870% |
| auto（规则 + AI） | 99.70% | 0.09% | 99.903% |
| ai（纯 AI） | 93.77% | 0.00% | 99.879% |

对比基线：ModSecurity PL1 检出 69.74%（误报 17.58%）、PL4 检出 94.61%（误报 52.46%）。
吞吐约 5,759 QPS，平均延迟 162 ms。AI 在规则漏报的 13 个样本中补拦 11 个，漏报降至 2。

## 目录结构

```
src/            数据平面源码（检测引擎、代理、HTTP、日志等）
admin/          管理平面源码（单文件 admin_server.c）
adminui/        管理后台前端（login / dashboard / index）
web/            监控大屏与静态资源
include/        公共头文件
rules/          检测规则（按攻击类型分文件）
models/         AI 模型（CNN / AE / 融合）
etc/            安装默认配置模板（waf.conf / sites.conf；admin.conf 由 configure 生成）
scripts/        发行构建脚本
packaging/      RPM spec 与 systemd 单元
docs/           安装手册、使用手册
```

运行时生成（不入库）：`config/`、`logs/`、`data/`、`certs/`、`bin/`、`build/`。

## 运维要点

- **配置校验**：修改 `config/waf.conf` 或站点配置后，先执行 `./waf check`（等价
  `nginx -t`）检查端口、站点必需项、重复域名、后端地址与证书/私钥配对，通过后再重启。
- **日志轮转**：默认单文件 50 MB 轮转为 `waf-xxx.log.YYYYmmdd-HHMMSS`，归档保留 30 天；每 24 小时自动清理。
- **自定义 404**：设置 `error_404_page = web/404.html`（相对 WAF_HOME 或绝对路径）即可替换为品牌页；
  未配置或文件不可读时回退内置演示页。
- **安全建议**：上线后立即修改默认管理员密码；管理端口 19000 建议仅内网可达或经 VPN；
  `config/` 与 `certs/` 含敏感信息，不要提交到版本库。

## 许可

本项目基于 [Apache License 2.0](LICENSE) 发布，版权归 内蒙古勤加软件有限公司 所有。

第三方组件遵循各自许可：OpenSSL（Apache-2.0）、libcurl（MIT）、json-c（MIT）、
libmaxminddb（Apache-2.0）。GeoIP 数据库（GeoLite2）需自行下载并遵循 MaxMind 许可，本仓库不包含该数据文件。

## 更新日志

见 [CHANGELOG.md](CHANGELOG.md)。
