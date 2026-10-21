# 壁垒WAF 安装手册

**版本：v1.0.1　|　内蒙古勤加软件有限公司　|　2026 年 10 月**

---

## 1 概述

壁垒WAF（BILEI WAF）是使用 C 语言开发的反向代理型 Web 应用防火墙，由两个进程平面组成：

| 组件 | 程序 | 职责 | 默认监听 |
| --- | --- | --- | --- |
| 数据平面 | `bin/bileiwaf` | 流量接入、HTTPS 卸载、攻击检测、反向代理、CC 防护 | 80 / 443 |
| 管理平面 | `bin/bileiwaf-admin` | 管理后台（REST API + 控制台）、产品官网、攻防演示页 | 19000 |

本手册覆盖源码编译安装、发行包快速安装、服务管理、初始配置、证书配置、升级卸载与故障排查。

## 2 系统要求

### 2.1 硬件与操作系统

| 项目 | 要求 |
| --- | --- |
| 架构 | x86_64 |
| 操作系统 | Linux（glibc ≥ 2.17），已在 BaiduLinux 3 / Anolis 8 / CentOS 8+ / Ubuntu 18.04+ 验证 |
| 内存 | ≥ 2 GB（生产建议 4 GB 以上） |
| 磁盘 | ≥ 2 GB（含日志空间） |
| 端口规划 | 数据平面 80/443（可改），管理平面 19000（可改），需在防火墙放行 |

### 2.2 软件依赖（源码编译时）

| 依赖 | 必需性 | dnf / yum 包名 | apt 包名 |
| --- | --- | --- | --- |
| gcc / make | 必需 | `gcc make` | `build-essential` |
| OpenSSL ≥ 1.1 | 必需 | `openssl-devel` | `libssl-dev` |
| libcurl | 必需 | `libcurl-devel` | `libcurl4-openssl-dev` |
| json-c | 必需 | `json-c-devel` | `libjson-c-dev` |
| libmaxminddb | 可选（IP 地理定位，缺失自动降级） | `libmaxminddb-devel` | `libmaxminddb-dev` |

以 BaiduLinux / Anolis / CentOS 为例：

```bash
dnf install -y gcc make openssl-devel libcurl-devel json-c-devel libmaxminddb-devel
```

> 说明：仅运行**发行包二进制**时无需编译依赖，只需 glibc ≥ 2.17 与 openssl 运行库。

## 3 获取软件

**方式一：源码发行包（推荐）**

```bash
# 在已有源码目录执行，生成 dist/bileiwaf-<版本>.tar.gz
make dist
# 分发到目标服务器解压
tar xzf bileiwaf-1.2.0.tar.gz && cd bileiwaf-1.2.0
```

**方式二：代码仓库**

```bash
git clone <代码仓库地址> bileiwaf && cd bileiwaf
```

## 4 源码编译安装（标准流程）

### 4.1 配置

```bash
cd bileiwaf
./configure --prefix=/opt/bileiwaf
```

configure 会检测编译器与依赖库，生成 `Makefile` 与 `include/waf_config.h`；检测失败会明确提示缺失项。

**常用 configure 选项：**

| 选项 | 说明 | 默认值 |
| --- | --- | --- |
| `--prefix=DIR` | 安装根目录 | `/opt/bileiwaf` |
| `--detection-mode=MODE` | 默认检测模式 `rules` / `ai` / `auto`，写入配置模板与编译默认值 | `auto` |
| `--admin-port=PORT` | 管理平面端口，写入 `etc/waf.conf` 模板 | `19000` |
| `--admin-dir=NAME` | 管理界面目录名（决定 `make install` 安装目录名） | `adminui` |
| `--admin-user=NAME` | 初始管理员账号（仅首次安装生效，已有 admin.conf 不覆盖） | `admin` |
| `--admin-password=PASS` | 初始管理员密码（随机加盐 sha256 存储，明文不落盘） | `admin123` |
| `--with-openssl=DIR` 等 | 依赖库安装在非标准路径时指定前缀（curl / json-c / geoip 同理） | 系统路径 |
| `--geoip-db=PATH` | GeoIP 数据文件路径，写入 `waf.conf` 的 `geoip_db` 键 | - |

### 4.2 编译与安装

```bash
make            # 构建数据平面 + 管理平面（make waf / make admin 可单独构建）
sudo make install
```

`make install` 行为要点：

- 安装到 `--prefix` 目录（默认 `/opt/bileiwaf`），支持 `DESTDIR` 用于打包；
- `config/`、`rules/`、`models/` **现场文件不覆盖**（升级安全）；`web/`、`adminui/` 随版本覆盖；
- 自动安装 systemd 单元到 `/usr/lib/systemd/system/bileiwaf.service`；
- 安装完成后控制台会输出启动命令与管理后台地址。

### 4.3 目录结构

```
/opt/bileiwaf
├── bin/          bileiwaf（数据平面）、bileiwaf-admin（管理平面）
├── config/       waf.conf、admin.conf、sites/（站点配置）、sites.conf
├── rules/        检测规则与黑白名单（sql_injection.rules 等 11 个文件）
├── models/       AI 模型文件（ai_model.dat.*、ai_fusion.dat 等）
├── web/          产品官网 / 攻防演示 / 大屏 / 报告 静态资源
├── adminui/      管理后台前端（与 web/ 平级、独立目录）
├── certs/        TLS 证书（首次启动自动生成自签名证书）
├── logs/         运行日志与 PID 文件
├── data/         运行数据
└── waf           服务管理脚本（start.sh / stop.sh 为兼容 wrapper）
```

## 5 发行包快速安装（免编译）

适用于拿到 `bileiwaf-<版本>.tar.gz` 二进制发行包的服务器：

```bash
cd bileiwaf-1.2.0
sudo ./packaging/install.sh              # 环境自检 + 生成自签名证书
sudo ./packaging/install.sh --systemd    # 额外注册 systemd 开机自启（不自动启动）
```

可选参数：`--http-only` 仅自检不生成证书；`--silent` 静默模式（供 RPM `%post` 调用）；`--uninstall` 停止服务并移除 systemd 单元（保留目录文件）。

脚本自检项：x86_64 架构、glibc ≥ 2.17、`bin/` 两个可执行文件完整。通过后自动生成 `certs/server.pem` 自签名证书（CN=localhost，SAN 包含 localhost 与 127.0.0.1）。

## 6 服务管理

### 6.1 `waf` 管理脚本

统一入口为安装目录下的 `waf` 脚本（`start.sh` / `stop.sh` 为等价兼容 wrapper）：

```bash
cd /opt/bileiwaf
sudo ./waf start                        # 启动全部平面（数据 80/443 + 管理平面）
sudo ./waf start -p 8080 -s 8444 -b 127.0.0.1:9000 -a 19000   # 自定义端口启动
sudo ./waf status                       # 查看运行状态（运行中 exit 0，停止 exit 3）
sudo ./waf restart                      # 重启
sudo ./waf stop                         # 停止全部平面；stop waf / stop admin 可单独停止
```

**start 参数说明：**

| 参数 | 说明 | 默认 |
| --- | --- | --- |
| `-p, --port` | 数据平面 HTTP 监听端口 | 80 |
| `-s, --https` | 数据平面 HTTPS 监听端口 | 443 |
| `-b, --backend` | 默认后端 `host:port`（反向代理目标） | `127.0.0.1:9000` |
| `-a, --admin` | 管理平面端口（覆盖 waf.conf 的 admin_port） | `waf.conf` 中 `admin_port` |
| `[waf\|admin]` | 仅操作指定平面 | 全部平面 |

### 6.2 systemd 服务

`make install` 或 `install.sh --systemd` 已注册 `bileiwaf.service`：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now bileiwaf    # 开机自启并立即启动
systemctl status bileiwaf
sudo systemctl reload bileiwaf          # 向数据平面发送 SIGHUP：热加载规则 + 证书
```

单元要点：`Restart=on-failure` 异常自动拉起、`LimitNOFILE=65535`、`ExecReload` 触发规则与 SSL 上下文热加载（证书续期后无需重启）。

### 6.3 CC 防护环境变量（可选调整）

`waf` 脚本启动时注入以下默认值，可在启动前 `export` 覆盖：

| 变量 | 含义 | 默认 |
| --- | --- | --- |
| `WAF_CC_MAX_REQUESTS` | 时间窗内单 IP 最大请求数 | 60 |
| `WAF_CC_TIME_WINDOW` | 统计时间窗（秒） | 60 |
| `WAF_CC_BLOCK_DURATION` | 触发后封禁时长（秒） | 60 |

## 7 初始配置

### 7.1 全局配置 config/waf.conf

| 键 | 说明 | 示例 |
| --- | --- | --- |
| `detection_mode` | `rules` 纯规则 / `ai` 纯 AI（模型缺失自动回退规则兜底）/ `auto` AI 先判 + 规则联级 | `auto` |
| `http_port` / `https_port` | 监听端口（可被 `-p/-s` 覆盖） | `80` / `443` |
| `backend_host` / `backend_port` | 默认后端 | `127.0.0.1` / `9000` |
| `mode` | 工作模式：`learning` 学习 / `detection` 检测 / `blocking` 拦截 | `blocking` |
| `admin_port` | 管理平面端口 | `19000` |
| `worker_threads` | 数据平面工作线程数 | `8`（生产可 64） |
| `cert_file` / `key_file` | 默认证书路径 | `certs/server.pem` |
| `ai_ensemble_threshold` | AI 集成决策阈值（0~1，越高越保守） | `0.5` |
| `ai_shadow_mode` | 影子模式：AI 只打分写 `logs/ai-shadow.log` 不拦截 | `off` |
| `ai_guard_enabled` | 护栏自主学习（AILEARN）：AI 高分未拦载荷聚类铸造新规则 | `off` |

### 7.2 管理后台账号 config/admin.conf

首次安装由 configure 写入初始账号（默认 `admin` / `admin123`，盐值 sha256 存储）。**上线后请立即登录后台修改密码**（后台右上角 → 修改密码，或调用 `/api/admin/password`）。

### 7.3 接入业务站点

每个站点一个 INI 文件，放在 `config/sites/` 下（可在后台"站点管理"页在线添加）。最小示例：

```ini
# config/sites/app.example.com.conf
[site]
domain = app.example.com
backend_host = 127.0.0.1      # 业务后端地址
backend_port = 9000           # 业务后端端口；本机静态站可设 0 并用 document_root
document_root = /web/app      # backend_port = 0 时由 WAF 直接托管静态文件
http_port = 80
https_port = 443
enabled = 1
cc_captcha = 1                # CC 超阈值返回验证码（人机验证）而非直接封禁

[ssl]
enabled = 1
cert_file = /opt/bileiwaf/certs/app.example.com/fullchain.pem
key_file  = /opt/bileiwaf/certs/app.example.com/privkey.pem

[logging]
enabled = 1
access_log = logs/app.example.com/access.log
error_log  = logs/app.example.com/error.log

[cache]
enabled = 1                   # 静态资源内存缓存
max_size = 256                # MB
expire_time = 7200            # 秒

[request_limit]
enabled = 1
rate = 500                    # 限速（请求/秒）
burst = 1000

[gzip]
enabled = 1
min_length = 20

[security]
csrf_protection = 1
xss_protection = 1
clickjacking_protection = 1

[error_pages]
enabled = 1
error_404 = web/errors/404.html
error_403 = web/errors/403.html
error_50x = web/errors/50x.html
```

多站点同时启用时，在 `config/sites.conf` 的 `[sites]` 段登记：

```ini
[sites]
site = app.example.com.conf
site = www.example.com.conf
```

修改站点配置后执行 `sudo ./waf restart`（或 `systemctl restart bileiwaf`）生效。

## 8 HTTPS 证书

1. **自动自签名**：首次启动检测到证书缺失时自动生成（仅测试用）；
2. **Let's Encrypt 自动签发/续期**：管理后台 → 证书管理 → 选择站点 → 一键签发/续期（ACME 自动化），续期完成后自动热加载，无需重启；
3. **手动上传**：管理后台 → 证书管理 → 上传 `fullchain.pem` + `privkey.pem`；
4. **替换配置**：将 `cert_file` / `key_file` 指向正式证书路径后 `./waf restart`。

## 9 安装验证

```bash
# 1. 服务状态
cd /opt/bileiwaf && sudo ./waf status

# 2. 正常请求放行（返回业务内容或 200）
curl -sI http://127.0.0.1/

# 3. 攻击载荷拦截（应返回 403 Forbidden）
curl -sI "http://127.0.0.1/?id=1%20UNION%20SELECT%20password%20FROM%20users"
curl -sI --path-as-is "http://127.0.0.1/../../etc/passwd"

# 4. 管理后台可访问（浏览器打开）
http://<服务器IP>:19000/admin/
```

浏览器登录管理后台后，在"安全防护监控大屏"确认今日攻击 / 累计拦截计数增长即表示检测链路正常。

## 10 升级与卸载

**升级**：重新执行 `./configure && make && sudo make install`（或解压新版发行包后执行 `install.sh`）。安装过程保留 `config/`、`rules/`、`models/`、`logs/`、`certs/`、`data/` 现场数据，仅覆盖程序与 Web 资源；安装后 `sudo systemctl restart bileiwaf`。

**卸载**：

```bash
sudo make uninstall                  # 源码安装方式：移除程序与 systemd 单元
sudo ./packaging/install.sh --uninstall   # 发行包方式：停止服务并移除 systemd 单元
# 两方式均保留 config/rules/models/logs/certs/data 现场数据；确认无需回滚后手动删除目录
```

## 11 故障排查

| 现象 | 排查方法 |
| --- | --- |
| 启动失败：端口占用 | `ss -tlnp \| grep -E ':80\|:443\|:19000'` 找到占用进程；脚本会等待端口释放 10 秒后给出警告 |
| 启动失败：缺依赖库 | `ldd bin/bileiwaf \| grep "not found"`；安装对应 devel/运行库后重新 `make` |
| 管理后台打不开 | 确认管理平面进程 `./waf status`；确认 `admin_port` 与防火墙放行；仅由管理端口提供后台 |
| 请求全部 500 | 查看 `logs/error.log` 与后端可达性（`curl` 直连后端）；确认 `-b` 后端地址正确 |
| 进程异常退出 | 查看 `logs/waf-crash.log`（记录信号、故障地址、调用帧），用 `addr2line -e bin/bileiwaf <地址>` 定位源码行；systemd 场景 `Restart=on-failure` 自动拉起 |
| 误拦截正常业务 | 管理后台 → 攻击日志确认命中规则；将该 URL 加入 `rules/whitelist.url`，IP 加入 `rules/whitelist.ip`，随后热加载 |
| 规则修改未生效 | 向数据平面发 SIGHUP：`sudo systemctl reload bileiwaf` 或 `kill -HUP $(cat logs/bileiwaf.pid)` |
| 大屏无地理来源 | 安装 `libmaxminddb-devel` 与 GeoLite2 数据库，configure 加 `--with-geoip --geoip-db=PATH` 重新编译安装 |

**日志文件一览：**

| 文件 | 内容 |
| --- | --- |
| `logs/waf-access.log` | 全局访问日志 |
| `logs/waf-attack.log` | 攻击拦截日志（时间、IP、规则、载荷） |
| `logs/waf-audit.log` | 管理操作审计 |
| `logs/ai-shadow.log` | AI 影子模式打分记录 |
| `logs/waf-crash.log` | 崩溃自诊断（信号 + 故障地址 + 帧链） |
| `logs/admin.log` | 管理平面日志 |
| `logs/<站点>/` | 各站点 access / error 日志 |

---

**内蒙古勤加软件有限公司 · © 2026 版权所有**
