Name:          bileiwaf
Version:       1.0.4
Release:       1%{?dist}
Summary:       BileiWAF - 一体化 Web 应用防火墙（反向代理 + 规则引擎）
License:       Apache-2.0
URL:           https://dbask.cn
BuildArch:     x86_64
Source0:       %{name}-%{version}.tar.gz

BuildRequires: gcc
BuildRequires: make
BuildRequires: openssl-devel
BuildRequires: libcurl-devel
BuildRequires: json-c-devel
# 目标机运行依赖（openssl-libs/libcurl/json-c 由 rpm 自动按 soname 生成）
Requires:      systemd
Requires(post): systemd

%description
壁垒WAF（BileiWAF）是前置部署的一体化 Web 应用防火墙：反向代理架构 +
规则引擎（SQLi/XSS/命令注入/路径穿越/XXE/SSRF 等 1,100+ 条规则）+
AI 影子评分。本 RPM 从源码编译安装至 /opt/bileiwaf（./configure && make &&
make install），包含 systemd 单元（默认不自启）。

%prep
%setup -q -n %{name}-%{version}

%build
./configure --prefix=/opt/bileiwaf
make %{?_smp_mflags}

%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}
# RPM 管理现场配置为 noreplace：把安装树中的默认配置改名为 .default 参考副本，
# 真正的 config 由 %files 以 %%config(noreplace) 接管
cd %{buildroot}/opt/bileiwaf/config
for f in *.conf; do cp -a "$f" "$f.default"; done
cd sites
for f in *.conf; do cp -a "$f" "$f.default"; done

%post
systemctl daemon-reload >/dev/null 2>&1 || true
if [ $1 -eq 1 ]; then
    echo "壁垒WAF 已安装到 /opt/bileiwaf"
    echo "启动: /opt/bileiwaf/start.sh  或  systemctl enable --now bileiwaf"
fi

%preun
# 只通过本安装目录的 stop.sh 按 pid 文件停止本实例；
# 禁止 systemctl stop bileiwaf——目标机上可能存在同名生产单元（/etc/systemd/system），
# systemctl 操作会误伤其它部署。
if [ $1 -eq 0 ] && [ -x /opt/bileiwaf/stop.sh ]; then
    cd /opt/bileiwaf && ./stop.sh >/dev/null 2>&1 || true
fi

%postun
if [ $1 -eq 0 ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

%files
%defattr(-,root,root,-)
%dir /opt/bileiwaf
/opt/bileiwaf/bin/
/opt/bileiwaf/waf
/opt/bileiwaf/start.sh
/opt/bileiwaf/stop.sh
%dir /opt/bileiwaf/logs
%dir /opt/bileiwaf/data
%dir /opt/bileiwaf/certs
/opt/bileiwaf/web/
/opt/bileiwaf/adminui/
/opt/bileiwaf/models/
/opt/bileiwaf/rules/
# 现场配置升级不覆盖；*.default 始终更新为发行默认参考
%config(noreplace) /opt/bileiwaf/config/waf.conf
%config(noreplace) /opt/bileiwaf/config/admin.conf
%config(noreplace) /opt/bileiwaf/config/sites.conf
%config(noreplace) /opt/bileiwaf/config/sites/demo.local.conf
/opt/bileiwaf/config/*.default
/opt/bileiwaf/config/sites/*.default
/usr/lib/systemd/system/bileiwaf.service

%changelog
* Thu Oct 22 2026 BileiWAF Team <dev@dbask.cn> - 1.0.4-1
- 修复日志轮转后管理后台统计清零：统计纳入保留期内全部轮转归档

* Wed Oct 21 2026 BileiWAF Team <dev@dbask.cn> - 1.0.3-1
- 修复请求总数口径：反代与 403 拦截请求统一写访问日志

* Wed Oct 21 2026 BileiWAF Team <dev@dbask.cn> - 1.0.2-1
- 新增版本号显示：bileiwaf version / waf version / 管理后台 /api/admin/version
- 数据平面本机响应 ACME HTTP-01 挑战，反代站点可正常签发与续期
- Let's Encrypt 续期：certbot 缺失提示、外部续期后自动回填、完整运行日志
- 自签证书重签兼容 el7 OpenSSL 1.0.2

* Wed Oct 21 2026 BileiWAF Team <dev@dbask.cn> - 1.0.1-1
- 修复管理后台登录后刷新/切换页面偶发跳回登录页（分段请求头丢 Cookie）
- 新建站点生成完整站点配置，并自动签发自签证书（含 SAN）
- 新增 waf check / bileiwaf check / bileiwaf -t 配置校验命令
- 自签证书兼容 el7 OpenSSL 1.0.2

* Wed Oct 21 2026 BileiWAF Team <dev@dbask.cn> - 1.0.0-1
- 正式发布 1.0.0：管理后台 RBAC（admin 全功能 / monitor 仅监控大屏）
- 新增自定义 404 页面（error_404_page 配置项）
- 新增日志按大小自动轮转与保留期自动清理
  （log_rotate_size / log_retention_days 配置项）
- 改为源码编译安装（configure/make/make install），依赖随目标机原生解析
- 修复配置/证书路径硬编码与 CLI 参数被站点配置覆盖的问题
