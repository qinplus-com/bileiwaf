#!/bin/sh
# 生成源码发行包 dist/bileiwaf-<ver>.tar.gz
# 内容为"可 configure && make && make install"的干净源码树：
# 不含生产 config/、build/、bin/、logs/、dist/ 与个人/生产白名单。
set -eu

VER="${1:-$(cat .version 2>/dev/null || echo 1.0.0)}"
NAME="bileiwaf-${VER}"
OUT="$(pwd)/dist"
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/$NAME.XXXXXX")/$NAME"

mkdir -p "$STAGE" "$OUT"

# 源码与构建脚本
cp -a configure Makefile.in waf start.sh stop.sh .version "$STAGE"/
cp -a src include admin "$STAGE"/
rm -f "$STAGE/include/waf_config.h" "$STAGE/include/version.h"
# 默认（通用）安装配置
cp -a etc "$STAGE/etc"
# 规则 / AI 模型槽位 / Web 资源
cp -a rules models web adminui "$STAGE"/
# v1.2.0：旧 64 槽 LR 蒸馏模型（ai_model.dat.*）在线检测已弃用，不再打包；
# 仅随包发布双通道模型（ai_cnn.dat / ai_ae.dat / ai_fusion.dat）
rm -f "$STAGE"/models/ai_model.dat.*
# 打包辅助
mkdir -p "$STAGE/scripts" "$STAGE/packaging"
cp -a scripts/mkdist.sh scripts/build-release.sh "$STAGE/scripts/"
cp -a packaging/bileiwaf.service.in packaging/bileiwaf.spec "$STAGE/packaging/"

# 白名单重置为回环（剥离生产 IP）
cat > "$STAGE/rules/whitelist.ip" <<'EOF'
# 白名单 IP（每行一个，# 开头为注释）
# 命中白名单的 IP 豁免 CC 限流/黑名单，规则与 AI 检测仍然生效
127.0.0.1
::1
EOF

# 空运行目录占位
mkdir -p "$STAGE/logs" "$STAGE/data" "$STAGE/certs"

tar -C "$(dirname "$STAGE")" -czf "$OUT/$NAME.tar.gz" "$NAME"
rm -rf "$(dirname "$STAGE")"
echo "[dist] $OUT/$NAME.tar.gz"
