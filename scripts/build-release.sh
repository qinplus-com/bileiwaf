#!/usr/bin/env bash
# ============================================================
# 壁垒WAF (BileiWAF) 发行构建脚本（源码发行模式）
#
# 产出（dist/ 目录）：
#   bileiwaf-<ver>.tar.gz          源码发行包：./configure && make && make install
#   bileiwaf-<ver>-<rel>.*.x86_64.rpm  RHEL 系 RPM（构建机在目标机原生编译）
#   checksums.sha256               校验和
#
# 用法: ./scripts/build-release.sh
# ============================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VER="$(cat .version 2>/dev/null || echo 1.0.0)"
DIST="$ROOT/dist"

log() { echo "[build] $*"; }

# ---------- 1. 源码发行包 ----------
log "生成源码发行包 ..."
./configure >/dev/null
make dist

TARBALL="$DIST/bileiwaf-${VER}.tar.gz"

# ---------- 2. 干净目录全流程自测：configure && make && make install(DESTDIR) ----------
log "干净目录自测（configure/make/make install DESTDIR）..."
SELFTEST="$(mktemp -d "${TMPDIR:-/tmp}/bileiwaf-selftest.XXXXXX")"
trap 'rm -rf "$SELFTEST"' EXIT
tar xzf "$TARBALL" -C "$SELFTEST"
(
    cd "$SELFTEST/bileiwaf-$VER"
    ./configure --prefix=/opt/bileiwaf >/dev/null
    make -j"$(nproc)" >/dev/null
    make install DESTDIR="$SELFTEST/rootfs" >/dev/null
    # 断言关键文件
    test -x "$SELFTEST/rootfs/opt/bileiwaf/bin/bileiwaf"
    test -x "$SELFTEST/rootfs/opt/bileiwaf/bin/bileiwaf-admin"
    test -x "$SELFTEST/rootfs/opt/bileiwaf/start.sh"
    test -f "$SELFTEST/rootfs/opt/bileiwaf/config/waf.conf"
    test -f "$SELFTEST/rootfs/usr/lib/systemd/system/bileiwaf.service"
    ! grep -q '@WAF_PREFIX@' "$SELFTEST/rootfs/usr/lib/systemd/system/bileiwaf.service"
)
log "自测通过"

# ---------- 3. RPM（源码编译型）----------
if command -v rpmbuild >/dev/null 2>&1; then
    log "构建 RPM ..."
    TOP="$DIST/rpmbuild"
    rm -rf "$TOP"
    mkdir -p "$TOP"/{SOURCES,SPECS,BUILD,RPMS,SRPMS,BUILDROOT}
    cp -a "$TARBALL" "$TOP/SOURCES/"
    cp -a packaging/bileiwaf.spec "$TOP/SPECS/"
    rpmbuild -bb --define "_topdir $TOP" \
             --define "debug_package %{nil}" \
             "$TOP/SPECS/bileiwaf.spec" >/tmp/bileiwaf-rpmbuild.log 2>&1 || {
        echo "rpmbuild 失败，末尾日志：" >&2
        tail -20 /tmp/bileiwaf-rpmbuild.log >&2
        exit 1
    }
    find "$TOP/RPMS" -name '*.rpm' -exec cp -a {} "$DIST/" \;
    log "RPM 构建完成"
else
    log "rpmbuild 不可用，跳过 RPM"
fi

# ---------- 4. 校验和与汇总 ----------
ARTIFACTS="$(find "$DIST" -maxdepth 1 \( -name '*.tar.gz' -o -name '*.rpm' \) -printf '%f\n' | sort)"
( cd "$DIST" && echo "$ARTIFACTS" | xargs sha256sum ) > "$DIST/checksums.sha256"

log "============================================================"
log "发行产物（$DIST）："
ls -lh "$DIST"/*.tar.gz "$DIST"/*.rpm 2>/dev/null | awk '{print "  "$5"\t"$9}'
log "校验和: $DIST/checksums.sha256"
log "============================================================"
