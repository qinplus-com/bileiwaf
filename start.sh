#!/usr/bin/env bash
# 兼容入口：等价于 ./waf start "$@"（历史 cron/systemd/用户习惯保留）
# 新用法请直接使用 ./waf start|stop|status|restart
set -u
cd "$(dirname "$0")" || exit 1
exec ./waf start "$@"
