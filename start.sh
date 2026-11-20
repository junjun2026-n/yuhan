#!/usr/bin/env bash
# ============================================================
# 文件名称：start.sh
# 生成日期：2026-10-27
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：执行 start 对应的启动、构建或运维任务。
#           文件用途：供WAF的 yuhan/start.sh 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [[ "$(uname -s)" != Linux ]]; then
  echo "Deploy on an Ubuntu Linux host with Docker Engine; host NIC access is required." >&2
  exit 1
fi
if ! command -v docker >/dev/null || ! docker compose version >/dev/null 2>&1; then
  echo "Install Docker Engine and Docker Compose v2 first." >&2
  exit 1
fi
if [[ ! -f mgrnic.ini ]]; then
  echo "mgrnic.ini is missing. Configure the management NIC before starting." >&2
  exit 1
fi
mkdir -p runtime
# Read the desired appliance hostname from the persistent database, using the
# existing image before recreating the service. Never evaluate database text.
if docker image inspect qionghai-waf:ubuntu24.04 >/dev/null 2>&1 && [[ -f runtime/waf.sqlite3 ]]; then
  WAF_HOSTNAME=$(docker compose run --rm --no-deps --entrypoint python waf -c 'from waf.store import Store; print(Store().platform_config().hostname)')
  export WAF_HOSTNAME
fi
exec docker compose up -d --build
