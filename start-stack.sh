#!/usr/bin/env bash
# ============================================================
# 文件名称：start-stack.sh
# 生成日期：2026-10-28
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：执行 start-stack 对应的启动、构建或运维任务。
#           文件用途：供WAF的 yuhan/start-stack.sh 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [[ "$(uname -s)" != Linux ]]; then
  echo 'Use Ubuntu with Docker Engine and Compose v2.' >&2
  exit 1
fi
docker compose version >/dev/null
[[ -f mgrnic.ini ]] || { echo 'Configure mgrnic.ini first.' >&2; exit 1; }
umask 077
mkdir -p runtime-stack .stack-secrets
if [[ ! -f .stack-secrets/postgres-password ]]; then
  # Never generate a replacement password for an already initialized DB volume.
  if [[ -n "$(docker volume ls -q --filter label=com.docker.compose.project=qionghai-waf-stack --filter label=com.docker.compose.volume=postgres_data)" ]]; then
    echo 'Database volume exists but password file is missing. Restore .stack-secrets/postgres-password from backup.' >&2
    exit 1
  fi
  od -An -N32 -tx1 /dev/urandom | tr -d ' \n' > .stack-secrets/postgres-password
fi
[[ -s .stack-secrets/postgres-password ]] || { echo 'Database password file is empty.' >&2; exit 1; }
exec docker compose -f compose.stack.yaml up -d --build
