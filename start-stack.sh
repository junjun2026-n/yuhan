#!/usr/bin/env bash
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
