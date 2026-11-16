#!/usr/bin/env bash
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
