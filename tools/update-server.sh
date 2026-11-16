#!/usr/bin/env bash
set -euo pipefail
umask 077
cd /opt/waf
archive=$1
digest=$2
release=$3
[[ "$release" =~ ^[0-9]{8}T[0-9]{6}Z$ ]]
[[ "$digest" =~ ^[a-f0-9]{64}$ ]]
printf '%s  %s\n' "$digest" "$archive" | sha256sum -c -
exec 9>/opt/waf/runtime/deployment.lock
flock -n 9 || { echo 'Another WAF deployment is running.'; exit 1; }
backup="runtime/deployment-backups/$release"
mkdir -p "$backup"
container=$(docker compose ps -q waf)
test -n "$container"
previous=$(docker inspect "$container" --format '{{.Image}}')
export WAF_HOSTNAME=$(docker inspect "$container" --format '{{.Config.Hostname}}')
docker image tag "$previous" "qionghai-waf:rollback-$release"
tar -czf "$backup/source.tar.gz" waf static docs Dockerfile compose.yaml .dockerignore start.sh stop.sh requirements-runtime.lock requirements-linux.txt
# Consistent logical database snapshot before updating code; contains no key files.
docker compose exec -T -e WAF_RELEASE_BACKUP="$release" waf python - <<'PY'
import json,os
from pathlib import Path
from waf.store import Store
from waf.network import adapters, network_status
from waf.migrate import TABLES
store=Store()
path=Path('/app/runtime/deployment-backups')/os.environ['WAF_RELEASE_BACKUP']/'database.json'
with store.connect() as db:
    # Store may read timeout configuration when opening PostgreSQL connections.
    # End that read transaction before requesting the snapshot isolation level.
    db.rollback()
    db.execute('BEGIN' if store.engine=='sqlite' else 'SET TRANSACTION ISOLATION LEVEL REPEATABLE READ')
    snapshot={table:[dict(row) for row in db.execute(f'SELECT * FROM {table} ORDER BY id').fetchall()] for table in TABLES}
path.write_text(json.dumps({'engine':store.engine,'tables':snapshot},ensure_ascii=False),encoding='utf-8')
path.chmod(0o600)
status=network_status(store.network(),adapters())
missing=store.network().deployment_mode in ('bypass','inline') and any(not item.physical_id for item in store.network().interfaces if item.role=='business')
path.with_name('preexisting-inactive.json').write_text(json.dumps({'unbound_business':missing,'network':store.network().model_dump()}))
PY
runtime_items=()
for item in runtime/admin.env runtime/database.env runtime/tls mgrnic.ini .env; do
  if [[ -e "$item" ]]; then runtime_items+=("$item"); fi
done
tar -czf "$backup/runtime-config.tar.gz" "${runtime_items[@]}"
rollback() {
  trap - ERR
  echo 'Update failed; restoring previous WAF source and image.'
  tar -xzf "$backup/source.tar.gz" -C /opt/waf
  docker image tag "$previous" qionghai-waf:ubuntu24.04
  docker compose up -d --no-build --pull never waf
  echo "Previous code/image restored; database was not overwritten. Backups: /opt/waf/$backup"
  exit 1
}
trap rollback ERR
# Release archive excludes runtime, .env and mgrnic.ini by construction.
tar -xzf "$archive" -C /opt/waf
bash -n start.sh start-stack.sh
docker compose config --quiet
docker compose --progress plain build waf >"$backup/build.log" 2>&1
docker compose up -d --no-build --pull never waf
for attempt in $(seq 1 60); do
  container=$(docker compose ps -q waf)
  state=$(docker inspect "$container" --format '{{.State.Health.Status}}')
  if [[ "$state" == healthy ]]; then break; fi
  # A pre-existing unbound data plane cannot become healthy through a code update.
  # Verify the core service and unchanged NIC config, while retaining degraded status.
  if docker compose exec -T -e WAF_RELEASE_BACKUP="$release" waf python - <<'PY'
import json,os
from pathlib import Path
from dotenv import load_dotenv
import httpx
load_dotenv('/app/runtime/admin.env')
prior=json.loads((Path('/app/runtime/deployment-backups')/os.environ['WAF_RELEASE_BACKUP']/'preexisting-inactive.json').read_text())
if not prior['unbound_business']: raise SystemExit(1)
with httpx.Client(trust_env=False,timeout=5,auth=(os.getenv('WAF_ADMIN_USER','admin'),os.environ['WAF_ADMIN_PASSWORD']),headers={'X-WAF-Probe':os.environ['WAF_ADMIN_PASSWORD']}) as client:
    network=client.get('http://127.0.0.1:8301/api/system');network.raise_for_status()
    assert network.json()==prior['network']
    status=client.get('http://127.0.0.1:8301/api/system/status');status.raise_for_status()
    tls=client.get('http://127.0.0.1:8301/api/tls');tls.raise_for_status()
    assert not tls.json()['enabled'] or tls.json()['running']
    assert client.get('http://127.0.0.1:8300/').status_code<500 or not client.get('http://127.0.0.1:8301/api/settings').json()['upstream']
PY
  then
    state=degraded-preexisting-unbound-nic
    echo 'Core service verified. Existing unbound business NIC configuration retained; data plane remains inactive.'
    break
  fi
  if [[ "$state" == unhealthy ]]; then false; fi
  sleep 2
done
[[ "$state" == healthy || "$state" == degraded-preexisting-unbound-nic ]]
if [[ "$state" == healthy ]]; then docker compose exec -T waf python -m waf.healthcheck; fi
image=$(docker inspect "$container" --format '{{.Image}}')
printf 'release=%s\nsource_sha256=%s\nimage=%s\n' "$release" "$digest" "$image" >"$backup/release.txt"
mkdir -p packages
docker image save qionghai-waf:ubuntu24.04 | gzip -1 >packages/qionghai-waf-ubuntu24.04.tar.gz
tar -czf packages/waf-deploy-files.tar.gz Dockerfile compose.yaml compose.stack.yaml .dockerignore .env mgrnic.ini start.sh start-stack.sh stop.sh requirements-runtime.lock requirements-linux.txt waf static docs tools README.md
(cd packages; sha256sum qionghai-waf-ubuntu24.04.tar.gz waf-deploy-files.tar.gz >WAF-SHA256SUMS; sha256sum -c WAF-SHA256SUMS)
docker image inspect qionghai-waf:ubuntu24.04 --format '{{.Id}}' >packages/WAF-IMAGE-ID
trap - ERR
rm -f -- "$archive"
echo "Updated release=$release image=$image health=$state backup=/opt/waf/$backup"
