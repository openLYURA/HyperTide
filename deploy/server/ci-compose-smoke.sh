#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-hypertide_ci}"
export COMPOSE_PROJECT_NAME
COMPOSE_FILES=(-f "$SCRIPT_DIR/docker-compose.prod.yml" -f "$SCRIPT_DIR/docker-compose.ci.yml")
ENV_FILE="$SCRIPT_DIR/.env.production"

dump_compose_diagnostics() {
  echo "::group::compose ps"
  docker compose "${COMPOSE_FILES[@]}" --env-file "$ENV_FILE" ps || true
  echo "::endgroup::"

  echo "::group::compose logs"
  docker compose "${COMPOSE_FILES[@]}" --env-file "$ENV_FILE" logs --no-color postgres hypertide || true
  echo "::endgroup::"
}

trap 'status=$?; if [[ $status -ne 0 ]]; then dump_compose_diagnostics; fi; exit $status' EXIT

mkdir -p "$SCRIPT_DIR/data/postgres" "$SCRIPT_DIR/data/storage" "$SCRIPT_DIR/keys" "$SCRIPT_DIR/backups"
chmod -R 777 "$SCRIPT_DIR/data" "$SCRIPT_DIR/backups"

openssl genrsa -out "$SCRIPT_DIR/keys/jwt-private.pem" 2048 >/dev/null 2>&1
openssl rsa -in "$SCRIPT_DIR/keys/jwt-private.pem" -pubout -out "$SCRIPT_DIR/keys/jwt-public.pem" >/dev/null 2>&1
cat > "$SCRIPT_DIR/keys/witness-config.json" <<JSON
{
  "witnesses": [
    {"id": "w1", "secret": "ci-witness-secret-1", "scope": "ci", "environment": "ci"},
    {"id": "w2", "secret": "ci-witness-secret-2", "scope": "ci", "environment": "ci"}
  ],
  "quorum": 2,
  "scope": "ci"
}
JSON
chmod 0644 "$SCRIPT_DIR/keys/jwt-private.pem" "$SCRIPT_DIR/keys/jwt-public.pem" "$SCRIPT_DIR/keys/witness-config.json"

# CI calls the published application port directly and does not run Caddy.
# Keep production validation enabled without trusting arbitrary proxy networks.
cat > "$SCRIPT_DIR/.env.production" <<ENV
APP_ENV=production
RUST_LOG=info,tower_http=info
LOG_FORMAT=json
POSTGRES_DB=hypertide
POSTGRES_USER=hypertide
POSTGRES_PASSWORD=ci-postgres-password
DATABASE_URL=postgres://hypertide:ci-postgres-password@postgres:5432/hypertide
MASTER_KEY=ci-master-key-32-plus-bytes-not-dev
AUTH_PEPPER=ci-auth-pepper-32-plus-bytes-not-dev
JWT_PRIVATE_KEY_PATH=/app/keys/jwt-private.pem
JWT_PUBLIC_KEY_PATH=/app/keys/jwt-public.pem
HIGH_RISK_SIGNATURE_REQUIRED=true
HIGH_RISK_SIGNING_SECRET=ci-high-risk-signing-secret-32-plus
WITNESS_CONFIG_FILE=/app/keys/witness-config.json
CORS_ALLOWED_ORIGINS=https://hypertide-ci.example.com
TRUSTED_PROXY_CIDRS=127.0.0.1/32,::1/128
RATE_LIMIT_REQUESTS_PER_MINUTE=600
STORAGE_PATH=/app/storage
HYPERTIDE_VERSION=ci
HYPERTIDE_PUBLIC_HOST=hypertide-ci.example.com
ENV

docker compose \
  "${COMPOSE_FILES[@]}" \
  --env-file "$ENV_FILE" \
  up -d --build postgres hypertide

BASE_URL=http://127.0.0.1:3000 bash "$SCRIPT_DIR/smoke.sh"
bash "$SCRIPT_DIR/backup.sh"
bash "$SCRIPT_DIR/storage-consistency.sh"
