# HyperTide Self-Hosting Guide

This guide describes the first production self-hosted deployment target for HyperTide Community Edition: a single-node Docker Compose installation for a VPS or internal server.

Kubernetes, Helm, S3/MinIO object storage, external SSO, and multi-node HA are planned follow-ups. They are not required for the `v0.2.0-self-hosted` baseline.

## Production Shape

The production Compose stack contains:

- `postgres`: authoritative metadata for repos, branches, changesets, locks, audit, sessions, and checkpoints.
- `hypertide`: the server API, running as a non-root user with `STORAGE_PATH=/app/storage`.
- `caddy`: TLS reverse proxy. Production deployments should expose Caddy, not the raw `:3000` server port.
- Persistent host directories under `deploy/server/data`, `deploy/server/keys`, and `deploy/server/backups`.

Production data boundaries:

- Postgres is the source of truth for metadata.
- `data/storage/objects` is the source of truth for CAS blobs.
- `keys/` and `.env.production` contain operational secrets and must be backed up and protected.

## Minimum Host

- Ubuntu 22.04 or 24.04 LTS.
- Docker Engine and Docker Compose plugin.
- A DNS record pointing to the host.
- Open inbound ports `80` and `443`.
- Enough disk for Postgres plus CAS storage. Start with at least 2x expected asset size so backup and restore drills fit on the same host.

## First Install

From `deploy/server`:

```bash
cp .env.production.example .env.production
cp Caddyfile.example Caddyfile
mkdir -p data/postgres data/storage data/caddy data/caddy-config keys backups
sudo chown -R 10001:65534 data/storage backups
```

Generate production secrets. Do not use any `CHANGE_ME` value:

```bash
openssl rand -base64 48
openssl rand -base64 48
openssl rand -base64 48
openssl genrsa -out keys/jwt-private.pem 2048
openssl rsa -in keys/jwt-private.pem -pubout -out keys/jwt-public.pem
```

Create `keys/witness-config.json`:

```json
{
  "witnesses": [
    {
      "id": "w1",
      "secret": "CHANGE_ME_RANDOM_WITNESS_SECRET_1",
      "scope": "primary",
      "environment": "self-hosted"
    },
    {
      "id": "w2",
      "secret": "CHANGE_ME_RANDOM_WITNESS_SECRET_2",
      "scope": "primary",
      "environment": "self-hosted"
    }
  ],
  "quorum": 2,
  "scope": "self-hosted"
}
```

Allow the non-root server container (`10001:65534`) to read mounted key material while keeping write access on the host:

```bash
sudo chown -R 10001:65534 keys
sudo chmod 0750 keys
sudo chmod 0640 keys/jwt-private.pem keys/witness-config.json
sudo chmod 0644 keys/jwt-public.pem
```

Edit `.env.production`:

- Set `HYPERTIDE_PUBLIC_HOST` and `CORS_ALLOWED_ORIGINS` to the real HTTPS origin.
- Set `POSTGRES_PASSWORD`, `DATABASE_URL`, `MASTER_KEY`, `AUTH_PEPPER`, and `HIGH_RISK_SIGNING_SECRET`.
- Keep `APP_ENV=production`, `HIGH_RISK_SIGNATURE_REQUIRED=true`, and `LOG_FORMAT=json`.

Validate the server-side configuration contract before starting:

```bash
cargo run -p hypertide-cli --bin ht -- server doctor --env-file deploy/server/.env.production
```

Start the stack:

```bash
docker compose -f docker-compose.prod.yml --env-file .env.production up -d
docker compose -f docker-compose.prod.yml --env-file .env.production ps
```

Check readiness:

```bash
curl -fsS https://hypertide.example.com/health/live
curl -fsS https://hypertide.example.com/health/ready
curl -fsS https://hypertide.example.com/metrics
```

Run the smoke script:

```bash
BASE_URL=https://hypertide.example.com ./smoke.sh
```

## Required Production Contract

Production startup must reject unsafe configuration. These settings are required:

- `APP_ENV=production`
- `DATABASE_URL`
- `MASTER_KEY`
- `AUTH_PEPPER`
- `JWT_PRIVATE_KEY_PATH`
- `JWT_PUBLIC_KEY_PATH`
- `HIGH_RISK_SIGNATURE_REQUIRED=true`
- `HIGH_RISK_SIGNING_SECRET`
- `WITNESS_CONFIG_JSON` or `WITNESS_CONFIG_FILE`
- `CORS_ALLOWED_ORIGINS`
- `RATE_LIMIT_REQUESTS_PER_MINUTE`
- `STORAGE_PATH`

Optional capacity tuning:

- `MAX_COMPOSED_BLOB_BYTES` defaults to `268435456` (256 MiB). Raise it only when the server has enough memory for in-process blob composition.

Operational rules:

- Terminate TLS at the reverse proxy.
- Do not publish server port `3000` directly to the internet.
- Store `.env.production` and `keys/` outside public repos and ticket attachments.
- Keep backups encrypted when moved off host.

## Backup

Back up before upgrades, migration changes, and security rotations:

```bash
./backup.sh
```

The backup directory contains:

- `postgres.sql`
- `storage.tar.gz`
- `keys.tar.gz` when `keys/` exists
- `manifest.json`
- `SHA256SUMS`

Move completed backups to durable storage. Treat them as sensitive because they may include signing keys and witness configuration.

## Restore

Restore is intentionally conservative. It refuses to restore storage into a non-empty directory and refuses to restore into a database with existing public tables unless explicitly overridden.

```bash
./restore.sh ./backups/20260503T120000Z
sudo chown -R 10001:65534 data/storage keys
sudo chmod -R u+rwX,go-rwx data/storage
sudo chmod 0750 keys
sudo chmod 0640 keys/jwt-private.pem keys/witness-config.json
sudo chmod 0644 keys/jwt-public.pem
```

For Windows operators:

```powershell
.\restore.ps1 -BackupDir .\backups\20260503T120000Z
```

If the target already has data, create a new target directory or host first. Manual data replacement should be reviewed separately; the provided restore scripts do not delete existing data.

## Observability

The server exposes Prometheus metrics at `/metrics`:

- total HTTP requests
- responses by status class
- requests by method, route, and status
- latency histogram buckets
- rate limit rejects

Use `deploy/observability/prometheus.yml` as the scrape example and import `deploy/observability/grafana-dashboard.json` into Grafana.

Production logs default to JSON through `LOG_FORMAT=json`. Each HTTP response receives an `x-request-id` header. Operators should preserve that request id when reporting incidents.

## Storage Consistency

Run the storage consistency check after restores, disk incidents, and before major upgrades:

```bash
./storage-consistency.sh
OUTPUT_FORMAT=json ./storage-consistency.sh
```

The script compares blob-like DB references with files under `data/storage/objects` and reports missing objects and orphan storage objects. It does not delete or repair data.

## Upgrade

Before every upgrade:

1. Read the release notes and migration notes.
2. Run `./backup.sh`.
3. Pull the target image tag.
4. Restart Compose with the explicit version tag.
5. Run `./smoke.sh`.
6. Keep the previous image tag and backup until smoke and real client workflows pass.

Example:

```bash
HYPERTIDE_VERSION=v0.2.0 docker compose -f docker-compose.prod.yml --env-file .env.production up -d
BASE_URL=https://hypertide.example.com ./smoke.sh
```

Rollback uses the previous image tag plus the backup made immediately before the upgrade when schema or data changes require it.
