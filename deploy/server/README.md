# HyperTide Server Deployment

This directory contains the server-only deployment entrypoints for HyperTide.

## What lives here

- `Dockerfile`: backend image build for `hypertide-server`
- `docker-compose.yml`: PostgreSQL + JWT key bootstrap + backend service
- `.env.example`: server deployment environment template
- `smoke.ps1`: wrapper for the existing runtime smoke workflow

## Quick Start

```powershell
docker compose -f deploy/server/docker-compose.yml --env-file deploy/server/.env.example up -d --build
powershell -ExecutionPolicy Bypass -File .\deploy\server\smoke.ps1
```

## What this deploys

- `postgres`
- `jwt-keys`
- `hypertide` backend service

## Operational Endpoints

- `GET /health/live`: process liveness
- `GET /health/ready`: database readiness
- `GET /metrics`: Prometheus-compatible HTTP counters

## Notes

- This is the preferred server deployment entrypoint going forward.
- The backend image is built from `deploy/server/Dockerfile`.
- JWT keys are generated into `deploy/server/keys/`.
- Persistent asset storage remains at the repository-level `storage/` directory.
- `RATE_LIMIT_REQUESTS_PER_MINUTE` defaults to `600`; set `0` only for trusted development environments.
- Production proxy deployments must set `TRUSTED_PROXY_CIDRS`; forwarded client IP headers are ignored unless the direct peer is in one of these CIDRs.
- Prefer `WITNESS_CONFIG_JSON` or `WITNESS_CONFIG_FILE` for witness configuration. Legacy `WITNESS_KEYS` remains supported for compatibility.
- For production, set `APP_ENV=production`, replace the example database password, pepper, JWT keys, witness secrets, and high-risk signing secret.
