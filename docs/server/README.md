# HyperTide Server 使用指南

`hypertide` 是 HyperTide 的服务端，提供 REST API 处理所有版本操作。

## 快速开始

### 方式一：Docker Compose（推荐）

```bash
cd HyperTide

# 启动服务（PostgreSQL + 服务端）
docker compose -f deploy/server/docker-compose.yml --env-file deploy/server/.env.example up -d

# 验证服务
curl http://localhost:3000/health/ready
# 应返回 READY
```

Docker Compose 会自动：
- 启动 PostgreSQL 15
- 生成 JWT 密钥对
- 运行数据库迁移
- 启动 HyperTide 服务端

### 方式二：从源码运行

```bash
# 1. 准备 PostgreSQL
# 确保有一个运行中的 PostgreSQL 实例，创建数据库：
# createdb hypertide

# 2. 设置环境变量
export DATABASE_URL=postgres://user:password@localhost:5432/hypertide
export MASTER_KEY=your-master-key
export STORAGE_PATH=./storage

# 3. 运行迁移
# （服务端启动时会自动运行迁移）

# 4. 构建并启动
cargo build --release
./target/release/hypertide
```

服务端默认监听 `http://0.0.0.0:3000`。

## 核心概念

### 仓库（Repo）

仓库是 HyperTide 的顶层组织单元。推荐通过 `ht init` 或 `/v2/repos` 显式创建仓库，让新工作区从清晰的 repo/branch 状态开始。

```bash
ht login --server http://localhost:3000 --token dev-master-key
ht init --repo my-game --branch main
```

### API Key

API Key 用于认证 CLI 请求。有两种使用模式：

1. **JWT 模式**（推荐）：用 API Key 换取短期 access_token + 长期 refresh_token
2. **直接模式**：API Key 直接作为认证凭据

### Changeset 生命周期

```
submit → draft → approve → promote → visible
```

- `draft`：刚提交，等待审批
- `approved`：已审批，等待晋升
- `visible`：已晋升为正式可见版本

## API Key 管理

### 生成 API Key

```bash
curl -X POST http://localhost:3000/v2/auth/generate \
  -H "X-API-Key: dev-master-key" \
  -H "Content-Type: application/json" \
  -d '{"name": "developer-1", "permissions": ["upload", "lock"]}'
```

响应：
```json
{
  "success": true,
  "data": {
    "key_id": "key-abc123",
    "api_key": "ht_live_xxxxxxxxxxxx",
    "name": "developer-1",
    "permissions": ["upload", "lock"]
  }
}
```

**注意**：`api_key` 只在创建时返回一次，请妥善保存。

### 列出 API Key

```bash
curl http://localhost:3000/v2/auth/keys \
  -H "X-API-Key: dev-master-key"
```

### 吊销 API Key

```bash
curl -X DELETE http://localhost:3000/v2/auth/revoke \
  -H "X-API-Key: dev-master-key" \
  -H "Content-Type: application/json" \
  -d '{"key_id": "key-abc123"}'
```

### 验证 API Key

```bash
curl http://localhost:3000/v2/auth/verify \
  -H "X-API-Key: ht_live_xxxxxxxxxxxx"
```

## 常用操作

### 创建或查看仓库

```bash
# 通过 CLI
ht repo create my-game --default-branch main --use
ht repo list
ht repo info my-game

# 通过 API
curl -X POST http://localhost:3000/v2/repos \
  -H "X-API-Key: dev-master-key" \
  -H "Content-Type: application/json" \
  -d '{"repo_id": "my-game", "default_branch": "main"}'

curl http://localhost:3000/v2/repos/my-game \
  -H "X-API-Key: dev-master-key"
```

### 创建分支

```bash
# 通过 CLI
ht branch create --repo my-game --name feature/new-assets

# 通过 API
curl -X POST http://localhost:3000/v2/branches \
  -H "X-API-Key: dev-master-key" \
  -H "Content-Type: application/json" \
  -d '{"repo_id": "my-game", "branch": "feature/new-assets"}'
```

### 查看分支列表

```bash
curl http://localhost:3000/v2/branches/my-game \
  -H "X-API-Key: dev-master-key"
```

### 提交资产

完整的提交流程需要先通过 CLI 操作（暂存文件），因为涉及文件上传。CLI 会自动处理：

```bash
ht login --server http://localhost:3000 --token <api-key>
ht init --repo my-game --branch main
ht sync
ht checkout
# 编辑文件...
ht add --file Content/Props/tree.uasset
ht submit --message "update tree"
```

### 查看提交历史

```bash
curl "http://localhost:3000/v2/changesets?repo_id=my-game&branch=main&limit=10" \
  -H "X-API-Key: dev-master-key"
```

## 环境变量

### 数据库

| 变量 | 说明 | 默认值 |
|---|---|---|
| `DATABASE_URL` | PostgreSQL 连接字符串 | 必填 |
| `DB_MAX_CONNECTIONS` | 连接池最大连接数 | `10` |
| `DB_ACQUIRE_TIMEOUT_SECS` | 获取连接超时（秒） | `5` |

### 认证

| 变量 | 说明 | 默认值 |
|---|---|---|
| `MASTER_KEY` | 主密钥（用于生成和管理 API Key） | `dev-master-key` |
| `AUTH_PEPPER` | API Key 哈希 pepper | `hypertide-dev-pepper` |
| `JWT_ISSUER` | JWT 签发者 | `hypertide` |
| `JWT_PRIVATE_KEY_PATH` | JWT 私钥路径 | 自动生成 |
| `JWT_PUBLIC_KEY_PATH` | JWT 公钥路径 | 自动生成 |
| `ACCESS_TOKEN_TTL_SECS` | access_token 有效期（秒） | `900`（15 分钟） |
| `REFRESH_TOKEN_TTL_SECS` | refresh_token 有效期（秒） | `604800`（7 天） |

### 存储

| 变量 | 说明 | 默认值 |
|---|---|---|
| `STORAGE_PATH` | 文件存储路径 | `./storage` |
| `MAX_COMPOSED_BLOB_BYTES` | 单次 manifest 合成的最大字节数 | `268435456` |

### 安全

| 变量 | 说明 | 默认值 |
|---|---|---|
| `APP_ENV` | 运行环境 | `development` |
| `HIGH_RISK_SIGNATURE_REQUIRED` | 是否要求高风险操作签名 | `false` |
| `HIGH_RISK_SIGNING_SECRET` | 高风险操作签名密钥 | `hypertide-dev-signing-secret` |
| `WITNESS_KEYS` | 见证者密钥列表 | 无 |
| `CORS_ALLOWED_ORIGINS` | CORS 允许的来源 | `*`（开发环境） |

### 日志

| 变量 | 说明 | 默认值 |
|---|---|---|
| `RUST_LOG` | 日志级别 | `hypertide=info` |

## 生产环境配置

生产环境（`APP_ENV=production`）有强制安全要求：

```bash
APP_ENV=production
MASTER_KEY=<随机生成的强密钥>
AUTH_PEPPER=<随机生成的 pepper>
HIGH_RISK_SIGNATURE_REQUIRED=true
HIGH_RISK_SIGNING_SECRET=<随机生成的签名密钥>
WITNESS_KEYS=w1:<secret>:region-a
CORS_ALLOWED_ORIGINS=https://your-domain.com
```

**必须满足以下条件**：
- `MASTER_KEY` 不能是 `dev-master-key`
- `AUTH_PEPPER` 不能是 `hypertide-dev-pepper`
- `HIGH_RISK_SIGNING_SECRET` 不能是开发默认值
- `WITNESS_KEYS` 不能包含 `dev-secret-`
- `CORS_ALLOWED_ORIGINS` 不能为空

## 数据库迁移

服务端启动时自动运行所有待执行的迁移。迁移文件位于 `migrations/` 目录。

手动运行迁移：

```bash
# 使用 sqlx-cli
cargo install sqlx-cli
sqlx migrate run --source migrations
```

回滚最后一个迁移：

```bash
sqlx migrate revert --source migrations
```

## 健康检查

```bash
# 就绪检查
curl http://localhost:3000/health/ready
# READY
```

## API 端点总览

| 路径 | 方法 | 说明 |
|---|---|---|
| **认证** | | |
| `/v2/auth/generate` | POST | 生成 API Key |
| `/v2/auth/verify` | GET | 验证 API Key |
| `/v2/auth/exchange-key` | POST | API Key 换 JWT |
| `/v2/auth/refresh` | POST | 刷新 JWT |
| `/v2/auth/keys` | GET | 列出 API Key |
| `/v2/auth/revoke` | DELETE | 吊销 API Key |
| `/v2/auth/revoke-refresh` | POST | 吊销 refresh token |
| **仓库** | | |
| `/v2/repos` | GET | 列出仓库 |
| `/v2/repos` | POST | 创建仓库 |
| `/v2/repos/{repo}` | GET | 查看仓库详情 |
| **分支** | | |
| `/v2/branches/{repo}` | GET | 列出分支 |
| `/v2/branches` | POST | 创建分支 |
| **版本** | | |
| `/v2/changesets` | POST | 提交 changeset |
| `/v2/history/{repo}` | GET | 查看历史 |
| `/v2/changesets/{id}/gate` | GET | 检查晋升就绪 |
| `/v2/changesets/{id}/approve` | POST | 审批 |
| `/v2/changesets/{id}/promote` | POST | 晋升 |
| `/v2/rollback` | POST | 回滚 |
| `/v2/sync/{repo}` | GET | 同步快照 |
| **存储** | | |
| `/v2/storage/upload` | POST | 上传文件 |
| `/v2/storage/download/{hash}` | GET | 下载文件 |
| `/v2/storage/exists/{hash}` | GET | 检查文件存在 |
| `/v2/storage/hash` | POST | 计算哈希 |
| `/v2/blobs/chunks/{hash}` | PUT | 上传分块 |
| `/v2/blobs/missing` | POST | 查询缺失分块 |
| `/v2/blobs/compose` | POST | 组合分块为 blob |
| `/v2/manifests` | POST | 创建 manifest |
| **锁** | | |
| `/v2/locks` | GET | 列出锁 |
| `/v2/locks/acquire` | POST | 获取锁 |
| `/v2/locks/release` | POST | 释放锁 |
| `/v2/locks/renew` | POST | 续期锁 |
| `/v2/locks/force-release` | POST | 强制释放锁 |
| **会话** | | |
| `/v2/sessions` | POST | 创建会话 |
| `/v2/sessions/{id}/save` | POST | 保存进度 |
| `/v2/sessions/{id}/checkpoints` | POST | 创建检查点 |
| `/v2/sessions/{id}/checkpoints` | GET | 列出检查点 |
| `/v2/checkpoints/{id}/snapshot` | GET | 获取检查点快照 |
| **治理** | | |
| `/v2/trust/checkpoints/generate` | POST | 生成系统状态证明 |
| `/v2/trust/checkpoints/latest` | GET | 获取最新证明 |
| `/v2/trust/checkpoints/{id}/witness/attest` | POST | 见证者签名 |
| `/v2/trust/witness/summary` | GET | 见证者摘要 |
| `/v2/trust/witness/topology` | GET | 见证者拓扑 |
| `/v2/trust/audit/verify` | POST | 审计链验证 |
| `/v2/trust/audit/export` | GET | 审计链导出 |
| `/v2/trust/replay/verify` | POST | 回放验证 |
| `/v2/trust/replay/readiness` | GET | 回放就绪检查 |
| `/v2/trust/retention/policy` | GET | 保留策略 |

详见 [OpenAPI 规格](../api/openapi.yaml)。
