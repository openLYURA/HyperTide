-- Optimistic concurrency guard for repo state persistence.
-- Lets replace_repo_state reject a write when another writer advanced the repo
-- since this process last persisted it, turning a silent lost update into a
-- detectable conflict.
ALTER TABLE repos
    ADD COLUMN IF NOT EXISTS state_version BIGINT NOT NULL DEFAULT 0;
