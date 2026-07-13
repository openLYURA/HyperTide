ALTER TABLE locks DROP CONSTRAINT IF EXISTS locks_pkey;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'locks_repo_scope_path'
          AND conrelid = 'locks'::regclass
    ) THEN
        ALTER TABLE locks ADD CONSTRAINT locks_repo_scope_path
            UNIQUE (repo_id, scope, file_path);
    END IF;
END $$;
