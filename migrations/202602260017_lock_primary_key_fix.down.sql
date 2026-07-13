DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM locks
        GROUP BY file_path
        HAVING COUNT(*) > 1
    ) THEN
        RAISE EXCEPTION 'cannot restore locks_pkey while duplicate file_path values exist';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'locks_pkey'
          AND conrelid = 'locks'::regclass
    ) THEN
        ALTER TABLE locks ADD CONSTRAINT locks_pkey PRIMARY KEY (file_path);
    END IF;
END $$;
