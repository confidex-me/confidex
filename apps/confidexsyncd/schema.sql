CREATE TABLE IF NOT EXISTS sync_locks (
    id TEXT PRIMARY KEY,
    vault_id TEXT NOT NULL,
    public_key TEXT NOT NULL,
    blob TEXT NOT NULL,
    signature TEXT NOT NULL,
    previous TEXT NOT NULL,
    cursor BIGINT NOT NULL DEFAULT 0 CHECK(cursor >= 0),
    commit_token TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS sync_records (
    lock_id TEXT NOT NULL REFERENCES sync_locks(id),
    sequence BIGINT NOT NULL CHECK(sequence > 0),
    revision TEXT NOT NULL,
    record_id TEXT NOT NULL,
    blob TEXT NOT NULL,
    size BIGINT NOT NULL CHECK(size > 0 AND size <= 4065668),
    PRIMARY KEY(lock_id, revision),
    UNIQUE(lock_id, sequence)
);
