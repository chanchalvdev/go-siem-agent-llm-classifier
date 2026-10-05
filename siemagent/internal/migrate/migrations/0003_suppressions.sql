-- Alert suppressions (snoozed noisy sources). Hit counts are kept in memory.
CREATE TABLE IF NOT EXISTS suppressions (
    id         TEXT        PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    data       JSONB       NOT NULL
);
