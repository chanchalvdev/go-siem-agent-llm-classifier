-- Applied on every start; every statement must stay idempotent.
CREATE TABLE IF NOT EXISTS response_actions (
    id          TEXT        PRIMARY KEY,
    dedup_key   TEXT        NOT NULL UNIQUE,
    incident_id TEXT        NOT NULL,
    status      TEXT        NOT NULL,
    proposed_at TIMESTAMPTZ NOT NULL,
    data        JSONB       NOT NULL
);
CREATE INDEX IF NOT EXISTS response_actions_incident_idx ON response_actions (incident_id);
CREATE INDEX IF NOT EXISTS response_actions_status_idx ON response_actions (status, proposed_at DESC);
