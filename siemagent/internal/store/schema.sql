-- Applied on every start; every statement must stay idempotent.
CREATE TABLE IF NOT EXISTS events (
    id           BIGSERIAL PRIMARY KEY,
    processed_at TIMESTAMPTZ NOT NULL,
    severity     TEXT        NOT NULL,
    attack_type  TEXT        NOT NULL,
    mitre_tactic TEXT        NOT NULL DEFAULT '',
    hostname     TEXT        NOT NULL DEFAULT '',
    source       TEXT        NOT NULL DEFAULT '',
    data         JSONB       NOT NULL
);

CREATE INDEX IF NOT EXISTS events_processed_at_idx ON events (processed_at DESC);
CREATE INDEX IF NOT EXISTS events_severity_idx ON events (severity);
