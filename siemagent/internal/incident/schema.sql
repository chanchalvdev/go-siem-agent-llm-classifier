-- Applied on every start; every statement must stay idempotent.
CREATE TABLE IF NOT EXISTS incidents (
    id          TEXT        PRIMARY KEY,
    title       TEXT        NOT NULL,
    severity    TEXT        NOT NULL,
    status      TEXT        NOT NULL,
    resolution  TEXT        NOT NULL DEFAULT '',
    assignee    TEXT        NOT NULL DEFAULT '',
    alert_count INTEGER     NOT NULL DEFAULT 0,
    first_seen  TIMESTAMPTZ NOT NULL,
    last_seen   TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL,
    resolved_at TIMESTAMPTZ,
    data        JSONB       NOT NULL
);
CREATE INDEX IF NOT EXISTS incidents_last_seen_idx ON incidents (last_seen DESC);
CREATE INDEX IF NOT EXISTS incidents_status_idx ON incidents (status);

CREATE TABLE IF NOT EXISTS incident_entities (
    incident_id TEXT NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    kind        TEXT NOT NULL,
    value       TEXT NOT NULL,
    PRIMARY KEY (incident_id, kind, value)
);
CREATE INDEX IF NOT EXISTS incident_entities_lookup_idx ON incident_entities (kind, value);

CREATE TABLE IF NOT EXISTS incident_alerts (
    id          BIGSERIAL   PRIMARY KEY,
    incident_id TEXT        NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    at          TIMESTAMPTZ NOT NULL,
    data        JSONB       NOT NULL
);
CREATE INDEX IF NOT EXISTS incident_alerts_incident_idx ON incident_alerts (incident_id, at);

CREATE TABLE IF NOT EXISTS incident_activity (
    id          BIGSERIAL   PRIMARY KEY,
    incident_id TEXT        NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    at          TIMESTAMPTZ NOT NULL,
    actor       TEXT        NOT NULL,
    kind        TEXT        NOT NULL,
    body        TEXT        NOT NULL
);
CREATE INDEX IF NOT EXISTS incident_activity_incident_idx ON incident_activity (incident_id, at);
