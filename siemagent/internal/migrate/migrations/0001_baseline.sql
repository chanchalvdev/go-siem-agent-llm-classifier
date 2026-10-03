-- Baseline: the schema as it stood before versioned migrations.
-- Statements stay idempotent so databases created by the old start-up
-- schema files adopt this version without changes.

-- ---- store
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

-- Analyst overrides of detection rules (enable/disable).
CREATE TABLE IF NOT EXISTS rule_states (
    rule_id    TEXT        PRIMARY KEY,
    enabled    BOOLEAN     NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---- incident
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

-- ---- response
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

-- ---- auth
CREATE TABLE IF NOT EXISTS users (
    id            TEXT        PRIMARY KEY,
    username      TEXT        NOT NULL UNIQUE,
    display_name  TEXT        NOT NULL DEFAULT '',
    role          TEXT        NOT NULL,
    disabled      BOOLEAN     NOT NULL DEFAULT false,
    password_hash BYTEA       NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL,
    last_login_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT        PRIMARY KEY,
    user_id    TEXT        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions (user_id);
CREATE INDEX IF NOT EXISTS sessions_expires_idx ON sessions (expires_at);

CREATE TABLE IF NOT EXISTS audit_log (
    id     BIGSERIAL   PRIMARY KEY,
    at     TIMESTAMPTZ NOT NULL,
    actor  TEXT        NOT NULL,
    action TEXT        NOT NULL,
    target TEXT        NOT NULL DEFAULT '',
    status INTEGER     NOT NULL DEFAULT 0,
    ip     TEXT        NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS audit_log_at_idx ON audit_log (at DESC);
CREATE INDEX IF NOT EXISTS audit_log_actor_idx ON audit_log (actor, at DESC);
