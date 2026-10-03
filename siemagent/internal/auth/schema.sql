-- Applied on every start; every statement must stay idempotent.
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
