-- IOC watchlists (manual lists and feeds) and hand-added indicators. Feed and
-- file indicators are downloaded/read at start and kept in memory.
CREATE TABLE IF NOT EXISTS watchlists (
    id         TEXT        PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    data       JSONB       NOT NULL
);

CREATE TABLE IF NOT EXISTS watchlist_indicators (
    watchlist_id TEXT        NOT NULL REFERENCES watchlists (id) ON DELETE CASCADE,
    value        TEXT        NOT NULL,
    type         TEXT        NOT NULL,
    note         TEXT        NOT NULL DEFAULT '',
    added_by     TEXT        NOT NULL DEFAULT '',
    added_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    seq          BIGSERIAL,  -- keeps the order indicators were added in
    PRIMARY KEY (watchlist_id, value)
);
