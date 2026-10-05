-- Indexes the retention purge filters on.
CREATE INDEX IF NOT EXISTS incidents_resolved_at_idx ON incidents (resolved_at) WHERE status = 'resolved';
CREATE INDEX IF NOT EXISTS response_actions_proposed_at_idx ON response_actions (proposed_at);
