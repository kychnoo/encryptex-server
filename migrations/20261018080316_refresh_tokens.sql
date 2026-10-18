ALTER TABLE sessions
    ADD COLUMN prev_token TEXT,
    ADD COLUMN prev_token_valid_until TIMESTAMPTZ;

CREATE INDEX idx_sessions_prev_token ON sessions(prev_token);
