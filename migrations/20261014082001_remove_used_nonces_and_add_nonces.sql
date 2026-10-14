DROP TABLE used_nonces;
CREATE TABLE nonces (
    nonce TEXT PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL
);
