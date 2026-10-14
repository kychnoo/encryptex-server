ALTER TABLE sessions ADD COLUMN public_key TEXT;
CREATE TABLE used_nonces (
    nonce TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
