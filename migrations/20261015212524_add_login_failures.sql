CREATE TABLE login_failures (
    id UUID PRIMARY KEY,
    username TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_login_failures_username ON login_failures(username, created_at)
