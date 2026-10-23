ALTER TABLE sessions ADD COLUMN is_master BOOLEAN NOT NULL DEFAULT false;
CREATE UNIQUE INDEX idx_one_master_per_user ON sessions(user_id) WHERE is_master;
