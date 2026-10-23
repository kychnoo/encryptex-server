ALTER TABLE sessions ADD COLUMN token_hash TEXT;

UPDATE sessions SET token_hash = encode(sha256(convert_to(token, 'UTF8')), 'hex');
UPDATE sessions SET prev_token = encode(sha256(convert_to(prev_token, 'UTF8')), 'hex') WHERE prev_token IS NOT NULL;

ALTER TABLE sessions ALTER COLUMN token_hash SET NOT NULL;
ALTER TABLE sessions ADD CONSTRAINT sessions_token_hash_key UNIQUE (token_hash);

ALTER TABLE sessions DROP COLUMN token;
ALTER TABLE sessions RENAME COLUMN prev_token TO prev_token_hash;
