CREATE TABLE refresh_token_families (
    id UUID PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

ALTER TABLE refresh_tokens ADD COLUMN family_id UUID;
UPDATE refresh_tokens SET family_id = gen_random_uuid();

-- Old rotations did not record ancestry. Invalidate legacy sessions once rather
-- than pretending their independently stored tokens form replay-safe families.
INSERT INTO refresh_token_families (id, user_id, expires_at, revoked_at)
SELECT family_id, user_id, expires_at, CURRENT_TIMESTAMP FROM refresh_tokens;
UPDATE refresh_tokens SET revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP);

ALTER TABLE refresh_tokens ALTER COLUMN family_id SET NOT NULL;
ALTER TABLE refresh_tokens ADD CONSTRAINT fk_refresh_tokens_family
    FOREIGN KEY (family_id) REFERENCES refresh_token_families(id) ON DELETE CASCADE;
CREATE INDEX idx_refresh_tokens_family ON refresh_tokens(family_id);
CREATE INDEX idx_refresh_token_families_expiry ON refresh_token_families(expires_at);
