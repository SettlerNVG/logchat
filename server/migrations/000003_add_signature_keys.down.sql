-- Revert signature key changes
DROP INDEX IF EXISTS idx_users_signature_public_key;
DROP INDEX IF EXISTS idx_users_encryption_public_key;

ALTER TABLE users DROP COLUMN IF EXISTS signature_public_key;
ALTER TABLE users DROP COLUMN IF EXISTS encryption_public_key;

-- Recreate public_keys table if needed
CREATE TABLE IF NOT EXISTS public_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_type VARCHAR(50) NOT NULL DEFAULT 'curve25519',
    public_key BYTEA NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id, key_type)
);

CREATE INDEX idx_public_keys_user_id ON public_keys(user_id);
