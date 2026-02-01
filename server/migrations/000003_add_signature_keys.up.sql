-- Add encryption and signature public keys directly to users table
ALTER TABLE users ADD COLUMN encryption_public_key BYTEA;
ALTER TABLE users ADD COLUMN signature_public_key BYTEA;

-- Migrate data from public_keys table if it exists
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'public_keys') THEN
        -- Copy curve25519 keys to encryption_public_key
        UPDATE users u
        SET encryption_public_key = pk.public_key
        FROM public_keys pk
        WHERE u.id = pk.user_id AND pk.key_type = 'curve25519';
        
        -- Drop old public_keys table
        DROP TABLE IF EXISTS public_keys;
    END IF;
END $$;

-- Make columns NOT NULL after migration
ALTER TABLE users ALTER COLUMN encryption_public_key SET NOT NULL;
ALTER TABLE users ALTER COLUMN signature_public_key SET NOT NULL;

-- Add indexes for faster lookups
CREATE INDEX idx_users_encryption_public_key ON users(encryption_public_key);
CREATE INDEX idx_users_signature_public_key ON users(signature_public_key);
