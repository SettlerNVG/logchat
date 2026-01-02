DROP TRIGGER IF EXISTS update_user_presence_updated_at ON user_presence;
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
DROP FUNCTION IF EXISTS update_updated_at_column();

DROP TABLE IF EXISTS chat_requests;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS user_presence;
DROP TABLE IF EXISTS public_keys;
DROP TABLE IF EXISTS users;
