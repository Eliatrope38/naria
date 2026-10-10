-- name: CreatePasswordReset :exec
INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3);

-- name: GetPasswordResetByHash :one
SELECT id, user_id, token_hash, expires_at, used_at, created_at
FROM password_reset_tokens
WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now();

-- name: CountRecentPasswordResets :one
SELECT count(*) FROM password_reset_tokens
WHERE user_id = $1 AND created_at > now() - interval '15 minutes';

-- name: ConsumePasswordResets :exec
UPDATE password_reset_tokens SET used_at = now() WHERE user_id = $1 AND used_at IS NULL;

-- name: DeleteExpiredPasswordResets :exec
DELETE FROM password_reset_tokens WHERE expires_at < now() - interval '1 day';
