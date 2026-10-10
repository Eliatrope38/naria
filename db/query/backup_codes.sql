-- name: CreateBackupCode :exec
INSERT INTO totp_backup_codes (user_id, code_hash) VALUES ($1, $2);

-- name: ListUnusedBackupCodes :many
SELECT id, code_hash FROM totp_backup_codes WHERE user_id = $1 AND used_at IS NULL;

-- name: MarkBackupCodeUsed :exec
UPDATE totp_backup_codes SET used_at = now() WHERE id = $1;

-- name: DeleteBackupCodes :exec
DELETE FROM totp_backup_codes WHERE user_id = $1;

-- name: CountUnusedBackupCodes :one
SELECT count(*) FROM totp_backup_codes WHERE user_id = $1 AND used_at IS NULL;
