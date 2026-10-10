-- name: CreateUser :one
INSERT INTO users (email, name, role, password_hash)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1;

-- name: ListUsers :many
SELECT u.*, (SELECT count(*) FROM sites s WHERE s.owner_id = u.id) AS site_count
FROM users u
WHERE (sqlc.narg('search')::text IS NULL OR u.name ILIKE '%' || sqlc.narg('search') || '%' OR u.email ILIKE '%' || sqlc.narg('search') || '%')
ORDER BY u.name
LIMIT sqlc.arg('page_limit') OFFSET sqlc.arg('page_offset');

-- name: ListActiveUsers :many
SELECT * FROM users WHERE active = TRUE ORDER BY name;

-- name: CountUsersMatching :one
SELECT count(*) FROM users u
WHERE (sqlc.narg('search')::text IS NULL OR u.name ILIKE '%' || sqlc.narg('search') || '%' OR u.email ILIKE '%' || sqlc.narg('search') || '%');

-- name: SetUserActive :exec
UPDATE users SET active = $2, updated_at = now() WHERE id = $1;

-- name: SetUserRole :exec
UPDATE users SET role = $2, updated_at = now() WHERE id = $1;

-- name: SetUserTOTP :exec
UPDATE users SET totp_secret = $2, totp_enabled = TRUE, updated_at = now() WHERE id = $1;

-- name: DisableUserTOTP :exec
UPDATE users SET totp_secret = NULL, totp_enabled = FALSE, updated_at = now() WHERE id = $1;

-- name: SetUserPassword :exec
UPDATE users SET password_hash = $2, updated_at = now() WHERE id = $1;

-- name: UpdateUserName :exec
UPDATE users SET name = $2, updated_at = now() WHERE id = $1;

-- name: UpdateUserEmail :exec
UPDATE users SET email = $2, updated_at = now() WHERE id = $1;

-- name: DeleteUser :exec
DELETE FROM users WHERE id = $1;

-- name: CountActiveAdmins :one
SELECT count(*) FROM users WHERE role = 'admin' AND active = TRUE;
