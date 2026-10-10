-- name: CreateUser :one
INSERT INTO users (email, name, role, password_hash, org_id)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1;

-- Les comptes d'une organisation, pour son administrateur. Le périmètre est
-- l'organisation de l'administrateur, passée par l'application.
-- name: ListOrgUsers :many
SELECT u.*, (SELECT count(*) FROM sites s WHERE s.owner_id = u.id) AS site_count
FROM users u
WHERE u.org_id = sqlc.arg('org_id')
  AND (sqlc.narg('search')::text IS NULL OR u.name ILIKE '%' || sqlc.narg('search') || '%' OR u.email ILIKE '%' || sqlc.narg('search') || '%')
ORDER BY u.name
LIMIT sqlc.arg('page_limit') OFFSET sqlc.arg('page_offset');

-- name: ListActiveOrgUsers :many
SELECT * FROM users WHERE org_id = sqlc.arg('org_id') AND active = TRUE ORDER BY name;

-- name: CountOrgUsersMatching :one
SELECT count(*) FROM users u
WHERE u.org_id = sqlc.arg('org_id')
  AND (sqlc.narg('search')::text IS NULL OR u.name ILIKE '%' || sqlc.narg('search') || '%' OR u.email ILIKE '%' || sqlc.narg('search') || '%');

-- Les écritures sur un compte ne visent que les comptes user de l'organisation de
-- l'administrateur (sqlc.arg('admin_org_id')). Un compte hors périmètre n'est pas
-- modifié, et le nombre de lignes le dit à l'application.
-- name: SetUserActiveScoped :execrows
UPDATE users SET active = sqlc.arg('active'), updated_at = now()
WHERE id = sqlc.arg('id') AND org_id = sqlc.arg('admin_org_id') AND role = 'user';

-- Remplacement de l'administrateur d'une organisation : l'ancien redevient user.
-- name: DemoteOrgAdmin :exec
UPDATE users SET role = 'user', updated_at = now() WHERE org_id = $1 AND role = 'admin_orga';

-- name: SetUserTOTP :exec
UPDATE users SET totp_secret = $2, totp_enabled = TRUE, updated_at = now() WHERE id = $1;

-- name: DisableUserTOTPScoped :execrows
UPDATE users SET totp_secret = NULL, totp_enabled = FALSE, updated_at = now()
WHERE id = sqlc.arg('id') AND org_id = sqlc.arg('admin_org_id') AND role = 'user';

-- name: SetUserPasswordScoped :execrows
UPDATE users SET password_hash = sqlc.arg('password_hash'), updated_at = now()
WHERE id = sqlc.arg('id') AND org_id = sqlc.arg('admin_org_id') AND role = 'user';

-- name: UpdateUserNameScoped :execrows
UPDATE users SET name = sqlc.arg('name'), updated_at = now()
WHERE id = sqlc.arg('id') AND org_id = sqlc.arg('admin_org_id') AND role = 'user';

-- name: UpdateUserEmail :exec
UPDATE users SET email = $2, updated_at = now() WHERE id = $1;

-- name: DeleteUserScoped :execrows
DELETE FROM users WHERE id = sqlc.arg('id') AND org_id = sqlc.arg('admin_org_id') AND role = 'user';

-- Le compte désigné dans un écran d'administration de l'organisation : un compte
-- user de cette organisation, sinon rien (404).
-- name: GetOrgUser :one
SELECT * FROM users WHERE id = sqlc.arg('id') AND org_id = sqlc.arg('org_id') AND role = 'user';

-- Opérations sur son propre compte, depuis /account ou la réinitialisation.
-- name: UpdateUserName :exec
UPDATE users SET name = $2, updated_at = now() WHERE id = $1;

-- name: SetUserPassword :exec
UPDATE users SET password_hash = $2, updated_at = now() WHERE id = $1;

-- name: DisableUserTOTP :exec
UPDATE users SET totp_secret = NULL, totp_enabled = FALSE, updated_at = now() WHERE id = $1;
