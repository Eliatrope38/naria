-- name: CreateAPIToken :one
INSERT INTO api_tokens (site_id, user_id, name, token_hash, expires_at)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- GetAPITokenByHash authentifie un appel d'API. Un jeton crée des formulaires, donc
-- il vaut par l'écriture du créateur (propriétaire du site, ou administrateur de
-- l'organisation du propriétaire), et non par la lecture. Ce droit est vérifié à
-- chaque appel : un jeton échu, ou dont le créateur n'écrit plus le site, est
-- introuvable.
-- name: GetAPITokenByHash :one
SELECT t.id, t.name, t.user_id, u.email AS user_email,
       s.id AS site_id, s.name AS site_name, s.domains AS site_domains
FROM api_tokens t
JOIN sites s ON s.id = t.site_id
JOIN users o ON o.id = s.owner_id
JOIN users u ON u.id = t.user_id
WHERE t.token_hash = $1
  AND (t.expires_at IS NULL OR t.expires_at > now())
  AND u.active
  AND (s.owner_id = u.id OR (u.role = 'admin_orga' AND o.org_id = u.org_id));

-- Une écriture par minute au plus : la date sert à repérer un jeton oublié, pas
-- à compter les appels.
-- name: TouchAPIToken :exec
UPDATE api_tokens SET last_used_at = now()
WHERE id = $1
  AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute');

-- has_access reprend ce que GetAPITokenByHash exige du créateur (compte actif,
-- écriture du site) : la page du site signale ainsi un jeton qu'il ne peut plus
-- faire valoir. L'échéance n'y entre pas, la page l'affiche à part.
-- name: ListAPITokensBySite :many
SELECT t.id, t.name, t.expires_at, t.last_used_at, t.created_at, u.name AS user_name,
       coalesce(u.active AND (s.owner_id = u.id OR (u.role = 'admin_orga' AND o.org_id = u.org_id)), false)::bool AS has_access
FROM api_tokens t
JOIN sites s ON s.id = t.site_id
JOIN users o ON o.id = s.owner_id
JOIN users u ON u.id = t.user_id
WHERE t.site_id = $1
ORDER BY t.created_at;

-- name: CountAPITokensBySite :one
SELECT count(*) FROM api_tokens WHERE site_id = $1;

-- name: DeleteAPIToken :one
DELETE FROM api_tokens WHERE id = $1 AND site_id = $2
RETURNING name;
