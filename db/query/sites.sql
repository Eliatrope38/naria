-- name: CreateSite :one
INSERT INTO sites (owner_id, name, domains)
VALUES ($1, $2, $3)
RETURNING *;

-- Cloisonnement : toute lecture ou écriture d'un site porte le périmètre du
-- demandeur (viewer_id / is_admin) dans la requête. Un membre ne voit que les
-- sites dont il est propriétaire ; un administrateur les voit tous.
-- name: GetSiteScoped :one
SELECT s.*, u.name AS owner_name
FROM sites s
JOIN users u ON u.id = s.owner_id
WHERE s.id = sqlc.arg('id')
  AND (sqlc.arg('is_admin')::bool OR s.owner_id = sqlc.arg('viewer_id'));

-- name: ListSitesScoped :many
SELECT s.*, u.name AS owner_name,
       (SELECT count(*) FROM forms f WHERE f.site_id = s.id) AS form_count,
       (SELECT count(*) FROM submissions sub JOIN forms f ON f.id = sub.form_id
         WHERE f.site_id = s.id AND sub.read_at IS NULL) AS unread_count
FROM sites s
JOIN users u ON u.id = s.owner_id
WHERE (sqlc.arg('is_admin')::bool OR s.owner_id = sqlc.arg('viewer_id'))
  AND (sqlc.narg('search')::text IS NULL
       OR s.name ILIKE '%' || sqlc.narg('search') || '%'
       OR array_to_string(s.domains, ' ') ILIKE '%' || sqlc.narg('search') || '%')
ORDER BY s.name
LIMIT sqlc.arg('page_limit') OFFSET sqlc.arg('page_offset');

-- name: CountSitesScoped :one
SELECT count(*) FROM sites s
WHERE (sqlc.arg('is_admin')::bool OR s.owner_id = sqlc.arg('viewer_id'))
  AND (sqlc.narg('search')::text IS NULL
       OR s.name ILIKE '%' || sqlc.narg('search') || '%'
       OR array_to_string(s.domains, ' ') ILIKE '%' || sqlc.narg('search') || '%');

-- name: UpdateSiteScoped :execrows
UPDATE sites SET name = sqlc.arg('name'), domains = sqlc.arg('domains'), updated_at = now()
WHERE id = sqlc.arg('id')
  AND (sqlc.arg('is_admin')::bool OR owner_id = sqlc.arg('viewer_id'));

-- name: SetSiteOwner :exec
UPDATE sites SET owner_id = $2, updated_at = now() WHERE id = $1;

-- name: DeleteSiteScoped :execrows
DELETE FROM sites
WHERE id = sqlc.arg('id')
  AND (sqlc.arg('is_admin')::bool OR owner_id = sqlc.arg('viewer_id'));

-- name: GetSiteOwnerEmail :one
SELECT u.email FROM sites s JOIN users u ON u.id = s.owner_id WHERE s.id = $1;
