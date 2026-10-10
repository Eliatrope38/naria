-- name: CreateSite :one
INSERT INTO sites (owner_id, name, domains)
VALUES ($1, $2, $3)
RETURNING *;

-- Cloisonnement : toute lecture ou écriture d'un site porte le périmètre du
-- demandeur (viewer_id, et admin_org_id s'il administre une organisation) dans la
-- requête. Lire : le propriétaire, l'administrateur de l'organisation du
-- propriétaire, ou un compte à qui cette organisation a accordé la lecture. Écrire :
-- les deux premiers seulement, une lecture n'ouvre aucune écriture.
-- name: GetSiteScoped :one
SELECT s.*, u.name AS owner_name,
       coalesce(s.owner_id = sqlc.arg('viewer_id') OR u.org_id = sqlc.narg('admin_org_id')::uuid, false)::bool AS can_write
FROM sites s
JOIN users u ON u.id = s.owner_id
WHERE s.id = sqlc.arg('id')
  AND (s.owner_id = sqlc.arg('viewer_id')
       OR u.org_id = sqlc.narg('admin_org_id')::uuid
       OR EXISTS (SELECT 1 FROM site_read_grants g WHERE g.site_id = s.id AND g.user_id = sqlc.arg('viewer_id')));

-- La pagination précède le calcul des compteurs : ils ne sont faits que pour les
-- sites de la page, même pour un administrateur d'organisation qui en gère beaucoup.
-- name: ListSitesScoped :many
SELECT p.*,
       (SELECT count(*) FROM forms f WHERE f.site_id = p.id) AS form_count,
       (SELECT count(*) FROM submissions sub JOIN forms f ON f.id = sub.form_id
         WHERE f.site_id = p.id AND sub.read_at IS NULL) AS unread_count
FROM (
    SELECT s.*, u.name AS owner_name,
           coalesce(s.owner_id = sqlc.arg('viewer_id') OR u.org_id = sqlc.narg('admin_org_id')::uuid, false)::bool AS can_write
    FROM sites s
    JOIN users u ON u.id = s.owner_id
    WHERE (s.owner_id = sqlc.arg('viewer_id')
           OR u.org_id = sqlc.narg('admin_org_id')::uuid
           OR EXISTS (SELECT 1 FROM site_read_grants g WHERE g.site_id = s.id AND g.user_id = sqlc.arg('viewer_id')))
      AND (sqlc.narg('search')::text IS NULL
           OR s.name ILIKE '%' || sqlc.narg('search') || '%'
           OR array_to_string(s.domains, ' ') ILIKE '%' || sqlc.narg('search') || '%')
    ORDER BY s.name, s.id
    LIMIT sqlc.arg('page_limit') OFFSET sqlc.arg('page_offset')
) p
ORDER BY p.name, p.id;

-- name: CountSitesScoped :one
SELECT count(*) FROM sites s
JOIN users u ON u.id = s.owner_id
WHERE (s.owner_id = sqlc.arg('viewer_id')
       OR u.org_id = sqlc.narg('admin_org_id')::uuid
       OR EXISTS (SELECT 1 FROM site_read_grants g WHERE g.site_id = s.id AND g.user_id = sqlc.arg('viewer_id')))
  AND (sqlc.narg('search')::text IS NULL
       OR s.name ILIKE '%' || sqlc.narg('search') || '%'
       OR array_to_string(s.domains, ' ') ILIKE '%' || sqlc.narg('search') || '%');

-- name: UpdateSiteScoped :execrows
UPDATE sites SET name = sqlc.arg('name'), domains = sqlc.arg('domains'), updated_at = now()
WHERE sites.id = sqlc.arg('id')
  AND (sites.owner_id = sqlc.arg('viewer_id')
       OR sites.owner_id IN (SELECT u.id FROM users u WHERE u.org_id = sqlc.narg('admin_org_id')::uuid));

-- Transfert à un compte actif de la même organisation que l'administrateur. La
-- lecture accordée au nouveau propriétaire est retirée par la même transaction.
-- name: TransferSiteScoped :execrows
UPDATE sites SET owner_id = sqlc.arg('new_owner_id'), updated_at = now()
WHERE sites.id = sqlc.arg('id')
  AND sites.owner_id IN (SELECT u.id FROM users u WHERE u.org_id = sqlc.narg('admin_org_id')::uuid)
  AND EXISTS (SELECT 1 FROM users n
              WHERE n.id = sqlc.arg('new_owner_id') AND n.active
                AND n.org_id = sqlc.narg('admin_org_id')::uuid);

-- name: DeleteSiteScoped :execrows
DELETE FROM sites
WHERE sites.id = sqlc.arg('id')
  AND (sites.owner_id = sqlc.arg('viewer_id')
       OR sites.owner_id IN (SELECT u.id FROM users u WHERE u.org_id = sqlc.narg('admin_org_id')::uuid));

-- name: GetSiteAlertEmails :one
SELECT ow.email AS owner_email, adm.email AS admin_email
FROM sites s
JOIN users ow ON ow.id = s.owner_id
LEFT JOIN users adm ON adm.org_id = ow.org_id AND adm.role = 'admin_orga' AND adm.active AND adm.id <> ow.id
WHERE s.id = $1;

-- Lecture accordée par l'administrateur de l'organisation du site. Le destinataire
-- doit être un compte actif de la même organisation, de rôle user, et pas le
-- propriétaire. Zéro ligne signifie refus ou lecture déjà accordée.
-- name: GrantSiteRead :execrows
INSERT INTO site_read_grants (site_id, user_id, granted_by)
SELECT s.id, g.id, sqlc.arg('granted_by')
FROM sites s
JOIN users o ON o.id = s.owner_id
JOIN users g ON g.id = sqlc.arg('user_id')
WHERE s.id = sqlc.arg('site_id')
  AND o.org_id = sqlc.arg('admin_org_id')
  AND g.org_id = sqlc.arg('admin_org_id')
  AND g.role = 'user' AND g.active
  AND s.owner_id <> g.id
ON CONFLICT DO NOTHING;

-- name: RevokeSiteRead :execrows
DELETE FROM site_read_grants g
WHERE g.site_id = sqlc.arg('site_id') AND g.user_id = sqlc.arg('user_id')
  AND EXISTS (SELECT 1 FROM sites s
              JOIN users o ON o.id = s.owner_id
              WHERE s.id = g.site_id AND o.org_id = sqlc.arg('admin_org_id'));

-- name: ListSiteReadGrants :many
SELECT u.id, u.name, u.email
FROM site_read_grants g
JOIN users u ON u.id = g.user_id
WHERE g.site_id = sqlc.arg('site_id')
  AND EXISTS (SELECT 1 FROM sites s
              JOIN users o ON o.id = s.owner_id
              WHERE s.id = g.site_id AND o.org_id = sqlc.arg('admin_org_id'))
ORDER BY u.name;

-- Comptes auxquels accorder la lecture d'un site : les comptes user actifs de
-- l'organisation, sauf le propriétaire.
-- name: ListGrantableUsers :many
SELECT id, name, email FROM users
WHERE org_id = sqlc.arg('org_id') AND role = 'user' AND active
  AND id <> sqlc.arg('owner_id')
ORDER BY name;

-- name: DeleteSiteReadGrant :exec
DELETE FROM site_read_grants WHERE site_id = $1 AND user_id = $2;
