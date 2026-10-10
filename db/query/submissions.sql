-- L'identifiant vient de l'application : elle doit le connaître avant
-- l'insertion, pour écarter de FormStorageBytes une soumission qu'elle est en
-- train de conserver.
-- name: CreateSubmission :one
INSERT INTO submissions (id, form_id, payload)
VALUES ($1, $2, $3)
RETURNING *;

-- name: ListSubmissionsByForm :many
SELECT * FROM submissions
WHERE form_id = $1
ORDER BY created_at DESC
LIMIT sqlc.arg('page_limit') OFFSET sqlc.arg('page_offset');

-- ListAllSubmissionsByForm alimente les exports (ordre chronologique).
-- L'identifiant départage deux soumissions reçues au même instant : l'ordre
-- des lignes ne varie pas d'un export à l'autre.
-- name: ListAllSubmissionsByForm :many
SELECT * FROM submissions WHERE form_id = $1 ORDER BY created_at, id;

-- name: CountSubmissionsByForm :one
SELECT count(*) FROM submissions WHERE form_id = $1;

-- Même périmètre que forms.sql. Les écritures portent la condition d'écriture
-- (propriétaire ou administrateur de l'organisation), jamais la lecture seule.
-- name: GetSubmissionScoped :one
SELECT sub.*, f.name AS form_name, f.site_id, s.name AS site_name,
       coalesce(s.owner_id = sqlc.arg('viewer_id') OR o.org_id = sqlc.narg('admin_org_id')::uuid, false)::bool AS can_write
FROM submissions sub
JOIN forms f ON f.id = sub.form_id
JOIN sites s ON s.id = f.site_id
JOIN users o ON o.id = s.owner_id
WHERE sub.id = sqlc.arg('id')
  AND (s.owner_id = sqlc.arg('viewer_id')
       OR o.org_id = sqlc.narg('admin_org_id')::uuid
       OR EXISTS (SELECT 1 FROM site_read_grants g WHERE g.site_id = s.id AND g.user_id = sqlc.arg('viewer_id')));

-- name: MarkSubmissionReadScoped :execrows
UPDATE submissions sub SET read_at = now()
WHERE sub.id = sqlc.arg('id') AND sub.read_at IS NULL
  AND sub.form_id IN (SELECT f.id FROM forms f
                      JOIN sites s ON s.id = f.site_id
                      WHERE s.owner_id = sqlc.arg('viewer_id')
                         OR s.owner_id IN (SELECT u.id FROM users u WHERE u.org_id = sqlc.narg('admin_org_id')::uuid));

-- name: MarkFormSubmissionsReadScoped :execrows
UPDATE submissions sub SET read_at = now()
WHERE sub.form_id = sqlc.arg('form_id') AND sub.read_at IS NULL
  AND sub.form_id IN (SELECT f.id FROM forms f
                      JOIN sites s ON s.id = f.site_id
                      WHERE s.owner_id = sqlc.arg('viewer_id')
                         OR s.owner_id IN (SELECT u.id FROM users u WHERE u.org_id = sqlc.narg('admin_org_id')::uuid));

-- name: DeleteSubmissionScoped :execrows
DELETE FROM submissions sub
WHERE sub.id = sqlc.arg('id')
  AND sub.form_id IN (SELECT f.id FROM forms f
                      JOIN sites s ON s.id = f.site_id
                      WHERE s.owner_id = sqlc.arg('viewer_id')
                         OR s.owner_id IN (SELECT u.id FROM users u WHERE u.org_id = sqlc.narg('admin_org_id')::uuid));

-- name: DeleteSubmissionsByFormScoped :execrows
DELETE FROM submissions sub
WHERE sub.form_id = sqlc.arg('form_id')
  AND sub.form_id IN (SELECT f.id FROM forms f
                      JOIN sites s ON s.id = f.site_id
                      WHERE s.owner_id = sqlc.arg('viewer_id')
                         OR s.owner_id IN (SELECT u.id FROM users u WHERE u.org_id = sqlc.narg('admin_org_id')::uuid));

-- PurgeExpiredSubmissions applique la durée de conservation de chaque formulaire
-- (retention_days = 0 : conservation sans limite).
-- name: PurgeExpiredSubmissions :execrows
DELETE FROM submissions sub
USING forms f
WHERE f.id = sub.form_id
  AND f.retention_days > 0
  AND sub.created_at < now() - make_interval(days => f.retention_days);

-- FormStorageBytes mesure le poids des soumissions conservées d'un formulaire :
-- leur contenu chiffré tel que stocké, et la taille en clair de leurs pièces
-- jointes. Deux sommes séparées : une sous-requête par soumission coûterait un
-- sondage d'index pour chacune. L'application ne l'appelle pas à chaque envoi,
-- elle en garde le résultat (voir formUsage). pending désigne les soumissions
-- qu'elle est en train de conserver : elle les compte à part, et les retrouver
-- ici, validées entre-temps, les compterait deux fois. Le coalesce couvre une
-- liste absente : comparé à NULL, aucun identifiant ne serait retenu, et la
-- mesure vaudrait zéro.
-- name: FormStorageBytes :one
SELECT ((SELECT coalesce(sum(octet_length(sub.payload)), 0) FROM submissions sub
         WHERE sub.form_id = sqlc.arg('form_id') AND sub.id <> ALL(coalesce(sqlc.arg('pending')::uuid[], '{}')))
      + (SELECT coalesce(sum(a.size), 0) FROM attachments a
         JOIN submissions sub ON sub.id = a.submission_id
         WHERE sub.form_id = sqlc.arg('form_id') AND sub.id <> ALL(coalesce(sqlc.arg('pending')::uuid[], '{}'))))::bigint;
