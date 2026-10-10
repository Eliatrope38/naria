-- name: CreateAttachment :exec
INSERT INTO attachments (submission_id, position, filename, size, content)
VALUES ($1, $2, $3, $4, $5);

-- ListAttachmentsBySubmission alimente la fiche d'une soumission : sans le
-- contenu, qui n'est lu qu'au téléchargement.
-- name: ListAttachmentsBySubmission :many
SELECT id, filename, size FROM attachments
WHERE submission_id = $1
ORDER BY position;

-- Même règle de cloisonnement que submissions.sql : le périmètre du demandeur
-- est vérifié dans la requête, via le site propriétaire du formulaire.
-- name: GetAttachmentScoped :one
SELECT a.filename, a.content
FROM attachments a
JOIN submissions sub ON sub.id = a.submission_id
JOIN forms f ON f.id = sub.form_id
JOIN sites s ON s.id = f.site_id
WHERE a.id = sqlc.arg('id')
  AND (sqlc.arg('is_admin')::bool OR s.owner_id = sqlc.arg('viewer_id'));

-- ListAttachmentsByForm alimente l'export en archive, dans l'ordre de l'export
-- CSV. Sans le contenu : il est lu fichier par fichier, pour ne pas tenir en
-- mémoire celui de toutes les pièces jointes d'un formulaire.
-- name: ListAttachmentsByForm :many
SELECT a.id, a.submission_id, a.position, a.filename
FROM attachments a
JOIN submissions sub ON sub.id = a.submission_id
WHERE sub.form_id = $1
ORDER BY sub.created_at, sub.id, a.position;

-- name: FormHasAttachments :one
SELECT EXISTS (
    SELECT 1 FROM attachments a
    JOIN submissions sub ON sub.id = a.submission_id
    WHERE sub.form_id = $1
);
