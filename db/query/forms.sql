-- name: CreateForm :one
INSERT INTO forms (site_id, name, access_key, notify_email, recipients, email_include_content, store_submissions, retention_days, redirect_url,
                   slack_webhook_url, teams_webhook_url, discord_webhook_url, chat_include_content,
                   telegram_bot_token, telegram_chat_id, accept_attachments, captcha, notification_lang)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
RETURNING *;

-- Même règle de cloisonnement que sites.sql : le périmètre du demandeur est
-- vérifié dans la requête, via le site propriétaire du formulaire.
-- name: GetFormScoped :one
SELECT f.*, s.name AS site_name, s.domains AS site_domains
FROM forms f
JOIN sites s ON s.id = f.site_id
WHERE f.id = sqlc.arg('id')
  AND (sqlc.arg('is_admin')::bool OR s.owner_id = sqlc.arg('viewer_id'));

-- GetFormByAccessKey sert le point d'entrée public : aucune notion d'utilisateur,
-- la clé d'accès désigne le formulaire.
-- name: GetFormByAccessKey :one
SELECT f.*, s.name AS site_name, s.domains AS site_domains
FROM forms f
JOIN sites s ON s.id = f.site_id
WHERE f.access_key = $1;

-- name: ListFormsBySite :many
SELECT f.*,
       (SELECT count(*) FROM submissions sub WHERE sub.form_id = f.id) AS submission_count,
       (SELECT count(*) FROM submissions sub WHERE sub.form_id = f.id AND sub.read_at IS NULL) AS unread_count
FROM forms f
WHERE f.site_id = $1
ORDER BY f.name;

-- name: UpdateForm :exec
UPDATE forms
SET name = $2, active = $3, notify_email = $4, recipients = $5, email_include_content = $6,
    store_submissions = $7, retention_days = $8, redirect_url = $9,
    slack_webhook_url = $10, teams_webhook_url = $11, discord_webhook_url = $12, chat_include_content = $13,
    telegram_bot_token = $14, telegram_chat_id = $15, accept_attachments = $16, captcha = $17,
    notification_lang = $18, updated_at = now()
WHERE id = $1;

-- name: SetFormAccessKey :exec
UPDATE forms SET access_key = $2, updated_at = now() WHERE id = $1;

-- name: DeleteForm :exec
DELETE FROM forms WHERE id = $1;

-- ListFormsOfSite et CountFormsBySite servent l'API. Pas de périmètre dans ces
-- requêtes : le site vient du jeton, que GetAPITokenByHash a déjà contrôlé.
-- name: ListFormsOfSite :many
SELECT * FROM forms WHERE site_id = $1 ORDER BY name;

-- name: CountFormsBySite :one
SELECT count(*) FROM forms WHERE site_id = $1;
