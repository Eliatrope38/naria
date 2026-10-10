-- name: CreateForm :one
INSERT INTO forms (site_id, name, access_key, notify_email, recipients, email_include_content, store_submissions, retention_days, redirect_url,
                   slack_webhook_url, teams_webhook_url, discord_webhook_url, chat_include_content,
                   telegram_bot_token, telegram_chat_id, accept_attachments, captcha, notification_lang)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
RETURNING *;

-- Même règle de cloisonnement que sites.sql, appliquée au site du formulaire.
-- name: GetFormScoped :one
SELECT f.*, s.name AS site_name, s.domains AS site_domains,
       coalesce(s.owner_id = sqlc.arg('viewer_id') OR o.org_id = sqlc.narg('admin_org_id')::uuid, false)::bool AS can_write
FROM forms f
JOIN sites s ON s.id = f.site_id
JOIN users o ON o.id = s.owner_id
WHERE f.id = sqlc.arg('id')
  AND (s.owner_id = sqlc.arg('viewer_id')
       OR o.org_id = sqlc.narg('admin_org_id')::uuid
       OR EXISTS (SELECT 1 FROM site_read_grants g WHERE g.site_id = s.id AND g.user_id = sqlc.arg('viewer_id')));

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

-- Écritures sur un formulaire : même condition d'écriture que sites.sql, par le
-- site du formulaire. Une lecture seule ne les passe jamais.
-- name: UpdateFormScoped :execrows
UPDATE forms
SET name = sqlc.arg('name'), active = sqlc.arg('active'), notify_email = sqlc.arg('notify_email'),
    recipients = sqlc.arg('recipients'), email_include_content = sqlc.arg('email_include_content'),
    store_submissions = sqlc.arg('store_submissions'), retention_days = sqlc.arg('retention_days'),
    redirect_url = sqlc.narg('redirect_url'),
    slack_webhook_url = sqlc.narg('slack_webhook_url'), teams_webhook_url = sqlc.narg('teams_webhook_url'),
    discord_webhook_url = sqlc.narg('discord_webhook_url'), chat_include_content = sqlc.arg('chat_include_content'),
    telegram_bot_token = sqlc.narg('telegram_bot_token'), telegram_chat_id = sqlc.narg('telegram_chat_id'),
    accept_attachments = sqlc.arg('accept_attachments'), captcha = sqlc.arg('captcha'),
    notification_lang = sqlc.arg('notification_lang'), updated_at = now()
WHERE forms.id = sqlc.arg('id')
  AND forms.site_id IN (SELECT s.id FROM sites s
                  WHERE s.owner_id = sqlc.arg('viewer_id')
                     OR s.owner_id IN (SELECT u.id FROM users u WHERE u.org_id = sqlc.narg('admin_org_id')::uuid));

-- name: SetFormAccessKeyScoped :execrows
UPDATE forms SET access_key = sqlc.arg('access_key'), updated_at = now()
WHERE forms.id = sqlc.arg('id')
  AND forms.site_id IN (SELECT s.id FROM sites s
                  WHERE s.owner_id = sqlc.arg('viewer_id')
                     OR s.owner_id IN (SELECT u.id FROM users u WHERE u.org_id = sqlc.narg('admin_org_id')::uuid));

-- name: DeleteFormScoped :execrows
DELETE FROM forms
WHERE forms.id = sqlc.arg('id')
  AND forms.site_id IN (SELECT s.id FROM sites s
                  WHERE s.owner_id = sqlc.arg('viewer_id')
                     OR s.owner_id IN (SELECT u.id FROM users u WHERE u.org_id = sqlc.narg('admin_org_id')::uuid));

-- ListFormsOfSite et CountFormsBySite servent l'API. Pas de périmètre dans ces
-- requêtes : le site vient du jeton, que GetAPITokenByHash a déjà contrôlé.
-- name: ListFormsOfSite :many
SELECT * FROM forms WHERE site_id = $1 ORDER BY name;

-- name: CountFormsBySite :one
SELECT count(*) FROM forms WHERE site_id = $1;
