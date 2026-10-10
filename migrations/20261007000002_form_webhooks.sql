-- +goose Up
-- +goose StatementBegin

-- Alertes vers un canal de discussion (Slack, Microsoft Teams), en plus des
-- destinations du formulaire. L'URL d'un webhook est un secret (qui la connaît
-- peut écrire dans le canal) : elle est donc chiffrée par l'application, comme
-- le contenu des soumissions. NULL = canal non configuré.
-- chat_include_content est faux par défaut : sans ce choix explicite, l'alerte
-- annonce la soumission sans rien transmettre de son contenu au service tiers.
ALTER TABLE forms
    ADD COLUMN slack_webhook_url    TEXT,
    ADD COLUMN teams_webhook_url    TEXT,
    ADD COLUMN chat_include_content BOOLEAN NOT NULL DEFAULT FALSE;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE forms
    DROP COLUMN chat_include_content,
    DROP COLUMN teams_webhook_url,
    DROP COLUMN slack_webhook_url;
-- +goose StatementEnd
