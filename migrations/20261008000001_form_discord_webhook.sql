-- +goose Up
-- +goose StatementBegin

-- Alerte Discord, au même titre que Slack et Teams (voir la migration
-- form_webhooks) : l'adresse du webhook est un secret, chiffrée par
-- l'application. NULL = canal non configuré.
ALTER TABLE forms
    ADD COLUMN discord_webhook_url TEXT;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE forms
    DROP COLUMN discord_webhook_url;
-- +goose StatementEnd
