-- +goose Up
-- +goose StatementBegin

-- kChat (Infomaniak) alert, like Slack, Teams and Discord: the webhook address
-- is a secret, encrypted by the application. NULL means not configured.
ALTER TABLE forms
    ADD COLUMN kchat_webhook_url TEXT;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE forms
    DROP COLUMN kchat_webhook_url;
-- +goose StatementEnd
