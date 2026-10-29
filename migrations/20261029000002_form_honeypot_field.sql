-- +goose Up
-- +goose StatementBegin

-- Name of a per-form honeypot field, recognised alongside "botcheck", which bots tuned
-- for Web3Forms know to leave empty. NULL for existing forms: a generated name could
-- match a field their page already uses, and every submission would then be dropped.
ALTER TABLE forms
    ADD COLUMN honeypot_field TEXT
        CHECK (honeypot_field ~ '^[A-Za-z][A-Za-z0-9_-]{0,39}$');

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE forms
    DROP COLUMN honeypot_field;
-- +goose StatementEnd
