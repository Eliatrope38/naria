-- +goose Up
-- +goose StatementBegin

-- Drop submissions that hold a link, per form. Off by default: a form already in
-- place may receive legitimate messages with a link, which would be lost silently.
ALTER TABLE forms
    ADD COLUMN refuse_links BOOLEAN NOT NULL DEFAULT FALSE;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE forms
    DROP COLUMN refuse_links;
-- +goose StatementEnd
