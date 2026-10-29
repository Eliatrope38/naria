-- +goose Up
-- +goose StatementBegin

-- Drop submissions from disposable e-mail domains, per site. Off by default: the
-- embedded list may hold a domain some legitimate visitors use, and their messages
-- would be lost silently.
ALTER TABLE sites
    ADD COLUMN block_disposable BOOLEAN NOT NULL DEFAULT FALSE;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE sites
    DROP COLUMN block_disposable;
-- +goose StatementEnd
