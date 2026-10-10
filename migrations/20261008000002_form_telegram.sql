-- +goose Up
-- +goose StatementBegin

-- Alerte Telegram : le message est posté par un bot dans une discussion. Le
-- jeton du bot est un secret (qui le connaît parle au nom du bot), chiffré par
-- l'application comme les adresses de webhook. L'identifiant de la discussion
-- n'en est pas un. L'un ne sert à rien sans l'autre : les deux colonnes sont
-- renseignées ensemble, ou aucune.
ALTER TABLE forms
    ADD COLUMN telegram_bot_token TEXT,
    ADD COLUMN telegram_chat_id   TEXT,
    ADD CONSTRAINT forms_telegram_pair
        CHECK ((telegram_bot_token IS NULL) = (telegram_chat_id IS NULL));

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE forms
    DROP CONSTRAINT forms_telegram_pair,
    DROP COLUMN telegram_chat_id,
    DROP COLUMN telegram_bot_token;
-- +goose StatementEnd
