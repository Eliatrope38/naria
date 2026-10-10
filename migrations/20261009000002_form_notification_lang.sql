-- +goose Up
-- +goose StatementBegin

-- Langue des emails et des alertes d'un formulaire. Le français par défaut :
-- c'est la langue dans laquelle les formulaires existants écrivent déjà.
ALTER TABLE forms
    ADD COLUMN notification_lang TEXT NOT NULL DEFAULT 'fr'
        CHECK (notification_lang IN ('fr', 'en'));

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE forms
    DROP COLUMN notification_lang;
-- +goose StatementEnd
