-- +goose Up
-- +goose StatementBegin

-- Vérification anti-robot, à activer formulaire par formulaire. Faux par
-- défaut : un formulaire déjà posé sur un site ne charge pas le script qui
-- résout le défi, et refuserait tous ses envois.
ALTER TABLE forms
    ADD COLUMN captcha BOOLEAN NOT NULL DEFAULT FALSE;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE forms
    DROP COLUMN captcha;
-- +goose StatementEnd
