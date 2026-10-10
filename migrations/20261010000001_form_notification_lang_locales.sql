-- +goose Up
-- +goose StatementBegin

-- Italian and German join French and English as notification languages.
ALTER TABLE forms DROP CONSTRAINT forms_notification_lang_check;
ALTER TABLE forms ADD CONSTRAINT forms_notification_lang_check
    CHECK (notification_lang IN ('fr', 'en', 'it', 'de'));

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Forms that chose a new language go back to French, the language the older
-- constraint can hold.
UPDATE forms SET notification_lang = 'fr' WHERE notification_lang NOT IN ('fr', 'en');
ALTER TABLE forms DROP CONSTRAINT forms_notification_lang_check;
ALTER TABLE forms ADD CONSTRAINT forms_notification_lang_check
    CHECK (notification_lang IN ('fr', 'en'));

-- +goose StatementEnd
