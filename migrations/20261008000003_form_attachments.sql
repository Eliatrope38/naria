-- +goose Up
-- +goose StatementBegin

-- Pièces jointes, à activer formulaire par formulaire. Faux par défaut : sans ce
-- choix, les fichiers d'un envoi restent ignorés.
ALTER TABLE forms
    ADD COLUMN accept_attachments BOOLEAN NOT NULL DEFAULT FALSE;

-- Fichiers joints à une soumission conservée. Ils en partagent le sort : la
-- suppression de la soumission (à la main, par la purge de rétention ou avec
-- son formulaire) les emporte. filename et content sont chiffrés par
-- l'application, comme le contenu de la soumission ; size est la taille du
-- fichier en clair. Comme pour submissions, aucune colonne d'adresse IP ni de
-- user-agent.
CREATE TABLE attachments (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    submission_id UUID NOT NULL REFERENCES submissions(id) ON DELETE CASCADE,
    position      SMALLINT NOT NULL,
    filename      TEXT NOT NULL,
    size          BIGINT NOT NULL,
    content       BYTEA NOT NULL,
    UNIQUE (submission_id, position)
);

-- Un contenu chiffré ne se compresse pas : inutile de laisser TOAST essayer.
ALTER TABLE attachments ALTER COLUMN content SET STORAGE EXTERNAL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE attachments;
ALTER TABLE forms
    DROP COLUMN accept_attachments;
-- +goose StatementEnd
