-- +goose Up
-- +goose StatementBegin

-- Jetons d'API d'un site. Un jeton agit pour le compte qui l'a créé, sur ce
-- seul site : il ne vaut que tant que ce compte est actif et garde accès au
-- site, ce qui se vérifie à chaque appel (voir GetAPITokenByHash). Seule
-- l'empreinte SHA-256 du jeton est conservée : il n'est montré qu'à sa création
-- et une lecture de la base ne le livre pas. expires_at NULL = sans échéance.
CREATE TABLE api_tokens (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    site_id      UUID NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    expires_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_api_tokens_site ON api_tokens(site_id);
CREATE INDEX idx_api_tokens_user ON api_tokens(user_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE api_tokens;
-- +goose StatementEnd
