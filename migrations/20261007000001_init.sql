-- +goose Up
-- +goose StatementBegin

-- Comptes de l'instance. role: admin (tout + administration) | member (ses sites).
CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email         TEXT NOT NULL UNIQUE,
    name          TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('admin','member')),
    password_hash TEXT NOT NULL,
    active        BOOLEAN NOT NULL DEFAULT TRUE,
    totp_secret   TEXT,
    totp_enabled  BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Sessions (store de github.com/alexedwards/scs/pgxstore)
CREATE TABLE sessions (
    token  TEXT PRIMARY KEY,
    data   BYTEA NOT NULL,
    expiry TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_sessions_expiry ON sessions(expiry);

CREATE TABLE totp_backup_codes (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_backup_codes_user ON totp_backup_codes(user_id);

-- Self-service password reset. The link sent by email carries a random token;
-- only its SHA-256 hash is stored. A token is single-use and short-lived.
CREATE TABLE password_reset_tokens (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_password_reset_tokens_user ON password_reset_tokens(user_id);

-- Sites : un site web dont on reçoit les formulaires. domains = hôtes autorisés à
-- soumettre (contrôle de l'en-tête Origin) ; vide = toute origine acceptée.
-- ON DELETE RESTRICT sur le propriétaire : on ne supprime pas un compte qui
-- emporterait des sites (et leurs soumissions) sans décision explicite.
CREATE TABLE sites (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id   UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    name       TEXT NOT NULL,
    domains    TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_sites_owner ON sites(owner_id);

-- Formulaires d'un site. access_key est la clé publique posée dans le HTML du
-- site (elle identifie le formulaire, elle n'authentifie personne).
-- Deux destinations indépendantes pour une soumission, au moins une active :
--   notify_email      : envoyée par email aux destinataires ;
--   store_submissions : conservée (chiffrée) et listée dans l'interface.
-- retention_days borne la conservation ; 0 = sans limite.
CREATE TABLE forms (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    site_id               UUID NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    name                  TEXT NOT NULL,
    access_key            TEXT NOT NULL UNIQUE,
    active                BOOLEAN NOT NULL DEFAULT TRUE,
    notify_email          BOOLEAN NOT NULL DEFAULT TRUE,
    recipients            TEXT[] NOT NULL DEFAULT '{}',
    email_include_content BOOLEAN NOT NULL DEFAULT TRUE,
    store_submissions     BOOLEAN NOT NULL DEFAULT TRUE,
    retention_days        INTEGER NOT NULL DEFAULT 90 CHECK (retention_days >= 0),
    redirect_url          TEXT,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (notify_email OR store_submissions)
);
CREATE INDEX idx_forms_site ON forms(site_id);

-- Soumissions conservées. payload = liste ordonnée des champs, chiffrée au repos
-- par l'application (AES-256-GCM) : la base ne voit jamais le contenu en clair.
-- Volontairement aucune colonne d'adresse IP ni de user-agent.
CREATE TABLE submissions (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    form_id    UUID NOT NULL REFERENCES forms(id) ON DELETE CASCADE,
    payload    TEXT NOT NULL,
    read_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_submissions_form_created ON submissions(form_id, created_at DESC);

-- Journal d'audit des actions privilégiées (comptes, sites, formulaires).
CREATE TABLE audit_log (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id   UUID REFERENCES users(id) ON DELETE SET NULL,
    action     TEXT NOT NULL,
    entity     TEXT NOT NULL,
    entity_id  UUID,
    detail     TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_entity ON audit_log(entity, entity_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS submissions;
DROP TABLE IF EXISTS forms;
DROP TABLE IF EXISTS sites;
DROP TABLE IF EXISTS password_reset_tokens;
DROP TABLE IF EXISTS totp_backup_codes;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS users;
-- +goose StatementEnd
