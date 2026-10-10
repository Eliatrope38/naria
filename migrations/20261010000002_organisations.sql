-- +goose Up
-- +goose StatementBegin

-- Organisations group accounts and the sites they own. Each has exactly one
-- administrator (role admin_orga). The platform administrator (role admin)
-- belongs to none.
CREATE TABLE organisations (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Existing accounts all join one initial organisation, which holds every site.
-- The oldest active administrator becomes its administrator. Every other account
-- becomes a plain user: an organisation has one admin_orga, and the platform
-- administrator is created afterwards with createadmin.
ALTER TABLE users DROP CONSTRAINT users_role_check;

INSERT INTO organisations (name)
SELECT 'Organisation initiale' WHERE EXISTS (SELECT 1 FROM users);

ALTER TABLE users ADD COLUMN org_id UUID REFERENCES organisations(id) ON DELETE RESTRICT;
UPDATE users
SET org_id = (SELECT id FROM organisations),
    role = CASE WHEN id = (SELECT id FROM users WHERE role = 'admin' AND active
                           ORDER BY created_at, id LIMIT 1)
                THEN 'admin_orga' ELSE 'user' END;

ALTER TABLE users ADD CONSTRAINT users_role_check
    CHECK (role IN ('admin', 'admin_orga', 'user'));
-- Only the platform administrator has no organisation.
ALTER TABLE users ADD CONSTRAINT users_org_check
    CHECK ((role = 'admin') = (org_id IS NULL));
CREATE INDEX idx_users_org ON users(org_id);
CREATE UNIQUE INDEX idx_users_one_admin_orga ON users(org_id) WHERE role = 'admin_orga';

-- Read access that an organisation's administrator grants to a user on a site
-- they do not own. Write access is never recorded here: it follows ownership
-- and the administrator of the owner's organisation.
CREATE TABLE site_read_grants (
    site_id    UUID NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    granted_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (site_id, user_id)
);
CREATE INDEX idx_site_read_grants_user ON site_read_grants(user_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Going back is refused once several organisations exist: every administrator
-- would become a full administrator of the instance. Former administrators
-- demoted by the Up are not restored.
DO $$
BEGIN
    IF (SELECT count(*) FROM organisations) > 1 THEN
        RAISE EXCEPTION 'rollback refused: several organisations exist';
    END IF;
END $$;

DROP TABLE site_read_grants;

ALTER TABLE users DROP CONSTRAINT users_org_check;
ALTER TABLE users DROP CONSTRAINT users_role_check;
DROP INDEX idx_users_one_admin_orga;
DROP INDEX idx_users_org;

-- The platform administrator keeps the admin role. Organisation administrators
-- and users go back to the two former roles.
UPDATE users SET role = 'admin' WHERE role = 'admin_orga';
UPDATE users SET role = 'member' WHERE role = 'user';

ALTER TABLE users DROP COLUMN org_id;
DROP TABLE organisations;
ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('admin', 'member'));
-- +goose StatementEnd
