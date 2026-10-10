-- +goose Up
-- +goose StatementBegin

-- Addresses and domains blocked per site. A submission with a field holding one of
-- these addresses, or an address at one of these domains, is accepted without being
-- kept or sent. A value containing "@" is an address, any other value a domain.
CREATE TABLE site_blocked_senders (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    site_id    UUID NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    value      TEXT NOT NULL CHECK (value = lower(value) AND length(value) BETWEEN 1 AND 255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (site_id, value)
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS site_blocked_senders;
-- +goose StatementEnd
