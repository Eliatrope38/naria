-- name: CreateOrganisation :one
INSERT INTO organisations (name)
VALUES ($1)
RETURNING *;

-- L'administrateur de plateforme voit les organisations et l'adresse de leur
-- administrateur, et rien de leurs comptes ni de leurs sites.
-- name: ListOrganisations :many
SELECT o.id, o.name, o.created_at, a.email AS admin_email
FROM organisations o
LEFT JOIN users a ON a.org_id = o.id AND a.role = 'admin_orga'
ORDER BY o.name, o.id;
