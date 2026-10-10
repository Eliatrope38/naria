-- name: ListBlockedSenders :many
SELECT * FROM site_blocked_senders WHERE site_id = $1 ORDER BY value;

-- name: AddBlockedSender :exec
INSERT INTO site_blocked_senders (site_id, value) VALUES ($1, $2)
ON CONFLICT (site_id, value) DO NOTHING;

-- name: RemoveBlockedSender :one
DELETE FROM site_blocked_senders WHERE id = $1 AND site_id = $2
RETURNING value;

-- The keys come from submission.SenderKeys, already lower-cased like the stored values.
-- name: IsSenderBlocked :one
SELECT EXISTS (SELECT 1 FROM site_blocked_senders WHERE site_id = $1 AND value = ANY(sqlc.arg('keys')::text[]));
