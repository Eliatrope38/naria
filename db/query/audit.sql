-- name: InsertAuditLog :exec
INSERT INTO audit_log (actor_id, action, entity, entity_id, detail)
VALUES ($1, $2, $3, $4, $5);

-- name: PurgeAuditOlderThan :exec
DELETE FROM audit_log WHERE created_at < now() - make_interval(days => $1::int);

-- name: ScrubAuditIPOlderThan :exec
UPDATE audit_log SET detail = (detail::jsonb - 'ip')::text
WHERE created_at < now() - make_interval(days => $1::int)
  AND detail LIKE '%"ip"%';
