package handlers

import (
	"context"
	"encoding/json"
	"log"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"gitlab.com/detag_inno/naria/internal/database"
)

// Audit log actions, in the form <domain>.<event>. Dashboards and alerts filter on them,
// so renaming one requires migrating its consumers.
const (
	auditLoginSucceeded    = "auth.login_succeeded"
	auditLoginFailed       = "auth.login_failed"
	auditUserCreated       = "user.created"
	auditUserActivated     = "user.activated"
	auditUserDeactivated   = "user.deactivated"
	auditUserRoleChanged   = "user.role_changed"
	auditUserRenamed       = "user.renamed"
	auditUserDeleted       = "user.deleted"
	auditUserPasswordReset = "user.password_reset"
	// Reset link issued through self-service: no actor, since the requester is not authenticated.
	auditPasswordResetRequested = "user.password_reset_requested"
	auditUser2FAReset           = "user.twofa_reset"
	auditSiteCreated            = "site.created"
	auditSiteDeleted            = "site.deleted"
	auditSiteOwnerChanged       = "site.owner_changed"
	auditTokenCreated           = "site.token_created" // #nosec G101 -- audit action name, not a secret
	auditTokenRevoked           = "site.token_revoked" // #nosec G101 -- audit action name, not a secret
	auditFormCreated            = "form.created"
	auditFormUpdated            = "form.updated"
	auditFormDeleted            = "form.deleted"
	auditFormKeyRegenerated     = "form.key_regenerated"
	auditSubmissionsPurged      = "form.submissions_purged"
	auditSubmissionsExported    = "form.submissions_exported"
	auditOrgCreated             = "org.created"
	auditOrgAdminReplaced       = "org.admin_replaced"
	auditReadGranted            = "site.read_granted"
	auditReadRevoked            = "site.read_revoked"
)

const (
	auditEntityUser = "user"
	auditEntitySite = "site"
	auditEntityForm = "form"
	auditEntityOrg  = "organisation"
)

// auditEntry describes an event. A nil *uuid.UUID becomes NULL in the database: an
// anonymous actor (failed login) or an unknown target.
type auditEntry struct {
	ActorID  *uuid.UUID
	Action   string
	Entity   string
	EntityID *uuid.UUID
	// Free-form context (IP, roles, etc.), never the content of a submission. There is no
	// IP column: it travels here.
	Meta map[string]string
}

// audit writes an entry without ever failing the business action: the audit trail is a
// record, not a precondition. A failure is logged as ERROR so that a log that stops
// receiving entries gets noticed.
func (a *App) audit(ctx context.Context, e auditEntry) {
	// A logout right after the action must not drop its audit entry.
	ctx = context.WithoutCancel(ctx)

	var detail *string
	if len(e.Meta) > 0 {
		if b, err := json.Marshal(e.Meta); err == nil {
			s := string(b)
			detail = &s
		} else {
			log.Printf("ERROR audit: sérialisation des métadonnées action=%q: %v", e.Action, err)
		}
	}

	if err := a.Q.InsertAuditLog(ctx, database.InsertAuditLogParams{
		ActorID:  nullableUUID(e.ActorID),
		Action:   e.Action,
		Entity:   e.Entity,
		EntityID: nullableUUID(e.EntityID),
		Detail:   detail,
	}); err != nil {
		log.Printf("ERROR audit: écriture impossible action=%q entity=%q: %v", e.Action, e.Entity, err)
	}
}

// refUUID returns a pointer to a copy, to tell a value apart from NULL.
func refUUID(id uuid.UUID) *uuid.UUID { return &id }

func nullableUUID(id *uuid.UUID) pgtype.UUID {
	if id == nil {
		return pgtype.UUID{}
	}
	return pgtype.UUID{Bytes: *id, Valid: true}
}
