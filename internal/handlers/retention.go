package handlers

import (
	"context"
	"log"
)

// Retention periods announced in the privacy policy: each submission is deleted when its
// form's retention_days expires (0 means no limit), the IP in the audit log is erased after
// 90 days and the entry is deleted after 365 days. PurgeRetention enforces them.
const (
	auditRetentionDays = 365
	auditIPScrubDays   = 90
)

// PurgeRetention is idempotent and runs daily. Errors are logged without interrupting the service.
func (a *App) PurgeRetention(ctx context.Context) {
	if n, err := a.Q.PurgeExpiredSubmissions(ctx); err != nil {
		log.Printf("ERROR rétention: purge des soumissions échues: %v", err)
	} else if n > 0 {
		log.Printf("rétention: %d soumission(s) échue(s) supprimée(s)", n)
		a.forgetStorage()
	}
	if err := a.Q.DeleteExpiredPasswordResets(ctx); err != nil {
		log.Printf("ERROR rétention: purge des jetons de réinitialisation: %v", err)
	}
	if err := a.Q.ScrubAuditIPOlderThan(ctx, auditIPScrubDays); err != nil {
		log.Printf("ERROR rétention: effacement IP audit (>%dj): %v", auditIPScrubDays, err)
	}
	if err := a.Q.PurgeAuditOlderThan(ctx, auditRetentionDays); err != nil {
		log.Printf("ERROR rétention: purge audit (>%dj): %v", auditRetentionDays, err)
	}
}
