package handlers

import (
	"context"
	"errors"
	"log"
	"net/http"
	"slices"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"gitlab.com/detag_inno/naria/internal/database"
	"gitlab.com/detag_inno/naria/internal/submission"
	"gitlab.com/detag_inno/naria/internal/web"
	"gitlab.com/detag_inno/naria/ui"
)

const maxBlockedSenderLen = 255

// senderBlocked reports whether the submission carries a sender blocked on the site.
// The reply address counts too: it is where the owner answers, even when the form
// has no field for it.
func (a *App) senderBlocked(ctx context.Context, siteID uuid.UUID, meta submission.Meta, data []submission.Field) (bool, error) {
	fields := append(slices.Clip(data), submission.Field{Name: "replyto", Value: meta.ReplyTo})
	keys := submission.SenderKeys(fields)
	if len(keys) == 0 {
		return false, nil
	}
	return a.Q.IsSenderBlocked(ctx, database.IsSenderBlockedParams{SiteID: siteID, Keys: keys})
}

// senderKind names what a blocklist value is, for the audit log. The value
// itself is an address the owner chose to block, and stays out of the log.
func senderKind(value string) string {
	if strings.Contains(value, "@") {
		return "email"
	}
	return "domain"
}

func (a *App) BlockSender(w http.ResponseWriter, r *http.Request) {
	u := web.UserFrom(r.Context())
	site, ok := a.writableSiteFor(w, r)
	if !ok {
		return
	}
	value, err := submission.NormalizeSender(r.FormValue("value"))
	if err != nil || len(value) > maxBlockedSenderLen {
		w.WriteHeader(http.StatusBadRequest)
		a.renderSite(w, r, site, ui.SiteVM{BlockErr: tr(r, "site.blocked.err.invalid")})
		return
	}
	if err := a.Q.AddBlockedSender(r.Context(), database.AddBlockedSenderParams{SiteID: site.ID, Value: value}); err != nil {
		log.Printf("ERROR blocage: ajout site=%s: %v", site.ID, err)
		w.WriteHeader(http.StatusInternalServerError)
		a.renderSite(w, r, site, ui.SiteVM{BlockErr: tr(r, "site.blocked.err.failed")})
		return
	}
	a.audit(r.Context(), auditEntry{
		ActorID:  refUUID(u.ID),
		Action:   auditSenderBlocked,
		Entity:   auditEntitySite,
		EntityID: refUUID(site.ID),
		Meta:     map[string]string{"kind": senderKind(value), "ip": web.ClientIP(r)},
	})
	web.Flash(a.Sessions, r, tr(r, "site.blocked.flash.added", value))
	http.Redirect(w, r, "/sites/"+site.ID.String(), http.StatusSeeOther)
}

func (a *App) UnblockSender(w http.ResponseWriter, r *http.Request) {
	u := web.UserFrom(r.Context())
	site, ok := a.writableSiteFor(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "entry"))
	if err != nil {
		http.Error(w, tr(r, "site.blocked.err.not_found"), http.StatusNotFound)
		return
	}
	value, err := a.Q.RemoveBlockedSender(r.Context(), database.RemoveBlockedSenderParams{ID: id, SiteID: site.ID})
	if errors.Is(err, pgx.ErrNoRows) {
		http.Error(w, tr(r, "site.blocked.err.not_found"), http.StatusNotFound)
		return
	}
	if err != nil {
		log.Printf("ERROR blocage: retrait site=%s: %v", site.ID, err)
		http.Error(w, tr(r, "common.err.update"), http.StatusInternalServerError)
		return
	}
	a.audit(r.Context(), auditEntry{
		ActorID:  refUUID(u.ID),
		Action:   auditSenderUnblocked,
		Entity:   auditEntitySite,
		EntityID: refUUID(site.ID),
		Meta:     map[string]string{"kind": senderKind(value), "ip": web.ClientIP(r)},
	})
	web.Flash(a.Sessions, r, tr(r, "site.blocked.flash.removed", value))
	http.Redirect(w, r, "/sites/"+site.ID.String(), http.StatusSeeOther)
}
