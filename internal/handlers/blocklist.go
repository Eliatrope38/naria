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

// senderBlocked reports whether the submission carries a sender, or a link to a
// domain, blocked on the site. The reply address counts too: it is where the owner
// answers, even when the form has no field for it. The subject too, since it
// becomes the subject of the email.
func (a *App) senderBlocked(ctx context.Context, siteID uuid.UUID, meta submission.Meta, data []submission.Field) (bool, error) {
	keys := submission.BlockKeys(withServiceText(meta, data))
	if len(keys) == 0 {
		return false, nil
	}
	return a.Q.IsSenderBlocked(ctx, database.IsSenderBlockedParams{SiteID: siteID, Keys: keys})
}

// withServiceText adds to the data the service fields a visitor writes freely and
// that reach the owner, for the blocklist and the link check. slices.Clip keeps
// append from writing into the caller's spare capacity.
func withServiceText(meta submission.Meta, data []submission.Field) []submission.Field {
	return append(slices.Clip(data),
		submission.Field{Name: "replyto", Value: meta.ReplyTo},
		submission.Field{Name: "subject", Value: meta.Subject})
}

// senderKind names what a blocklist value is, for the audit log. The value
// itself, an address, a domain or an extension the owner chose, stays out of the log.
func senderKind(value string) string {
	switch {
	case strings.Contains(value, "@"):
		return "email"
	case strings.HasPrefix(value, "."):
		return "tld"
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

// SetBlockDisposable turns on or off the drop of submissions sent from a
// disposable e-mail domain, for a whole site.
func (a *App) SetBlockDisposable(w http.ResponseWriter, r *http.Request) {
	u := web.UserFrom(r.Context())
	site, ok := a.writableSiteFor(w, r)
	if !ok {
		return
	}
	on := r.FormValue("block_disposable") != ""
	sc := scopeOf(u)
	n, err := a.Q.SetSiteBlockDisposableScoped(r.Context(), database.SetSiteBlockDisposableScopedParams{
		ID: site.ID, BlockDisposable: on, ViewerID: sc.viewerID, AdminOrgID: sc.adminOrgID,
	})
	if err != nil || n == 0 {
		log.Printf("ERROR blocage: adresses jetables site=%s: %v (lignes=%d)", site.ID, err, n)
		http.Error(w, tr(r, "common.err.update"), http.StatusInternalServerError)
		return
	}
	action, flash := auditSenderUnblocked, "site.blocked.flash.disposable_off"
	if on {
		action, flash = auditSenderBlocked, "site.blocked.flash.disposable_on"
	}
	if on != site.BlockDisposable {
		a.audit(r.Context(), auditEntry{
			ActorID:  refUUID(u.ID),
			Action:   action,
			Entity:   auditEntitySite,
			EntityID: refUUID(site.ID),
			Meta:     map[string]string{"kind": "disposable", "ip": web.ClientIP(r)},
		})
	}
	web.Flash(a.Sessions, r, tr(r, flash))
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
