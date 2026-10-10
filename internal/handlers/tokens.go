package handlers

import (
	"errors"
	"log"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"gitlab.com/detag_inno/naria/internal/auth"
	"gitlab.com/detag_inno/naria/internal/database"
	"gitlab.com/detag_inno/naria/internal/web"
	"gitlab.com/detag_inno/naria/ui"
)

const (
	maxAPITokens = 10
	maxTokenName = 80
)

// CreateAPIToken shows the token once, in the response to the POST: it does not
// pass through the session or the database. Reloading the page creates another token
// without invalidating the first.
func (a *App) CreateAPIToken(w http.ResponseWriter, r *http.Request) {
	u := web.UserFrom(r.Context())
	site, ok := a.writableSiteFor(w, r)
	if !ok {
		return
	}
	fail := func(status int, msg string) {
		w.WriteHeader(status)
		a.renderSite(w, r, site, ui.SiteVM{TokenErr: msg})
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" || len(name) > maxTokenName {
		fail(http.StatusBadRequest, tr(r, "site.tokens.err.name", maxTokenName))
		return
	}
	days, err := strconv.Atoi(r.FormValue("expires_in"))
	if err != nil || !slices.Contains(ui.TokenLifetimes, days) {
		fail(http.StatusBadRequest, tr(r, "site.tokens.err.lifetime"))
		return
	}
	n, err := a.Q.CountAPITokensBySite(r.Context(), site.ID)
	if err != nil {
		log.Printf("ERROR jeton: comptage site=%s: %v", site.ID, err)
		fail(http.StatusInternalServerError, tr(r, "site.tokens.err.create_failed"))
		return
	}
	if n >= maxAPITokens {
		fail(http.StatusBadRequest, tr(r, "site.tokens.err.too_many", maxAPITokens))
		return
	}
	plain, hash, err := auth.GenerateAPIToken()
	if err != nil {
		log.Printf("ERROR jeton: génération site=%s: %v", site.ID, err)
		fail(http.StatusInternalServerError, tr(r, "site.tokens.err.create_failed"))
		return
	}
	var expires pgtype.Timestamptz
	if days > 0 {
		expires = pgtype.Timestamptz{Time: time.Now().AddDate(0, 0, days), Valid: true}
	}
	tok, err := a.Q.CreateAPIToken(r.Context(), database.CreateAPITokenParams{
		SiteID: site.ID, UserID: u.ID, Name: name, TokenHash: hash, ExpiresAt: expires,
	})
	if err != nil {
		log.Printf("ERROR jeton: création site=%s: %v", site.ID, err)
		fail(http.StatusInternalServerError, tr(r, "site.tokens.err.create_failed"))
		return
	}
	a.audit(r.Context(), auditEntry{
		ActorID:  refUUID(u.ID),
		Action:   auditTokenCreated,
		Entity:   auditEntitySite,
		EntityID: refUUID(site.ID),
		Meta:     map[string]string{"token": tok.ID.String(), "name": name, "days": strconv.Itoa(days), "ip": web.ClientIP(r)},
	})
	w.Header().Set("Cache-Control", "no-store")
	a.renderSite(w, r, site, ui.SiteVM{NewToken: plain})
}

func (a *App) RevokeAPIToken(w http.ResponseWriter, r *http.Request) {
	u := web.UserFrom(r.Context())
	site, ok := a.writableSiteFor(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "token"))
	if err != nil {
		http.Error(w, tr(r, "site.tokens.err.not_found"), http.StatusNotFound)
		return
	}
	name, err := a.Q.DeleteAPIToken(r.Context(), database.DeleteAPITokenParams{ID: id, SiteID: site.ID})
	if errors.Is(err, pgx.ErrNoRows) {
		http.Error(w, tr(r, "site.tokens.err.not_found"), http.StatusNotFound)
		return
	}
	if err != nil {
		log.Printf("ERROR jeton: révocation site=%s: %v", site.ID, err)
		http.Error(w, tr(r, "common.err.update"), http.StatusInternalServerError)
		return
	}
	a.audit(r.Context(), auditEntry{
		ActorID:  refUUID(u.ID),
		Action:   auditTokenRevoked,
		Entity:   auditEntitySite,
		EntityID: refUUID(site.ID),
		Meta:     map[string]string{"token": id.String(), "name": name, "ip": web.ClientIP(r)},
	})
	web.Flash(a.Sessions, r, tr(r, "site.tokens.flash.revoked", name))
	http.Redirect(w, r, "/sites/"+site.ID.String(), http.StatusSeeOther)
}
