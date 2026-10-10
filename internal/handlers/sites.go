package handlers

import (
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/justinas/nosurf"

	"gitlab.com/detag_inno/naria/internal/auth"
	"gitlab.com/detag_inno/naria/internal/database"
	"gitlab.com/detag_inno/naria/internal/submission"
	"gitlab.com/detag_inno/naria/internal/web"
	"gitlab.com/detag_inno/naria/ui"
)

const sitesPerPage = 25

func (a *App) SiteList(w http.ResponseWriter, r *http.Request) {
	// The platform administrator has no sites: its home is the organisations.
	if web.UserFrom(r.Context()).Role == auth.RoleAdmin {
		http.Redirect(w, r, "/organisations", http.StatusSeeOther)
		return
	}
	a.renderSites(w, r, "")
}

func (a *App) renderSites(w http.ResponseWriter, r *http.Request, errMsg string) {
	u := web.UserFrom(r.Context())
	sc := scopeOf(u)
	q, search := searchParam(r)
	total, err := a.Q.CountSitesScoped(r.Context(), database.CountSitesScopedParams{
		ViewerID: sc.viewerID, AdminOrgID: sc.adminOrgID, Search: search,
	})
	if err != nil {
		http.Error(w, tr(r, "common.err.load"), http.StatusInternalServerError)
		return
	}
	qs := ""
	if q != "" {
		qs = "q=" + url.QueryEscape(q)
	}
	pg, offset := paginate("/", qs, pageParam(r), sitesPerPage, total)
	sites, err := a.Q.ListSitesScoped(r.Context(), database.ListSitesScopedParams{
		ViewerID: sc.viewerID, AdminOrgID: sc.adminOrgID, Search: search, PageLimit: sitesPerPage, PageOffset: offset,
	})
	if err != nil {
		http.Error(w, tr(r, "common.err.load"), http.StatusInternalServerError)
		return
	}
	renderPage(w, r, ui.SitesPage(u, sites, q, pg, nosurf.Token(r), errMsg, web.PopFlash(a.Sessions, r)))
}

// siteInput reads and validates the name and domains of a site. Returns a
// translated error message if the input is refused.
func siteInput(r *http.Request) (name string, domains []string, errMsg string) {
	name = strings.TrimSpace(r.FormValue("name"))
	if name == "" || len(name) > 120 {
		return "", nil, tr(r, "site.err.name_required")
	}
	domains, err := submission.NormalizeDomains(r.FormValue("domains"))
	if err != nil {
		return "", nil, tr(r, "site.err.domains_invalid", err.Error())
	}
	return name, domains, ""
}

func (a *App) CreateSite(w http.ResponseWriter, r *http.Request) {
	u := web.UserFrom(r.Context())
	if u.Role == auth.RoleAdmin {
		http.Error(w, tr(r, "site.err.not_found"), http.StatusNotFound)
		return
	}
	name, domains, errMsg := siteInput(r)
	if errMsg != "" {
		w.WriteHeader(http.StatusBadRequest)
		a.renderSites(w, r, errMsg)
		return
	}
	site, err := a.Q.CreateSite(r.Context(), database.CreateSiteParams{OwnerID: u.ID, Name: name, Domains: domains})
	if err != nil {
		a.renderSites(w, r, tr(r, "site.err.create_failed"))
		return
	}
	a.audit(r.Context(), auditEntry{
		ActorID:  refUUID(u.ID),
		Action:   auditSiteCreated,
		Entity:   auditEntitySite,
		EntityID: refUUID(site.ID),
		Meta:     map[string]string{"name": name, "ip": web.ClientIP(r)},
	})
	http.Redirect(w, r, "/sites/"+site.ID.String(), http.StatusSeeOther)
}

// siteFor loads the site "{id}" within the user's scope, for reading. Out of scope
// or missing, it is the same 404: another user's site must not be revealed. It writes
// the response itself on failure. The row says whether the account may write the site.
func (a *App) siteFor(w http.ResponseWriter, r *http.Request) (database.GetSiteScopedRow, bool) {
	u := web.UserFrom(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, tr(r, "site.err.not_found"), http.StatusNotFound)
		return database.GetSiteScopedRow{}, false
	}
	sc := scopeOf(u)
	site, err := a.Q.GetSiteScoped(r.Context(), database.GetSiteScopedParams{ID: id, ViewerID: sc.viewerID, AdminOrgID: sc.adminOrgID})
	if err != nil {
		http.Error(w, tr(r, "site.err.not_found"), http.StatusNotFound)
		return database.GetSiteScopedRow{}, false
	}
	return site, true
}

// writableSiteFor is siteFor for a change. A reader gets the same 404 as for a site
// they cannot see: a read-only share does not tell them the site exists to be changed.
func (a *App) writableSiteFor(w http.ResponseWriter, r *http.Request) (database.GetSiteScopedRow, bool) {
	site, ok := a.siteFor(w, r)
	if !ok {
		return site, false
	}
	if !site.CanWrite {
		http.Error(w, tr(r, "site.err.not_found"), http.StatusNotFound)
		return site, false
	}
	return site, true
}

func (a *App) SiteDetail(w http.ResponseWriter, r *http.Request) {
	site, ok := a.siteFor(w, r)
	if !ok {
		return
	}
	a.renderSite(w, r, site, ui.SiteVM{})
}

// renderSite renders the page of a site. vm carries what the caller has of its own
// to show (an error, a token just created); the rest is loaded here.
func (a *App) renderSite(w http.ResponseWriter, r *http.Request, site database.GetSiteScopedRow, vm ui.SiteVM) {
	u := web.UserFrom(r.Context())
	forms, err := a.Q.ListFormsBySite(r.Context(), site.ID)
	if err != nil {
		http.Error(w, tr(r, "common.err.load"), http.StatusInternalServerError)
		return
	}
	tokens, err := a.Q.ListAPITokensBySite(r.Context(), site.ID)
	if err != nil {
		http.Error(w, tr(r, "common.err.load"), http.StatusInternalServerError)
		return
	}
	vm.User, vm.Site, vm.Forms = u, site, forms
	vm.APIBase = strings.TrimRight(a.Cfg.BaseURL, "/") + "/api/v1"
	vm.CSRF, vm.Flash = nosurf.Token(r), web.PopFlash(a.Sessions, r)
	// A reader sees the forms and their submissions, not the tokens, which act for their creator.
	if site.CanWrite {
		vm.Tokens = tokens
	}
	if u.Role == auth.RoleOrgAdmin {
		vm.Owners, _ = a.Q.ListActiveOrgUsers(r.Context(), u.OrgID)
		vm.Readers, _ = a.Q.ListSiteReadGrants(r.Context(), database.ListSiteReadGrantsParams{SiteID: site.ID, AdminOrgID: u.OrgID})
		vm.Grantable, _ = a.Q.ListGrantableUsers(r.Context(), database.ListGrantableUsersParams{OrgID: u.OrgID, OwnerID: site.OwnerID})
	}
	renderPage(w, r, ui.SitePage(vm))
}

func (a *App) UpdateSite(w http.ResponseWriter, r *http.Request) {
	u := web.UserFrom(r.Context())
	site, ok := a.writableSiteFor(w, r)
	if !ok {
		return
	}
	name, domains, errMsg := siteInput(r)
	if errMsg != "" {
		w.WriteHeader(http.StatusBadRequest)
		a.renderSite(w, r, site, ui.SiteVM{ErrMsg: errMsg})
		return
	}
	sc := scopeOf(u)
	n, err := a.Q.UpdateSiteScoped(r.Context(), database.UpdateSiteScopedParams{
		ID: site.ID, Name: name, Domains: domains, ViewerID: sc.viewerID, AdminOrgID: sc.adminOrgID,
	})
	if err != nil || n == 0 {
		http.Error(w, tr(r, "common.err.update"), http.StatusInternalServerError)
		return
	}
	web.Flash(a.Sessions, r, tr(r, "site.flash.updated"))
	http.Redirect(w, r, "/sites/"+site.ID.String(), http.StatusSeeOther)
}

// SetSiteOwner transfers a site to an active account of the same organisation
// (organisation administrator only). The new owner's read grant on the site is
// dropped in the same transaction: it would be redundant, and it would outlive the
// transfer otherwise.
func (a *App) SetSiteOwner(w http.ResponseWriter, r *http.Request) {
	u := web.UserFrom(r.Context())
	if u.Role != auth.RoleOrgAdmin {
		http.Error(w, tr(r, "site.err.not_found"), http.StatusNotFound)
		return
	}
	site, ok := a.writableSiteFor(w, r)
	if !ok {
		return
	}
	ownerID, err := uuid.Parse(r.FormValue("owner_id"))
	if err != nil {
		http.Error(w, tr(r, "common.err.bad_id"), http.StatusBadRequest)
		return
	}
	tx, err := a.Pool.Begin(r.Context())
	if err != nil {
		http.Error(w, tr(r, "common.err.update"), http.StatusInternalServerError)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	q := a.Q.WithTx(tx)
	n, err := q.TransferSiteScoped(r.Context(), database.TransferSiteScopedParams{
		ID: site.ID, NewOwnerID: ownerID, AdminOrgID: u.OrgID,
	})
	if err != nil {
		http.Error(w, tr(r, "common.err.update"), http.StatusInternalServerError)
		return
	}
	if n == 0 {
		http.Error(w, tr(r, "common.err.account_not_found"), http.StatusBadRequest)
		return
	}
	if err := q.DeleteSiteReadGrant(r.Context(), database.DeleteSiteReadGrantParams{SiteID: site.ID, UserID: ownerID}); err != nil {
		http.Error(w, tr(r, "common.err.update"), http.StatusInternalServerError)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		http.Error(w, tr(r, "common.err.update"), http.StatusInternalServerError)
		return
	}
	a.audit(r.Context(), auditEntry{
		ActorID:  refUUID(u.ID),
		Action:   auditSiteOwnerChanged,
		Entity:   auditEntitySite,
		EntityID: refUUID(site.ID),
		Meta:     map[string]string{"name": site.Name, "from": site.OwnerID.String(), "to": ownerID.String(), "ip": web.ClientIP(r)},
	})
	newOwner, err := a.Q.GetUserByID(r.Context(), ownerID)
	if err != nil {
		log.Printf("ERROR site: nom du nouveau propriétaire id=%s: %v", ownerID, err)
	}
	web.Flash(a.Sessions, r, tr(r, "site.flash.owner_changed", newOwner.Name))
	http.Redirect(w, r, "/sites/"+site.ID.String(), http.StatusSeeOther)
}

// GrantSiteRead lets a user of the organisation read a site's submissions, without
// changing it (organisation administrator only).
func (a *App) GrantSiteRead(w http.ResponseWriter, r *http.Request) {
	u := web.UserFrom(r.Context())
	if u.Role != auth.RoleOrgAdmin {
		http.Error(w, tr(r, "site.err.not_found"), http.StatusNotFound)
		return
	}
	site, ok := a.writableSiteFor(w, r)
	if !ok {
		return
	}
	userID, err := uuid.Parse(r.FormValue("user_id"))
	if err != nil {
		http.Error(w, tr(r, "common.err.bad_id"), http.StatusBadRequest)
		return
	}
	n, err := a.Q.GrantSiteRead(r.Context(), database.GrantSiteReadParams{
		SiteID: site.ID, UserID: userID, GrantedBy: pgUUID(u.ID), AdminOrgID: u.OrgID,
	})
	if err != nil {
		http.Error(w, tr(r, "common.err.update"), http.StatusInternalServerError)
		return
	}
	if n == 0 {
		web.Flash(a.Sessions, r, tr(r, "site.flash.reader_refused"))
		http.Redirect(w, r, "/sites/"+site.ID.String(), http.StatusSeeOther)
		return
	}
	a.audit(r.Context(), auditEntry{
		ActorID:  refUUID(u.ID),
		Action:   auditReadGranted,
		Entity:   auditEntitySite,
		EntityID: refUUID(site.ID),
		Meta:     map[string]string{"name": site.Name, "user": userID.String(), "ip": web.ClientIP(r)},
	})
	web.Flash(a.Sessions, r, tr(r, "site.flash.reader_added"))
	http.Redirect(w, r, "/sites/"+site.ID.String(), http.StatusSeeOther)
}

// RevokeSiteRead withdraws a read grant. The account's tokens need no change: they
// are checked against the creator's write access, which a grant never gave.
func (a *App) RevokeSiteRead(w http.ResponseWriter, r *http.Request) {
	u := web.UserFrom(r.Context())
	if u.Role != auth.RoleOrgAdmin {
		http.Error(w, tr(r, "site.err.not_found"), http.StatusNotFound)
		return
	}
	site, ok := a.writableSiteFor(w, r)
	if !ok {
		return
	}
	userID, err := uuid.Parse(chi.URLParam(r, "user"))
	if err != nil {
		http.Error(w, tr(r, "common.err.bad_id"), http.StatusBadRequest)
		return
	}
	n, err := a.Q.RevokeSiteRead(r.Context(), database.RevokeSiteReadParams{
		SiteID: site.ID, UserID: userID, AdminOrgID: u.OrgID,
	})
	if err != nil {
		http.Error(w, tr(r, "common.err.update"), http.StatusInternalServerError)
		return
	}
	if n == 0 {
		http.Error(w, tr(r, "site.err.not_found"), http.StatusNotFound)
		return
	}
	a.audit(r.Context(), auditEntry{
		ActorID:  refUUID(u.ID),
		Action:   auditReadRevoked,
		Entity:   auditEntitySite,
		EntityID: refUUID(site.ID),
		Meta:     map[string]string{"name": site.Name, "user": userID.String(), "ip": web.ClientIP(r)},
	})
	web.Flash(a.Sessions, r, tr(r, "site.flash.reader_removed"))
	http.Redirect(w, r, "/sites/"+site.ID.String(), http.StatusSeeOther)
}

func (a *App) DeleteSite(w http.ResponseWriter, r *http.Request) {
	u := web.UserFrom(r.Context())
	site, ok := a.writableSiteFor(w, r)
	if !ok {
		return
	}
	sc := scopeOf(u)
	n, err := a.Q.DeleteSiteScoped(r.Context(), database.DeleteSiteScopedParams{ID: site.ID, ViewerID: sc.viewerID, AdminOrgID: sc.adminOrgID})
	if err != nil {
		log.Printf("ERROR site: suppression id=%s: %v", site.ID, err)
	}
	if err != nil || n == 0 {
		web.Flash(a.Sessions, r, tr(r, "site.flash.delete_failed"))
		http.Redirect(w, r, "/sites/"+site.ID.String(), http.StatusSeeOther)
		return
	}
	a.audit(r.Context(), auditEntry{
		ActorID:  refUUID(u.ID),
		Action:   auditSiteDeleted,
		Entity:   auditEntitySite,
		EntityID: refUUID(site.ID),
		Meta:     map[string]string{"name": site.Name, "ip": web.ClientIP(r)},
	})
	web.Flash(a.Sessions, r, tr(r, "site.flash.deleted"))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
