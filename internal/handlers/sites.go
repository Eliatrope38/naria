package handlers

import (
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
	a.renderSites(w, r, "")
}

func (a *App) renderSites(w http.ResponseWriter, r *http.Request, errMsg string) {
	u := web.UserFrom(r.Context())
	isAdmin, viewer := scope(u)
	q, search := searchParam(r)
	total, err := a.Q.CountSitesScoped(r.Context(), database.CountSitesScopedParams{IsAdmin: isAdmin, ViewerID: viewer, Search: search})
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
		IsAdmin: isAdmin, ViewerID: viewer, Search: search, PageLimit: sitesPerPage, PageOffset: offset,
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

// siteFor loads the site "{id}" within the user's scope. Out of scope
// or missing, it is the same 404: another user's site must not be revealed. It writes
// the response itself on failure.
func (a *App) siteFor(w http.ResponseWriter, r *http.Request) (database.GetSiteScopedRow, bool) {
	u := web.UserFrom(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, tr(r, "site.err.not_found"), http.StatusNotFound)
		return database.GetSiteScopedRow{}, false
	}
	isAdmin, viewer := scope(u)
	site, err := a.Q.GetSiteScoped(r.Context(), database.GetSiteScopedParams{ID: id, IsAdmin: isAdmin, ViewerID: viewer})
	if err != nil {
		http.Error(w, tr(r, "site.err.not_found"), http.StatusNotFound)
		return database.GetSiteScopedRow{}, false
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
	vm.User, vm.Site, vm.Forms, vm.Tokens = u, site, forms, tokens
	vm.APIBase = strings.TrimRight(a.Cfg.BaseURL, "/") + "/api/v1"
	vm.CSRF, vm.Flash = nosurf.Token(r), web.PopFlash(a.Sessions, r)
	if auth.IsAdmin(u.Role) { // ownership transfer is reserved to the administrator
		vm.Owners, _ = a.Q.ListActiveUsers(r.Context())
	}
	renderPage(w, r, ui.SitePage(vm))
}

func (a *App) UpdateSite(w http.ResponseWriter, r *http.Request) {
	u := web.UserFrom(r.Context())
	site, ok := a.siteFor(w, r)
	if !ok {
		return
	}
	name, domains, errMsg := siteInput(r)
	if errMsg != "" {
		w.WriteHeader(http.StatusBadRequest)
		a.renderSite(w, r, site, ui.SiteVM{ErrMsg: errMsg})
		return
	}
	isAdmin, viewer := scope(u)
	n, err := a.Q.UpdateSiteScoped(r.Context(), database.UpdateSiteScopedParams{
		ID: site.ID, Name: name, Domains: domains, IsAdmin: isAdmin, ViewerID: viewer,
	})
	if err != nil || n == 0 {
		http.Error(w, tr(r, "common.err.update"), http.StatusInternalServerError)
		return
	}
	web.Flash(a.Sessions, r, tr(r, "site.flash.updated"))
	http.Redirect(w, r, "/sites/"+site.ID.String(), http.StatusSeeOther)
}

// SetSiteOwner transfers a site to another account (administrator only).
func (a *App) SetSiteOwner(w http.ResponseWriter, r *http.Request) {
	u := web.UserFrom(r.Context())
	site, ok := a.siteFor(w, r)
	if !ok {
		return
	}
	ownerID, err := uuid.Parse(r.FormValue("owner_id"))
	if err != nil {
		http.Error(w, tr(r, "common.err.bad_id"), http.StatusBadRequest)
		return
	}
	owner, err := a.Q.GetUserByID(r.Context(), ownerID)
	if err != nil || !owner.Active {
		http.Error(w, tr(r, "common.err.account_not_found"), http.StatusBadRequest)
		return
	}
	if err := a.Q.SetSiteOwner(r.Context(), database.SetSiteOwnerParams{ID: site.ID, OwnerID: owner.ID}); err != nil {
		http.Error(w, tr(r, "common.err.update"), http.StatusInternalServerError)
		return
	}
	a.audit(r.Context(), auditEntry{
		ActorID:  refUUID(u.ID),
		Action:   auditSiteOwnerChanged,
		Entity:   auditEntitySite,
		EntityID: refUUID(site.ID),
		Meta:     map[string]string{"name": site.Name, "from": site.OwnerID.String(), "to": owner.ID.String(), "ip": web.ClientIP(r)},
	})
	web.Flash(a.Sessions, r, tr(r, "site.flash.owner_changed", owner.Name))
	http.Redirect(w, r, "/sites/"+site.ID.String(), http.StatusSeeOther)
}

func (a *App) DeleteSite(w http.ResponseWriter, r *http.Request) {
	u := web.UserFrom(r.Context())
	site, ok := a.siteFor(w, r)
	if !ok {
		return
	}
	isAdmin, viewer := scope(u)
	n, err := a.Q.DeleteSiteScoped(r.Context(), database.DeleteSiteScopedParams{ID: site.ID, IsAdmin: isAdmin, ViewerID: viewer})
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
