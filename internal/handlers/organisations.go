package handlers

import (
	"errors"
	"log"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/justinas/nosurf"

	"gitlab.com/detag_inno/naria/internal/auth"
	"gitlab.com/detag_inno/naria/internal/database"
	"gitlab.com/detag_inno/naria/internal/web"
	"gitlab.com/detag_inno/naria/ui"
)

// The platform administrator sees the organisations and their administrator's
// address, and nothing else: no account list, no site, no submission.

func (a *App) OrganisationsList(w http.ResponseWriter, r *http.Request) {
	a.renderOrganisations(w, r, "")
}

func (a *App) renderOrganisations(w http.ResponseWriter, r *http.Request, errMsg string) {
	rows, err := a.Q.ListOrganisations(r.Context())
	if err != nil {
		http.Error(w, tr(r, "common.err.load"), http.StatusInternalServerError)
		return
	}
	renderPage(w, r, ui.OrganisationsPage(web.UserFrom(r.Context()), rows, nosurf.Token(r), errMsg, web.PopFlash(a.Sessions, r)))
}

// adminInput reads the name, address and initial password of an administrator account.
// The returned message is translated when the input is refused.
func (a *App) adminInput(r *http.Request) (name, email, password, errMsg string) {
	name = strings.TrimSpace(r.FormValue("name"))
	email = auth.NormalizeEmail(r.FormValue("email"))
	password = r.FormValue("password")
	if name == "" || email == "" || len(password) < a.Cfg.PasswordMinLength {
		return "", "", "", tr(r, "users.err.required", a.Cfg.PasswordMinLength)
	}
	return name, email, password, ""
}

// isUniqueViolation reports a refused duplicate, such as a concurrent sign-up with the same address.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// emailTaken reports whether an address already has an account. Other errors are
// returned to the caller, which answers with a server error.
func (a *App) emailTaken(r *http.Request, email string) (bool, error) {
	_, err := a.Q.GetUserByEmail(r.Context(), email)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return false, err
}

// CreateOrganisation creates an organisation and its administrator in one transaction.
func (a *App) CreateOrganisation(w http.ResponseWriter, r *http.Request) {
	u := web.UserFrom(r.Context())
	orgName := strings.TrimSpace(r.FormValue("org_name"))
	name, email, password, errMsg := a.adminInput(r)
	if orgName == "" || utf8.RuneCountInString(orgName) > 120 {
		errMsg = tr(r, "orgs.err.name_required")
	}
	if errMsg != "" {
		a.renderOrganisations(w, r, errMsg)
		return
	}
	taken, err := a.emailTaken(r, email)
	if err != nil {
		http.Error(w, tr(r, "common.err.verify"), http.StatusInternalServerError)
		return
	}
	if taken {
		a.renderOrganisations(w, r, tr(r, "users.err.email_exists"))
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		http.Error(w, tr(r, "common.err.internal"), http.StatusInternalServerError)
		return
	}
	tx, err := a.Pool.Begin(r.Context())
	if err != nil {
		http.Error(w, tr(r, "common.err.update"), http.StatusInternalServerError)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	q := a.Q.WithTx(tx)
	org, err := q.CreateOrganisation(r.Context(), orgName)
	if err != nil {
		http.Error(w, tr(r, "common.err.update"), http.StatusInternalServerError)
		return
	}
	admin, err := q.CreateUser(r.Context(), database.CreateUserParams{
		Email: email, Name: name, Role: auth.RoleOrgAdmin, PasswordHash: hash, OrgID: pgUUID(org.ID),
	})
	if err != nil {
		if isUniqueViolation(err) {
			a.renderOrganisations(w, r, tr(r, "users.err.email_exists"))
			return
		}
		log.Printf("ERROR organisations: création de l'administrateur de %s: %v", org.ID, err)
		a.renderOrganisations(w, r, tr(r, "users.err.create_failed"))
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		http.Error(w, tr(r, "common.err.update"), http.StatusInternalServerError)
		return
	}
	a.audit(r.Context(), auditEntry{
		ActorID:  refUUID(u.ID),
		Action:   auditOrgCreated,
		Entity:   auditEntityOrg,
		EntityID: refUUID(org.ID),
		Meta:     map[string]string{"name": orgName, "admin": admin.ID.String(), "email": email, "ip": web.ClientIP(r)},
	})
	web.Flash(a.Sessions, r, tr(r, "orgs.flash.created", orgName))
	http.Redirect(w, r, "/organisations", http.StatusSeeOther)
}

// ReplaceOrgAdmin installs a new administrator for an organisation. The current one
// becomes a user first, so the one-administrator index is never violated, and both
// changes commit together.
func (a *App) ReplaceOrgAdmin(w http.ResponseWriter, r *http.Request) {
	u := web.UserFrom(r.Context())
	orgID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, tr(r, "common.err.bad_id"), http.StatusBadRequest)
		return
	}
	name, email, password, errMsg := a.adminInput(r)
	if errMsg != "" {
		a.renderOrganisations(w, r, errMsg)
		return
	}
	taken, err := a.emailTaken(r, email)
	if err != nil {
		http.Error(w, tr(r, "common.err.verify"), http.StatusInternalServerError)
		return
	}
	if taken {
		a.renderOrganisations(w, r, tr(r, "users.err.email_exists"))
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		http.Error(w, tr(r, "common.err.internal"), http.StatusInternalServerError)
		return
	}
	tx, err := a.Pool.Begin(r.Context())
	if err != nil {
		http.Error(w, tr(r, "common.err.update"), http.StatusInternalServerError)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	q := a.Q.WithTx(tx)
	if err := q.DemoteOrgAdmin(r.Context(), pgUUID(orgID)); err != nil {
		http.Error(w, tr(r, "common.err.update"), http.StatusInternalServerError)
		return
	}
	admin, err := q.CreateUser(r.Context(), database.CreateUserParams{
		Email: email, Name: name, Role: auth.RoleOrgAdmin, PasswordHash: hash, OrgID: pgUUID(orgID),
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" { // unknown organisation
			http.Error(w, tr(r, "orgs.err.not_found"), http.StatusNotFound)
			return
		}
		if isUniqueViolation(err) {
			a.renderOrganisations(w, r, tr(r, "users.err.email_exists"))
			return
		}
		log.Printf("ERROR organisations: remplacement de l'administrateur de %s: %v", orgID, err)
		http.Error(w, tr(r, "common.err.update"), http.StatusInternalServerError)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		http.Error(w, tr(r, "common.err.update"), http.StatusInternalServerError)
		return
	}
	a.audit(r.Context(), auditEntry{
		ActorID:  refUUID(u.ID),
		Action:   auditOrgAdminReplaced,
		Entity:   auditEntityOrg,
		EntityID: refUUID(orgID),
		Meta:     map[string]string{"admin": admin.ID.String(), "email": email, "ip": web.ClientIP(r)},
	})
	web.Flash(a.Sessions, r, tr(r, "orgs.flash.admin_replaced"))
	http.Redirect(w, r, "/organisations", http.StatusSeeOther)
}
