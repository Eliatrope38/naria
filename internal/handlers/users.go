package handlers

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

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

func (a *App) UsersList(w http.ResponseWriter, r *http.Request) {
	a.renderUsers(w, r, "")
}

const usersPerPage = 25

func (a *App) renderUsers(w http.ResponseWriter, r *http.Request, errMsg string) {
	u := web.UserFrom(r.Context())
	q, search := searchParam(r)
	total, err := a.Q.CountUsersMatching(r.Context(), search)
	if err != nil {
		http.Error(w, tr(r, "common.err.load"), http.StatusInternalServerError)
		return
	}
	qs := ""
	if q != "" {
		qs = "q=" + url.QueryEscape(q)
	}
	pg, offset := paginate("/users", qs, pageParam(r), usersPerPage, total)
	list, err := a.Q.ListUsers(r.Context(), database.ListUsersParams{PageLimit: usersPerPage, PageOffset: offset, Search: search})
	if err != nil {
		http.Error(w, tr(r, "common.err.load"), http.StatusInternalServerError)
		return
	}
	rows := make([]ui.UserRowVM, 0, len(list))
	for _, x := range list {
		rows = append(rows, ui.UserRowVM{
			IDString: x.ID.String(), Name: x.Name, Email: x.Email, Role: x.Role,
			Active: x.Active, IsSelf: x.ID == u.ID, TotpEnabled: x.TotpEnabled, SiteCount: x.SiteCount,
		})
	}
	renderPage(w, r, ui.UsersPage(u, rows, nosurf.Token(r), errMsg, web.PopFlash(a.Sessions, r), pg, q))
}

func (a *App) CreateUser(w http.ResponseWriter, r *http.Request) {
	u := web.UserFrom(r.Context())
	name := strings.TrimSpace(r.FormValue("name"))
	email := auth.NormalizeEmail(r.FormValue("email"))
	password := r.FormValue("password")
	role := r.FormValue("role")

	if !auth.ValidRole(role) {
		a.renderUsers(w, r, tr(r, "users.err.role_invalid"))
		return
	}
	minLen := a.Cfg.PasswordMinLength
	if name == "" || email == "" || len(password) < minLen {
		a.renderUsers(w, r, tr(r, "users.err.required", minLen))
		return
	}

	if _, err := a.Q.GetUserByEmail(r.Context(), email); err == nil {
		a.renderUsers(w, r, tr(r, "users.err.email_exists"))
		return
	} else if !errors.Is(err, pgx.ErrNoRows) {
		http.Error(w, tr(r, "common.err.verify"), http.StatusInternalServerError)
		return
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		http.Error(w, tr(r, "common.err.internal"), http.StatusInternalServerError)
		return
	}
	created, err := a.Q.CreateUser(r.Context(), database.CreateUserParams{
		Email: email, Name: name, Role: role, PasswordHash: hash,
	})
	if err != nil {
		a.renderUsers(w, r, tr(r, "users.err.create_failed"))
		return
	}
	a.audit(r.Context(), auditEntry{
		ActorID:  refUUID(u.ID),
		Action:   auditUserCreated,
		Entity:   auditEntityUser,
		EntityID: refUUID(created.ID),
		Meta:     map[string]string{"email": email, "role": role, "ip": web.ClientIP(r)},
	})
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// targetUser loads the account "{id}". It writes the response itself on failure.
func (a *App) targetUser(w http.ResponseWriter, r *http.Request) (database.User, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, tr(r, "common.err.bad_id"), http.StatusBadRequest)
		return database.User{}, false
	}
	target, err := a.Q.GetUserByID(r.Context(), id)
	if err != nil {
		http.Error(w, tr(r, "common.err.account_not_found"), http.StatusNotFound)
		return database.User{}, false
	}
	return target, true
}

// isLastActiveAdmin: removing this account (deactivation, demotion,
// deletion) would leave the instance without an administrator.
func (a *App) isLastActiveAdmin(r *http.Request, target database.User) bool {
	if target.Role != auth.RoleAdmin || !target.Active {
		return false
	}
	n, err := a.Q.CountActiveAdmins(r.Context())
	return err != nil || n <= 1
}

func (a *App) ToggleUser(w http.ResponseWriter, r *http.Request) {
	u := web.UserFrom(r.Context())
	target, ok := a.targetUser(w, r)
	if !ok {
		return
	}
	if target.ID == u.ID {
		http.Error(w, tr(r, "users.err.self_deactivate"), http.StatusForbidden)
		return
	}
	newActive := !target.Active
	if !newActive && a.isLastActiveAdmin(r, target) {
		web.Flash(a.Sessions, r, tr(r, "users.flash.last_admin"))
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}
	if err := a.Q.SetUserActive(r.Context(), database.SetUserActiveParams{ID: target.ID, Active: newActive}); err != nil {
		http.Error(w, tr(r, "common.err.update"), http.StatusInternalServerError)
		return
	}
	action := auditUserDeactivated
	if newActive {
		action = auditUserActivated
	}
	a.audit(r.Context(), auditEntry{
		ActorID:  refUUID(u.ID),
		Action:   action,
		Entity:   auditEntityUser,
		EntityID: refUUID(target.ID),
		Meta:     map[string]string{"email": target.Email, "ip": web.ClientIP(r)},
	})
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func (a *App) ChangeUserRole(w http.ResponseWriter, r *http.Request) {
	u := web.UserFrom(r.Context())
	target, ok := a.targetUser(w, r)
	if !ok {
		return
	}
	if target.ID == u.ID { // a user does not change their own role (risk of losing access)
		web.Flash(a.Sessions, r, tr(r, "users.flash.self_role"))
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}
	role := r.FormValue("role")
	if !auth.ValidRole(role) {
		http.Error(w, tr(r, "users.err.role_invalid"), http.StatusBadRequest)
		return
	}
	if role != auth.RoleAdmin && a.isLastActiveAdmin(r, target) {
		web.Flash(a.Sessions, r, tr(r, "users.flash.last_admin"))
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}
	if err := a.Q.SetUserRole(r.Context(), database.SetUserRoleParams{ID: target.ID, Role: role}); err != nil {
		http.Error(w, tr(r, "common.err.update"), http.StatusInternalServerError)
		return
	}
	a.audit(r.Context(), auditEntry{
		ActorID:  refUUID(u.ID),
		Action:   auditUserRoleChanged,
		Entity:   auditEntityUser,
		EntityID: refUUID(target.ID),
		Meta:     map[string]string{"email": target.Email, "from": target.Role, "to": role, "ip": web.ClientIP(r)},
	})
	web.Flash(a.Sessions, r, tr(r, "users.flash.role_updated", target.Name))
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func (a *App) EditUserName(w http.ResponseWriter, r *http.Request) {
	u := web.UserFrom(r.Context())
	target, ok := a.targetUser(w, r)
	if !ok {
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		web.Flash(a.Sessions, r, tr(r, "users.err.name_required"))
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}
	if err := a.Q.UpdateUserName(r.Context(), database.UpdateUserNameParams{ID: target.ID, Name: name}); err != nil {
		http.Error(w, tr(r, "common.err.update"), http.StatusInternalServerError)
		return
	}
	a.audit(r.Context(), auditEntry{
		ActorID:  refUUID(u.ID),
		Action:   auditUserRenamed,
		Entity:   auditEntityUser,
		EntityID: refUUID(target.ID),
		Meta:     map[string]string{"email": target.Email, "renamed_to": name, "ip": web.ClientIP(r)},
	})
	web.Flash(a.Sessions, r, tr(r, "users.flash.name_updated", name))
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// DeleteUser deletes an account. An account that still owns sites is blocked
// by the FK constraint: they must first be transferred or deleted.
func (a *App) DeleteUser(w http.ResponseWriter, r *http.Request) {
	u := web.UserFrom(r.Context())
	target, ok := a.targetUser(w, r)
	if !ok {
		return
	}
	if target.ID == u.ID {
		web.Flash(a.Sessions, r, tr(r, "users.flash.self_delete"))
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}
	if a.isLastActiveAdmin(r, target) {
		web.Flash(a.Sessions, r, tr(r, "users.flash.last_admin"))
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}
	if err := a.Q.DeleteUser(r.Context(), target.ID); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			web.Flash(a.Sessions, r, tr(r, "users.flash.delete_has_refs"))
		} else {
			web.Flash(a.Sessions, r, tr(r, "users.flash.delete_failed"))
		}
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}
	a.audit(r.Context(), auditEntry{
		ActorID:  refUUID(u.ID),
		Action:   auditUserDeleted,
		Entity:   auditEntityUser,
		EntityID: refUUID(target.ID),
		Meta:     map[string]string{"email": target.Email, "name": target.Name, "ip": web.ClientIP(r)},
	})
	web.Flash(a.Sessions, r, tr(r, "users.flash.deleted"))
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func (a *App) ResetUser2FA(w http.ResponseWriter, r *http.Request) {
	u := web.UserFrom(r.Context())
	target, ok := a.targetUser(w, r)
	if !ok {
		return
	}
	if err := a.Q.DisableUserTOTP(r.Context(), target.ID); err != nil {
		http.Error(w, tr(r, "common.err.reset"), http.StatusInternalServerError)
		return
	}
	_ = a.Q.DeleteBackupCodes(r.Context(), target.ID)
	a.audit(r.Context(), auditEntry{
		ActorID:  refUUID(u.ID),
		Action:   auditUser2FAReset,
		Entity:   auditEntityUser,
		EntityID: refUUID(target.ID),
		Meta:     map[string]string{"email": target.Email, "ip": web.ClientIP(r)},
	})
	web.Flash(a.Sessions, r, tr(r, "users.flash.2fa_reset", target.Name))
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func (a *App) SetUserPassword(w http.ResponseWriter, r *http.Request) {
	u := web.UserFrom(r.Context())
	target, ok := a.targetUser(w, r)
	if !ok {
		return
	}
	password := r.FormValue("password")
	if minLen := a.Cfg.PasswordMinLength; len(password) < minLen {
		web.Flash(a.Sessions, r, tr(r, "users.flash.pwd_too_short", minLen))
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		http.Error(w, tr(r, "common.err.internal"), http.StatusInternalServerError)
		return
	}
	if err := a.Q.SetUserPassword(r.Context(), database.SetUserPasswordParams{ID: target.ID, PasswordHash: hash}); err != nil {
		http.Error(w, tr(r, "common.err.update"), http.StatusInternalServerError)
		return
	}
	a.audit(r.Context(), auditEntry{
		ActorID:  refUUID(u.ID),
		Action:   auditUserPasswordReset,
		Entity:   auditEntityUser,
		EntityID: refUUID(target.ID),
		Meta:     map[string]string{"email": target.Email, "ip": web.ClientIP(r)},
	})
	web.Flash(a.Sessions, r, tr(r, "users.flash.pwd_reset", target.Name))
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}
