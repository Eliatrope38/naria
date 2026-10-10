package handlers

import (
	"context"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/justinas/nosurf"

	"gitlab.com/detag_inno/naria/internal/auth"
	"gitlab.com/detag_inno/naria/internal/database"
	"gitlab.com/detag_inno/naria/internal/web"
	"gitlab.com/detag_inno/naria/ui"
)

// TOTP secret being enrolled, not yet confirmed, kept in the session.
const totpSetupKey = "totp_setup_secret"

func (a *App) AccountPage(w http.ResponseWriter, r *http.Request) {
	u := web.UserFrom(r.Context())
	remaining := int64(0)
	if u.TotpEnabled {
		remaining, _ = a.Q.CountUnusedBackupCodes(r.Context(), u.ID)
	}
	renderPage(w, r, ui.AccountPage(u, web.PopFlash(a.Sessions, r), nosurf.Token(r), int(remaining)))
}

func (a *App) TOTPSetup(w http.ResponseWriter, r *http.Request) {
	u := web.UserFrom(r.Context())
	if u.TotpEnabled {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	key, err := auth.GenerateTOTP(u.Email)
	if err != nil {
		http.Error(w, tr(r, "account.err.totp_gen"), http.StatusInternalServerError)
		return
	}
	a.Sessions.Put(r.Context(), totpSetupKey, key.Secret())

	qr, err := auth.QRCodeDataURI(key)
	if err != nil {
		http.Error(w, tr(r, "account.err.qr"), http.StatusInternalServerError)
		return
	}
	renderPage(w, r, ui.TOTPSetupPage(u, qr, key.Secret(), nosurf.Token(r), ""))
}

func (a *App) TOTPEnable(w http.ResponseWriter, r *http.Request) {
	u := web.UserFrom(r.Context())
	secret := a.Sessions.GetString(r.Context(), totpSetupKey)
	if secret == "" {
		http.Redirect(w, r, "/account/2fa/setup", http.StatusSeeOther)
		return
	}
	if !auth.ValidateTOTP(r.FormValue("code"), secret) {
		qr, _ := auth.QRCodeFromSecret(u.Email, secret)
		renderPage(w, r, ui.TOTPSetupPage(u, qr, secret, nosurf.Token(r), tr(r, "login.verify.err.bad")))
		return
	}
	stored, err := a.Crypto.Encrypt(secret) // encrypted at rest
	if err != nil {
		http.Error(w, tr(r, "account.err.encrypt"), http.StatusInternalServerError)
		return
	}
	if err := a.Q.SetUserTOTP(r.Context(), database.SetUserTOTPParams{ID: u.ID, TotpSecret: &stored}); err != nil {
		http.Error(w, tr(r, "account.err.enable"), http.StatusInternalServerError)
		return
	}
	a.Sessions.Remove(r.Context(), totpSetupKey)

	codes, err := a.regenBackupCodes(r.Context(), u.ID)
	if err != nil {
		http.Error(w, tr(r, "account.err.codes_gen"), http.StatusInternalServerError)
		return
	}
	renderPage(w, r, ui.TOTPCodesPage(u, codes))
}

// regenBackupCodes replaces the backup codes and returns them in clear text, to be shown once.
func (a *App) regenBackupCodes(ctx context.Context, userID uuid.UUID) ([]string, error) {
	_ = a.Q.DeleteBackupCodes(ctx, userID)
	codes, err := auth.GenerateBackupCodes(10)
	if err != nil {
		return nil, err
	}
	for _, c := range codes {
		hash, err := auth.HashPassword(auth.CanonicalCode(c))
		if err != nil {
			return nil, err
		}
		if err := a.Q.CreateBackupCode(ctx, database.CreateBackupCodeParams{UserID: userID, CodeHash: hash}); err != nil {
			return nil, err
		}
	}
	return codes, nil
}

func (a *App) consumeBackupCode(ctx context.Context, userID uuid.UUID, input string) bool {
	canon := auth.CanonicalCode(input)
	if canon == "" {
		return false
	}
	rows, err := a.Q.ListUnusedBackupCodes(ctx, userID)
	if err != nil {
		return false
	}
	for _, row := range rows {
		if ok, _ := auth.VerifyPassword(canon, row.CodeHash); ok {
			_ = a.Q.MarkBackupCodeUsed(ctx, row.ID)
			return true
		}
	}
	return false
}

func (a *App) TOTPDisable(w http.ResponseWriter, r *http.Request) {
	u := web.UserFrom(r.Context())
	if a.Limiter != nil && !a.Limiter.Allow(web.RateLimitKey(r)) {
		web.Flash(a.Sessions, r, tr(r, "account.flash.rate"))
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	if !u.TotpEnabled || u.TotpSecret == nil {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	secret, err := a.Crypto.Decrypt(*u.TotpSecret)
	if err != nil || !auth.ValidateTOTP(r.FormValue("code"), secret) {
		web.Flash(a.Sessions, r, tr(r, "account.flash.wrong_code"))
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	if err := a.Q.DisableUserTOTP(r.Context(), u.ID); err != nil {
		http.Error(w, tr(r, "account.err.disable"), http.StatusInternalServerError)
		return
	}
	_ = a.Q.DeleteBackupCodes(r.Context(), u.ID)
	web.Flash(a.Sessions, r, tr(r, "account.flash.disabled"))
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}

func (a *App) ChangeOwnName(w http.ResponseWriter, r *http.Request) {
	u := web.UserFrom(r.Context())
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		web.Flash(a.Sessions, r, tr(r, "account.err.name_required"))
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	if err := a.Q.UpdateUserName(r.Context(), database.UpdateUserNameParams{ID: u.ID, Name: name}); err != nil {
		web.Flash(a.Sessions, r, tr(r, "common.err.update"))
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	web.Flash(a.Sessions, r, tr(r, "account.flash.name_updated"))
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}

// Uniqueness is checked before the write; the UNIQUE constraint still guards against races.
func (a *App) ChangeOwnEmail(w http.ResponseWriter, r *http.Request) {
	u := web.UserFrom(r.Context())
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	if email == "" || !strings.Contains(email, "@") {
		web.Flash(a.Sessions, r, tr(r, "account.err.email_invalid"))
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	if email != strings.ToLower(u.Email) {
		if _, err := a.Q.GetUserByEmail(r.Context(), email); err == nil {
			web.Flash(a.Sessions, r, tr(r, "account.err.email_taken"))
			http.Redirect(w, r, "/account", http.StatusSeeOther)
			return
		}
	}
	if err := a.Q.UpdateUserEmail(r.Context(), database.UpdateUserEmailParams{ID: u.ID, Email: email}); err != nil {
		web.Flash(a.Sessions, r, tr(r, "account.err.email_taken"))
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	web.Flash(a.Sessions, r, tr(r, "account.flash.email_updated"))
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}

// Every response redirects to /account without revealing anything.
func (a *App) ChangeOwnPassword(w http.ResponseWriter, r *http.Request) {
	u := web.UserFrom(r.Context())
	current := r.FormValue("current_password")
	next := r.FormValue("new_password")
	if ok, _ := auth.VerifyPassword(current, u.PasswordHash); !ok {
		web.Flash(a.Sessions, r, tr(r, "account.err.pwd_wrong"))
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	if len(next) < a.Cfg.PasswordMinLength {
		web.Flash(a.Sessions, r, tr(r, "users.flash.pwd_too_short", a.Cfg.PasswordMinLength))
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	hash, err := auth.HashPassword(next)
	if err != nil {
		web.Flash(a.Sessions, r, tr(r, "common.err.update"))
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	if err := a.Q.SetUserPassword(r.Context(), database.SetUserPasswordParams{ID: u.ID, PasswordHash: hash}); err != nil {
		web.Flash(a.Sessions, r, tr(r, "common.err.update"))
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	web.Flash(a.Sessions, r, tr(r, "account.flash.pwd_updated"))
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}
