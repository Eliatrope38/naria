package handlers

import (
	"context"
	"html"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/justinas/nosurf"

	"gitlab.com/detag_inno/naria/internal/auth"
	"gitlab.com/detag_inno/naria/internal/database"
	"gitlab.com/detag_inno/naria/internal/email"
	"gitlab.com/detag_inno/naria/internal/web"
	"gitlab.com/detag_inno/naria/ui"
)

// Validity period of a link sent by email.
const resetTokenTTL = time.Hour

// Cap on links per account within the CountRecentPasswordResets window: a
// known address must not be used to flood an inbox.
const resetMaxPerWindow = 3

// The whole flow answers 404 without outgoing email: the link could not be sent.
func (a *App) ShowForgotPassword(w http.ResponseWriter, r *http.Request) {
	if a.Mailer == nil {
		http.NotFound(w, r)
		return
	}
	if web.UserFrom(r.Context()) != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	renderPage(w, r, ui.ForgotPasswordPage(nosurf.Token(r), "", false))
}

// Same response whether or not the account exists: no enumeration.
func (a *App) DoForgotPassword(w http.ResponseWriter, r *http.Request) {
	if a.Mailer == nil {
		http.NotFound(w, r)
		return
	}
	if a.Limiter != nil && !a.Limiter.Allow(web.RateLimitKey(r)) {
		w.WriteHeader(http.StatusTooManyRequests)
		renderPage(w, r, ui.ForgotPasswordPage(nosurf.Token(r), tr(r, "login.err.rate"), false))
		return
	}
	addr := auth.NormalizeEmail(r.FormValue("email"))
	if key, status := a.turnstileGate(r, addr); key != "" {
		w.WriteHeader(status)
		renderPage(w, r, ui.ForgotPasswordPage(nosurf.Token(r), tr(r, key), false))
		return
	}
	a.issuePasswordReset(r, addr)
	renderPage(w, r, ui.ForgotPasswordPage(nosurf.Token(r), "", true))
}

// issuePasswordReset issues a single-use token and sends the link. Silent on
// failure: the caller's response must not depend on whether the account exists.
func (a *App) issuePasswordReset(r *http.Request, addr string) {
	ctx := r.Context()
	u, err := a.Q.GetUserByEmail(ctx, addr)
	if err != nil || !u.Active {
		return
	}
	_ = a.Q.DeleteExpiredPasswordResets(ctx)
	n, err := a.Q.CountRecentPasswordResets(ctx, u.ID)
	if err != nil || n >= resetMaxPerWindow {
		if err != nil {
			log.Printf("ERROR password reset: comptage des demandes: %v", err)
		}
		return
	}
	plain, hash, err := auth.GenerateResetToken()
	if err != nil {
		log.Printf("ERROR password reset: génération du jeton: %v", err)
		return
	}
	if err := a.Q.CreatePasswordReset(ctx, database.CreatePasswordResetParams{
		UserID: u.ID, TokenHash: hash, ExpiresAt: time.Now().Add(resetTokenTTL),
	}); err != nil {
		log.Printf("ERROR password reset: enregistrement du jeton: %v", err)
		return
	}
	a.audit(ctx, auditEntry{
		Action:   auditPasswordResetRequested,
		Entity:   auditEntityUser,
		EntityID: refUUID(u.ID),
		Meta:     map[string]string{"email": u.Email, "ip": web.ClientIP(r)},
	})

	link := strings.TrimRight(a.Cfg.BaseURL, "/") + "/login/reset?token=" + url.QueryEscape(plain)
	subject := tr(r, "forgot.email.subject", a.Cfg.Brand.Name)
	body := resetEmailHTML(tr(r, "forgot.email.intro", u.Name), tr(r, "forgot.email.note"),
		link, tr(r, "forgot.email.button"), a.Cfg.Brand.Company, a.Cfg.Brand.Color)
	to := []string{u.Email}
	go func() { // #nosec G118 -- the send must outlive the request, which does not wait for it
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		if err := a.Mailer.Send(ctx, email.Message{To: to, Subject: subject, HTML: body}); err != nil {
			log.Printf("email: lien de réinitialisation user=%s: %v", u.ID, err) // #nosec G706 -- u.ID is a UUID, not user input
		}
	}()
}

func (a *App) ShowResetPassword(w http.ResponseWriter, r *http.Request) {
	if a.Mailer == nil {
		http.NotFound(w, r)
		return
	}
	token := r.URL.Query().Get("token")
	if _, ok := a.validResetToken(r.Context(), token); !ok {
		w.WriteHeader(http.StatusBadRequest)
		renderPage(w, r, ui.ResetInvalidPage())
		return
	}
	renderPage(w, r, ui.ResetPasswordPage(nosurf.Token(r), token, "", a.Cfg.PasswordMinLength))
}

// DoResetPassword changes the password and invalidates all open tokens of the account.
func (a *App) DoResetPassword(w http.ResponseWriter, r *http.Request) {
	if a.Mailer == nil {
		http.NotFound(w, r)
		return
	}
	token := r.FormValue("token")
	t, ok := a.validResetToken(r.Context(), token)
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		renderPage(w, r, ui.ResetInvalidPage())
		return
	}
	password := r.FormValue("password")
	fail := func(msg string) {
		w.WriteHeader(http.StatusBadRequest)
		renderPage(w, r, ui.ResetPasswordPage(nosurf.Token(r), token, msg, a.Cfg.PasswordMinLength))
	}
	if minLen := a.Cfg.PasswordMinLength; len(password) < minLen {
		fail(tr(r, "users.flash.pwd_too_short", minLen))
		return
	}
	if password != r.FormValue("password_confirm") {
		fail(tr(r, "reset.err.mismatch"))
		return
	}
	u, err := a.Q.GetUserByID(r.Context(), t.UserID)
	if err != nil || !u.Active {
		w.WriteHeader(http.StatusBadRequest)
		renderPage(w, r, ui.ResetInvalidPage())
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		http.Error(w, tr(r, "common.err.internal"), http.StatusInternalServerError)
		return
	}
	if err := a.Q.SetUserPassword(r.Context(), database.SetUserPasswordParams{ID: u.ID, PasswordHash: hash}); err != nil {
		http.Error(w, tr(r, "common.err.update"), http.StatusInternalServerError)
		return
	}
	if err := a.Q.ConsumePasswordResets(r.Context(), u.ID); err != nil {
		log.Printf("ERROR password reset: invalidation des jetons user=%s: %v", u.ID, err)
	}
	a.audit(r.Context(), auditEntry{
		ActorID:  refUUID(u.ID),
		Action:   auditUserPasswordReset,
		Entity:   auditEntityUser,
		EntityID: refUUID(u.ID),
		Meta:     map[string]string{"email": u.Email, "ip": web.ClientIP(r), "stage": "self_service"},
	})
	web.Flash(a.Sessions, r, tr(r, "reset.done"))
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// validResetToken looks up by hash a token that is neither expired nor used.
func (a *App) validResetToken(ctx context.Context, plain string) (database.PasswordResetToken, bool) {
	plain = strings.TrimSpace(plain)
	if plain == "" || len(plain) > 128 {
		return database.PasswordResetToken{}, false
	}
	t, err := a.Q.GetPasswordResetByHash(ctx, auth.HashToken(plain))
	if err != nil {
		return database.PasswordResetToken{}, false
	}
	return t, true
}

func resetEmailHTML(intro, note, link, button, company, color string) string {
	var b strings.Builder
	b.WriteString(`<div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#15202b">`)
	b.WriteString("<p>" + html.EscapeString(intro) + "</p>")
	b.WriteString(`<p style="margin-top:16px"><a href="` + html.EscapeString(link) + `" style="background:` + color + `;color:#fff;padding:9px 18px;border-radius:4px;text-decoration:none">` + html.EscapeString(button) + `</a></p>`)
	b.WriteString(`<p style="color:#555c63">` + html.EscapeString(note) + `</p>`)
	b.WriteString(`<hr style="border:none;border-top:1px solid #e8eaed;margin:18px 0"><p style="color:#8b9298;font-size:12px">` + html.EscapeString(company) + `</p>`)
	b.WriteString("</div>")
	return b.String()
}
