package handlers

import (
	"errors"
	"log"
	"net/http"

	"github.com/google/uuid"
	"github.com/justinas/nosurf"

	"gitlab.com/detag_inno/naria/internal/auth"
	"gitlab.com/detag_inno/naria/internal/turnstile"
	"gitlab.com/detag_inno/naria/internal/web"
	"gitlab.com/detag_inno/naria/ui"
)

// pending2FAKey holds, in the session, the user whose password is verified
// but whose 2FA is not yet.
const pending2FAKey = "pending_2fa"

func (a *App) ShowLogin(w http.ResponseWriter, r *http.Request) {
	if web.UserFrom(r.Context()) != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	renderPage(w, r, ui.LoginPage(nosurf.Token(r), "", web.PopFlash(a.Sessions, r)))
}

func (a *App) DoLogin(w http.ResponseWriter, r *http.Request) {
	if a.Limiter != nil && !a.Limiter.Allow(web.RateLimitKey(r)) {
		w.WriteHeader(http.StatusTooManyRequests)
		renderPage(w, r, ui.LoginPage(nosurf.Token(r), tr(r, "login.err.rate"), ""))
		return
	}

	ip := web.ClientIP(r)
	email := auth.NormalizeEmail(r.FormValue("email"))
	password := r.FormValue("password")

	// Runs before any credential work: a bot reaches neither argon2id nor the failed-login log.
	if key, status := a.turnstileGate(r, email); key != "" {
		w.WriteHeader(status)
		renderPage(w, r, ui.LoginPage(nosurf.Token(r), tr(r, key), ""))
		return
	}

	fail := func() {
		w.WriteHeader(http.StatusUnauthorized)
		renderPage(w, r, ui.LoginPage(nosurf.Token(r), tr(r, "login.err.bad"), ""))
	}

	u, err := a.Q.GetUserByEmail(r.Context(), email)
	if err != nil || !u.Active {
		// Dummy verification: without it, response time would reveal whether the account exists.
		auth.FakeVerify()
		// Do not reveal, even in the log, whether the email is unknown or the account is disabled.
		a.audit(r.Context(), auditEntry{
			Action: auditLoginFailed,
			Entity: auditEntityUser,
			Meta:   map[string]string{"email": email, "ip": ip, "stage": "password"},
		})
		fail()
		return
	}
	ok, err := auth.VerifyPassword(password, u.PasswordHash)
	if err != nil || !ok {
		a.audit(r.Context(), auditEntry{
			Action:   auditLoginFailed,
			Entity:   auditEntityUser,
			EntityID: refUUID(u.ID),
			Meta:     map[string]string{"email": email, "ip": ip, "stage": "password"},
		})
		fail()
		return
	}

	if u.TotpEnabled {
		// Password valid, 2FA required: the session stays anonymous until the code is verified.
		if err := a.Sessions.RenewToken(r.Context()); err != nil {
			http.Error(w, "Erreur de session", http.StatusInternalServerError)
			return
		}
		a.Sessions.Put(r.Context(), pending2FAKey, u.ID.String())
		http.Redirect(w, r, "/login/2fa", http.StatusSeeOther)
		return
	}

	if err := web.Login(a.Sessions, r, u.ID); err != nil {
		http.Error(w, "Erreur de session", http.StatusInternalServerError)
		return
	}
	a.audit(r.Context(), auditEntry{
		ActorID:  refUUID(u.ID),
		Action:   auditLoginSucceeded,
		Entity:   auditEntityUser,
		EntityID: refUUID(u.ID),
		Meta:     map[string]string{"ip": ip},
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) Show2FA(w http.ResponseWriter, r *http.Request) {
	if a.Sessions.GetString(r.Context(), pending2FAKey) == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	renderPage(w, r, ui.TwoFALoginPage(nosurf.Token(r), ""))
}

func (a *App) Verify2FA(w http.ResponseWriter, r *http.Request) {
	if a.Limiter != nil && !a.Limiter.Allow(web.RateLimitKey(r)) {
		w.WriteHeader(http.StatusTooManyRequests)
		renderPage(w, r, ui.TwoFALoginPage(nosurf.Token(r), tr(r, "login.err.rate")))
		return
	}
	pending := a.Sessions.GetString(r.Context(), pending2FAKey)
	if pending == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	id, err := uuid.Parse(pending)
	if err != nil {
		a.Sessions.Remove(r.Context(), pending2FAKey)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	u, err := a.Q.GetUserByID(r.Context(), id)
	if err != nil || !u.Active || !u.TotpEnabled || u.TotpSecret == nil {
		a.Sessions.Remove(r.Context(), pending2FAKey)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	code := r.FormValue("code")
	secret, derr := a.Crypto.Decrypt(*u.TotpSecret)
	ok := derr == nil && auth.ValidateTOTP(code, secret)
	if !ok {
		// Fallback: backup code (single use).
		ok = a.consumeBackupCode(r.Context(), u.ID, code)
	}
	if !ok {
		a.audit(r.Context(), auditEntry{
			Action:   auditLoginFailed,
			Entity:   auditEntityUser,
			EntityID: refUUID(u.ID),
			Meta:     map[string]string{"email": u.Email, "ip": web.ClientIP(r), "stage": "2fa"},
		})
		w.WriteHeader(http.StatusUnauthorized)
		renderPage(w, r, ui.TwoFALoginPage(nosurf.Token(r), tr(r, "login.verify.err.bad")))
		return
	}
	a.Sessions.Remove(r.Context(), pending2FAKey)
	if err := web.Login(a.Sessions, r, u.ID); err != nil {
		http.Error(w, "Erreur de session", http.StatusInternalServerError)
		return
	}
	a.audit(r.Context(), auditEntry{
		ActorID:  refUUID(u.ID),
		Action:   auditLoginSucceeded,
		Entity:   auditEntityUser,
		EntityID: refUUID(u.ID),
		Meta:     map[string]string{"ip": web.ClientIP(r), "stage": "2fa"},
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) DoLogout(w http.ResponseWriter, r *http.Request) {
	_ = web.Logout(a.Sessions, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// turnstileGate verifies the Cloudflare token when Turnstile is enabled. It returns the
// error key and status to send, or an empty key if the request may proceed. A rejected
// token is logged as a failure at the turnstile stage. An unreachable Cloudflare fails closed.
func (a *App) turnstileGate(r *http.Request, email string) (errKey string, status int) {
	if a.Turnstile == nil {
		return "", 0
	}
	ip := web.ClientIP(r)
	err := a.Turnstile.Verify(r.Context(), r.FormValue(turnstile.FormField), ip)
	if err == nil {
		return "", 0
	}
	if errors.Is(err, turnstile.ErrRejected) {
		a.audit(r.Context(), auditEntry{
			Action: auditLoginFailed,
			Entity: auditEntityUser,
			Meta:   map[string]string{"email": email, "ip": ip, "stage": "turnstile"},
		})
		return "login.err.turnstile", http.StatusBadRequest
	}
	log.Printf("ERROR turnstile: vérification impossible ip=%q: %v", ip, err) // #nosec G706 -- ip is quoted (%q escapes CRLF) and comes from RemoteAddr or a trusted proxy header
	return "login.err.turnstile.unavailable", http.StatusServiceUnavailable
}
