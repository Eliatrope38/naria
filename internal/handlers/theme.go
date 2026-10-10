package handlers

import (
	"net/http"
	"time"
)

// Read server-side to render data-theme: localStorage can be blocked on mobile.
const themeCookieName = "naria-theme"

// SetTheme stores the theme in a cookie and redirects back to the original page. A
// deliberate GET, as with SetLang.
func (a *App) SetTheme(w http.ResponseWriter, r *http.Request) {
	to := r.URL.Query().Get("to")
	if to != "dark" && to != "light" {
		to = "light"
	}
	// #nosec G124 -- HttpOnly and SameSite are set; Secure follows the environment (TLS in prod), as the CSRF cookie does.
	// nosemgrep: go.lang.security.audit.net.cookie-missing-secure.cookie-missing-secure -- same reason as the #nosec above
	http.SetCookie(w, &http.Cookie{
		Name:     themeCookieName,
		Value:    to,
		Path:     "/",
		MaxAge:   int((365 * 24 * time.Hour).Seconds()),
		HttpOnly: true, // read only server-side (data-theme), never by the JS
		Secure:   a.Cfg.Secure,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, safeNext(r), http.StatusSeeOther) // #nosec G710 -- safeNext only returns an internal path (internalPath) or "/"
}
