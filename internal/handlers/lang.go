package handlers

import (
	"net/http"
	"net/url"
	"time"

	"gitlab.com/detag_inno/naria/internal/i18n"
)

// langCookieMaxAge is the lifetime of the language choice (one year).
const langCookieMaxAge = 365 * 24 * time.Hour

// SetLang stores the language in a cookie and redirects back to the original page. It is a
// deliberate GET: only a display preference changes, and pages outside a session
// (login, 2FA) have no CSRF token. The target is limited to internal paths.
func (a *App) SetLang(w http.ResponseWriter, r *http.Request) {
	to := r.URL.Query().Get("to")
	if !i18n.Supported(to) {
		to = string(i18n.DefaultLocale)
	}
	// #nosec G124 -- HttpOnly and SameSite are set; Secure follows the environment (TLS in prod), as the CSRF cookie does.
	// nosemgrep: go.lang.security.audit.net.cookie-missing-secure.cookie-missing-secure -- same reason as the #nosec above
	http.SetCookie(w, &http.Cookie{
		Name:     i18n.LangCookieName,
		Value:    to,
		Path:     "/",
		MaxAge:   int(langCookieMaxAge.Seconds()),
		HttpOnly: true,
		Secure:   a.Cfg.Secure,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, safeNext(r), http.StatusSeeOther) // #nosec G710 -- safeNext only returns an internal path (internalPath) or "/"
}

// safeNext picks the safe target: "next", otherwise the Referer from the same host, otherwise the root.
func safeNext(r *http.Request) string {
	if p := internalPath(r.URL.Query().Get("next")); p != "" {
		return p
	}
	if ref := r.Referer(); ref != "" {
		if u, err := url.Parse(ref); err == nil {
			if u.Host == "" || u.Host == r.Host {
				if p := internalPath(u.RequestURI()); p != "" {
					return p
				}
			}
		}
	}
	return "/"
}

// internalPath returns s if it is an absolute internal path, otherwise the empty string.
// It rejects "//host" and "/\host" (browsers read "\" as "/").
func internalPath(s string) string {
	if s == "" || s[0] != '/' {
		return ""
	}
	if len(s) > 1 && (s[1] == '/' || s[1] == '\\') {
		return ""
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return ""
		}
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return ""
	}
	return s
}
