package web

import (
	"net/http"
	"slices"

	"github.com/alexedwards/scs/v2"
	"github.com/google/uuid"

	"gitlab.com/detag_inno/naria/internal/database"
)

const sessionUserKey = "userID"

func LoadUser(sm *scs.SessionManager, q *database.Queries) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := sm.GetString(r.Context(), sessionUserKey)
			if id != "" {
				if uid, err := uuid.Parse(id); err == nil {
					if u, err := q.GetUserByID(r.Context(), uid); err == nil && u.Active {
						r = r.WithContext(WithUser(r.Context(), &u))
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Login opens the user's session. RenewToken prevents session fixation.
func Login(sm *scs.SessionManager, r *http.Request, userID uuid.UUID) error {
	if err := sm.RenewToken(r.Context()); err != nil {
		return err
	}
	sm.Put(r.Context(), sessionUserKey, userID.String())
	return nil
}

func Logout(sm *scs.SessionManager, r *http.Request) error {
	return sm.Destroy(r.Context())
}

func Flash(sm *scs.SessionManager, r *http.Request, msg string) {
	sm.Put(r.Context(), "flash", msg)
}

func PopFlash(sm *scs.SessionManager, r *http.Request) string {
	return sm.PopString(r.Context(), "flash")
}

// Origin of the Turnstile widget script and iframe.
const turnstileOrigin = "https://challenges.cloudflare.com"

// SecurityHeaders sets the security headers. The CSP allows no third-party origin except the Turnstile
// widget when turnstile is true. HSTS is only sent in secure mode.
func SecurityHeaders(secure, turnstile bool) func(http.Handler) http.Handler {
	scriptSrc, frameSrc := "'self'", "'none'"
	if turnstile {
		scriptSrc += " " + turnstileOrigin
		frameSrc = turnstileOrigin
	}
	csp := "default-src 'self'; " +
		"script-src " + scriptSrc + "; " +
		"style-src 'self' 'unsafe-inline'; " +
		"font-src 'self'; " +
		"img-src 'self' data:; " +
		"connect-src 'self'; " +
		"frame-src " + frameSrc + "; " +
		"form-action 'self'; base-uri 'self'; frame-ancestors 'none'"
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
			h.Set("Content-Security-Policy", csp)
			if secure {
				h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			}
			next.ServeHTTP(w, r)
		})
	}
}

func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if UserFrom(r.Context()) == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func RequireRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u := UserFrom(r.Context())
			if u == nil || !slices.Contains(roles, u.Role) {
				http.Error(w, "Accès refusé", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
