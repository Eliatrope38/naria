package web

import (
	"net/http"

	"gitlab.com/detag_inno/naria/internal/i18n"
	"gitlab.com/detag_inno/naria/ui"
)

// Localize stores the request's Localizer in the context, as LoadUser does for the user.
func Localize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie := ""
		if c, err := r.Cookie(i18n.LangCookieName); err == nil {
			cookie = c.Value
		}
		loc := i18n.Match(r.Header.Get("Accept-Language"), cookie)
		ctx := ui.WithLocalizer(r.Context(), i18n.Get(loc))
		if c, err := r.Cookie("naria-theme"); err == nil && (c.Value == "dark" || c.Value == "light") {
			ctx = ui.WithTheme(ctx, c.Value)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
