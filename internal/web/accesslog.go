package web

import (
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

// AccessLog writes neither the IP nor the query string: the public form endpoint must not keep visitor
// addresses, and the query string carries the reset-link token.
func AccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		start := time.Now()
		defer func() {
			log.Printf("%q %q %d %dB %s", r.Method, r.URL.Path, ww.Status(), ww.BytesWritten(), time.Since(start).Round(time.Millisecond)) // #nosec G706 -- method and path are quoted (%q escapes CR/LF); the rest is numeric
		}()
		next.ServeHTTP(ww, r)
	})
}
