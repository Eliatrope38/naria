package handlers

import (
	"encoding/json"
	"net/http"
)

// Manifest serves the home screen web app manifest. Name and colors follow the deployment's branding.
func (a *App) Manifest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/manifest+json; charset=utf-8")
	// json, not a format string: %q writes Go syntax, which is not always valid JSON.
	_ = json.NewEncoder(w).Encode(map[string]any{
		"name":             a.Cfg.Brand.Name,
		"short_name":       a.Cfg.Brand.Name,
		"start_url":        "/",
		"display":          "standalone",
		"background_color": "#ffffff",
		"theme_color":      a.Cfg.Brand.Color,
		"icons": []map[string]string{
			{"src": "/static/favicon.png", "sizes": "256x256", "type": "image/png", "purpose": "any"},
		},
	})
}
