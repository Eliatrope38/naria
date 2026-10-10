package handlers

import (
	"net/http"
	"os"
	"path/filepath"

	"gitlab.com/detag_inno/naria/internal/web"
	"gitlab.com/detag_inno/naria/ui"
)

// PrivacyPolicy and LegalNotice serve, without login, the HTML fragment provided by
// the deployment (BRAND_PRIVACY_FILE, BRAND_LEGAL_FILE). Without a file, the page returns 404.
func (a *App) PrivacyPolicy(w http.ResponseWriter, r *http.Request) {
	a.serveLegal(w, r, a.Cfg.Brand.PrivacyFile, tr(r, "footer.privacy"))
}

func (a *App) LegalNotice(w http.ResponseWriter, r *http.Request) {
	a.serveLegal(w, r, a.Cfg.Brand.LegalFile, tr(r, "footer.legal"))
}

func (a *App) serveLegal(w http.ResponseWriter, r *http.Request, path, title string) {
	if path == "" {
		http.NotFound(w, r)
		return
	}
	content, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	renderPage(w, r, ui.LegalPage(title, web.UserFrom(r.Context()), string(content)))
}
