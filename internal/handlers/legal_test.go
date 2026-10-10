package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gitlab.com/detag_inno/naria/internal/config"
)

func TestLegalWhiteLabel(t *testing.T) {
	unset := &App{Cfg: config.Config{}}
	rec := httptest.NewRecorder()
	unset.PrivacyPolicy(rec, httptest.NewRequest(http.MethodGet, "/confidentialite", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("sans BRAND_PRIVACY_FILE : got %d, want 404", rec.Code)
	}

	f := filepath.Join(t.TempDir(), "privacy.html")
	if err := os.WriteFile(f, []byte("<h1>Politique maison</h1>"), 0o600); err != nil {
		t.Fatal(err)
	}
	set := &App{Cfg: config.Config{Brand: config.Branding{PrivacyFile: f}}}
	rec2 := httptest.NewRecorder()
	set.PrivacyPolicy(rec2, httptest.NewRequest(http.MethodGet, "/confidentialite", nil))
	if rec2.Code != http.StatusOK {
		t.Fatalf("avec fichier : got %d, want 200", rec2.Code)
	}
	if !strings.Contains(rec2.Body.String(), "Politique maison") {
		t.Errorf("fragment non rendu dans la page : %s", rec2.Body.String())
	}
}
