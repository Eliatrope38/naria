package i18n

import "testing"

func TestMatchPriority(t *testing.T) {
	tests := []struct {
		name   string
		accept string
		cookie string
		want   Locale
	}{
		{"cookie wins over header", "fr-FR,fr;q=0.9", "en", English},
		{"cookie en", "", "en", English},
		{"cookie fr", "en-US", "fr", French},
		{"cookie it", "fr-FR", "it", Italian},
		{"cookie de", "en-US", "de", German},
		{"invalid cookie falls back to header", "en-US,en;q=0.9", "es", English},
		{"header english", "en-GB,en;q=0.8", "", English},
		{"header french", "fr-CH,fr;q=0.9", "", French},
		{"header italian", "it-CH,it;q=0.9", "", Italian},
		{"header german", "de-DE,de;q=0.9", "", German},
		{"unknown header defaults to french", "ru-RU,ru;q=0.9", "", French},
		{"empty everything defaults to french", "", "", French},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Match(tt.accept, tt.cookie); got != tt.want {
				t.Fatalf("Match(%q,%q) = %q, want %q", tt.accept, tt.cookie, got, tt.want)
			}
		})
	}
}

func TestTranslateAndFallback(t *testing.T) {
	en := Get(English)
	if got := en.T("nav.sites"); got != "Sites" {
		t.Fatalf("en nav.sites = %q", got)
	}
	if got := en.T("form.mode.stored"); got != "Listed" {
		t.Fatalf("en form.mode.stored = %q", got)
	}
	if got := en.T("does.not.exist"); got != "does.not.exist" {
		t.Fatalf("missing key should return the key, got %q", got)
	}
}

func TestFormatArgs(t *testing.T) {
	fr := Get(French)
	if got := fr.T("pagination.page", 2, 5); got != "Page 2 sur 5" {
		t.Fatalf("fr pagination.page = %q", got)
	}
	en := Get(English)
	if got := en.T("pagination.page", 2, 5); got != "Page 2 of 5" {
		t.Fatalf("en pagination.page = %q", got)
	}
	// Without arguments, text containing format verbs is returned as-is.
	if got := fr.T("pagination.page"); got != "Page %d sur %d" {
		t.Fatalf("fr pagination.page without args = %q", got)
	}
}

func TestUnknownLocaleFallsBackToDefault(t *testing.T) {
	loc := Get(Locale("es"))
	if loc.Locale != DefaultLocale {
		t.Fatalf("Get(es).Locale = %q, want %q", loc.Locale, DefaultLocale)
	}
}

// A key missing from one catalog would silently show in another language; this test catches it.
func TestCatalogsHaveSameKeys(t *testing.T) {
	for _, loc := range Locales {
		for key := range catalogs[French] {
			if _, ok := catalogs[loc][key]; !ok {
				t.Errorf("clé %q absente du catalogue %s", key, loc)
			}
		}
		for key := range catalogs[loc] {
			if _, ok := catalogs[French][key]; !ok {
				t.Errorf("clé %q absente du catalogue français (%s)", key, loc)
			}
		}
	}
}
