// Package i18n translates the server-side UI from embedded JSON catalogs.
package i18n

import (
	_ "embed"
	"encoding/json"
	"fmt"

	"golang.org/x/text/language"
)

type Locale string

const (
	French  Locale = "fr"
	English Locale = "en"
	Italian Locale = "it"
	German  Locale = "de"

	// Fallback when the language cannot be determined, and the default language for notifications.
	DefaultLocale = French

	LangCookieName = "lang"
)

//go:embed fr.json
var frBytes []byte

//go:embed en.json
var enBytes []byte

//go:embed it.json
var itBytes []byte

//go:embed de.json
var deBytes []byte

var catalogs = map[Locale]map[string]string{}

// Locales lists the supported languages, in the order of the language switch and of the form select.
var Locales = []Locale{French, English, Italian, German}

// Fallback order when a key is missing from the active locale.
var fallbackOrder = []Locale{English, French}

func init() {
	catalogs[French] = mustParse(frBytes)
	catalogs[English] = mustParse(enBytes)
	catalogs[Italian] = mustParse(itBytes)
	catalogs[German] = mustParse(deBytes)
}

func mustParse(b []byte) map[string]string {
	m := map[string]string{}
	if err := json.Unmarshal(b, &m); err != nil {
		panic("i18n: catalogue invalide: " + err.Error())
	}
	return m
}

func Supported(code string) bool {
	for _, loc := range Locales {
		if code == string(loc) {
			return true
		}
	}
	return false
}

type Localizer struct {
	Locale Locale
}

func Get(loc Locale) *Localizer {
	if _, ok := catalogs[loc]; !ok {
		loc = DefaultLocale
	}
	return &Localizer{Locale: loc}
}

// Lang returns the language code for the lang attribute of <html>.
func (l *Localizer) Lang() string { return string(l.Locale) }

// T falls back to the active locale, then English, then French, then the raw key. With arguments, the text goes through fmt.Sprintf.
func (l *Localizer) T(key string, args ...any) string {
	if s, ok := catalogs[l.Locale][key]; ok {
		return format(s, args)
	}
	for _, loc := range fallbackOrder {
		if loc == l.Locale {
			continue
		}
		if s, ok := catalogs[loc][key]; ok {
			return format(s, args)
		}
	}
	return key
}

func format(s string, args []any) string {
	if len(args) == 0 {
		return s
	}
	return fmt.Sprintf(s, args...)
}

// The matcher's tags follow Locales. French comes first, so it is the fallback when no
// preference matches.
var matcher = language.NewMatcher([]language.Tag{
	language.French,
	language.English,
	language.Italian,
	language.German,
})

// Priority: explicit cookie, then Accept-Language, then French.
func Match(acceptLanguage, cookie string) Locale {
	if Supported(cookie) {
		return Locale(cookie)
	}
	tags, _, err := language.ParseAcceptLanguage(acceptLanguage)
	if err != nil {
		return DefaultLocale
	}
	_, idx, _ := matcher.Match(tags...)
	return Locales[idx]
}
