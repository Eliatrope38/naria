package ui

import (
	"fmt"
	"math"
)

type Brand struct {
	Name         string
	Company      string
	SupportEmail string
	Tagline      string
	Color        string
	ColorDark    string
	LogoURL      string
	HasLogo      bool // true: wordmark image; false: icon and name as text
	FaviconURL   string
}

// Naria defaults, replaced at startup by SetBrand.
var Theme = Brand{
	Name:       "Naria",
	Company:    "Naria",
	Tagline:    "Les formulaires de vos sites, sans confier vos données à un tiers.",
	Color:      "#197a9c",
	ColorDark:  "#146480",
	LogoURL:    "/static/logo.webp",
	FaviconURL: "/static/favicon.png",
}

func SetBrand(b Brand) { Theme = b }

// Shown in the footer. Stays "dev" outside release builds.
var Version = "dev"

func SetVersion(v string) {
	if v != "" {
		Version = v
	}
}

// Configured legal pages (BRAND_PRIVACY_FILE, BRAND_LEGAL_FILE). Without a page, the footer has no link.
type LegalLinks struct {
	HasPrivacy bool
	HasLegal   bool
}

var Legal LegalLinks

func SetLegal(l LegalLinks) { Legal = l }

// In production, the footer hides the version and the health indicator.
var Prod bool

func SetProd(p bool) { Prod = p }

// "Forgot password" link on the login page. Without email sending, it would lead nowhere.
var ForgotPasswordEnabled = false

func SetForgotPassword(on bool) { ForgotPasswordEnabled = on }

// Turnstile key for the login form. Empty: the widget is not rendered.
var TurnstileSiteKey = ""

func SetTurnstileSiteKey(k string) { TurnstileSiteKey = k }

// Brand CSS variables set on <body>. --brand-700 is darkened when needed to keep 4.5:1 contrast
// with white text (WCAG AA), including for the buttons that rely on it.
func brandVars() string {
	return "--brand:" + Theme.Color +
		";--brand-700:" + darkEnoughForWhite(Theme.ColorDark, Theme.Color) +
		";--brand-50:" + lightBrandTint(Theme.Color)
}

// Light brand background (8% colour, the rest white) for --brand-50. An unreadable colour falls back to the Naria tint.
func lightBrandTint(base string) string {
	r, g, b, ok := parseHex(base)
	if !ok {
		return "#edf4f7"
	}
	const frac = 0.08
	mix := func(c int) int { return int(float64(c)*frac + 255*(1-frac) + 0.5) }
	return fmt.Sprintf("#%02x%02x%02x", mix(r), mix(g), mix(b))
}

// Returns dark if it reaches 4.5:1 against white, otherwise darkens base while keeping its hue.
// The result is not guaranteed for a colour that is not hexadecimal.
func darkEnoughForWhite(dark, base string) string {
	const aa = 4.5
	if dr, dg, db, ok := parseHex(dark); ok && whiteContrast(dr, dg, db) >= aa {
		return dark
	}
	br, bg, bb, ok := parseHex(base)
	if !ok {
		return dark
	}
	r, g, b := float64(br), float64(bg), float64(bb)
	for i := 0; i < 64 && whiteContrast(int(r+0.5), int(g+0.5), int(b+0.5)) < aa; i++ {
		r *= 0.92
		g *= 0.92
		b *= 0.92
	}
	return fmt.Sprintf("#%02x%02x%02x", int(r+0.5), int(g+0.5), int(b+0.5))
}

func parseHex(s string) (r, g, b int, ok bool) {
	if len(s) == 7 && s[0] == '#' {
		s = s[1:]
	}
	if len(s) != 6 {
		return 0, 0, 0, false
	}
	var v int
	if _, err := fmt.Sscanf(s, "%06x", &v); err != nil {
		return 0, 0, 0, false
	}
	return v >> 16 & 0xff, v >> 8 & 0xff, v & 0xff, true
}

func whiteContrast(r, g, b int) float64 {
	lum := relLuminance(r, g, b)
	return 1.05 / (lum + 0.05)
}

func relLuminance(r, g, b int) float64 {
	return 0.2126*channelLum(r) + 0.7152*channelLum(g) + 0.0722*channelLum(b)
}

func channelLum(c int) float64 {
	s := float64(c) / 255
	if s <= 0.03928 {
		return s / 12.92
	}
	return math.Pow((s+0.055)/1.055, 2.4)
}
