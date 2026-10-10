package config

import (
	"fmt"
	"log"
	"math"
	"net/mail"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Addr              string // e.g. ":8080"
	DatabaseURL       string
	SessionLifetime   time.Duration
	Secure            bool // Secure cookies (HTTPS), true in production
	BaseURL           string
	SecretKey         string // encryption at rest of submissions and TOTP secrets; empty = disabled
	PasswordMinLength int    // required when setting a password, never at login
	MaxBodyBytes      int64

	MaxSubmissionBytes int64
	// Per IP address (/64 prefix for IPv6) and per form. The IP is neither stored nor logged.
	SubmitRateLimit    int
	SubmitRateWindow   time.Duration
	MaxAttachmentBytes int64
	// 0 = no limit.
	MaxFormStorageBytes int64

	// Proxies whose X-Forwarded-For is trusted. Empty: no header is read.
	TrustedProxyCIDRs []netip.Prefix

	EmailProvider     string // "smtp" (default) or "graph". With smtp, an empty SMTPHost disables sending.
	SMTPHost          string
	SMTPPort          int
	SMTPUsername      string
	SMTPPassword      string
	SMTPFrom          string
	SMTPTLS           string // "starttls" | "implicit" | "none"
	GraphTenantID     string
	GraphClientID     string
	GraphClientSecret string
	GraphMailbox      string

	// An entry ".example.com" covers subdomains. Empty = official hosts only.
	WebhookAllowedHosts []string
	ClamAVAddr          string // "host:port" or the path of a Unix socket; empty = no antivirus

	// Turnstile on the login form. Setting both keys enables it: setting only one
	// is a configuration error, refused at startup. Both empty: Turnstile is disabled.
	TurnstileSiteKey   string
	TurnstileSecretKey string

	Brand Branding
}

type Branding struct {
	Name         string
	Company      string
	SupportEmail string // footer contact; empty = hidden
	Tagline      string
	Color        string
	ColorDark    string // derived from Color if empty
	LogoURL      string
	LogoFile     string // path of a mounted wordmark; enables image mode
	HasLogo      bool
	FaviconURL   string
	FaviconFile  string // empty = embedded favicon
	CSSFile      string // empty = embedded CSS
	PrivacyFile  string // mounted HTML fragment; empty = no page
	LegalFile    string // mounted HTML fragment; empty = no page
}

func Load() (Config, error) {
	c := Config{
		Addr:              getenv("ADDR", ":8080"),
		DatabaseURL:       os.Getenv("DATABASE_URL"),
		SessionLifetime:   12 * time.Hour,
		Secure:            getenv("APP_ENV", "dev") == "prod",
		BaseURL:           getenv("BASE_URL", "http://localhost:8080"),
		SecretKey:         os.Getenv("APP_SECRET_KEY"),
		PasswordMinLength: PasswordMinLength(),
		MaxBodyBytes:      1 << 20, // 1 MB: the interface only sends small forms

		MaxSubmissionBytes: int64(getint("SUBMISSION_MAX_KB", 256)) << 10,
		SubmitRateLimit:    getint("SUBMIT_RATE_LIMIT", 10),
		SubmitRateWindow:   10 * time.Minute,
		MaxAttachmentBytes: int64(getint("ATTACHMENTS_MAX_MB", 10)) << 20,

		EmailProvider: strings.ToLower(strings.TrimSpace(getenv("EMAIL_PROVIDER", "smtp"))),
		SMTPHost:      os.Getenv("SMTP_HOST"),
		SMTPPort:      atoi(os.Getenv("SMTP_PORT")),
		SMTPUsername:  os.Getenv("SMTP_USERNAME"),
		SMTPPassword:  os.Getenv("SMTP_PASSWORD"),
		SMTPFrom:      os.Getenv("SMTP_FROM"),
		SMTPTLS:       os.Getenv("SMTP_TLS"),

		GraphTenantID:     strings.TrimSpace(os.Getenv("GRAPH_TENANT_ID")),
		GraphClientID:     strings.TrimSpace(os.Getenv("GRAPH_CLIENT_ID")),
		GraphClientSecret: strings.TrimSpace(os.Getenv("GRAPH_CLIENT_SECRET")),
		GraphMailbox:      strings.TrimSpace(os.Getenv("GRAPH_MAILBOX")),

		WebhookAllowedHosts: splitList(os.Getenv("WEBHOOK_ALLOWED_HOSTS")),
		ClamAVAddr:          os.Getenv("CLAMAV_ADDR"),

		TurnstileSiteKey:   strings.TrimSpace(os.Getenv("TURNSTILE_SITE_KEY")),
		TurnstileSecretKey: strings.TrimSpace(os.Getenv("TURNSTILE_SECRET_KEY")),

		Brand: Branding{
			Name:         getenv("BRAND_NAME", "Naria"),
			Company:      getenv("BRAND_COMPANY", "Naria"),
			SupportEmail: os.Getenv("BRAND_SUPPORT_EMAIL"),
			Tagline:      getenv("BRAND_TAGLINE", "Les formulaires de vos sites, sans confier vos données à un tiers."),
			Color:        getenv("BRAND_COLOR", "#197a9c"),
			ColorDark:    os.Getenv("BRAND_COLOR_DARK"),
			LogoFile:     os.Getenv("BRAND_LOGO_FILE"),
			FaviconFile:  os.Getenv("BRAND_FAVICON_FILE"),
			CSSFile:      os.Getenv("BRAND_CSS_FILE"),
			PrivacyFile:  os.Getenv("BRAND_PRIVACY_FILE"),
			LegalFile:    os.Getenv("BRAND_LEGAL_FILE"),
			LogoURL:      "/static/logo.webp",
			FaviconURL:   "/static/favicon.png",
		},
	}
	if c.DatabaseURL == "" {
		return c, fmt.Errorf("DATABASE_URL est requis")
	}
	// Without a key in production, encryption at rest would be a passthrough: submissions and secrets
	// TOTP stored in clear. Fail at startup rather than degrade silently.
	if c.Secure && c.SecretKey == "" {
		return c, fmt.Errorf("APP_SECRET_KEY est requis en production (APP_ENV=prod) : sans cette clé, les soumissions et les secrets TOTP seraient stockés en clair ; générez-la avec `openssl rand -base64 32`")
	}
	// sslmode=disable is only acceptable on a trusted private network. Warn without failing,
	// since this case is legitimate.
	if c.Secure && strings.Contains(c.DatabaseURL, "sslmode=disable") {
		log.Printf("ATTENTION: DATABASE_URL utilise sslmode=disable en production. Acceptable uniquement si la base est sur un réseau privé de confiance ; passez à sslmode=require ou verify-full si la base est déportée")
	}
	if c.SubmitRateLimit < 1 {
		return c, fmt.Errorf("SUBMIT_RATE_LIMIT doit être supérieur ou égal à 1")
	}
	if c.MaxSubmissionBytes < 1<<10 {
		return c, fmt.Errorf("SUBMISSION_MAX_KB doit être supérieur ou égal à 1")
	}
	if c.MaxAttachmentBytes < 1<<20 {
		return c, fmt.Errorf("ATTACHMENTS_MAX_MB doit être supérieur ou égal à 1")
	}
	// An unreadable value must not become "no limit": the quota would vanish without a signal.
	if v := strings.TrimSpace(os.Getenv("FORM_STORAGE_MAX_MB")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || int64(n) > math.MaxInt64>>20 {
			return c, fmt.Errorf("FORM_STORAGE_MAX_MB doit être un nombre entier de méga-octets, ou 0 pour ne pas limiter")
		}
		c.MaxFormStorageBytes = int64(n) << 20
	}
	if c.Brand.ColorDark == "" {
		c.Brand.ColorDark = darken(c.Brand.Color, 0.82)
	}
	c.Brand.HasLogo = c.Brand.LogoFile != ""
	// A widget without server-side verification would be decorative; a verification without a widget would block
	// every user.
	if (c.TurnstileSiteKey == "") != (c.TurnstileSecretKey == "") {
		return c, fmt.Errorf("TURNSTILE_SITE_KEY et TURNSTILE_SECRET_KEY doivent être définies ensemble (ou toutes deux vides)")
	}
	// A sender chosen but half configured would silence the instance: forms in email
	// only would refuse every submission, without any signal.
	switch c.EmailProvider {
	case "smtp":
		if c.SMTPHost != "" && c.SMTPFrom == "" {
			return c, fmt.Errorf("SMTP_FROM est requis quand SMTP_HOST est défini")
		}
		if c.SMTPHost == "" && c.GraphTenantID+c.GraphClientID+c.GraphClientSecret+c.GraphMailbox != "" {
			return c, fmt.Errorf("EMAIL_PROVIDER=graph est requis pour envoyer par Microsoft Graph : des variables GRAPH_* sont définies, mais l'expéditeur est SMTP et il n'est pas configuré")
		}
	case "graph":
		for _, v := range []struct{ name, value string }{
			{"GRAPH_TENANT_ID", c.GraphTenantID}, {"GRAPH_CLIENT_ID", c.GraphClientID},
			{"GRAPH_CLIENT_SECRET", c.GraphClientSecret}, {"GRAPH_MAILBOX", c.GraphMailbox},
		} {
			if v.value == "" {
				return c, fmt.Errorf("%s est requis avec EMAIL_PROVIDER=graph", v.name)
			}
		}
		// The tenant and the mailbox are part of the called address path.
		if !graphTenant.MatchString(c.GraphTenantID) {
			return c, fmt.Errorf("GRAPH_TENANT_ID doit être l'identifiant du locataire ou son nom de domaine")
		}
		if addr, err := mail.ParseAddress(c.GraphMailbox); err != nil || addr.Address != c.GraphMailbox {
			return c, fmt.Errorf("GRAPH_MAILBOX doit être l'adresse de la boîte qui envoie")
		}
	default:
		return c, fmt.Errorf("EMAIL_PROVIDER doit valoir smtp ou graph")
	}
	proxies, err := parseCIDRs(os.Getenv("TRUSTED_PROXY_CIDRS"))
	if err != nil {
		return c, fmt.Errorf("TRUSTED_PROXY_CIDRS invalide : %w", err)
	}
	c.TrustedProxyCIDRs = proxies
	// Cookies are Secure in production and the binary does no TLS: a proxy is always in front.
	if c.Secure && len(proxies) == 0 {
		log.Printf("ATTENTION: TRUSTED_PROXY_CIDRS est vide en production. Tous les visiteurs ont alors l'adresse du reverse proxy et partagent la même limite de débit ; déclarez-y l'adresse du proxy")
	}
	return c, nil
}

// An Entra tenant is identified by its GUID or a domain name.
var graphTenant = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)

// parseCIDRs splits a comma-separated list of CIDRs. An empty list returns nil.
func parseCIDRs(s string) ([]netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	var out []netip.Prefix
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, fmt.Errorf("%q : %w", part, err)
		}
		out = append(out, p)
	}
	return out, nil
}

// splitList splits a comma-separated list, lowercased.
func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.ToLower(strings.TrimSpace(part)); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// darken darkens a #rrggbb color by a factor between 0 and 1. Returns the input if it is invalid.
func darken(hex string, f float64) string {
	s := strings.TrimPrefix(hex, "#")
	if len(s) != 6 {
		return hex
	}
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return hex
	}
	r := int(float64((v>>16)&0xff) * f)
	g := int(float64((v>>8)&0xff) * f)
	b := int(float64(v&0xff) * f)
	return fmt.Sprintf("#%02x%02x%02x", r, g, b)
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// getint reads an integer; a missing or non-numeric value returns the default.
func getint(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

// DefaultPasswordMinLength is the default minimum length. OWASP asks for 8; 12 is more cautious.
const DefaultPasswordMinLength = 12

// PasswordMinLength reads PASSWORD_MIN_LENGTH. Exported for cmd/createadmin, which does not build a Config.
// Applies when setting a password, never at login.
func PasswordMinLength() int {
	v := strings.TrimSpace(os.Getenv("PASSWORD_MIN_LENGTH"))
	if v == "" {
		return DefaultPasswordMinLength
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return DefaultPasswordMinLength
	}
	return n
}
