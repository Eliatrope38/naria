package config

// In production, a missing APP_SECRET_KEY refuses startup: submissions and TOTP secrets
// would be stored in clear.

import (
	"strings"
	"testing"
)

// clearConfigEnv unsets the variables that affect Load, so each case starts from a known state.
func clearConfigEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"APP_ENV", "APP_SECRET_KEY", "DATABASE_URL", "TRUSTED_PROXY_CIDRS",
		"ADDR", "BASE_URL", "SUBMIT_RATE_LIMIT", "SUBMISSION_MAX_KB", "ATTACHMENTS_MAX_MB", "WEBHOOK_ALLOWED_HOSTS", "CLAMAV_ADDR", "FORM_STORAGE_MAX_MB",
		"TURNSTILE_SITE_KEY", "TURNSTILE_SECRET_KEY",
		"EMAIL_PROVIDER", "SMTP_HOST", "SMTP_PORT", "SMTP_USERNAME", "SMTP_PASSWORD", "SMTP_FROM", "SMTP_TLS",
		"GRAPH_TENANT_ID", "GRAPH_CLIENT_ID", "GRAPH_CLIENT_SECRET", "GRAPH_MAILBOX",
	} {
		t.Setenv(k, "")
	}
}

// Unset means no quota. An unreadable value refuses startup
// rather than silently lifting the quota.
func TestLoadFormStorageMax(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("DATABASE_URL", "postgres://u:p@db:5432/app?sslmode=disable")
	for _, tc := range []struct {
		value string
		want  int64
		fails bool
	}{
		{"", 0, false}, {"0", 0, false}, {"500", 500 << 20, false}, {" 2 ", 2 << 20, false},
		{"-1", 0, true}, {"500Mo", 0, true}, {"1.5", 0, true},
		// Beyond this, the conversion to bytes would overflow: quota lifted or wrong.
		{"8796093022208", 0, true}, {"17592186044416", 0, true}, {"17592186044417", 0, true},
	} {
		t.Setenv("FORM_STORAGE_MAX_MB", tc.value)
		cfg, err := Load()
		if tc.fails {
			if err == nil || !strings.Contains(err.Error(), "FORM_STORAGE_MAX_MB") {
				t.Errorf("FORM_STORAGE_MAX_MB=%q : erreur %v (un refus est attendu)", tc.value, err)
			}
			continue
		}
		if err != nil || cfg.MaxFormStorageBytes != tc.want {
			t.Errorf("FORM_STORAGE_MAX_MB=%q : %d octets, erreur %v (%d attendus)", tc.value, cfg.MaxFormStorageBytes, err, tc.want)
		}
	}
}

// An address that is not read would leave the instance without antivirus, silently.
func TestLoadClamAVAddr(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("DATABASE_URL", "postgres://u:p@db:5432/app?sslmode=disable")
	cfg, err := Load()
	if err != nil || cfg.ClamAVAddr != "" {
		t.Fatalf("sans CLAMAV_ADDR : adresse %q, erreur %v (vide attendu)", cfg.ClamAVAddr, err)
	}
	t.Setenv("CLAMAV_ADDR", "clamav:3310")
	cfg, err = Load()
	if err != nil || cfg.ClamAVAddr != "clamav:3310" {
		t.Fatalf("avec CLAMAV_ADDR : adresse %q, erreur %v", cfg.ClamAVAddr, err)
	}
}

func TestLoadFailFastSecretKeyInProd(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("APP_ENV", "prod")
	t.Setenv("DATABASE_URL", "postgres://u:p@db:5432/app?sslmode=require")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() a réussi en prod sans APP_SECRET_KEY (fail-fast attendu)")
	}
	if !strings.Contains(err.Error(), "APP_SECRET_KEY") {
		t.Fatalf("message d'erreur inattendu : %v", err)
	}
}

func TestLoadSucceedsInProdWithSecretKey(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("APP_ENV", "prod")
	t.Setenv("APP_SECRET_KEY", "une-cle-secrete-de-test")
	t.Setenv("DATABASE_URL", "postgres://u:p@db:5432/app?sslmode=require")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() a échoué en prod avec une clé présente : %v", err)
	}
	if !cfg.Secure {
		t.Fatal("APP_ENV=prod devrait produire Secure=true")
	}
	if cfg.SecretKey == "" {
		t.Fatal("SecretKey ne devrait pas être vide")
	}
}

func TestLoadSucceedsInDevWithoutSecretKey(t *testing.T) {
	clearConfigEnv(t)
	// APP_ENV unset defaults to dev; APP_SECRET_KEY empty.
	t.Setenv("DATABASE_URL", "postgres://u:p@db:5432/app?sslmode=disable")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() a échoué en dev sans APP_SECRET_KEY : %v", err)
	}
	if cfg.Secure {
		t.Fatal("hors prod, Secure devrait être false")
	}
}

func TestLoadRequiresDatabaseURL(t *testing.T) {
	clearConfigEnv(t)
	// Neither DATABASE_URL nor the rest: Load must fail before even the key check.
	if _, err := Load(); err == nil {
		t.Fatal("Load() a réussi sans DATABASE_URL (erreur attendue)")
	}
}

func TestLoadRejectsHalfConfiguredTurnstile(t *testing.T) {
	for _, tc := range []struct{ site, secret string }{{"site", ""}, {"", "secret"}} {
		clearConfigEnv(t)
		t.Setenv("DATABASE_URL", "postgres://u:p@db:5432/app")
		t.Setenv("TURNSTILE_SITE_KEY", tc.site)
		t.Setenv("TURNSTILE_SECRET_KEY", tc.secret)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "TURNSTILE") {
			t.Fatalf("site=%q secret=%q: want a TURNSTILE error, got %v", tc.site, tc.secret, err)
		}
	}
}

func TestLoadAcceptsTurnstilePair(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("DATABASE_URL", "postgres://u:p@db:5432/app")
	t.Setenv("TURNSTILE_SITE_KEY", " site ")
	t.Setenv("TURNSTILE_SECRET_KEY", "secret")
	c, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.TurnstileSiteKey != "site" || c.TurnstileSecretKey != "secret" {
		t.Fatalf("keys not loaded/trimmed: %+v", c)
	}
}

// A zero or negative limit would disable the protection: it is refused.
func TestLoadSubmissionLimits(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("DATABASE_URL", "postgres://u:p@db:5432/app")
	c, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.SubmitRateLimit != 10 || c.MaxSubmissionBytes != 256<<10 || c.MaxAttachmentBytes != 10<<20 {
		t.Fatalf("défauts inattendus: limit=%d max=%d pièces jointes=%d", c.SubmitRateLimit, c.MaxSubmissionBytes, c.MaxAttachmentBytes)
	}

	t.Setenv("SUBMIT_RATE_LIMIT", "0")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "SUBMIT_RATE_LIMIT") {
		t.Fatalf("SUBMIT_RATE_LIMIT=0 : erreur attendue, got %v", err)
	}
	t.Setenv("SUBMIT_RATE_LIMIT", "")
	t.Setenv("ATTACHMENTS_MAX_MB", "0")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "ATTACHMENTS_MAX_MB") {
		t.Fatalf("ATTACHMENTS_MAX_MB=0 : erreur attendue, got %v", err)
	}
}

func TestLoadWebhookAllowedHosts(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("DATABASE_URL", "postgres://u:p@db:5432/app")
	c, err := Load()
	if err != nil || len(c.WebhookAllowedHosts) != 0 {
		t.Fatalf("défaut : hôtes=%v err=%v (aucun hôte attendu)", c.WebhookAllowedHosts, err)
	}
	t.Setenv("WEBHOOK_ALLOWED_HOSTS", " Chat.Exemple.com , ,.equipe.exemple ")
	c, err = Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := strings.Join(c.WebhookAllowedHosts, "|"); got != "chat.exemple.com|.equipe.exemple" {
		t.Fatalf("hôtes = %q", got)
	}
}

// Without EMAIL_PROVIDER, the sender stays SMTP: an existing instance does not change behavior.
func TestLoadEmailProviderDefaultsToSMTP(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("DATABASE_URL", "postgres://u:p@db:5432/app")
	c, err := Load()
	if err != nil || c.EmailProvider != "smtp" || c.SMTPHost != "" {
		t.Fatalf("sans réglage : expéditeur %q, hôte %q, erreur %v (smtp sans hôte attendu)", c.EmailProvider, c.SMTPHost, err)
	}
	// The example .env sets SMTP_FROM without SMTP_HOST: sending is disabled,
	// which is not an error.
	t.Setenv("SMTP_FROM", "formulaires@exemple.fr")
	if _, err := Load(); err != nil {
		t.Fatalf("SMTP_FROM seul : %v", err)
	}
	t.Setenv("SMTP_HOST", "smtp.exemple.fr")
	// With SMTP configured, leftover GRAPH_* variables do not change the sender.
	t.Setenv("GRAPH_TENANT_ID", "contoso.onmicrosoft.com")
	c, err = Load()
	if err != nil || c.EmailProvider != "smtp" || c.SMTPHost != "smtp.exemple.fr" {
		t.Fatalf("SMTP réglé : expéditeur %q, hôte %q, erreur %v", c.EmailProvider, c.SMTPHost, err)
	}
	t.Setenv("EMAIL_PROVIDER", " SMTP ")
	if c, err = Load(); err != nil || c.EmailProvider != "smtp" {
		t.Fatalf("EMAIL_PROVIDER=SMTP : expéditeur %q, erreur %v", c.EmailProvider, err)
	}
}

// An unknown or half-configured sender refuses startup: sending would be disabled without a signal.
func TestLoadRejectsIncompleteEmailProvider(t *testing.T) {
	graph := map[string]string{
		"EMAIL_PROVIDER":      "graph",
		"GRAPH_TENANT_ID":     "11111111-2222-3333-4444-555555555555",
		"GRAPH_CLIENT_ID":     "66666666-7777-8888-9999-000000000000",
		"GRAPH_CLIENT_SECRET": "s3cr3t~valeur",
		"GRAPH_MAILBOX":       "formulaires@exemple.fr",
	}
	load := func(t *testing.T, env map[string]string) (Config, error) {
		t.Helper()
		clearConfigEnv(t)
		t.Setenv("DATABASE_URL", "postgres://u:p@db:5432/app")
		for k, v := range env {
			t.Setenv(k, v)
		}
		return Load()
	}
	with := func(k, v string) map[string]string {
		env := map[string]string{k: v}
		for name, value := range graph {
			if name != k {
				env[name] = value
			}
		}
		return env
	}

	c, err := load(t, graph)
	if err != nil || c.EmailProvider != "graph" || c.GraphMailbox != "formulaires@exemple.fr" || c.GraphClientSecret != "s3cr3t~valeur" {
		t.Fatalf("Graph réglé : expéditeur %q, boîte %q, erreur %v", c.EmailProvider, c.GraphMailbox, err)
	}
	if _, err := load(t, with("GRAPH_TENANT_ID", "contoso.onmicrosoft.com")); err != nil {
		t.Errorf("locataire désigné par son domaine : %v", err)
	}

	for _, tc := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{"expéditeur inconnu", map[string]string{"EMAIL_PROVIDER": "sendgrid"}, "EMAIL_PROVIDER"},
		{"SMTP sans expéditeur", map[string]string{"SMTP_HOST": "smtp.exemple.fr"}, "SMTP_FROM"},
		{"Graph sans rien", map[string]string{"EMAIL_PROVIDER": "graph"}, "GRAPH_TENANT_ID"},
		{"Graph réglé sans être choisi", with("EMAIL_PROVIDER", ""), "EMAIL_PROVIDER=graph"},
		{"Graph sans locataire", with("GRAPH_TENANT_ID", ""), "GRAPH_TENANT_ID"},
		{"Graph sans identifiant", with("GRAPH_CLIENT_ID", ""), "GRAPH_CLIENT_ID"},
		{"Graph sans secret", with("GRAPH_CLIENT_SECRET", " "), "GRAPH_CLIENT_SECRET"},
		{"Graph sans boîte", with("GRAPH_MAILBOX", ""), "GRAPH_MAILBOX"},
		{"locataire qui sort du chemin", with("GRAPH_TENANT_ID", "../common"), "GRAPH_TENANT_ID"},
		{"locataire avec une barre", with("GRAPH_TENANT_ID", "contoso.com/x"), "GRAPH_TENANT_ID"},
		{"boîte qui n'est pas une adresse", with("GRAPH_MAILBOX", "formulaires"), "GRAPH_MAILBOX"},
		{"boîte avec un nom affiché", with("GRAPH_MAILBOX", "Naria <formulaires@exemple.fr>"), "GRAPH_MAILBOX"},
	} {
		_, err := load(t, tc.env)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s : erreur %v (un refus qui nomme %s est attendu)", tc.name, err, tc.want)
		}
		if err != nil && strings.Contains(err.Error(), "s3cr3t") {
			t.Errorf("%s : l'erreur cite le secret : %v", tc.name, err)
		}
	}
}
