package main

import (
	"context"
	"database/sql"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alexedwards/scs/pgxstore"
	"github.com/alexedwards/scs/v2"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/justinas/nosurf"
	"github.com/pressly/goose/v3"

	naria "gitlab.com/detag_inno/naria"
	"gitlab.com/detag_inno/naria/internal/antivirus"
	"gitlab.com/detag_inno/naria/internal/auth"
	"gitlab.com/detag_inno/naria/internal/captcha"
	"gitlab.com/detag_inno/naria/internal/chat"
	"gitlab.com/detag_inno/naria/internal/config"
	"gitlab.com/detag_inno/naria/internal/crypto"
	"gitlab.com/detag_inno/naria/internal/database"
	"gitlab.com/detag_inno/naria/internal/email"
	"gitlab.com/detag_inno/naria/internal/handlers"
	"gitlab.com/detag_inno/naria/internal/turnstile"
	"gitlab.com/detag_inno/naria/internal/version"
	"gitlab.com/detag_inno/naria/internal/web"
	"gitlab.com/detag_inno/naria/ui"
)

// sessionIdleTimeout applies on top of SessionLifetime, which caps the absolute duration.
const sessionIdleTimeout = 2 * time.Hour

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	if err := migrate(cfg.DatabaseURL); err != nil {
		log.Fatalf("migrations: %v", err)
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("connexion db: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		log.Fatalf("ping db: %v", err)
	}

	q := database.New(pool)

	sm := scs.New()
	sm.Store = pgxstore.New(pool)
	sm.Lifetime = cfg.SessionLifetime
	// An idle session must not stay usable until the absolute limit.
	sm.IdleTimeout = sessionIdleTimeout
	sm.Cookie.HttpOnly = true
	sm.Cookie.Secure = cfg.Secure
	sm.Cookie.SameSite = http.SameSiteLaxMode

	// Keys derived from the same secret, one per purpose: a value encrypted for one
	// purpose cannot be decrypted with another purpose's key.
	totpCipher, err := crypto.New(cfg.SecretKey, crypto.PurposeTOTP)
	if err != nil {
		log.Fatalf("init chiffrement: %v", err)
	}
	submissionCipher, err := crypto.New(cfg.SecretKey, crypto.PurposeSubmission)
	if err != nil {
		log.Fatalf("init chiffrement: %v", err)
	}
	attachmentCipher, err := crypto.New(cfg.SecretKey, crypto.PurposeAttachment)
	if err != nil {
		log.Fatalf("init chiffrement: %v", err)
	}
	webhookCipher, err := crypto.New(cfg.SecretKey, crypto.PurposeWebhook)
	if err != nil {
		log.Fatalf("init chiffrement: %v", err)
	}
	botTokenCipher, err := crypto.New(cfg.SecretKey, crypto.PurposeBotToken)
	if err != nil {
		log.Fatalf("init chiffrement: %v", err)
	}
	if !submissionCipher.Enabled() {
		log.Println("ATTENTION: APP_SECRET_KEY non défini. Soumissions, adresses de webhook, jetons de bot et secrets TOTP sont stockés en clair (toléré hors production uniquement)")
	}

	challenges, err := captcha.New(cfg.SecretKey, captcha.Difficulty)
	if err != nil {
		log.Fatalf("init vérification anti-robot: %v", err)
	}

	mailer := email.New(email.Options{
		Provider:     cfg.EmailProvider,
		SMTPHost:     cfg.SMTPHost,
		SMTPPort:     cfg.SMTPPort,
		SMTPUsername: cfg.SMTPUsername,
		SMTPPassword: cfg.SMTPPassword,
		SMTPFrom:     cfg.SMTPFrom,
		SMTPTLS:      cfg.SMTPTLS,

		GraphTenantID:     cfg.GraphTenantID,
		GraphClientID:     cfg.GraphClientID,
		GraphClientSecret: cfg.GraphClientSecret,
		GraphMailbox:      cfg.GraphMailbox,
	})
	sender := "désactivé"
	if mailer != nil {
		sender = cfg.EmailProvider
	}
	if graph, ok := mailer.(*email.Graph); ok {
		// An expired or mistyped secret shows up here rather than at the first submission.
		// An unreachable Microsoft endpoint does not block startup: forms that store
		// submissions keep working without email.
		pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		if err := graph.Ping(pingCtx); err != nil {
			log.Printf("ATTENTION: Microsoft ne délivre pas de jeton à l'application (%v). Aucun email ne part tant que cela dure", err)
		}
		cancel()
	}
	ui.SetBrand(ui.Brand{
		Name: cfg.Brand.Name, Company: cfg.Brand.Company, SupportEmail: cfg.Brand.SupportEmail,
		Tagline: cfg.Brand.Tagline, Color: cfg.Brand.Color, ColorDark: cfg.Brand.ColorDark,
		LogoURL: cfg.Brand.LogoURL, HasLogo: cfg.Brand.HasLogo, FaviconURL: cfg.Brand.FaviconURL,
	})
	auth.SetTOTPIssuer(cfg.Brand.Name)
	ui.SetVersion(version.Version)
	ui.SetLegal(ui.LegalLinks{HasPrivacy: cfg.Brand.PrivacyFile != "", HasLegal: cfg.Brand.LegalFile != ""})
	ui.SetProd(cfg.Secure)
	ui.SetTurnstileSiteKey(cfg.TurnstileSiteKey)
	ui.SetForgotPassword(mailer != nil)
	var captcha *turnstile.Verifier // nil when disabled
	if cfg.TurnstileSecretKey != "" {
		captcha = turnstile.New(cfg.TurnstileSecretKey)
		log.Printf("turnstile: vérification anti-robot activée sur le login")
	}

	// A clamd still loading its signatures must not block startup. Until it answers,
	// submissions with attachments are refused and the others pass.
	scanner := antivirus.New(cfg.ClamAVAddr)
	if scanner != nil {
		pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		if err := scanner.Ping(pingCtx); err != nil {
			log.Printf("ATTENTION: antivirus injoignable (%v). Les soumissions avec pièces jointes sont refusées tant qu'il ne répond pas", err)
		}
		cancel()
	}

	app := &handlers.App{
		Cfg: cfg, Q: q, Pool: pool, Sessions: sm, Mailer: mailer, MailAttachmentBytes: email.MaxAttachmentBytes(mailer),
		Limiter:            web.NewRateLimiter(10, 5*time.Minute), // brute-force protection on login
		SubmitLimiter:      web.NewRateLimiter(cfg.SubmitRateLimit, cfg.SubmitRateWindow),
		Crypto:             totpCipher,
		SubmissionCrypto:   submissionCipher,
		AttachmentCrypto:   attachmentCipher,
		Antivirus:          scanner,
		Captcha:            challenges,
		Chat:               chat.New(cfg.WebhookAllowedHosts),
		WebhookCrypto:      webhookCipher,
		BotTokenCrypto:     botTokenCipher,
		WebhookTestLimiter: web.NewRateLimiter(10, 5*time.Minute), // per account
		APILimiter:         web.NewRateLimiter(60, time.Minute),
		Turnstile:          captcha,
	}

	staticFS, err := fs.Sub(naria.StaticFiles, "web/static")
	if err != nil {
		log.Fatalf("static fs: %v", err)
	}

	srv := &http.Server{
		Addr:         cfg.Addr,
		Handler:      buildRouter(app, cfg, staticFS),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	// Run once at startup, then daily.
	go func() {
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		app.PurgeRetention(context.Background())
		for range t.C {
			app.PurgeRetention(context.Background())
		}
	}()

	log.Printf("%s démarré sur %s (secure=%v, chiffrement=%v, email=%s, antivirus=%v)", cfg.Brand.Name, cfg.Addr, cfg.Secure, submissionCipher.Enabled(), sender, scanner != nil)

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("serveur: %v", err)
		}
	}()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	log.Println("arrêt en cours…")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("arrêt: %v", err)
	}
}

// buildRouter assembles the HTTP router, kept apart from main so it can be tested.
func buildRouter(app *handlers.App, cfg config.Config, staticFS fs.FS) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	// Without a declared proxy, the client address is the connection's own: no header
	// is trusted (see web.TrustedRealIP). chi's middleware.RealIP trusts headers
	// from any peer.
	r.Use(web.TrustedRealIP(cfg.TrustedProxyCIDRs))
	// Custom access log: no IP address and no query string (see web.AccessLog).
	r.Use(web.AccessLog)
	r.Use(middleware.Recoverer)
	r.Use(web.SecurityHeaders(cfg.Secure, cfg.TurnstileSiteKey != ""))

	fileServer := http.StripPrefix("/static/", http.FileServer(http.FS(staticFS)))
	r.Handle("/static/*", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// White-label: a mounted external logo or CSS takes precedence over the embedded one.
		switch req.URL.Path {
		case "/static/main.css":
			if cfg.Brand.CSSFile != "" {
				w.Header().Set("Content-Type", "text/css; charset=utf-8")
				http.ServeFile(w, req, cfg.Brand.CSSFile)
				return
			}
		case "/static/logo.webp":
			if cfg.Brand.LogoFile != "" {
				http.ServeFile(w, req, cfg.Brand.LogoFile)
				return
			}
		case "/static/favicon.png":
			if cfg.Brand.FaviconFile != "" {
				http.ServeFile(w, req, cfg.Brand.FaviconFile)
				return
			}
		}
		fileServer.ServeHTTP(w, req)
	}))

	r.Get("/healthz", app.Healthz)
	r.Get("/readyz", app.Readyz)

	// Public entry point, called from client websites: no session, no CSRF, no cookie.
	// The size limit is set by the handler, which knows whether the form accepts files.
	r.Get("/f/{key}/challenge", app.CaptchaChallenge)
	r.Group(func(r chi.Router) {
		r.Use(web.Localize)
		r.Post("/submit", app.Submit)
		r.Options("/submit", app.SubmitPreflight)
		r.Post("/f/{key}", app.Submit)
		r.Options("/f/{key}", app.SubmitPreflight)
	})

	// No session or cookie: authenticated by API token (handlers.APIAuth).
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(maxBody(cfg.MaxBodyBytes))
		r.Use(web.Localize)
		r.Use(app.APIAuth)
		r.Get("/site", app.APISite)
		r.Get("/forms", app.APIListForms)
		r.Post("/forms", app.APICreateForm)
	})

	r.Group(func(r chi.Router) {
		r.Use(maxBody(cfg.MaxBodyBytes))
		r.Use(app.Sessions.LoadAndSave)
		r.Use(csrf(cfg.Secure))
		r.Use(web.LoadUser(app.Sessions, app.Q))
		r.Use(web.Localize)

		// Language and theme switches (public: available before login).
		r.Get("/lang", app.SetLang)
		r.Get("/theme", app.SetTheme)
		r.Get("/manifest.webmanifest", app.Manifest)

		r.Get("/login", app.ShowLogin)
		r.Get("/confidentialite", app.PrivacyPolicy)
		r.Get("/mentions-legales", app.LegalNotice)
		r.Post("/login", app.DoLogin)
		r.Get("/login/2fa", app.Show2FA)
		r.Post("/login/2fa", app.Verify2FA)
		r.Get("/login/forgot", app.ShowForgotPassword)
		r.Post("/login/forgot", app.DoForgotPassword)
		r.Get("/login/reset", app.ShowResetPassword)
		r.Post("/login/reset", app.DoResetPassword)
		r.Post("/logout", app.DoLogout)

		r.Group(func(r chi.Router) {
			r.Use(web.RequireAuth)

			// Account isolation (an account sees the sites it owns, its organisation's sites
			// if it administers them, and those shared with it) is enforced in the queries,
			// not by a middleware: each handler loads its resource within the user's scope.
			r.Get("/", app.SiteList)
			r.Post("/sites", app.CreateSite)
			r.Get("/sites/{id}", app.SiteDetail)
			r.Post("/sites/{id}", app.UpdateSite)
			r.Post("/sites/{id}/delete", app.DeleteSite)
			r.Post("/sites/{id}/tokens", app.CreateAPIToken)
			r.Post("/sites/{id}/tokens/{token}/delete", app.RevokeAPIToken)
			r.Post("/sites/{id}/blocked", app.BlockSender)
			r.Post("/sites/{id}/blocked/{entry}/delete", app.UnblockSender)
			r.Post("/sites/{id}/owner", app.SetSiteOwner)
			r.Post("/sites/{id}/readers", app.GrantSiteRead)
			r.Post("/sites/{id}/readers/{user}/delete", app.RevokeSiteRead)

			r.Get("/sites/{id}/forms/new", app.NewForm)
			r.Post("/sites/{id}/forms", app.CreateForm)
			r.Get("/forms/{id}", app.FormSubmissions)
			r.Get("/forms/{id}/settings", app.FormSettings)
			r.Post("/forms/{id}/settings", app.UpdateForm)
			r.Post("/forms/{id}/webhooks/test", app.TestWebhook)
			r.Post("/forms/{id}/key", app.RegenerateFormKey)
			r.Post("/forms/{id}/delete", app.DeleteForm)

			r.Get("/forms/{id}/export.csv", app.ExportCSV)
			r.Get("/forms/{id}/export.zip", app.ExportZIP)
			r.Post("/forms/{id}/read", app.MarkAllRead)
			r.Post("/forms/{id}/purge", app.PurgeFormSubmissions)
			r.Get("/submissions/{id}", app.SubmissionDetail)
			r.Post("/submissions/{id}/delete", app.DeleteSubmission)
			r.Get("/attachments/{id}", app.DownloadAttachment)

			r.Get("/account", app.AccountPage)
			r.Post("/account/name", app.ChangeOwnName)
			r.Post("/account/email", app.ChangeOwnEmail)
			r.Post("/account/password", app.ChangeOwnPassword)
			r.Get("/account/2fa/setup", app.TOTPSetup)
			r.Post("/account/2fa/enable", app.TOTPEnable)
			r.Post("/account/2fa/disable", app.TOTPDisable)

			// The organisation's accounts, managed by its administrator.
			r.Group(func(r chi.Router) {
				r.Use(web.RequireRole(auth.RoleOrgAdmin))
				r.Get("/users", app.UsersList)
				r.Post("/users", app.CreateUser)
				r.Post("/users/{id}/toggle", app.ToggleUser)
				r.Post("/users/{id}/name", app.EditUserName)
				r.Post("/users/{id}/delete", app.DeleteUser)
				r.Post("/users/{id}/reset-2fa", app.ResetUser2FA)
				r.Post("/users/{id}/password", app.SetUserPassword)
			})

			// Organisations, managed by the platform administrator. It has no site.
			r.Group(func(r chi.Router) {
				r.Use(web.RequireRole(auth.RoleAdmin))
				r.Get("/organisations", app.OrganisationsList)
				r.Post("/organisations", app.CreateOrganisation)
				r.Post("/organisations/{id}/admin", app.ReplaceOrgAdmin)
			})
		})
	})

	return r
}

func maxBody(limit int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, limit)
			next.ServeHTTP(w, r)
		})
	}
}

// csrf protects state-changing requests; the token is expected in the csrf_token field.
func csrf(secure bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		h := nosurf.New(next)
		// #nosec G124 -- HttpOnly and SameSite are fixed; Secure follows the environment (TLS in production).
		// nosemgrep: go.lang.security.audit.net.cookie-missing-secure.cookie-missing-secure -- same reason as the #nosec above
		h.SetBaseCookie(http.Cookie{
			Path:     "/",
			HttpOnly: true,
			Secure:   secure,
			SameSite: http.SameSiteLaxMode,
		})
		return h
	}
}

func migrate(dsn string) error {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	goose.SetBaseFS(naria.Migrations)
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}
	return goose.Up(db, "migrations")
}
