package handlers

import (
	"context"
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/a-h/templ"
	"github.com/alexedwards/scs/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/justinas/nosurf"

	"gitlab.com/detag_inno/naria/internal/antivirus"
	"gitlab.com/detag_inno/naria/internal/auth"
	"gitlab.com/detag_inno/naria/internal/captcha"
	"gitlab.com/detag_inno/naria/internal/chat"
	"gitlab.com/detag_inno/naria/internal/config"
	"gitlab.com/detag_inno/naria/internal/crypto"
	"gitlab.com/detag_inno/naria/internal/database"
	"gitlab.com/detag_inno/naria/internal/email"
	"gitlab.com/detag_inno/naria/internal/turnstile"
	"gitlab.com/detag_inno/naria/internal/web"
	"gitlab.com/detag_inno/naria/ui"
)

type App struct {
	Cfg      config.Config
	Q        *database.Queries
	Pool     *pgxpool.Pool
	Sessions *scs.SessionManager
	Mailer   email.Sender // nil disables email sending
	// MailAttachmentBytes is the size of files the sender can attach to an
	// email. 0 means no limit other than the instance's.
	MailAttachmentBytes int64
	Limiter             *web.RateLimiter // brute-force protection on login
	// SubmitLimiter caps submissions per IP and per form on the public
	// entry point. nil means no limit (tests).
	SubmitLimiter *web.RateLimiter
	Crypto        *crypto.Cipher // encrypts TOTP secrets at rest (nil means plain text)
	// SubmissionCrypto encrypts submission content (nil means plain text, tolerated outside
	// production only).
	SubmissionCrypto *crypto.Cipher
	// nil means plain text.
	AttachmentCrypto *crypto.Cipher
	// nil means attachments are not scanned.
	Antivirus *antivirus.Scanner
	uploads   atomic.Int32
	exports   atomic.Int32
	usageMu   sync.Mutex
	usage     map[uuid.UUID]*formUsage
	// Time from which a new quota alert may be sent.
	quotaAlertMu    sync.Mutex
	quotaAlertAfter map[uuid.UUID]time.Time
	Captcha         *captcha.Checker
	captchaMu       sync.Mutex
	captchaWatch    map[uuid.UUID]*captchaWatch
	// nil disables alerts.
	Chat *chat.Notifier
	// WebhookCrypto encrypts webhook addresses at rest (nil means plain text).
	WebhookCrypto *crypto.Cipher
	// BotTokenCrypto encrypts Telegram bot tokens at rest (nil means plain text).
	BotTokenCrypto *crypto.Cipher
	// WebhookTestLimiter caps, per account, the sends from the "Test" button.
	// nil means no limit (tests).
	WebhookTestLimiter *web.RateLimiter
	// APILimiter caps API calls, per IP address and then per token.
	// nil means no limit (tests).
	APILimiter *web.RateLimiter
	// nil disables it. Validates the Cloudflare widget token on the login form.
	Turnstile *turnstile.Verifier
}

// Healthz does not touch the database: a DB incident would restart the container in a
// loop without fixing anything. That signal belongs to Readyz.
func (a *App) Healthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok"))
}

// Readyz requires a responding database: otherwise 503 takes the instance out of rotation without killing it.
func (a *App) Readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if a.Pool == nil || a.Pool.Ping(ctx) != nil {
		http.Error(w, "non prêt", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ready"))
}

// pageParam reads the page number from "?page=" (default 1, never below 1).
func pageParam(r *http.Request) int {
	if n, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && n > 1 {
		return n
	}
	return 1
}

// paginate caps the page to the real page count and returns the matching SQL offset.
func paginate(path, query string, page, perPage int, total int64) (ui.Pagination, int32) {
	totalPages := int((total + int64(perPage) - 1) / int64(perPage))
	if totalPages < 1 {
		totalPages = 1
	}
	if page > totalPages {
		page = totalPages
	}
	offset := (page - 1) * perPage
	if offset < 0 || offset > math.MaxInt32 {
		offset = 0
	}
	return ui.Pagination{Path: path, Query: query, Page: page, TotalPages: totalPages}, int32(offset)
}

// scope returns the scope of partitioned queries (…Scoped): an administrator sees
// everything, a member only their own sites.
func scope(u *database.User) (isAdmin bool, viewerID uuid.UUID) {
	return auth.IsAdmin(u.Role), u.ID
}

// searchParam reads "?q=": the input text and its nullable form for SQL.
func searchParam(r *http.Request) (string, *string) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		return "", nil
	}
	return q, &q
}

// tr translates a key into the request's locale, set by web.Localize.
func tr(r *http.Request, key string, args ...any) string {
	return ui.LocalizerFrom(r.Context()).T(key, args...)
}

// renderPage writes a templ component. A rendering error is only logged:
// the response has already started.
func renderPage(w http.ResponseWriter, r *http.Request, c templ.Component) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// The header's logout form is a POST, which must carry the token.
	ctx := ui.WithCSRF(r.Context(), nosurf.Token(r))
	if err := c.Render(ctx, w); err != nil {
		log.Printf("rendu page: %v", err)
	}
}
