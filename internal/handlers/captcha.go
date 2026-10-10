package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"gitlab.com/detag_inno/naria/internal/captcha"
	"gitlab.com/detag_inno/naria/internal/database"
	"gitlab.com/detag_inno/naria/internal/email"
	"gitlab.com/detag_inno/naria/internal/i18n"
)

const (
	// An anonymous visitor can trigger refusals at will: at most one alert per day.
	captchaAlertEvery = 24 * time.Hour
	captchaAlertRetry = 10 * time.Minute
)

var errCaptchaMissing = &submitError{http.StatusForbidden, "submit.err.captcha_missing"}

// captchaWatch counts, for a protected form, the browser submissions without a
// solution: visitors the page did not prepare to submit (script missing or not run).
// The count is per process.
type captchaWatch struct {
	// Reset on the next verified submission.
	unsolved   int
	alertAfter time.Time
}

type captchaChallenge struct {
	Challenge  string `json:"challenge"`
	Difficulty int    `json:"difficulty"`
}

// CaptchaChallenge issues a challenge for the key in the URL. It is a public endpoint, with
// no session or cookie, and no rate limit: a limiter would keep the visitor's address in
// memory to protect an answer that costs only a signature. The database is not read.
func (a *App) CaptchaChallenge(w http.ResponseWriter, r *http.Request) {
	submitCORS(w)
	w.Header().Set("Cache-Control", "no-store")
	// Trimmed as in admit: a key pasted with a space must yield an accepted challenge.
	key := strings.TrimSpace(chi.URLParam(r, "key"))
	if len(key) > maxAccessKeyLen {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(captchaChallenge{
		Challenge: a.Captcha.Challenge(key, time.Now()), Difficulty: a.Captcha.Difficulty(),
	})
}

// checkCaptcha verifies and consumes the solution. A wrong, expired or replayed
// solution always gets the same refusal.
func (a *App) checkCaptcha(r *http.Request, form database.GetFormByAccessKeyRow, solution string) error {
	err := a.Captcha.Check(form.AccessKey, solution, time.Now())
	if err == nil {
		a.captchaMu.Lock()
		if watch, ok := a.captchaWatch[form.ID]; ok {
			watch.unsolved = 0
		}
		a.captchaMu.Unlock()
		return nil
	}
	if !errors.Is(err, captcha.ErrMissing) {
		return &submitError{http.StatusForbidden, "submit.err.captcha_invalid"}
	}
	// Sec-Fetch-Site is only sent by a browser. Whoever forges it gets one more alert at
	// most, bounded by captchaAlertEvery.
	if r.Header.Get("Sec-Fetch-Site") != "" {
		a.captchaUnsolved(form)
	}
	return errCaptchaMissing
}

// captchaUnsolved records a refusal for lack of a solution and alerts the owner at most
// once per captchaAlertEvery, sooner if the previous alert could not be sent. Without
// this, a site with a broken script would refuse its visitors without anyone knowing.
func (a *App) captchaUnsolved(form database.GetFormByAccessKeyRow) {
	now := time.Now()
	a.captchaMu.Lock()
	watch := a.captchaWatch[form.ID]
	if watch == nil {
		if a.captchaWatch == nil {
			a.captchaWatch = map[uuid.UUID]*captchaWatch{}
		}
		watch = &captchaWatch{}
		a.captchaWatch[form.ID] = watch
	}
	watch.unsolved++
	due := now.After(watch.alertAfter)
	if due {
		watch.alertAfter = now.Add(captchaAlertEvery)
	}
	a.captchaMu.Unlock()
	if !due {
		return
	}
	log.Printf("captcha: envoi d'un navigateur refusé faute de solution formulaire=%s", form.ID)
	if a.Mailer == nil {
		return
	}
	go func() { // #nosec G118 -- the alert must outlive the request, which does not wait for the send
		ctx, cancel := context.WithTimeout(context.Background(), sendTimeout)
		defer cancel()
		err := a.sendCaptchaAlert(ctx, form)
		if err == nil {
			return
		}
		log.Printf("ERROR email: alerte de vérification anti-robot formulaire=%s: %q", form.ID, err.Error()) // #nosec G706 -- form.ID is a UUID; the error is quoted (%q escapes CR/LF)
		a.captchaMu.Lock()
		watch.alertAfter = time.Now().Add(captchaAlertRetry)
		a.captchaMu.Unlock()
	}()
}

// sendCaptchaAlert writes to the site owner. The email carries no visitor data.
func (a *App) sendCaptchaAlert(ctx context.Context, form database.GetFormByAccessKeyRow) error {
	owner, err := a.Q.GetSiteOwnerEmail(ctx, form.SiteID)
	if err != nil {
		return err
	}
	loc := i18n.Get(i18n.Locale(form.NotificationLang))
	link := strings.TrimRight(a.Cfg.BaseURL, "/") + "/forms/" + form.ID.String()
	return a.Mailer.Send(ctx, email.Message{
		To:      []string{owner},
		Subject: loc.T("mail.captcha.subject", form.SiteName, form.Name),
		HTML: submissionEmailHTML(loc.T("mail.captcha.intro", form.Name, form.SiteName), loc.T("mail.captcha.note"), nil,
			link, loc.T("mail.quota.button"), loc.T("mail.submission.footer", a.Cfg.Brand.Name), a.Cfg.Brand.Color),
	})
}

func (a *App) captchaUnsolvedCount(formID uuid.UUID) int {
	a.captchaMu.Lock()
	defer a.captchaMu.Unlock()
	if watch, ok := a.captchaWatch[formID]; ok {
		return watch.unsolved
	}
	return 0
}
