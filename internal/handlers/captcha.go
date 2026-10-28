package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"gitlab.com/detag_inno/naria/internal/captcha"
	"gitlab.com/detag_inno/naria/internal/database"
)

var errCaptchaMissing = &submitError{http.StatusForbidden, "submit.err.captcha_missing"}

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
		a.captchaWatch.reset(form.ID)
		return nil
	}
	if !errors.Is(err, captcha.ErrMissing) {
		return &submitError{http.StatusForbidden, "submit.err.captcha_invalid"}
	}
	// Sec-Fetch-Site is only sent by a browser. A forged one triggers no more than one
	// alert per refusalAlertEvery for the form. Without the alert, a site with a
	// broken script would refuse its visitors without anyone knowing.
	if r.Header.Get("Sec-Fetch-Site") != "" {
		a.refused(&a.captchaWatch, form, "captcha")
	}
	return errCaptchaMissing
}

// captchaUnsolvedCount: browser submissions refused for lack of a solution since
// the last verified one.
func (a *App) captchaUnsolvedCount(formID uuid.UUID) int {
	return a.captchaWatch.count(formID)
}
