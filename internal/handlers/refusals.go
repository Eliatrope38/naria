package handlers

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"gitlab.com/detag_inno/naria/internal/database"
	"gitlab.com/detag_inno/naria/internal/email"
	"gitlab.com/detag_inno/naria/internal/i18n"
)

const (
	// An anonymous visitor can trigger refusals at will: one alert per day, and one
	// retry after refusalAlertRetry when the send fails.
	refusalAlertEvery = 24 * time.Hour
	refusalAlertRetry = 10 * time.Minute
)

// refusalWatch counts, per form, the submissions turned away without the owner
// seeing them, and spaces out the alerts about them. The count is per process.
type refusalWatch struct {
	mu    sync.Mutex
	forms map[uuid.UUID]*refusalCount
}

type refusalCount struct {
	n          int
	alertAfter time.Time
}

// record counts a refusal and reports whether an alert is due.
func (w *refusalWatch) record(id uuid.UUID, now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	c := w.forms[id]
	if c == nil {
		if w.forms == nil {
			w.forms = map[uuid.UUID]*refusalCount{}
		}
		c = &refusalCount{}
		w.forms[id] = c
	}
	c.n++
	if now.Before(c.alertAfter) {
		return false
	}
	c.alertAfter = now.Add(refusalAlertEvery)
	return true
}

// retrySoon lets a refusal refusalAlertRetry from now send the alert that just failed.
func (w *refusalWatch) retrySoon(id uuid.UUID) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if c, ok := w.forms[id]; ok {
		c.alertAfter = time.Now().Add(refusalAlertRetry)
	}
}

// reset clears the count shown on the form page, not the alert spacing.
func (w *refusalWatch) reset(id uuid.UUID) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if c, ok := w.forms[id]; ok {
		c.n = 0
	}
}

func (w *refusalWatch) count(id uuid.UUID) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	if c, ok := w.forms[id]; ok {
		return c.n
	}
	return 0
}

// refused records a refusal and, at most once per refusalAlertEvery, writes to the
// site owner. kind names the "mail.<kind>.*" texts of the alert, which carries no
// visitor data.
func (a *App) refused(watch *refusalWatch, form database.GetFormByAccessKeyRow, kind string) {
	if !watch.record(form.ID, time.Now()) {
		return
	}
	log.Printf("%s: envoi refusé formulaire=%s", kind, form.ID)
	if a.Mailer == nil {
		return
	}
	go func() { // #nosec G118 -- the alert must outlive the request, which does not wait for the send
		ctx, cancel := context.WithTimeout(context.Background(), sendTimeout)
		defer cancel()
		if err := a.sendRefusalAlert(ctx, form, kind); err != nil {
			log.Printf("ERROR email: alerte %s formulaire=%s: %q", kind, form.ID, err.Error()) // #nosec G706 -- kind is a constant, form.ID a UUID; the error is quoted (%q escapes CR/LF)
			watch.retrySoon(form.ID)
		}
	}()
}

func (a *App) sendRefusalAlert(ctx context.Context, form database.GetFormByAccessKeyRow, kind string) error {
	owner, orgAdmin, err := a.siteAlertAddresses(ctx, form.SiteID)
	if err != nil {
		return err
	}
	loc := i18n.Get(i18n.Locale(form.NotificationLang))
	link := strings.TrimRight(a.Cfg.BaseURL, "/") + "/forms/" + form.ID.String()
	msg := email.Message{
		To:      []string{owner},
		Subject: loc.T("mail."+kind+".subject", form.SiteName, form.Name),
		HTML: submissionEmailHTML(loc.T("mail."+kind+".intro", form.Name, form.SiteName), loc.T("mail."+kind+".note"), nil,
			link, loc.T("mail.quota.button"), loc.T("mail.submission.footer", a.Cfg.Brand.Name), a.Cfg.Brand.Color),
	}
	if err := a.Mailer.Send(ctx, msg); err != nil {
		return err
	}
	if orgAdmin != "" {
		msg.To = []string{orgAdmin}
		if err := a.Mailer.Send(ctx, msg); err != nil {
			log.Printf("ERROR email: alerte %s à l'administrateur de l'organisation formulaire=%s: %q", kind, form.ID, err.Error()) // #nosec G706 -- kind is a constant, form.ID a UUID; the error is quoted (%q escapes CR/LF)
		}
	}
	return nil
}
