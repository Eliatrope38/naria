package handlers

import (
	"context"
	"errors"
	"log"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"gitlab.com/detag_inno/naria/internal/database"
	"gitlab.com/detag_inno/naria/internal/email"
	"gitlab.com/detag_inno/naria/internal/i18n"
)

const (
	// Beyond this, the usage is measured again in the database. Between two measurements, the process
	// keeps it up to date with what it stores itself.
	usageMaxAge = time.Minute
	// Does not follow the request: otherwise a visitor who drops the connection
	// would trigger a new measurement on every send.
	measureTimeout = 15 * time.Second
	// A dropped submission must not cost an email each time.
	quotaAlertEvery = 24 * time.Hour
	// A failing email server must not be hit on every dropped submission.
	quotaAlertRetry = 10 * time.Minute
)

var errFormFull = errors.New("quota de stockage atteint")

// formUsage is the space held by a form, as seen by this process. Measuring it
// in the database on each send would let a visitor load the database, and keeping it
// up to date in the database would make sends to the same form wait in line
// behind one another. The count is per process, like the rate limiters.
type formUsage struct {
	mu sync.Mutex
	// Size measured in the database at readAt, plus what the process has kept since.
	stored int64
	// Size of each storage in progress. Without it, concurrent sends
	// would all pass under the quota.
	pending map[uuid.UUID]int64
	readAt  time.Time
}

func (u *formUsage) used() int64 {
	total := u.stored
	for _, size := range u.pending {
		total += size
	}
	return total
}

// usageOf returns the state of a form, locked and up to date. The caller
// unlocks it.
func (a *App) usageOf(ctx context.Context, formID uuid.UUID) (*formUsage, error) {
	a.usageMu.Lock()
	u, ok := a.usage[formID]
	if !ok {
		if a.usage == nil {
			a.usage = map[uuid.UUID]*formUsage{}
		}
		u = &formUsage{pending: map[uuid.UUID]int64{}}
		a.usage[formID] = u
	}
	a.usageMu.Unlock()

	u.mu.Lock()
	if time.Since(u.readAt) > usageMaxAge {
		// The lock is held during the measurement: the form's sends
		// wait for it, rather than each running their own.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), measureTimeout)
		stored, err := a.Q.FormStorageBytes(ctx, database.FormStorageBytesParams{FormID: formID, Pending: slices.Collect(maps.Keys(u.pending))})
		cancel()
		if err != nil {
			u.mu.Unlock()
			return nil, err
		}
		u.stored, u.readAt = stored, time.Now()
	}
	// nosemgrep: trailofbits.go.missing-unlock-before-return.missing-unlock-before-return -- the lock is handed to the caller, see usageOf
	return u, nil
}

func (a *App) storageUsed(ctx context.Context, formID uuid.UUID) (int64, error) {
	u, err := a.usageOf(ctx, formID)
	if err != nil {
		return 0, err
	}
	defer u.mu.Unlock()
	return u.used(), nil
}

// reserveStorage holds the space of a submission before it is stored. The space
// already held is compared to the quota without the incoming submission: the one that
// crosses it still passes, the next ones do not. settleStorage must follow.
func (a *App) reserveStorage(ctx context.Context, formID, submissionID uuid.UUID, size int64) error {
	u, err := a.usageOf(ctx, formID)
	if err != nil {
		return err
	}
	defer u.mu.Unlock()
	if u.used() >= a.Cfg.MaxFormStorageBytes {
		return errFormFull
	}
	u.pending[submissionID] = size
	return nil
}

// settleStorage closes a reservation. The form's state exists: reserveStorage
// created it, and nothing removes it.
func (a *App) settleStorage(formID, submissionID uuid.UUID, kept bool) {
	a.usageMu.Lock()
	u := a.usage[formID]
	a.usageMu.Unlock()
	u.mu.Lock()
	defer u.mu.Unlock()
	if kept {
		u.stored += u.pending[submissionID]
	}
	delete(u.pending, submissionID)
}

// forgetStorage forces a new measurement of the affected forms after
// submissions are deleted. Without a designated form, all of them are.
func (a *App) forgetStorage(formIDs ...uuid.UUID) {
	// Locked outside usageMu: a measurement in the database can hold one of them for a long time.
	a.usageMu.Lock()
	var stale []*formUsage
	if len(formIDs) == 0 {
		stale = slices.Collect(maps.Values(a.usage))
	}
	for _, id := range formIDs {
		if u, ok := a.usage[id]; ok {
			stale = append(stale, u)
		}
	}
	a.usageMu.Unlock()
	for _, u := range stale {
		u.mu.Lock()
		u.readAt = time.Time{}
		u.mu.Unlock()
	}
}

// emailCarries reports whether the notification email is enough to deliver a submission
// in full, that is, whether it is sent with its content.
func (a *App) emailCarries(notify, includeContent bool, recipients []string) bool {
	return notify && includeContent && a.Mailer != nil && len(recipients) > 0
}

func (a *App) refuseFull(form database.GetFormByAccessKeyRow) {
	log.Printf("soumission: refusée, quota de stockage atteint formulaire=%s", form.ID)
	a.alertFormFull(form)
}

// alertFormFull warns the site owner, and the recipients if the
// form sends notifications, that the storage quota is reached. Without this alert,
// nobody would know that submissions have stopped being stored. The email
// carries no visitor data and is sent at most once per quotaAlertEvery.
func (a *App) alertFormFull(form database.GetFormByAccessKeyRow) {
	if a.Mailer == nil {
		return
	}
	a.quotaAlertMu.Lock()
	if next, ok := a.quotaAlertAfter[form.ID]; ok && time.Now().Before(next) {
		a.quotaAlertMu.Unlock()
		return
	}
	if a.quotaAlertAfter == nil {
		a.quotaAlertAfter = map[uuid.UUID]time.Time{}
	}
	a.quotaAlertAfter[form.ID] = time.Now().Add(quotaAlertEvery)
	a.quotaAlertMu.Unlock()

	go func() { // #nosec G118 -- the alert must outlive the request, which does not wait for the send
		ctx, cancel := context.WithTimeout(context.Background(), sendTimeout)
		defer cancel()
		err := a.sendFormFullAlert(ctx, form)
		if err == nil {
			return
		}
		log.Printf("ERROR email: alerte de quota formulaire=%s: %q", form.ID, err.Error()) // #nosec G706 -- form.ID is a UUID; the error is quoted (%q escapes CR/LF)
		a.quotaAlertMu.Lock()
		a.quotaAlertAfter[form.ID] = time.Now().Add(quotaAlertRetry)
		a.quotaAlertMu.Unlock()
	}()
}

// siteAlertAddresses returns the address of the site's owner and, when it is another
// account, the address of its organisation's administrator. An empty administrator
// address means there is none active. Readers of a shared site get no alert.
func (a *App) siteAlertAddresses(ctx context.Context, siteID uuid.UUID) (owner, orgAdmin string, err error) {
	row, err := a.Q.GetSiteAlertEmails(ctx, siteID)
	if err != nil {
		return "", "", err
	}
	if row.AdminEmail != nil && *row.AdminEmail != row.OwnerEmail {
		orgAdmin = *row.AdminEmail
	}
	return row.OwnerEmail, orgAdmin, nil
}

// sendFormFullAlert sends the alert. The owner and recipients each receive
// their own message, so the owner's login address is not exposed. Only
// the owner's failure is returned, and so retried: retrying for a recipient
// refused would send the alert to the owner every ten minutes.
func (a *App) sendFormFullAlert(ctx context.Context, form database.GetFormByAccessKeyRow) error {
	owner, orgAdmin, err := a.siteAlertAddresses(ctx, form.SiteID)
	if err != nil {
		return err
	}
	loc := i18n.Get(i18n.Locale(form.NotificationLang))
	consequence := loc.T("mail.quota.refused")
	if a.emailCarries(form.NotifyEmail, form.EmailIncludeContent, form.Recipients) {
		consequence = loc.T("mail.quota.email_only")
	}
	link := strings.TrimRight(a.Cfg.BaseURL, "/") + "/forms/" + form.ID.String()
	msg := email.Message{
		To:      []string{owner},
		Subject: loc.T("mail.quota.subject", form.SiteName, form.Name),
		HTML: submissionEmailHTML(loc.T("mail.quota.intro", form.Name, form.SiteName), consequence, nil,
			link, loc.T("mail.quota.button"), loc.T("mail.submission.footer", a.Cfg.Brand.Name), a.Cfg.Brand.Color),
	}
	if err := a.Mailer.Send(ctx, msg); err != nil {
		return err
	}
	if orgAdmin != "" {
		msg.To = []string{orgAdmin}
		if err := a.Mailer.Send(ctx, msg); err != nil {
			log.Printf("ERROR email: alerte de quota à l'administrateur de l'organisation formulaire=%s: %q", form.ID, err.Error()) // #nosec G706 -- form.ID is a UUID; the error is quoted (%q escapes CR/LF)
		}
	}
	if !form.NotifyEmail {
		return nil
	}
	msg.To = slices.DeleteFunc(slices.Clone(form.Recipients), func(to string) bool { return to == owner || to == orgAdmin })
	if len(msg.To) == 0 {
		return nil
	}
	if err := a.Mailer.Send(ctx, msg); err != nil {
		log.Printf("ERROR email: alerte de quota aux destinataires formulaire=%s: %q", form.ID, err.Error()) // #nosec G706 -- form.ID is a UUID; the error is quoted (%q escapes CR/LF)
	}
	return nil
}
