package handlers

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"gitlab.com/detag_inno/naria/internal/database"
	"gitlab.com/detag_inno/naria/internal/email"
	"gitlab.com/detag_inno/naria/internal/submission"
	"gitlab.com/detag_inno/naria/internal/web"
	"gitlab.com/detag_inno/naria/ui"
)

const sendTimeout = 25 * time.Second

const (
	maxAttachments = 5
	// Each submission takes several times ATTACHMENTS_MAX_MB in memory, and the
	// per-IP rate limit alone does not cap their number.
	maxUploads = 4
	// Short timeouts, set for small requests, would cut off an attachment transfer
	// over a slow connection.
	transferTimeout = 2 * time.Minute
	scanTimeout     = 30 * time.Second
	// An access key is a UUID: any longer, it would neither be looked up in the database nor
	// signed into a bot challenge.
	maxAccessKeyLen = 64
)

type submitError struct {
	status int
	key    string
}

func (e *submitError) Error() string { return e.key }

// submitBody caps the body like http.MaxBytesReader. The cap is only raised
// at form admission, for attachments: the multipart reader
// reads ahead, so a field close to the cap would exceed it before this raise.
type submitBody struct {
	io.ReadCloser
	limit, left int64
	// multipart ignores read errors by skipping a part: the next read
	// must report the overflow again.
	exceeded error
}

func (b *submitBody) Read(p []byte) (int, error) {
	if b.exceeded != nil {
		return 0, b.exceeded
	}
	// One byte beyond the remaining allowance is enough to detect the overflow.
	if int64(len(p)) > b.left+1 {
		p = p[:b.left+1]
	}
	n, err := b.ReadCloser.Read(p)
	if int64(n) <= b.left {
		b.left -= int64(n)
		return n, err
	}
	n = int(b.left)
	b.left = 0
	b.exceeded = &http.MaxBytesError{Limit: b.limit}
	return n, b.exceeded
}

func (b *submitBody) raise(n int64) {
	b.limit += n
	b.left += n
}

// submitCORS opens the public entry point to cross-origin requests. "*"
// stays safe: the response carries no data, no cookie is read, and the
// domain is checked server-side (submission.OriginAllowed).
func submitCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
}

func (a *App) SubmitPreflight(w http.ResponseWriter, r *http.Request) {
	submitCORS(w)
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept, X-Requested-With")
	w.Header().Set("Access-Control-Max-Age", "600")
	w.WriteHeader(http.StatusNoContent)
}

// Submit receives a public submission: no session or CSRF, the access key
// identifies the form. No identifier is kept: the IP only serves the
// in-memory rate limiter.
func (a *App) Submit(w http.ResponseWriter, r *http.Request) {
	submitCORS(w)
	body := &submitBody{ReadCloser: r.Body, limit: a.Cfg.MaxSubmissionBytes, left: a.Cfg.MaxSubmissionBytes}
	r.Body = body

	// Files are only read after admission, so the key must be known
	// by the first file (in the URL, or in an "access_key" field placed before it).
	var form *database.GetFormByAccessKeyRow
	filesBeforeKey, uploading := false, false
	maxFileBytes := a.Cfg.MaxAttachmentBytes
	defer func() {
		if uploading {
			a.uploads.Add(-1)
		}
	}()
	gate := func(seen submission.Meta) (submission.FileLimits, error) {
		key := cmp.Or(chi.URLParam(r, "key"), seen.AccessKey)
		if key == "" {
			filesBeforeKey = true
			return submission.FileLimits{}, nil
		}
		f, err := a.admit(r, key, seen.Captcha)
		if errors.Is(err, errCaptchaMissing) {
			// The message names the field right away, without waiting for the files to be read.
			err = &submitError{http.StatusForbidden, "submit.err.captcha_after_files"}
		}
		if err != nil {
			return submission.FileLimits{}, err
		}
		form = &f
		if !f.AcceptAttachments {
			return submission.FileLimits{}, nil
		}
		if a.uploads.Add(1) > maxUploads {
			a.uploads.Add(-1)
			w.Header().Set("Retry-After", "30")
			return submission.FileLimits{}, &submitError{http.StatusServiceUnavailable, "submit.err.busy"}
		}
		uploading = true
		maxFileBytes = a.attachmentLimit(f.StoreSubmissions)
		body.raise(maxFileBytes)
		rc := http.NewResponseController(w)
		deadline := time.Now().Add(transferTimeout)
		if err := errors.Join(rc.SetReadDeadline(deadline), rc.SetWriteDeadline(deadline.Add(scanTimeout+transferTimeout))); err != nil {
			log.Printf("ERROR soumission: délai d'envoi des pièces jointes non prolongé formulaire=%s: %v", f.ID, err)
		}
		return submission.FileLimits{MaxFiles: maxAttachments, MaxBytes: maxFileBytes}, nil
	}

	fields, files, err := submission.Parse(r, submission.DefaultLimits, gate)
	if err != nil {
		a.submitRefused(w, r, err, maxFileBytes)
		return
	}
	meta, data := submission.Split(fields)
	if form == nil {
		f, err := a.admit(r, cmp.Or(chi.URLParam(r, "key"), meta.AccessKey), meta.Captcha)
		if err != nil {
			a.submitRefused(w, r, err, maxFileBytes)
			return
		}
		form = &f
	}
	// Rather than accept the submission without its files, it is refused: whoever
	// embeds the form sees the error on the first try.
	if filesBeforeKey && form.AcceptAttachments {
		a.submitFail(w, r, http.StatusBadRequest, "submit.err.key_after_files")
		return
	}
	// This refusal comes before the honeypot: otherwise a bot filling "botcheck"
	// would get a success where a visitor gets an error.
	if !hasContent(data) {
		a.submitFail(w, r, http.StatusBadRequest, "submit.err.empty")
		return
	}
	// A bot gets a success so it does not learn to bypass the honeypot. The
	// bot check was already passed at admission: a success without it
	// would point the honeypot out to anyone comparing responses with and without "botcheck".
	if meta.Bot {
		a.submitOK(w, r, *form, meta)
		return
	}
	// A blocked sender gets the success of any other visitor. Nothing is stored,
	// sent or scanned for it.
	blocked, err := a.senderBlocked(r.Context(), form.SiteID, meta, data)
	if err != nil {
		log.Printf("ERROR soumission: lecture des expéditeurs bloqués formulaire=%s: %v", form.ID, err)
		a.submitFail(w, r, http.StatusInternalServerError, "submit.err.internal")
		return
	}
	if blocked {
		a.submitOK(w, r, *form, meta)
		return
	}

	if status, errKey := a.scanFiles(r.Context(), form.ID, files); errKey != "" {
		if status == http.StatusServiceUnavailable {
			w.Header().Set("Retry-After", "30")
		}
		a.submitFail(w, r, status, errKey)
		return
	}

	stored, status, errKey := a.deliver(r.Context(), *form, meta, data, files)
	if errKey != "" {
		a.submitFail(w, r, status, errKey)
		return
	}
	a.notifyChat(*form, data, stored)
	a.submitOK(w, r, *form, meta)
}

// admit finds the form targeted by the key and checks that it can receive
// the submission. A refusal is a *submitError.
func (a *App) admit(r *http.Request, key, captchaSolution string) (database.GetFormByAccessKeyRow, error) {
	var none database.GetFormByAccessKeyRow
	key = strings.TrimSpace(key)
	if key == "" || len(key) > maxAccessKeyLen {
		return none, &submitError{http.StatusBadRequest, "submit.err.missing_key"}
	}
	form, err := a.Q.GetFormByAccessKey(r.Context(), key)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return none, &submitError{http.StatusNotFound, "submit.err.unknown_form"}
		}
		log.Printf("ERROR soumission: lecture du formulaire: %v", err)
		return none, &submitError{http.StatusInternalServerError, "submit.err.internal"}
	}
	if !form.Active {
		return none, &submitError{http.StatusForbidden, "submit.err.inactive"}
	}
	if !submission.OriginAllowed(form.SiteDomains, r.Header.Get("Origin"), r.Referer()) {
		return none, &submitError{http.StatusForbidden, "submit.err.origin"}
	}
	if a.SubmitLimiter != nil && !a.SubmitLimiter.Allow(form.ID.String()+"|"+web.RateLimitKey(r)) {
		return none, &submitError{http.StatusTooManyRequests, "submit.err.rate"}
	}
	// After the rate limit, which caps verified solutions, and before the
	// quota: a bot without a solution triggers no measurement or alert.
	if form.Captcha {
		if err := a.checkCaptcha(r, form, captchaSolution); err != nil {
			return none, err
		}
	}
	// Early refusal, before reading files. store decides by reserving the space.
	if a.Cfg.MaxFormStorageBytes > 0 && form.StoreSubmissions && !a.emailCarries(form.NotifyEmail, form.EmailIncludeContent, form.Recipients) {
		used, err := a.storageUsed(r.Context(), form.ID)
		if err != nil {
			log.Printf("ERROR soumission: mesure du stockage formulaire=%s: %v", form.ID, err)
			return none, &submitError{http.StatusInternalServerError, "submit.err.internal"}
		}
		if used >= a.Cfg.MaxFormStorageBytes {
			a.refuseFull(form)
			return none, &submitError{http.StatusInsufficientStorage, "submit.err.full"}
		}
	}
	return form, nil
}

// attachmentLimit caps the size of files. Without storage, they live
// only in the email: their limit is then the email's, applied from admission.
func (a *App) attachmentLimit(stored bool) int64 {
	if !stored && a.MailAttachmentBytes > 0 {
		return min(a.Cfg.MaxAttachmentBytes, a.MailAttachmentBytes)
	}
	return a.Cfg.MaxAttachmentBytes
}

func (a *App) submitRefused(w http.ResponseWriter, r *http.Request, err error, maxFileBytes int64) {
	var refused *submitError
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &refused):
		a.submitFail(w, r, refused.status, refused.key)
	case errors.As(err, &tooLarge), errors.Is(err, submission.ErrTooManyFields), errors.Is(err, submission.ErrFieldTooLong):
		a.submitFail(w, r, http.StatusRequestEntityTooLarge, "submit.err.too_large")
	case errors.Is(err, submission.ErrTooManyFiles):
		a.submitFail(w, r, http.StatusRequestEntityTooLarge, "submit.err.too_many_files", maxAttachments)
	case errors.Is(err, submission.ErrFilesTooLarge):
		a.submitFail(w, r, http.StatusRequestEntityTooLarge, "submit.err.files_too_large", maxFileBytes>>20)
	case errors.Is(err, os.ErrDeadlineExceeded):
		a.submitFail(w, r, http.StatusRequestTimeout, "submit.err.timeout")
	case errors.Is(err, submission.ErrUnsupportedType):
		a.submitFail(w, r, http.StatusUnsupportedMediaType, "submit.err.unsupported")
	default:
		a.submitFail(w, r, http.StatusBadRequest, "submit.err.malformed")
	}
}

// scanFiles scans the attachments with the instance's antivirus, if there is one.
// A detected file or a failed scan refuses the whole submission:
// nothing is sent without inspection. The log keeps the signature and sizes, never
// a file name.
func (a *App) scanFiles(ctx context.Context, formID uuid.UUID, files []submission.File) (status int, errKey string) {
	if a.Antivirus == nil || len(files) == 0 {
		return 0, ""
	}
	ctx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()
	for i, f := range files {
		signature, err := a.Antivirus.Scan(ctx, f.Data)
		if err != nil {
			// The size helps locate a file that clamd refuses (StreamMaxLength).
			log.Printf("ERROR antivirus: analyse impossible formulaire=%s fichier=%d/%d octets=%d: %q", formID, i+1, len(files), len(f.Data), err.Error()) // #nosec G706 -- formID is a UUID, the rest are integers; the error is quoted (%q escapes CR/LF)
			return http.StatusServiceUnavailable, "submit.err.scan_unavailable"
		}
		if signature != "" {
			log.Printf("antivirus: pièce jointe refusée formulaire=%s signature=%q", formID, signature)
			return http.StatusUnprocessableEntity, "submit.err.infected"
		}
	}
	return 0, ""
}

// deliver routes a submission to its destinations. An error key means
// none was reached, so the visitor retries. stored is nil if the
// submission is not stored. A full form no longer stores: if its
// email carries the content, delivery goes only through this path, and the email says so.
func (a *App) deliver(ctx context.Context, form database.GetFormByAccessKeyRow, meta submission.Meta, data []submission.Field, files []submission.File) (stored *database.Submission, status int, errKey string) {
	full := false
	if form.StoreSubmissions {
		sub, err := a.store(ctx, form.ID, data, files)
		switch {
		case errors.Is(err, errFormFull):
			if !a.emailCarries(form.NotifyEmail, form.EmailIncludeContent, form.Recipients) {
				a.refuseFull(form)
				return nil, http.StatusInsufficientStorage, "submit.err.full"
			}
			full = true
			a.alertFormFull(form)
		case err != nil:
			log.Printf("ERROR soumission: conservation formulaire=%s: %v", form.ID, err)
			return nil, http.StatusInternalServerError, "submit.err.internal"
		default:
			stored = &sub
		}
	}

	if !form.NotifyEmail {
		return stored, 0, ""
	}
	if a.Mailer == nil || len(form.Recipients) == 0 {
		if stored != nil {
			return stored, 0, "" // stored: nothing is lost, the email is simply unavailable
		}
		log.Printf("ERROR soumission: formulaire=%s en mode email seul, mais l'envoi d'email n'est pas configuré", form.ID)
		return nil, http.StatusServiceUnavailable, "submit.err.unavailable"
	}
	note := ""
	if full {
		note = "mail.submission.not_stored"
	}
	// An email with attachments weighs several MB: it needs the transfer timeout.
	attached, timeout := 0, sendTimeout
	if form.EmailIncludeContent && len(files) > 0 {
		attached, timeout = len(files), transferTimeout
	}
	if stored != nil && attached == 0 {
		go func() { // #nosec G118 -- the send must outlive the request, which is already answered
			sendCtx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			if err := a.sendSubmissionEmail(sendCtx, form, meta, data, files, stored, note); err != nil {
				log.Printf("ERROR email: notification formulaire=%s: %q", form.ID, err.Error()) // #nosec G706 -- form.ID is a UUID; the sender's error is quoted (%q escapes CR/LF)
			}
		}()
		return stored, 0, ""
	}
	// Without storage, the email is the submission: no success is reported before
	// it leaves. With files, they stay in memory until then, which
	// maxUploads counts.
	sendCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()
	err := a.sendSubmissionEmail(sendCtx, form, meta, data, files, stored, note)
	switch {
	case err == nil:
		return stored, 0, ""
	case stored != nil:
		log.Printf("ERROR email: notification formulaire=%s pièces jointes=%d: %q", form.ID, attached, err.Error()) // #nosec G706 -- form.ID is a UUID; the sender's error is quoted (%q escapes CR/LF)
		return stored, 0, ""
	}
	log.Printf("ERROR email: notification formulaire=%s pièces jointes=%d (soumission non conservée, non remise): %q", form.ID, attached, err.Error()) // #nosec G706 -- form.ID is a UUID; the sender's error is quoted (%q escapes CR/LF)
	if errors.Is(err, email.ErrTooLarge) {
		// Retrying would be pointless: the visitor must know it is the
		// size of their message.
		return nil, http.StatusRequestEntityTooLarge, "submit.err.too_large"
	}
	return nil, http.StatusBadGateway, "submit.err.unavailable"
}

// sendSubmissionEmail sends the notification. If the sender refuses the message
// (size or volume) and the submission is stored, it is sent lighter, without
// files then without content, rather than not at all. A submission that is not stored
// is never lightened: the email is its only trace.
func (a *App) sendSubmissionEmail(ctx context.Context, form database.GetFormByAccessKeyRow, meta submission.Meta, data []submission.Field, files []submission.File, stored *database.Submission, noteKey string) error {
	msg := a.submissionEmail(form, meta, data, files, stored, noteKey)
	err := a.Mailer.Send(ctx, msg)
	if stored == nil || !form.EmailIncludeContent || !tooHeavy(err) {
		return err
	}
	if len(msg.Attachments) > 0 {
		log.Printf("email: notification sans ses pièces jointes formulaire=%s: %q", form.ID, err.Error()) // #nosec G706 -- form.ID is a UUID; the sender's error is quoted (%q escapes CR/LF)
		err = a.Mailer.Send(ctx, a.submissionEmail(form, meta, data, nil, stored, "mail.submission.files_left"))
		if !tooHeavy(err) {
			return err
		}
	}
	log.Printf("email: notification sans son contenu formulaire=%s: %q", form.ID, err.Error()) // #nosec G706 -- form.ID is a UUID; the sender's error is quoted (%q escapes CR/LF)
	form.EmailIncludeContent = false
	return a.Mailer.Send(ctx, a.submissionEmail(form, meta, data, nil, stored, ""))
}

func tooHeavy(err error) bool {
	return errors.Is(err, email.ErrTooLarge) || errors.Is(err, email.ErrVolume)
}

// store saves a submission and its encrypted attachments in a
// transaction: a submission is never listed without its files. The space
// is reserved before encryption, so that a full form does not incur its cost.
func (a *App) store(ctx context.Context, formID uuid.UUID, data []submission.Field, files []submission.File) (sub database.Submission, err error) {
	var none database.Submission
	plain, err := submission.Encode(data)
	if err != nil {
		return none, fmt.Errorf("sérialisation: %w", err)
	}
	payload, err := a.SubmissionCrypto.Encrypt(plain)
	if err != nil {
		return none, fmt.Errorf("chiffrement: %w", err)
	}
	params := database.CreateSubmissionParams{ID: uuid.New(), FormID: formID, Payload: payload}
	if a.Cfg.MaxFormStorageBytes > 0 {
		size := int64(len(payload))
		for _, f := range files {
			size += int64(len(f.Data))
		}
		if err := a.reserveStorage(ctx, formID, params.ID, size); err != nil {
			return none, err
		}
		defer func() { a.settleStorage(formID, params.ID, err == nil) }()
	}
	if len(files) == 0 {
		return a.Q.CreateSubmission(ctx, params)
	}

	// Encrypted before opening the transaction: it holds a connection only
	// for the duration of the writes.
	rows := make([]database.CreateAttachmentParams, len(files))
	for i, f := range files {
		name, err := a.AttachmentCrypto.Encrypt(f.Name)
		if err != nil {
			return none, fmt.Errorf("chiffrement: %w", err)
		}
		content, err := a.AttachmentCrypto.EncryptBytes(f.Data)
		if err != nil {
			return none, fmt.Errorf("chiffrement: %w", err)
		}
		rows[i] = database.CreateAttachmentParams{
			Position: int16(i), // #nosec G115 -- i < maxAttachments
			Filename: name, Size: int64(len(f.Data)), Content: content,
		}
	}

	tx, err := a.Pool.Begin(ctx)
	if err != nil {
		return none, fmt.Errorf("ouverture de la transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := a.Q.WithTx(tx)
	sub, err = q.CreateSubmission(ctx, params)
	if err != nil {
		return none, fmt.Errorf("soumission: %w", err)
	}
	for _, row := range rows {
		row.SubmissionID = sub.ID
		if err := q.CreateAttachment(ctx, row); err != nil {
			return none, fmt.Errorf("pièce jointe: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return none, fmt.Errorf("validation de la transaction: %w", err)
	}
	return sub, nil
}

func hasContent(data []submission.Field) bool {
	for _, f := range data {
		if f.Value != "" {
			return true
		}
	}
	return false
}

// wantsJSON tells a JavaScript call apart from a classic HTML form submission.
func wantsJSON(r *http.Request) bool {
	if strings.Contains(r.Header.Get("Accept"), "application/json") ||
		strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") ||
		r.Header.Get("X-Requested-With") != "" {
		return true
	}
	// A browser sends "navigate" for a form submission, and
	// "cors" / "same-origin" for a fetch call.
	if mode := r.Header.Get("Sec-Fetch-Mode"); mode != "" && mode != "navigate" {
		return true
	}
	return false
}

type submitResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func writeSubmitJSON(w http.ResponseWriter, status int, ok bool, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(submitResponse{Success: ok, Message: message})
}

func (a *App) submitOK(w http.ResponseWriter, r *http.Request, form database.GetFormByAccessKeyRow, meta submission.Meta) {
	if wantsJSON(r) {
		writeSubmitJSON(w, http.StatusOK, true, tr(r, "submit.ok"))
		return
	}
	// Order: redirect requested by the form (if it is on a domain
	// of the site), then the settings redirect, then the embedded page.
	if meta.Redirect != "" && submission.URLAllowed(form.SiteDomains, meta.Redirect) {
		http.Redirect(w, r, meta.Redirect, http.StatusSeeOther) // #nosec G710 -- http(s) URL restricted to the site's domains by URLAllowed
		return
	}
	if target := deref(form.RedirectUrl); target != "" {
		http.Redirect(w, r, target, http.StatusSeeOther) // #nosec G710 -- URL entered by the form owner, validated on save
		return
	}
	renderPage(w, r, ui.PublicResultPage(true, tr(r, "submit.page.ok_title"), tr(r, "submit.ok"), backLink(r)))
}

func (a *App) submitFail(w http.ResponseWriter, r *http.Request, status int, errKey string, args ...any) {
	if wantsJSON(r) {
		writeSubmitJSON(w, status, false, tr(r, errKey, args...))
		return
	}
	w.WriteHeader(status)
	renderPage(w, r, ui.PublicResultPage(false, tr(r, "submit.page.err_title"), tr(r, errKey, args...), backLink(r)))
}

// backLink takes the Referer for the "Back" link, only if it is an http(s) URL.
func backLink(r *http.Request) string {
	u, err := url.Parse(r.Referer())
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}
	return u.String()
}
