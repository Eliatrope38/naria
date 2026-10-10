package handlers

import (
	"log"
	"mime"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/justinas/nosurf"

	"gitlab.com/detag_inno/naria/internal/database"
	"gitlab.com/detag_inno/naria/internal/submission"
	"gitlab.com/detag_inno/naria/internal/web"
	"gitlab.com/detag_inno/naria/ui"
)

const submissionsPerPage = 25

// decodeSubmission decrypts a submission. If unreadable (key changed, data altered),
// it returns ok=false: the page shows it as such instead of failing.
func (a *App) decodeSubmission(sub database.Submission) ([]submission.Field, bool) {
	plain, err := a.SubmissionCrypto.Decrypt(sub.Payload)
	if err != nil {
		log.Printf("ERROR soumission illisible id=%s: %v", sub.ID, err)
		return nil, false
	}
	fields, err := submission.Decode(plain)
	if err != nil {
		log.Printf("ERROR soumission illisible id=%s: %v", sub.ID, err)
		return nil, false
	}
	return fields, true
}

func (a *App) FormSubmissions(w http.ResponseWriter, r *http.Request) {
	form, ok := a.formFor(w, r)
	if !ok {
		return
	}
	total, err := a.Q.CountSubmissionsByForm(r.Context(), form.ID)
	if err != nil {
		http.Error(w, tr(r, "common.err.load"), http.StatusInternalServerError)
		return
	}
	path := "/forms/" + form.ID.String()
	pg, offset := paginate(path, "", pageParam(r), submissionsPerPage, total)
	list, err := a.Q.ListSubmissionsByForm(r.Context(), database.ListSubmissionsByFormParams{
		FormID: form.ID, PageLimit: submissionsPerPage, PageOffset: offset,
	})
	if err != nil {
		http.Error(w, tr(r, "common.err.load"), http.StatusInternalServerError)
		return
	}
	rows := make([]ui.SubmissionRowVM, 0, len(list))
	for _, sub := range list {
		fields, readable := a.decodeSubmission(sub)
		rows = append(rows, ui.SubmissionRowVM{
			ID: sub.ID.String(), CreatedAt: sub.CreatedAt, Unread: !sub.ReadAt.Valid,
			Fields: fields, Unreadable: !readable,
		})
	}
	hasAttachments, err := a.Q.FormHasAttachments(r.Context(), form.ID)
	if err != nil {
		http.Error(w, tr(r, "common.err.load"), http.StatusInternalServerError)
		return
	}
	var used int64
	notice := ""
	if limit := a.Cfg.MaxFormStorageBytes; limit > 0 && form.StoreSubmissions {
		if used, err = a.storageUsed(r.Context(), form.ID); err != nil {
			http.Error(w, tr(r, "common.err.load"), http.StatusInternalServerError)
			return
		}
		switch {
		case used < limit:
		case a.emailCarries(form.NotifyEmail, form.EmailIncludeContent, form.Recipients):
			notice = tr(r, "form.storage.full_email")
		default:
			notice = tr(r, "form.storage.full_refused")
		}
	}
	// The embed code states the real limit: the instance's, or the email's if nothing is stored.
	files := a.fileLimits()
	files.MaxMB = a.attachmentLimit(form.StoreSubmissions) >> 20
	renderPage(w, r, ui.FormPage(ui.FormVM{
		User: web.UserFrom(r.Context()), Form: form,
		Rows: rows, Total: total, Pg: pg, HasAttachments: hasAttachments,
		StorageUsed: used, StorageMax: a.Cfg.MaxFormStorageBytes, StorageNotice: notice,
		CaptchaUnsolved: a.captchaUnsolvedCount(form.ID),
		Endpoint:        a.submitURL(), MailEnabled: a.Mailer != nil, Files: files,
		CSRF: nosurf.Token(r), Flash: web.PopFlash(a.Sessions, r),
	}))
}

// submissionFor loads the submission "{id}" within the user's scope, for reading.
func (a *App) submissionFor(w http.ResponseWriter, r *http.Request) (database.GetSubmissionScopedRow, bool) {
	u := web.UserFrom(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, tr(r, "submission.err.not_found"), http.StatusNotFound)
		return database.GetSubmissionScopedRow{}, false
	}
	sc := scopeOf(u)
	sub, err := a.Q.GetSubmissionScoped(r.Context(), database.GetSubmissionScopedParams{ID: id, ViewerID: sc.viewerID, AdminOrgID: sc.adminOrgID})
	if err != nil {
		http.Error(w, tr(r, "submission.err.not_found"), http.StatusNotFound)
		return database.GetSubmissionScopedRow{}, false
	}
	return sub, true
}

func (a *App) SubmissionDetail(w http.ResponseWriter, r *http.Request) {
	sub, ok := a.submissionFor(w, r)
	if !ok {
		return
	}
	fields, readable := a.decodeSubmission(database.Submission{ID: sub.ID, Payload: sub.Payload})
	var attachments []ui.AttachmentVM
	if readable {
		list, err := a.Q.ListAttachmentsBySubmission(r.Context(), sub.ID)
		if err != nil {
			http.Error(w, tr(r, "common.err.load"), http.StatusInternalServerError)
			return
		}
		for _, att := range list {
			name, err := a.AttachmentCrypto.Decrypt(att.Filename)
			if err != nil {
				log.Printf("ERROR pièce jointe illisible id=%s: %v", att.ID, err)
				name = tr(r, "submission.unreadable")
			}
			attachments = append(attachments, ui.AttachmentVM{ID: att.ID.String(), Name: name, Size: att.Size})
		}
	}
	// A reader does not mark submissions read: that changes the owner's list.
	if sub.CanWrite {
		sc := scopeOf(web.UserFrom(r.Context()))
		if _, err := a.Q.MarkSubmissionReadScoped(r.Context(), database.MarkSubmissionReadScopedParams{
			ID: sub.ID, ViewerID: sc.viewerID, AdminOrgID: sc.adminOrgID,
		}); err != nil {
			log.Printf("ERROR soumission: marquage lu id=%s: %v", sub.ID, err)
		}
	}
	renderPage(w, r, ui.SubmissionPage(ui.SubmissionVM{
		User: web.UserFrom(r.Context()), Sub: sub,
		Fields: fields, Attachments: attachments, Unreadable: !readable, CSRF: nosurf.Token(r),
	}))
}

// DownloadAttachment serves an attachment within the user's scope. The
// file comes from an anonymous visitor: it is offered for download, never
// displayed, and without a type a browser could interpret.
func (a *App) DownloadAttachment(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, tr(r, "submission.err.attachment_not_found"), http.StatusNotFound)
		return
	}
	sc := scopeOf(web.UserFrom(r.Context()))
	att, err := a.Q.GetAttachmentScoped(r.Context(), database.GetAttachmentScopedParams{ID: id, ViewerID: sc.viewerID, AdminOrgID: sc.adminOrgID})
	if err != nil {
		http.Error(w, tr(r, "submission.err.attachment_not_found"), http.StatusNotFound)
		return
	}
	name, err := a.AttachmentCrypto.Decrypt(att.Filename)
	var data []byte
	if err == nil {
		data, err = a.AttachmentCrypto.DecryptBytes(att.Content)
	}
	if err != nil {
		log.Printf("ERROR pièce jointe illisible id=%s: %v", id, err) // #nosec G706 -- id is a parsed UUID, the error comes from decryption
		http.Error(w, tr(r, "submission.err.attachment_unreadable"), http.StatusInternalServerError)
		return
	}
	if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(transferTimeout)); err != nil {
		log.Printf("ERROR pièce jointe: délai de téléchargement non prolongé: %v", err)
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Header().Set("Cache-Control", "no-store")
	// nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter -- served as application/octet-stream with Content-Disposition: attachment, never rendered
	_, _ = w.Write(data)
}

func (a *App) DeleteSubmission(w http.ResponseWriter, r *http.Request) {
	u := web.UserFrom(r.Context())
	sub, ok := a.submissionFor(w, r)
	if !ok {
		return
	}
	if !sub.CanWrite {
		http.Error(w, tr(r, "submission.err.not_found"), http.StatusNotFound)
		return
	}
	sc := scopeOf(u)
	n, err := a.Q.DeleteSubmissionScoped(r.Context(), database.DeleteSubmissionScopedParams{ID: sub.ID, ViewerID: sc.viewerID, AdminOrgID: sc.adminOrgID})
	if err != nil || n == 0 {
		http.Error(w, tr(r, "common.err.update"), http.StatusInternalServerError)
		return
	}
	a.forgetStorage(sub.FormID)
	web.Flash(a.Sessions, r, tr(r, "submission.flash.deleted"))
	http.Redirect(w, r, "/forms/"+sub.FormID.String(), http.StatusSeeOther)
}

func (a *App) MarkAllRead(w http.ResponseWriter, r *http.Request) {
	form, ok := a.writableFormFor(w, r)
	if !ok {
		return
	}
	sc := scopeOf(web.UserFrom(r.Context()))
	if _, err := a.Q.MarkFormSubmissionsReadScoped(r.Context(), database.MarkFormSubmissionsReadScopedParams{
		FormID: form.ID, ViewerID: sc.viewerID, AdminOrgID: sc.adminOrgID,
	}); err != nil {
		http.Error(w, tr(r, "common.err.update"), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/forms/"+form.ID.String(), http.StatusSeeOther)
}

func (a *App) PurgeFormSubmissions(w http.ResponseWriter, r *http.Request) {
	u := web.UserFrom(r.Context())
	form, ok := a.writableFormFor(w, r)
	if !ok {
		return
	}
	sc := scopeOf(u)
	n, err := a.Q.DeleteSubmissionsByFormScoped(r.Context(), database.DeleteSubmissionsByFormScopedParams{
		FormID: form.ID, ViewerID: sc.viewerID, AdminOrgID: sc.adminOrgID,
	})
	if err != nil {
		http.Error(w, tr(r, "common.err.update"), http.StatusInternalServerError)
		return
	}
	a.forgetStorage(form.ID)
	a.audit(r.Context(), auditEntry{
		ActorID:  refUUID(u.ID),
		Action:   auditSubmissionsPurged,
		Entity:   auditEntityForm,
		EntityID: refUUID(form.ID),
		Meta:     map[string]string{"name": form.Name, "ip": web.ClientIP(r)},
	})
	web.Flash(a.Sessions, r, tr(r, "submission.flash.purged", n))
	http.Redirect(w, r, "/forms/"+form.ID.String()+"/settings", http.StatusSeeOther)
}
