package main

// Integration tests for sending through Microsoft Graph, against a fake Microsoft (skipped without TEST_DATABASE_URL).

import (
	"net/http"
	"strings"
	"testing"

	"gitlab.com/detag_inno/naria/internal/email"
	"gitlab.com/detag_inno/naria/internal/email/graphtest"
	"gitlab.com/detag_inno/naria/internal/handlers"
)

// withGraph accepts files heavier than a Graph email can carry.
func withGraph(ms *graphtest.Server) func(*handlers.App) {
	return func(a *handlers.App) {
		a.Mailer = ms.Sender()
		a.MailAttachmentBytes = email.MaxAttachmentBytes(a.Mailer)
		a.Cfg.MaxAttachmentBytes = 4 << 20
	}
}

// A email-only form rejects the excess before reading it. A form that keeps submissions
// sends its email without the files and says so: no lost submission, no silent notification.
func TestGraphPiecesJointes(t *testing.T) {
	ms := graphtest.Start(t)
	e := setup(t, withGraph(ms))
	emailOnly := mustForm(t, e.q, e.fx.siteB, "Email seul", true, false)
	acceptAttachments(t, e, emailOnly)
	acceptAttachments(t, e, e.fx.formB)
	small := strings.Repeat("contenu-du-cv ", 50_000)
	big := strings.Repeat("x", email.GraphMaxAttachmentBytes+1)

	ct, body := multipartBody([]string{"name", "Ada"}, []string{"cv", "cv.pdf", small})
	if resp, out := submit(t, e.url, submitOpts{path: "/f/" + emailOnly.AccessKey, contentType: ct, body: body}); resp.StatusCode != http.StatusOK {
		t.Fatalf("email seul, fichier sous la limite : statut %d, corps %s", resp.StatusCode, out)
	}
	mails := ms.Mails()
	if len(mails) != 1 || len(mails[0].Attachments) != 1 || mails[0].Attachments[0].Name != "cv.pdf" || string(mails[0].Attachments[0].Data) != small {
		t.Fatalf("email seul, fichier sous la limite : l'email doit porter le fichier, entier")
	}

	ct, bigBody := multipartBody([]string{"name", "Ada"}, []string{"cv", "cv.pdf", big})
	resp, out := submit(t, e.url, submitOpts{path: "/f/" + emailOnly.AccessKey, contentType: ct, body: bigBody})
	if resp.StatusCode != http.StatusRequestEntityTooLarge || !strings.Contains(out, "2 Mo au maximum") {
		t.Errorf("email seul, fichier au-dessus : statut %d (413 attendu), corps %s", resp.StatusCode, out)
	}
	if n := ms.Calls(); n != 1 {
		t.Errorf("email seul, fichier au-dessus : %d appel(s) à Graph, 1 attendu (aucun pour l'envoi refusé)", n)
	}

	// Three megabytes exceed the Graph limit, whatever the rest of the message contains.
	ct, bigBody = multipartBody([]string{"name", "Ada"}, []string{"cv", "cv.pdf", strings.Repeat("x", 3<<20)})
	if resp, out := submit(t, e.url, submitOpts{path: "/f/" + e.fx.formB.AccessKey, contentType: ct, body: bigBody}); resp.StatusCode != http.StatusOK {
		t.Fatalf("formulaire conservé, fichier au-dessus : statut %d, corps %s", resp.StatusCode, out)
	}
	if n, files := countSubmissions(t, e, e.fx.formB), countAttachments(t, e); n != 1 || files != 1 {
		t.Errorf("formulaire conservé, fichier au-dessus : %d soumission(s), %d fichier(s) (1 et 1 attendus)", n, files)
	}
	mails = ms.Mails()
	if len(mails) != 2 {
		t.Fatalf("formulaire conservé, fichier au-dessus : %d email(s) reçu(s) par Graph, 2 attendus", len(mails))
	}
	notice := mails[1]
	if len(notice.Attachments) != 0 || !strings.Contains(notice.HTML, "ils se téléchargent depuis la soumission") {
		t.Errorf("formulaire conservé, fichier au-dessus : l'email doit partir sans le fichier et le dire")
	}
	if !strings.Contains(notice.HTML, "cv.pdf") || !strings.Contains(notice.HTML, "/submissions/") {
		t.Errorf("formulaire conservé, fichier au-dessus : l'email doit nommer le fichier et pointer vers la soumission")
	}

	ct, body = multipartBody([]string{"name", "Ada"}, []string{"cv", "cv.pdf", small})
	if resp, out := submit(t, e.url, submitOpts{path: "/f/" + e.fx.formB.AccessKey, contentType: ct, body: body}); resp.StatusCode != http.StatusOK {
		t.Fatalf("formulaire conservé, fichier sous la limite : statut %d, corps %s", resp.StatusCode, out)
	}
	if mails = ms.Mails(); len(mails) != 3 || len(mails[2].Attachments) != 1 || strings.Contains(mails[2].HTML, "ils se téléchargent") {
		t.Errorf("formulaire conservé, fichier sous la limite : l'email doit porter le fichier")
	}

	// Graph rejects the reduced email: the submission is kept along with its file.
	ms.RefuseSend(http.StatusForbidden, `{"error":{"code":"ErrorAccessDenied"}}`, "")
	ct, bigBody = multipartBody([]string{"name", "Ada"}, []string{"cv", "cv.pdf", strings.Repeat("x", 3<<20)})
	if resp, out := submit(t, e.url, submitOpts{path: "/f/" + e.fx.formB.AccessKey, contentType: ct, body: bigBody}); resp.StatusCode != http.StatusOK {
		t.Errorf("formulaire conservé, email allégé refusé : statut %d, corps %s", resp.StatusCode, out)
	}
	if n, files := countSubmissions(t, e, e.fx.formB), countAttachments(t, e); n != 3 || files != 3 {
		t.Errorf("formulaire conservé, email allégé refusé : %d soumission(s), %d fichier(s) (3 et 3 attendus)", n, files)
	}
	if n := len(ms.Mails()); n != 3 {
		t.Errorf("formulaire conservé, email allégé refusé : %d email(s) reçu(s) par Graph, 3 attendus", n)
	}
	ms.RefuseSend(0, "", "")

	c := newClient()
	login(t, c, e.url, e.fx.orgAdmin.Email)
	if _, page := get(t, c, e.url+"/forms/"+e.fx.formB.ID.String()+"/settings"); !strings.Contains(page, "Un email en porte 2 Mo au plus") {
		t.Errorf("réglages : la limite des fichiers par email n'est pas annoncée")
	}
	if _, page := get(t, c, e.url+"/forms/"+emailOnly.ID.String()); !strings.Contains(page, "5 fichiers et 2 Mo au plus") {
		t.Errorf("code d'intégration du formulaire en mode email seul : sa limite de 2 Mo n'est pas annoncée")
	}
	if _, page := get(t, c, e.url+"/forms/"+e.fx.formB.ID.String()); !strings.Contains(page, "5 fichiers et 4 Mo au plus") {
		t.Errorf("code d'intégration du formulaire conservé : la limite de l'instance n'est pas annoncée")
	}
}

func TestGraphLimiteParMicrosoft(t *testing.T) {
	ms := graphtest.Start(t)
	e := setup(t, withGraph(ms))
	emailOnly := mustForm(t, e.q, e.fx.siteB, "Email seul", true, false)
	ms.RefuseSend(http.StatusTooManyRequests, `{"error":{"code":"ApplicationThrottled"}}`, "300")

	for range 3 {
		if resp, _ := submit(t, e.url, submitOpts{path: "/f/" + emailOnly.AccessKey, body: "message=x"}); resp.StatusCode != http.StatusBadGateway {
			t.Errorf("email seul sous limitation : statut %d (502 attendu)", resp.StatusCode)
		}
	}
	if n := ms.Calls(); n != 1 {
		t.Errorf("%d appels à Graph sous limitation, 1 attendu", n)
	}
	if resp, out := submit(t, e.url, submitOpts{path: "/f/" + e.fx.formB.AccessKey, body: "message=x"}); resp.StatusCode != http.StatusOK {
		t.Errorf("formulaire conservé sous limitation : statut %d, corps %s", resp.StatusCode, out)
	}
	if n := countSubmissions(t, e, e.fx.formB); n != 1 {
		t.Errorf("formulaire conservé sous limitation : %d soumission(s) conservée(s), 1 attendue", n)
	}
}
