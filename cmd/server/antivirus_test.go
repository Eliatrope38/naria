package main

// Integration tests for the antivirus against a fake clamd, skipped without TEST_DATABASE_URL.

import (
	"net/http"
	"strings"
	"testing"

	"gitlab.com/detag_inno/naria/internal/antivirus"
	"gitlab.com/detag_inno/naria/internal/antivirus/clamdtest"
	"gitlab.com/detag_inno/naria/internal/handlers"
)

func withAntivirus(srv *clamdtest.Server) func(*handlers.App) {
	return func(a *handlers.App) { a.Antivirus = antivirus.New(srv.Addr) }
}

// An infected file rejects the whole submission: nothing is kept or sent by email.
func TestAntivirusRefuseUnFichierInfecte(t *testing.T) {
	clamd := clamdtest.Start(t)
	e := setup(t, withAntivirus(clamd))
	acceptAttachments(t, e, e.fx.formB)
	path := "/f/" + e.fx.formB.AccessKey

	const clean = "contenu-du-cv"
	ct, body := multipartBody([]string{"name", "Ada"}, []string{"cv", "cv.pdf", clean}, []string{"notes", "notes.txt", "deuxième fichier"})
	if resp, out := submit(t, e.url, submitOpts{path: path, contentType: ct, body: body}); resp.StatusCode != http.StatusOK {
		t.Fatalf("fichiers sains : statut %d, corps %s", resp.StatusCode, out)
	}
	if got := clamd.Streams(); len(got) != 2 || string(got[0]) != clean || string(got[1]) != "deuxième fichier" {
		t.Errorf("l'antivirus doit recevoir chaque fichier, entier : %d flux reçus", len(got))
	}
	if n, files := countSubmissions(t, e, e.fx.formB), countAttachments(t, e); n != 1 || files != 2 {
		t.Fatalf("fichiers sains : %d soumission(s), %d fichier(s) (1 et 2 attendus)", n, files)
	}
	e.mailer.messages(t, 1)

	// The infected file comes second: the clean one first must not save the submission.
	infected := "début " + clamdtest.Marker + " fin"
	ct, body = multipartBody([]string{"name", "Mallory"}, []string{"cv", "cv.pdf", clean}, []string{"facture", "facture.pdf", infected})
	for _, html := range []bool{false, true} {
		resp, out := submit(t, e.url, submitOpts{path: path, contentType: ct, body: body, html: html})
		if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(out, "Renvoyez-le sans ce fichier") {
			t.Errorf("fichier infecté (html=%v) : statut %d, corps %.200s", html, resp.StatusCode, out)
		}
		// Neither the signature nor the file name is returned to the visitor.
		if strings.Contains(out, clamdtest.Signature) || strings.Contains(out, "facture.pdf") {
			t.Errorf("fichier infecté (html=%v) : la réponse nomme la signature ou le fichier", html)
		}
	}
	if n, files := countSubmissions(t, e, e.fx.formB), countAttachments(t, e); n != 1 || files != 2 {
		t.Errorf("fichier infecté : %d soumission(s), %d fichier(s) en base (rien ne doit s'ajouter)", n, files)
	}
	if sent := e.mailer.messages(t, 1); len(sent) != 1 {
		t.Errorf("fichier infecté : %d email(s) envoyé(s) (1 attendu, celui de l'envoi sain)", len(sent))
	}

	// A submission without a file does not go through the antivirus.
	before := len(clamd.Streams())
	if resp, out := submit(t, e.url, submitOpts{path: path, body: "name=Ada&message=" + clamdtest.Marker}); resp.StatusCode != http.StatusOK {
		t.Errorf("envoi sans fichier : statut %d, corps %s", resp.StatusCode, out)
	}
	if got := len(clamd.Streams()); got != before {
		t.Errorf("envoi sans fichier : %d flux envoyé(s) à l'antivirus", got-before)
	}
}

// Files sent to a form that does not accept them are ignored: they are neither read
// nor sent to the antivirus, infected or not.
func TestAntivirusNeVoitPasLesFichiersIgnores(t *testing.T) {
	clamd := clamdtest.Start(t)
	e := setup(t, withAntivirus(clamd))
	ct, body := multipartBody([]string{"name", "Ada"}, []string{"cv", "cv.pdf", clamdtest.Marker})
	if resp, out := submit(t, e.url, submitOpts{path: "/f/" + e.fx.formB.AccessKey, contentType: ct, body: body}); resp.StatusCode != http.StatusOK {
		t.Fatalf("statut %d, corps %s", resp.StatusCode, out)
	}
	if got := clamd.Streams(); len(got) != 0 {
		t.Errorf("%d flux envoyé(s) à l'antivirus pour un formulaire sans pièces jointes", len(got))
	}
	if n := countAttachments(t, e); n != 0 {
		t.Errorf("%d fichier(s) conservé(s)", n)
	}
}

func TestAntivirusIgnoreLeChampPiege(t *testing.T) {
	clamd := clamdtest.Start(t)
	e := setup(t, withAntivirus(clamd))
	acceptAttachments(t, e, e.fx.formB)
	ct, body := multipartBody([]string{"botcheck", "on"}, []string{"cv", "cv.pdf", clamdtest.Marker})
	if resp, out := submit(t, e.url, submitOpts{path: "/f/" + e.fx.formB.AccessKey, contentType: ct, body: body}); resp.StatusCode != http.StatusOK {
		t.Errorf("statut %d, corps %s", resp.StatusCode, out)
	}
	if got := clamd.Streams(); len(got) != 0 {
		t.Errorf("%d flux envoyé(s) à l'antivirus pour un envoi de robot", len(got))
	}
}

// A file that was not scanned is rejected, even in email-only mode. Submissions without files are unaffected.
func TestAntivirusInjoignable(t *testing.T) {
	clamd := clamdtest.Start(t)
	e := setup(t, withAntivirus(clamd))
	clamd.Stop()
	emailOnly := mustForm(t, e.q, e.fx.siteB, "Email seul", true, false)
	acceptAttachments(t, e, e.fx.formB)
	acceptAttachments(t, e, emailOnly)

	ct, body := multipartBody([]string{"name", "Ada"}, []string{"cv", "cv.pdf", "contenu-du-cv"})
	for _, form := range []string{e.fx.formB.AccessKey, emailOnly.AccessKey} {
		resp, out := submit(t, e.url, submitOpts{path: "/f/" + form, contentType: ct, body: body})
		if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(out, `"success":false`) {
			t.Errorf("antivirus injoignable : statut %d, corps %s (503 attendu)", resp.StatusCode, out)
		}
		if resp.Header.Get("Retry-After") == "" {
			t.Errorf("antivirus injoignable : la réponse doit dire quand réessayer")
		}
	}
	if n, files := countSubmissions(t, e, e.fx.formB), countAttachments(t, e); n != 0 || files != 0 {
		t.Errorf("antivirus injoignable : %d soumission(s), %d fichier(s) conservé(s)", n, files)
	}
	if resp, out := submit(t, e.url, submitOpts{path: "/f/" + e.fx.formB.AccessKey, body: "name=Ada"}); resp.StatusCode != http.StatusOK {
		t.Errorf("envoi sans fichier, antivirus injoignable : statut %d, corps %s", resp.StatusCode, out)
	}
	if sent := e.mailer.messages(t, 1); len(sent) != 1 || len(sent[0].Attachments) != 0 {
		t.Errorf("seul l'envoi sans fichier doit être notifié : %d email(s)", len(sent))
	}
}

// In email-only mode nothing keeps the submission in the database: scanning is the only
// safeguard before the email carrying the file is sent.
func TestAntivirusInfecteEnEmailSeul(t *testing.T) {
	clamd := clamdtest.Start(t)
	e := setup(t, withAntivirus(clamd))
	emailOnly := mustForm(t, e.q, e.fx.siteB, "Email seul", true, false)
	acceptAttachments(t, e, emailOnly)
	ct, body := multipartBody([]string{"name", "Mallory"}, []string{"facture", "facture.pdf", clamdtest.Marker})
	if resp, out := submit(t, e.url, submitOpts{path: "/f/" + emailOnly.AccessKey, contentType: ct, body: body}); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("statut %d, corps %s (422 attendu)", resp.StatusCode, out)
	}
	// In this mode the email is sent before the response, so if it had gone out it would be there.
	e.mailer.mu.Lock()
	sent := len(e.mailer.sent)
	e.mailer.mu.Unlock()
	if sent != 0 {
		t.Errorf("%d email(s) envoyé(s) pour une soumission refusée", sent)
	}
}

// A file that clamd refuses to scan, too large for its StreamMaxLength,
// is not treated as clean.
func TestAntivirusFluxRefuse(t *testing.T) {
	clamd := clamdtest.Start(t)
	clamd.LimitStream(1000)
	e := setup(t, withAntivirus(clamd))
	acceptAttachments(t, e, e.fx.formB)
	ct, body := multipartBody([]string{"name", "Ada"}, []string{"cv", "cv.pdf", strings.Repeat("x", 5000)})
	if resp, out := submit(t, e.url, submitOpts{path: "/f/" + e.fx.formB.AccessKey, contentType: ct, body: body}); resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("statut %d, corps %s (503 attendu)", resp.StatusCode, out)
	}
	if n, files := countSubmissions(t, e, e.fx.formB), countAttachments(t, e); n != 0 || files != 0 {
		t.Errorf("%d soumission(s), %d fichier(s) conservé(s)", n, files)
	}
}

func TestReglagesAnnoncentLAntivirus(t *testing.T) {
	for _, tc := range []struct {
		what    string
		scanned bool
		want    string
		absent  string
	}{
		{"avec antivirus", true, "L&#39;antivirus de l&#39;instance les examine", "Aucun antivirus"},
		{"sans antivirus", false, "Aucun antivirus ne les examine", "L&#39;antivirus de l&#39;instance"},
	} {
		var opts []func(*handlers.App)
		if tc.scanned {
			opts = append(opts, withAntivirus(clamdtest.Start(t)))
		}
		e := setup(t, opts...)
		c := newClient()
		login(t, c, e.url, e.fx.memberA.Email)
		_, page := get(t, c, e.url+"/forms/"+e.fx.formA.ID.String()+"/settings")
		if !strings.Contains(page, tc.want) || strings.Contains(page, tc.absent) {
			t.Errorf("%s : la page de réglages n'annonce pas le bon état", tc.what)
		}
	}
}
