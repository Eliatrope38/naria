package main

// Integration tests for the reduced notification, used when the sender cannot carry the submission (skipped without TEST_DATABASE_URL).

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"gitlab.com/detag_inno/naria/internal/email"
	"gitlab.com/detag_inno/naria/internal/handlers"
)

// refuseFiles and refuseContent make a sender that cannot carry the files, or the
// content of a submission (detected by the word 'bonjour').
func refuseFiles(err error) func(email.Message) error {
	return func(m email.Message) error {
		if len(m.Attachments) > 0 {
			return fmt.Errorf("expéditeur: %w", err)
		}
		return nil
	}
}

func refuseContent(err error) func(email.Message) error {
	return func(m email.Message) error {
		if len(m.Attachments) > 0 || strings.Contains(m.HTML, "bonjour") {
			return fmt.Errorf("expéditeur: %w", err)
		}
		return nil
	}
}

func setRefuse(e testEnv, refuse func(email.Message) error) {
	e.mailer.mu.Lock()
	e.mailer.refuse, e.mailer.attempts = refuse, 0
	e.mailer.mu.Unlock()
}

func attempts(e testEnv) int {
	e.mailer.mu.Lock()
	defer e.mailer.mu.Unlock()
	return e.mailer.attempts
}

// A kept submission is always notified, even reduced: nothing is removed from what is kept.
func TestNotificationAllegeeQuandConservee(t *testing.T) {
	e := setup(t)
	acceptAttachments(t, e, e.fx.formB)
	path := "/f/" + e.fx.formB.AccessKey
	ct, withFile := multipartBody([]string{"message", "bonjour"}, []string{"cv", "cv.pdf", "contenu-du-cv"})

	for _, cause := range []error{email.ErrTooLarge, email.ErrVolume} {
		setRefuse(e, refuseFiles(cause))
		before := len(e.mailer.messages(t, 0))
		if resp, out := submit(t, e.url, submitOpts{path: path, contentType: ct, body: withFile}); resp.StatusCode != http.StatusOK {
			t.Fatalf("fichiers non portés (%v) : statut %d, corps %s", cause, resp.StatusCode, out)
		}
		m := e.mailer.messages(t, before+1)[before]
		if len(m.Attachments) != 0 || !strings.Contains(m.HTML, "ils se téléchargent depuis la soumission") {
			t.Errorf("fichiers non portés (%v) : l'email doit partir sans eux et le dire", cause)
		}
		if !strings.Contains(m.HTML, "bonjour") || !strings.Contains(m.HTML, "cv.pdf") || !strings.Contains(m.HTML, "/submissions/") {
			t.Errorf("fichiers non portés (%v) : l'email garde le contenu, le nom du fichier et le lien", cause)
		}
		if n := attempts(e); n != 2 {
			t.Errorf("fichiers non portés (%v) : %d envois tentés, 2 attendus", cause, n)
		}
	}

	setRefuse(e, refuseContent(email.ErrVolume))
	before := len(e.mailer.messages(t, 0))
	if resp, out := submit(t, e.url, submitOpts{path: path, contentType: ct, body: withFile}); resp.StatusCode != http.StatusOK {
		t.Fatalf("contenu non porté : statut %d, corps %s", resp.StatusCode, out)
	}
	m := e.mailer.messages(t, before+1)[before]
	if len(m.Attachments) != 0 || strings.Contains(m.HTML, "bonjour") || strings.Contains(m.HTML, "cv.pdf") {
		t.Errorf("contenu non porté : l'email ne doit plus porter ni fichier ni contenu")
	}
	if !strings.Contains(m.HTML, "consultez-le dans l") || !strings.Contains(m.HTML, "/submissions/") || m.ReplyTo != "" {
		t.Errorf("contenu non porté : l'email doit renvoyer à l'interface, sans adresse de réponse")
	}
	if n := attempts(e); n != 3 {
		t.Errorf("contenu non porté : %d envois tentés, 3 attendus", n)
	}

	// Without files, the notification is sent in the background and reduced the same way.
	setRefuse(e, refuseContent(email.ErrTooLarge))
	before = len(e.mailer.messages(t, 0))
	if resp, out := submit(t, e.url, submitOpts{path: path, body: "message=bonjour"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("contenu non porté, sans fichier : statut %d, corps %s", resp.StatusCode, out)
	}
	if m := e.mailer.messages(t, before+1)[before]; strings.Contains(m.HTML, "bonjour") || !strings.Contains(m.HTML, "/submissions/") {
		t.Errorf("contenu non porté, sans fichier : l'email doit renvoyer à l'interface sans le contenu")
	}

	// A failure unrelated to size reduces nothing: the submission is kept and the visitor
	// is not affected.
	setRefuse(e, func(m email.Message) error {
		if len(m.Attachments) > 0 {
			return email.ErrTooLarge
		}
		return errors.New("expéditeur en panne")
	})
	before = len(e.mailer.messages(t, 0))
	if resp, out := submit(t, e.url, submitOpts{path: path, contentType: ct, body: withFile}); resp.StatusCode != http.StatusOK {
		t.Errorf("expéditeur en panne après l'allègement : statut %d, corps %s", resp.StatusCode, out)
	}
	if n, sent := attempts(e), len(e.mailer.messages(t, 0)); n != 2 || sent != before {
		t.Errorf("expéditeur en panne après l'allègement : %d envois tentés, %d email(s) de plus (2 et 0 attendus)", n, sent-before)
	}
	if n, files := countSubmissions(t, e, e.fx.formB), countAttachments(t, e); n != 5 || files != 4 {
		t.Errorf("%d soumission(s) et %d fichier(s) conservés (5 et 4 attendus)", n, files)
	}
}

// A submission that is not kept is never reduced: the email is its only trace.
// The visitor is refused and learns whether retrying may help.
func TestNotificationJamaisAllegeeSansConservation(t *testing.T) {
	check := func(t *testing.T, e testEnv, path string) {
		t.Helper()
		ct, withFile := multipartBody([]string{"message", "bonjour"}, []string{"cv", "cv.pdf", "contenu-du-cv"})
		before := len(e.mailer.messages(t, 0))
		for _, tc := range []struct {
			cause  error
			status int
			text   string
		}{
			{email.ErrTooLarge, http.StatusRequestEntityTooLarge, "trop volumineux"},
			{email.ErrVolume, http.StatusBadGateway, "Réessayez dans un instant"},
		} {
			setRefuse(e, refuseFiles(tc.cause))
			resp, out := submit(t, e.url, submitOpts{path: path, contentType: ct, body: withFile})
			if resp.StatusCode != tc.status || !strings.Contains(out, tc.text) {
				t.Errorf("%v : statut %d (%d attendu), corps %s", tc.cause, resp.StatusCode, tc.status, out)
			}
			if n := attempts(e); n != 1 {
				t.Errorf("%v : %d envois tentés, 1 attendu (aucun email allégé)", tc.cause, n)
			}
		}
		if sent := len(e.mailer.messages(t, 0)); sent != before {
			t.Errorf("%d email(s) parti(s) malgré les refus", sent-before)
		}
	}

	t.Run("mode email seul", func(t *testing.T) {
		e := setup(t)
		form := mustForm(t, e.q, e.fx.siteB, "Email seul", true, false)
		acceptAttachments(t, e, form)
		check(t, e, "/f/"+form.AccessKey)
	})
	t.Run("formulaire plein", func(t *testing.T) {
		e, app := quotaEnv(t)
		acceptAttachments(t, e, e.fx.formB)
		fillToQuota(t, e, app, e.fx.formB, quotaBody)
		// The first submission on the full form sends the quota alert, which is not sent again:
		// two regular notifications, this one, then the alert to the owner and the recipients.
		if resp, out := submit(t, e.url, submitOpts{path: "/f/" + e.fx.formB.AccessKey, body: quotaBody}); resp.StatusCode != http.StatusOK {
			t.Fatalf("formulaire plein, sans fichier : statut %d, corps %s", resp.StatusCode, out)
		}
		e.mailer.messages(t, 5)
		check(t, e, "/f/"+e.fx.formB.AccessKey)
		if n := countSubmissions(t, e, e.fx.formB); n != 2 {
			t.Errorf("%d soumission(s) conservée(s), 2 attendues", n)
		}
	})
}

// An email-only form is capped at what the sender can carry.
func TestPlafondDeFichiersSelonLExpediteur(t *testing.T) {
	for _, tc := range []struct {
		name            string
		instance, email int64
		emailOnly       bool
		accepted        int
		refused         int
	}{
		{"expéditeur sans borne", 64 << 10, 0, true, 60 << 10, 70 << 10},
		{"expéditeur plus strict, email seul", 64 << 10, 16 << 10, true, 15 << 10, 20 << 10},
		{"expéditeur plus strict, conservé", 64 << 10, 16 << 10, false, 60 << 10, 70 << 10},
		{"instance plus stricte, email seul", 16 << 10, 64 << 10, true, 15 << 10, 20 << 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := setup(t, func(a *handlers.App) {
				a.Cfg.MaxAttachmentBytes, a.MailAttachmentBytes = tc.instance, tc.email
			})
			form := e.fx.formB
			if tc.emailOnly {
				form = mustForm(t, e.q, e.fx.siteB, "Email seul", true, false)
			}
			acceptAttachments(t, e, form)
			for size, want := range map[int]int{tc.accepted: http.StatusOK, tc.refused: http.StatusRequestEntityTooLarge} {
				ct, body := multipartBody([]string{"message", "bonjour"}, []string{"f", "f.bin", strings.Repeat("x", size)})
				if resp, out := submit(t, e.url, submitOpts{path: "/f/" + form.AccessKey, contentType: ct, body: body}); resp.StatusCode != want {
					t.Errorf("fichier de %d octets : statut %d (%d attendu), corps %s", size, resp.StatusCode, want, out)
				}
			}
		})
	}
}
