package email_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"gitlab.com/detag_inno/naria/internal/email"
	"gitlab.com/detag_inno/naria/internal/email/graphtest"
)

func ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return c
}

func plain() email.Message {
	return email.Message{To: []string{"dest@exemple.fr"}, Subject: "Contact", HTML: "<p>bonjour</p>"}
}

// withFile returns a heavy message, which counts among the heavy requests.
func withFile() email.Message {
	m := plain()
	m.Attachments = []email.Attachment{{Name: "a.bin", Data: make([]byte, 100_000)}}
	return m
}

// Microsoft responses as it writes them: their text names the mailbox, a recipient or the application.
const (
	accessDenied  = `{"error":{"code":"ErrorAccessDenied","message":"Access is denied for mailbox formulaires@exemple.fr while sending to dest@exemple.fr."}}`
	throttledBody = `{"error":{"code":"ApplicationThrottled","message":"Application is over its MailboxConcurrency limit for formulaires@exemple.fr."}}`
	invalidClient = `{"error":"invalid_client","error_description":"AADSTS7000222: The provided client secret keys for app '66666666-7777-8888-9999-000000000000' are expired.","error_codes":[7000222]}`
)

// leaks looks for what an error must never quote: it ends up in the logs.
func leaks(t *testing.T, err error) {
	t.Helper()
	for _, secret := range []string{
		graphtest.Secret, "jeton-", graphtest.Mailbox, "dest@exemple.fr", graphtest.Tenant,
		"Access is denied", "client secret", "https://", "/oauth2/", "/sendMail",
	} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("l'erreur cite %q : %v", secret, err)
		}
	}
}

// No copy in sent items: a submission in email-only mode must not remain anywhere.
func TestGraphSend(t *testing.T) {
	ms := graphtest.Start(t)
	g := ms.Sender()
	html := `<p>Une "citation" & <b>du gras</b></p>` + strings.Repeat("é", 2000)
	msg := email.Message{To: []string{"a@exemple.fr", "b@exemple.fr"}, Subject: "Devis été 2026", HTML: html}
	if err := g.Send(ctx(t), msg); err != nil {
		t.Fatalf("Send: %v", err)
	}
	mails := ms.Mails()
	if len(mails) != 1 {
		t.Fatalf("%d message(s) reçu(s), 1 attendu", len(mails))
	}
	got := mails[0]
	if strings.Join(got.To, ",") != "a@exemple.fr,b@exemple.fr" || got.Subject != "Devis été 2026" || got.HTML != html {
		t.Errorf("message reçu : destinataires %v, sujet %q, HTML identique=%v", got.To, got.Subject, got.HTML == html)
	}
	if len(got.ReplyTo) != 0 || len(got.Attachments) != 0 {
		t.Errorf("adresse de réponse %v et %d pièce(s) jointe(s) : aucune attendue", got.ReplyTo, len(got.Attachments))
	}
	if got.Saved {
		t.Error("le message serait gardé dans les éléments envoyés de la boîte")
	}
	if ms.Tokens() != 1 || ms.Calls() != 1 {
		t.Errorf("%d jeton(s) et %d appel(s) pour un email, 1 et 1 attendus", ms.Tokens(), ms.Calls())
	}
}

// The subject and the reply address come from a visitor.
func TestGraphSendReplyToAndSubject(t *testing.T) {
	ms := graphtest.Start(t)
	msg := plain()
	msg.ReplyTo = "visiteur@exemple.org"
	msg.Subject = "Contact\r\nBcc: attaquant@evil.tld " + strings.Repeat("é", 300)
	if err := ms.Sender().Send(ctx(t), msg); err != nil {
		t.Fatalf("Send: %v", err)
	}
	got := ms.Mails()[0]
	if len(got.ReplyTo) != 1 || got.ReplyTo[0] != "visiteur@exemple.org" {
		t.Errorf("adresse de réponse %v", got.ReplyTo)
	}
	if strings.ContainsAny(got.Subject, "\r\n") {
		t.Errorf("le sujet garde un saut de ligne : %q", got.Subject)
	}
	if n := len([]rune(got.Subject)); n != 255 || !strings.HasSuffix(got.Subject, "é") {
		t.Errorf("sujet de %d caractères, 255 attendus, coupé entre deux caractères", n)
	}
}

// The type announced by the visitor is not reused. An empty file stays a file.
func TestGraphSendAttachments(t *testing.T) {
	ms := graphtest.Start(t)
	files := []email.Attachment{
		{Name: "devis été 2026.pdf", Data: bytes.Repeat([]byte{0x00, 0xff, '\r', '\n', 0x80}, 200_000)},
		{Name: `a".txt`, Data: []byte("x")},
		{Name: "vide.txt"},
		{Name: "reste.bin", Data: bytes.Repeat([]byte{7}, email.GraphMaxAttachmentBytes-1_000_001)},
	}
	msg := plain()
	msg.Attachments = files
	if err := ms.Sender().Send(ctx(t), msg); err != nil {
		t.Fatalf("Send: %v", err)
	}
	got := ms.Mails()[0]
	if len(got.Attachments) != len(files) {
		t.Fatalf("%d pièce(s) jointe(s) reçue(s), %d attendues", len(got.Attachments), len(files))
	}
	for i, want := range files {
		a := got.Attachments[i]
		if a.Name != want.Name || a.ContentType != "application/octet-stream" || !bytes.Equal(a.Data, want.Data) {
			t.Errorf("%q : reçue sous %q, type %q, %d octet(s) pour %d", want.Name, a.Name, a.ContentType, len(a.Data), len(want.Data))
		}
	}
	if got.Saved {
		t.Error("le message serait gardé dans les éléments envoyés de la boîte")
	}
}

// Nothing goes beyond the limit: neither a truncated message nor a message without its attachments.
// The caller recognizes the case and decides.
func TestGraphSendTooLarge(t *testing.T) {
	ms := graphtest.Start(t)
	g := ms.Sender()
	file := func(size int) email.Attachment { return email.Attachment{Name: "f.bin", Data: make([]byte, size)} }
	for _, tc := range []struct {
		name  string
		html  string
		files []email.Attachment
	}{
		{name: "un fichier", files: []email.Attachment{file(3 << 20)}},
		{name: "plusieurs", files: []email.Attachment{file(1 << 20), file(1 << 20), file(1 << 20)}},
		{name: "dix méga-octets", files: []email.Attachment{file(10 << 20)}},
		{name: "juste au-dessus", files: []email.Attachment{file(email.GraphMaxRequest / 4 * 3)}},
		// 200,000 quote characters become 400,000 once in JSON: the overflow only shows after encoding.
		{name: "fichiers à la limite et long texte", html: strings.Repeat(`"`, 200_000), files: []email.Attachment{file(email.GraphMaxAttachmentBytes)}},
		{name: "texte seul", html: strings.Repeat("x", email.GraphMaxRequest)},
	} {
		msg := plain()
		msg.Attachments = tc.files
		if tc.html != "" {
			msg.HTML = tc.html
		}
		if err := g.Send(ctx(t), msg); !errors.Is(err, email.ErrTooLarge) {
			t.Errorf("%s : erreur %v (ErrTooLarge attendue)", tc.name, err)
		}
	}
	if ms.Calls() != 0 || ms.TokenCalls() != 0 {
		t.Errorf("%d appel(s) à Graph, %d demande(s) de jeton : rien ne devait partir", ms.Calls(), ms.TokenCalls())
	}

	// The announced limit fits a send with 240 KB of HTML, loaded with characters that
	// encoding/json would write on six bytes if it escaped them.
	msg := plain()
	msg.HTML = strings.Repeat("<b>&</b>", 30_000)
	msg.Attachments = []email.Attachment{file(email.GraphMaxAttachmentBytes)}
	if err := g.Send(ctx(t), msg); err != nil {
		t.Fatalf("fichiers à la limite annoncée : %v", err)
	}
	if got := ms.Mails()[0]; got.HTML != msg.HTML || len(got.Attachments[0].Data) != email.GraphMaxAttachmentBytes {
		t.Error("fichiers à la limite annoncée : message reçu incomplet")
	}
	msg = plain()
	msg.HTML = strings.Repeat("<br>&amp;", 300_000)
	if err := g.Send(ctx(t), msg); err != nil {
		t.Fatalf("long message sans fichier : %v", err)
	}
}

func TestGraphTokenRenewed(t *testing.T) {
	ms := graphtest.Start(t)
	g := ms.Sender()
	for range 3 {
		if err := g.Send(ctx(t), plain()); err != nil {
			t.Fatalf("Send: %v", err)
		}
	}
	if ms.Tokens() != 1 {
		t.Fatalf("%d jeton(s) pour trois envois, 1 attendu", ms.Tokens())
	}

	g.ExpireToken()
	if err := g.Send(ctx(t), plain()); err != nil {
		t.Fatalf("après l'échéance : %v", err)
	}
	if ms.Tokens() != 2 {
		t.Fatalf("après l'échéance : %d jeton(s), 2 attendus", ms.Tokens())
	}

	ms.RevokeToken()
	if err := g.Send(ctx(t), plain()); err != nil {
		t.Fatalf("jeton refusé par Graph : %v", err)
	}
	if ms.Tokens() != 3 || len(ms.Mails()) != 5 {
		t.Fatalf("jeton refusé par Graph : %d jeton(s), %d message(s) (3 et 5 attendus)", ms.Tokens(), len(ms.Mails()))
	}
}

// The renewal margin must not make a short-lived token be requested again on each send.
func TestGraphShortLivedToken(t *testing.T) {
	ms := graphtest.Start(t)
	ms.ExpiresIn(120)
	g := ms.Sender()
	for range 2 {
		if err := g.Send(ctx(t), plain()); err != nil {
			t.Fatalf("Send: %v", err)
		}
	}
	if ms.Tokens() != 1 {
		t.Fatalf("%d jetons pour deux envois, 1 attendu", ms.Tokens())
	}
}

// A single retry, then the error. Without this bound, each send would call Entra and Graph again until its timeout.
func TestGraphTokenRejectedTwice(t *testing.T) {
	ms := graphtest.Start(t)
	ms.RejectTokens()
	err := ms.Sender().Send(ctx(t), plain())
	if err == nil || !strings.HasSuffix(err.Error(), "HTTP 401 (InvalidAuthenticationToken)") {
		t.Fatalf("erreur %v", err)
	}
	leaks(t, err)
	if ms.Tokens() != 2 || ms.Calls() != 2 {
		t.Fatalf("%d jeton(s), %d appel(s) à Graph (2 et 2 attendus)", ms.Tokens(), ms.Calls())
	}
}

// The sender's slots stay under the four concurrent requests Microsoft allows per mailbox.
func TestGraphConcurrentSends(t *testing.T) {
	ms := graphtest.Start(t)
	ms.Hold(30 * time.Millisecond)
	g := ms.Sender()
	var wg sync.WaitGroup
	errs := make(chan error, 24)
	for i := range 24 {
		wg.Go(func() {
			msg := plain()
			if i%2 == 0 {
				msg = withFile()
			}
			errs <- g.Send(ctx(t), msg)
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("Send: %v", err)
		}
	}
	if ms.Tokens() != 1 || ms.TokenCalls() != 1 {
		t.Errorf("%d jeton(s) en %d demande(s) pour 24 envois simultanés, 1 attendu", ms.Tokens(), ms.TokenCalls())
	}
	all, heavy := ms.MaxInFlight()
	if all != email.GraphSlots {
		t.Errorf("%d requêtes simultanées au plus fort, %d attendues", all, email.GraphSlots)
	}
	if heavy > email.GraphHeavySlots {
		t.Errorf("%d requêtes lourdes simultanées, %d au plus attendues", heavy, email.GraphHeavySlots)
	}
	if len(ms.Mails()) != 24 {
		t.Errorf("%d messages reçus, 24 attendus", len(ms.Mails()))
	}
}

// A password reset link does not wait behind file sends.
func TestGraphHeavySendsLeaveASlot(t *testing.T) {
	ms := graphtest.Start(t)
	g := ms.Sender()
	if err := g.Ping(ctx(t)); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	ms.Stall()
	sendCtx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for range 6 {
		wg.Go(func() { _ = g.Send(sendCtx, withFile()) })
	}
	wg.Go(func() { _ = g.Send(sendCtx, plain()) })
	// The others wait for their slot.
	want := email.GraphHeavySlots + 1
	ms.WaitCalls(want)
	time.Sleep(100 * time.Millisecond)
	if got := ms.Calls(); got != want {
		t.Errorf("%d envois ont atteint le service, %d attendus", got, want)
	}
	cancel()
	wg.Wait()
}

// A heavy send that gives up while waiting for its slot returns the heavy slot: otherwise,
// a few timeouts would be enough to never send files again.
func TestGraphGivingUpReturnsTheHeavySlot(t *testing.T) {
	ms := graphtest.Start(t)
	g := ms.Sender()
	if err := g.Ping(ctx(t)); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	ms.Stall()
	var wg sync.WaitGroup
	for range email.GraphSlots {
		wg.Go(func() {
			if err := g.Send(ctx(t), plain()); err != nil {
				t.Errorf("envoi retenu puis libéré : %v", err)
			}
		})
	}
	ms.WaitCalls(email.GraphSlots)
	for range email.GraphHeavySlots + 1 {
		short, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		err := g.Send(short, withFile())
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "créneau") {
			t.Fatalf("créneaux tous pris : erreur %v (attente d'un créneau dépassée attendue)", err)
		}
	}
	ms.Release()
	wg.Wait()
	if err := g.Send(ctx(t), withFile()); err != nil {
		t.Fatalf("créneaux rendus : %v", err)
	}
}

// Whoever waits for a token requested by another keeps its own deadline.
func TestGraphTokenWaiterKeepsItsDeadline(t *testing.T) {
	ms := graphtest.Start(t)
	g := ms.Sender()
	ms.Stall()
	var wg sync.WaitGroup
	wg.Go(func() {
		if err := g.Send(ctx(t), plain()); err != nil {
			t.Errorf("envoi qui demande le jeton : %v", err)
		}
	})
	ms.WaitTokenCalls(1)
	short, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	start := time.Now()
	err := g.Send(short, plain())
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "attente du jeton") {
		t.Errorf("erreur %v (attente du jeton dépassée attendue)", err)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("%v d'attente pour un délai de 100 ms", took)
	}
	if ms.TokenCalls() != 1 {
		t.Errorf("%d demandes de jeton, 1 attendue", ms.TokenCalls())
	}
	ms.Release()
	wg.Wait()
}

// A Graph refusal is an error that states the status and code without repeating Microsoft's text.
// In email-only mode, it is what prevents reporting success to the visitor.
func TestGraphSendRefused(t *testing.T) {
	ms := graphtest.Start(t)
	g := ms.Sender()
	for _, tc := range []struct {
		status int
		body   string
		want   string
	}{
		{http.StatusForbidden, accessDenied, "HTTP 403 (ErrorAccessDenied)"},
		{http.StatusNotFound, `{"error":{"code":"ErrorInvalidUser","message":"The requested user 'formulaires@exemple.fr' is invalid."}}`, "HTTP 404 (ErrorInvalidUser)"},
		{http.StatusInternalServerError, "<html>formulaires@exemple.fr</html>", "HTTP 500"},
		{http.StatusBadRequest, `{"error":{"code":"dest@exemple.fr est refusé","message":"x"}}`, "HTTP 400"},
		// Only a 202 counts as acceptance: a 200 is an error like any other.
		{http.StatusOK, `{}`, "HTTP 200"},
	} {
		ms.RefuseSend(tc.status, tc.body, "")
		err := g.Send(ctx(t), plain())
		if err == nil || !strings.HasSuffix(err.Error(), tc.want) {
			t.Errorf("statut %d : erreur %v (attendue : … %s)", tc.status, err, tc.want)
			continue
		}
		leaks(t, err)
	}
	if len(ms.Mails()) != 0 {
		t.Errorf("%d message(s) accepté(s) malgré les refus", len(ms.Mails()))
	}
	ms.RefuseSend(0, "", "")
	if err := g.Send(ctx(t), plain()); err != nil {
		t.Fatalf("refus levé : %v", err)
	}
}

// An expired secret: the following sends fail without calling Entra again while the refusal is recent.
func TestGraphTokenRefused(t *testing.T) {
	ms := graphtest.Start(t)
	ms.RefuseToken(http.StatusUnauthorized, invalidClient)
	g := ms.Sender()
	err := g.Ping(ctx(t))
	if err == nil || !strings.HasSuffix(err.Error(), "HTTP 401 (invalid_client, AADSTS7000222)") {
		t.Fatalf("erreur %v", err)
	}
	leaks(t, err)

	ms.RefuseToken(0, "")
	if err := g.Send(ctx(t), plain()); err == nil || !strings.Contains(err.Error(), "invalid_client") {
		t.Fatalf("refus récent : erreur %v (celle d'Entra attendue, sans nouvel appel)", err)
	}
	if ms.TokenCalls() != 1 || ms.Calls() != 0 {
		t.Fatalf("refus récent : %d demande(s) de jeton, %d envoi(s) (1 et 0 attendus)", ms.TokenCalls(), ms.Calls())
	}
	g.ForgetTokenRefusal()
	if err := g.Send(ctx(t), plain()); err != nil {
		t.Fatalf("refus ancien, secret remplacé : %v", err)
	}
}

// An Entra response that is neither a token nor an application refusal is not remembered:
// the next send calls it again.
func TestGraphTokenEndpointFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"sans jeton", http.StatusOK, `{"token_type":"Bearer","expires_in":3599}`, "inexploitable"},
		{"sans durée", http.StatusOK, `{"token_type":"Bearer","access_token":"x"}`, "inexploitable"},
		{"illisible", http.StatusOK, `<html>formulaires@exemple.fr</html>`, "inexploitable"},
		{"en panne", http.StatusServiceUnavailable, ``, "HTTP 503"},
	} {
		ms := graphtest.Start(t)
		g := ms.Sender()
		ms.RefuseToken(tc.status, tc.body)
		err := g.Send(ctx(t), plain())
		if err == nil || !strings.HasSuffix(err.Error(), tc.want) {
			t.Errorf("%s : erreur %v (attendue : … %s)", tc.name, err, tc.want)
			continue
		}
		leaks(t, err)
		ms.RefuseToken(0, "")
		if err := g.Send(ctx(t), plain()); err != nil {
			t.Errorf("%s, puis Entra rétabli : %v", tc.name, err)
		}
		if ms.TokenCalls() != 2 || ms.Calls() != 1 {
			t.Errorf("%s : %d demande(s) de jeton, %d envoi(s) (2 et 1 attendus)", tc.name, ms.TokenCalls(), ms.Calls())
		}
	}
}

// Under throttling, Microsoft still counts each call: the sender stops calling for the requested time.
func TestGraphThrottled(t *testing.T) {
	ms := graphtest.Start(t)
	g := ms.Sender()
	ms.RefuseSend(http.StatusTooManyRequests, throttledBody, "120")
	err := g.Send(ctx(t), plain())
	if err == nil || !strings.HasSuffix(err.Error(), "HTTP 429 (ApplicationThrottled)") {
		t.Fatalf("erreur %v", err)
	}
	leaks(t, err)
	ms.RefuseSend(0, "", "")
	for range 3 {
		if err := g.Send(ctx(t), plain()); err == nil || !strings.Contains(err.Error(), "suspendu") {
			t.Fatalf("pendant la pause : erreur %v", err)
		}
	}
	if ms.Calls() != 1 {
		t.Fatalf("%d appels à Graph, 1 attendu : la pause ne doit pas appeler", ms.Calls())
	}
	g.EndThrottle()
	if err := g.Send(ctx(t), plain()); err != nil {
		t.Fatalf("après la pause : %v", err)
	}
}

// The pause is the one Microsoft asks for, bounded: no immediate resume on an unreadable value,
// nor a suspension of several hours.
func TestGraphThrottleDuration(t *testing.T) {
	ms := graphtest.Start(t)
	for _, tc := range []struct {
		retryAfter string
		want       time.Duration
	}{
		{"120", 2 * time.Minute},
		{" 45 ", 45 * time.Second},
		{"", 30 * time.Second},
		{"bientôt", 30 * time.Second},
		{"0", 30 * time.Second},
		{"-5", 30 * time.Second},
		{"999999", 10 * time.Minute},
	} {
		g := ms.Sender()
		ms.RefuseSend(http.StatusTooManyRequests, throttledBody, tc.retryAfter)
		if err := g.Send(ctx(t), plain()); err == nil {
			t.Fatalf("Retry-After %q : une erreur était attendue", tc.retryAfter)
		}
		if got := g.ThrottledFor(); got > tc.want || got < tc.want-5*time.Second {
			t.Errorf("Retry-After %q : pause de %v, %v attendue", tc.retryAfter, got.Round(time.Second), tc.want)
		}
	}
}

// The volume sent is bounded per window. Heavy requests, whose weight a visitor decides,
// get only a share of it: when that share is taken, light emails still go out.
func TestGraphVolume(t *testing.T) {
	ms := graphtest.Start(t)
	g := ms.Sender()
	if !g.Spend(email.GraphHeavyVolume - 200_000) {
		t.Fatal("la part des requêtes lourdes devrait tenir")
	}
	if err := g.Send(ctx(t), withFile()); err != nil {
		t.Fatalf("sous la part des requêtes lourdes : %v", err)
	}
	if err := g.Send(ctx(t), withFile()); !errors.Is(err, email.ErrVolume) {
		t.Fatalf("part des requêtes lourdes prise : erreur %v (ErrVolume attendue)", err)
	}
	long := plain()
	long.HTML = strings.Repeat("x", 2*email.GraphLightBytes)
	if err := g.Send(ctx(t), long); !errors.Is(err, email.ErrVolume) {
		t.Fatalf("part des requêtes lourdes prise, long texte : erreur %v (ErrVolume attendue)", err)
	}
	if err := g.Send(ctx(t), plain()); err != nil {
		t.Fatalf("part des requêtes lourdes prise, email léger : %v", err)
	}
	if ms.Calls() != 2 {
		t.Fatalf("%d appels à Graph, 2 attendus", ms.Calls())
	}

	// The rest of the window is taken by light requests, down to the last byte.
	for _, n := range []int{email.GraphLightBytes, 1 << 10, 1} {
		for g.Spend(n) {
		}
	}
	if err := g.Send(ctx(t), plain()); !errors.Is(err, email.ErrVolume) {
		t.Fatalf("volume de la fenêtre atteint : erreur %v (ErrVolume attendue)", err)
	}
	if ms.Calls() != 2 {
		t.Fatalf("volume atteint : %d appels à Graph, 2 attendus", ms.Calls())
	}
	g.EndWindow()
	if err := g.Send(ctx(t), withFile()); err != nil {
		t.Fatalf("fenêtre suivante : %v", err)
	}
}

// A send that never reaches Microsoft takes nothing from the volume: during a pause or an outage,
// incoming submissions must not exhaust the window and get files refused at resume.
func TestGraphVolumeSpentOnlyWhenSending(t *testing.T) {
	ms := graphtest.Start(t)
	g := ms.Sender()
	ms.RefuseSend(http.StatusTooManyRequests, throttledBody, "120")
	_ = g.Send(ctx(t), withFile())
	for range 500 {
		if err := g.Send(ctx(t), withFile()); errors.Is(err, email.ErrVolume) {
			t.Fatal("un envoi suspendu a été compté au volume")
		}
	}
	g.EndThrottle()
	ms.RefuseSend(0, "", "")
	ms.RefuseToken(http.StatusServiceUnavailable, "")
	g.ExpireToken()
	for range 500 {
		if err := g.Send(ctx(t), withFile()); errors.Is(err, email.ErrVolume) {
			t.Fatal("un envoi sans jeton a été compté au volume")
		}
	}
	ms.RefuseToken(0, "")
	if err := g.Send(ctx(t), withFile()); err != nil {
		t.Fatalf("à la reprise : %v", err)
	}
}

// A service that no longer answers does not hold the send beyond the caller's deadline, whether Entra or Graph.
func TestGraphRespectsDeadline(t *testing.T) {
	for _, step := range []string{"jeton", "envoi"} {
		ms := graphtest.Start(t)
		g := ms.Sender()
		if step == "envoi" {
			if err := g.Ping(ctx(t)); err != nil {
				t.Fatalf("Ping: %v", err)
			}
		}
		ms.Stall()
		short, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		start := time.Now()
		err := g.Send(short, plain())
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("%s muet : erreur %v (délai dépassé attendu)", step, err)
		}
		if took := time.Since(start); took > 3*time.Second {
			t.Errorf("%s muet : %v d'attente pour un délai de 300 ms", step, took)
		}
		// The silent service was indeed reached: the deadline did not run elsewhere.
		if step == "jeton" {
			ms.WaitTokenCalls(1)
		} else {
			ms.WaitCalls(1)
		}
	}
}

// A 307 would replay the request elsewhere, body included: the application secret for the token,
// the message for the send.
func TestGraphDoesNotFollowRedirects(t *testing.T) {
	var mu sync.Mutex
	var received []string
	elsewhere := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		received = append(received, r.URL.Path+" "+r.Header.Get("Authorization")+" "+string(body))
		mu.Unlock()
	}))
	defer elsewhere.Close()

	ms := graphtest.Start(t)
	g := ms.Sender()
	ms.RedirectToken(elsewhere.URL + "/jeton")
	if err := g.Send(ctx(t), plain()); err == nil || !strings.HasSuffix(err.Error(), "HTTP 307") {
		t.Errorf("jeton redirigé : erreur %v (HTTP 307 attendu)", err)
	}
	if ms.Tokens() != 0 || ms.Calls() != 0 {
		t.Errorf("jeton redirigé : %d jeton(s), %d envoi(s)", ms.Tokens(), ms.Calls())
	}

	ms.RedirectToken("")
	g = ms.Sender()
	ms.RedirectSend(elsewhere.URL + "/envoi")
	if err := g.Send(ctx(t), plain()); err == nil || !strings.HasSuffix(err.Error(), "HTTP 307") {
		t.Errorf("envoi redirigé : erreur %v (HTTP 307 attendu)", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 0 {
		t.Fatalf("redirection suivie, reçu ailleurs : %q", received)
	}
}

// The HTTP client error quotes the called address: the tenant for the token, the mailbox for the send.
// Only the cause remains.
func TestGraphTransportErrorsDoNotLeakURL(t *testing.T) {
	for _, step := range []string{"jeton", "envoi"} {
		ms := graphtest.Start(t)
		g := ms.Sender()
		if step == "envoi" {
			if err := g.Ping(ctx(t)); err != nil {
				t.Fatalf("Ping: %v", err)
			}
		}
		ms.Stop()
		err := g.Send(ctx(t), plain())
		if err == nil || !strings.Contains(err.Error(), step) {
			t.Fatalf("service arrêté : erreur %v (un échec à l'étape « %s » attendu)", err, step)
		}
		leaks(t, err)
	}
}

// New picks the sender the configuration names, and only Graph bounds the attachment weight of an email.
func TestNewPicksProvider(t *testing.T) {
	none := email.New(email.Options{Provider: "smtp"})
	if none != nil || email.MaxAttachmentBytes(none) != 0 {
		t.Errorf("SMTP sans hôte : %T, nil attendu (envoi désactivé)", none)
	}
	smtp := email.New(email.Options{Provider: "smtp", SMTPHost: "smtp.exemple.fr", SMTPFrom: "a@exemple.fr"})
	if _, ok := smtp.(*email.SMTP); !ok || email.MaxAttachmentBytes(smtp) != 0 {
		t.Errorf("SMTP réglé : %T, borne de fichiers %d (*email.SMTP et 0 attendus)", smtp, email.MaxAttachmentBytes(smtp))
	}
	sender := email.New(email.Options{Provider: "graph", GraphTenantID: "t", GraphClientID: "c", GraphClientSecret: "s", GraphMailbox: "a@exemple.fr"})
	g, ok := sender.(*email.Graph)
	if !ok {
		t.Fatalf("Graph : %T, *email.Graph attendu", sender)
	}
	if email.MaxAttachmentBytes(sender) != email.GraphMaxAttachmentBytes {
		t.Errorf("Graph : borne de fichiers %d, %d attendue", email.MaxAttachmentBytes(sender), email.GraphMaxAttachmentBytes)
	}
	if g.LoginURL != "https://login.microsoftonline.com" || g.APIURL != "https://graph.microsoft.com" {
		t.Errorf("hôtes appelés : %s et %s", g.LoginURL, g.APIURL)
	}
}
