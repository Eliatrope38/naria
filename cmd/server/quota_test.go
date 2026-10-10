package main

// Integration tests for the per-form storage quota, skipped without TEST_DATABASE_URL.

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"gitlab.com/detag_inno/naria/internal/database"
	"gitlab.com/detag_inno/naria/internal/email"
	"gitlab.com/detag_inno/naria/internal/handlers"
)

// quotaEnv returns the App, to set the quota during a test.
func quotaEnv(t *testing.T, opts ...func(*handlers.App)) (testEnv, *handlers.App) {
	t.Helper()
	var app *handlers.App
	e := setup(t, append(opts, func(a *handlers.App) { app = a })...)
	return e, app
}

func storageBytes(t *testing.T, e testEnv, form database.Form) int64 {
	t.Helper()
	n, err := e.q.FormStorageBytes(context.Background(), database.FormStorageBytesParams{FormID: form.ID})
	if err != nil {
		t.Fatalf("mesure du stockage: %v", err)
	}
	return n
}

// fillToQuota keeps a submission, then sets the quota just above its size: the next one
// still passes, and the form is then full.
func fillToQuota(t *testing.T, e testEnv, app *handlers.App, form database.Form, body string) {
	t.Helper()
	path := "/f/" + form.AccessKey
	for i := range 2 {
		if resp, out := submit(t, e.url, submitOpts{path: path, body: body}); resp.StatusCode != http.StatusOK {
			t.Fatalf("soumission %d : statut %d, corps %s", i+1, resp.StatusCode, out)
		}
		if i == 0 {
			app.Cfg.MaxFormStorageBytes = storageBytes(t, e, form) + 1
		}
	}
}

func alerts(sent []email.Message) []email.Message {
	return slices.DeleteFunc(slices.Clone(sent), func(m email.Message) bool {
		return !strings.Contains(m.Subject, "Quota de stockage atteint")
	})
}

const quotaBody = "name=Ada&message=une+soumission+ordinaire"

// A full form whose email carries the content loses nothing: the submission is no longer
// kept, but it is sent by email, which says so. Its owner and recipients are warned once.
// A deletion frees the space.
func TestQuotaRepliSurLEmail(t *testing.T) {
	e, app := quotaEnv(t)
	path := "/f/" + e.fx.formB.AccessKey
	fillToQuota(t, e, app, e.fx.formB, quotaBody)

	for i := range 2 {
		if resp, out := submit(t, e.url, submitOpts{path: path, body: "name=Grace&message=arrive+quand+meme"}); resp.StatusCode != http.StatusOK {
			t.Fatalf("soumission %d sur le formulaire plein : statut %d, corps %s", i+1, resp.StatusCode, out)
		}
	}
	if n := countSubmissions(t, e, e.fx.formB); n != 2 {
		t.Errorf("%d soumission(s) conservée(s) (2 attendues : le formulaire plein ne conserve plus)", n)
	}
	// Two regular notifications, two announcing that the submission is not kept, and the
	// alert, sent to the owner, to the administrator of their organisation, then to the
	// recipients.
	sent := e.mailer.messages(t, 7)
	var notStored int
	for _, m := range sent {
		if strings.Contains(m.HTML, "arrive quand meme") {
			if !strings.Contains(m.HTML, "pas été conservée") || strings.Contains(m.HTML, "/submissions/") {
				t.Errorf("l'email d'une soumission non conservée doit le dire, sans lien vers l'interface")
			}
			notStored++
		}
	}
	got := alerts(sent)
	if len(sent) != 7 || notStored != 2 || len(got) != 3 {
		t.Fatalf("%d email(s), dont %d sans conservation et %d alerte(s) (7, 2 et 3 attendus)", len(sent), notStored, len(got))
	}
	// The site owner and the form recipient each receive their own message: the second one
	// does not have to read the first one's login address. The alert carries nothing from a visitor.
	var to []string
	for _, alert := range got {
		to = append(to, strings.Join(alert.To, "+"))
		if !strings.Contains(alert.HTML, "/forms/"+e.fx.formB.ID.String()) || !strings.Contains(alert.HTML, "que par email") ||
			strings.Contains(alert.HTML, "Grace") || strings.Contains(alert.HTML, "Ada") || strings.Contains(alert.HTML, "b@b.test") {
			t.Errorf("alerte inattendue : %s", alert.HTML)
		}
	}
	slices.Sort(to)
	if strings.Join(to, ",") != "b@b.test,dest@exemple.fr,orga@naria.test" {
		t.Errorf("destinataires des alertes : %v", to)
	}

	c := newClient()
	login(t, c, e.url, e.fx.memberB.Email)
	formPage := e.url + "/forms/" + e.fx.formB.ID.String()
	if code, page := get(t, c, formPage); code != http.StatusOK || !strings.Contains(page, "Stockage : ") || !strings.Contains(page, "que par email") {
		t.Errorf("la page d'un formulaire plein doit montrer son stockage et ce que deviennent les soumissions (statut %d)", code)
	}
	// Reading and exporting remain possible: that is how space is made.
	if code, csv := get(t, c, formPage+"/export.csv"); code != http.StatusOK || strings.Count(csv, "Ada") != 2 {
		t.Errorf("export d'un formulaire plein : statut %d", code)
	}

	var id string
	if err := e.pool.QueryRow(context.Background(), `SELECT id::text FROM submissions WHERE form_id = $1 LIMIT 1`, e.fx.formB.ID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	resp := postForm(t, c, e.url+"/submissions/"+id+"/delete", url.Values{"csrf_token": {csrfToken(t, c, e.url+"/account")}})
	resp.Body.Close()
	if _, page := get(t, c, formPage); strings.Contains(page, "que par email") {
		t.Errorf("après une suppression, la page ne doit plus annoncer un formulaire plein")
	}
	if resp, out := submit(t, e.url, submitOpts{path: path, body: quotaBody}); resp.StatusCode != http.StatusOK || countSubmissions(t, e, e.fx.formB) != 2 {
		t.Errorf("après une suppression, la soumission doit être conservée : statut %d, corps %s", resp.StatusCode, out)
	}
}

// Without an email carrying its content, a submission received by a full form would have
// nowhere to go: it is refused, the visitor is told, and the owner is alerted. Other forms
// are not affected.
func TestQuotaRefus(t *testing.T) {
	e, app := quotaEnv(t)
	stored := mustForm(t, e.q, e.fx.siteB, "Conservé seul", false, true)
	acceptAttachments(t, e, stored)
	path := "/f/" + stored.AccessKey
	fillToQuota(t, e, app, stored, quotaBody)

	ct, multipart := multipartBody([]string{"name", "Ada"}, []string{"cv", "cv.pdf", "contenu-du-cv"})
	for _, o := range []submitOpts{
		{path: path, body: quotaBody},
		{path: path, body: quotaBody, html: true},
		// The form is designated by a field, not by the address.
		{body: quotaBody + "&access_key=" + stored.AccessKey},
		{path: path, contentType: ct, body: multipart},
		{path: path, body: "name=robot&botcheck=on"},
	} {
		resp, out := submit(t, e.url, o)
		if resp.StatusCode != http.StatusInsufficientStorage || (!o.html && !strings.Contains(out, "ne peut plus recevoir de message")) {
			t.Errorf("envoi sur un formulaire plein (%+v) : statut %d, corps %.120s", o.path, resp.StatusCode, out)
		}
	}
	if n, files := countSubmissions(t, e, stored), countAttachments(t, e); n != 2 || files != 0 {
		t.Errorf("%d soumission(s), %d fichier(s) conservé(s) (2 et 0 attendus)", n, files)
	}
	// One alert per address for five refusals, to the owner and to the administrator of their
	// organisation: this form does not notify, and its recipients asked for nothing.
	e.mailer.messages(t, 1)
	time.Sleep(250 * time.Millisecond)
	sent := e.mailer.messages(t, 2)
	got := alerts(sent)
	to := map[string]bool{}
	for _, m := range got {
		to[strings.Join(m.To, ",")] = true
	}
	if len(sent) != 2 || len(got) != 2 || !to["b@b.test"] || !to["orga@naria.test"] || !strings.Contains(got[0].HTML, "sont refusées") {
		t.Fatalf("%d email(s), %d alerte(s) à %v (deux alertes, au propriétaire et à l'administrateur, attendues)", len(sent), len(got), to)
	}

	c := newClient()
	login(t, c, e.url, e.fx.memberB.Email)
	if _, page := get(t, c, e.url+"/forms/"+stored.ID.String()); !strings.Contains(page, "sont refusées") {
		t.Errorf("la page d'un formulaire plein doit dire que les soumissions sont refusées")
	}
	// The neighbouring form has its own quota.
	if resp, out := submit(t, e.url, submitOpts{path: "/f/" + e.fx.formB.AccessKey, body: quotaBody}); resp.StatusCode != http.StatusOK || countSubmissions(t, e, e.fx.formB) != 1 {
		t.Errorf("autre formulaire : statut %d, corps %s", resp.StatusCode, out)
	}
}

// The email fallback only applies if the email is sent and carries the content.
func TestQuotaSansRepliPossible(t *testing.T) {
	t.Run("email sans le contenu", func(t *testing.T) {
		e, app := quotaEnv(t)
		if _, err := e.pool.Exec(context.Background(), `UPDATE forms SET email_include_content = FALSE WHERE id = $1`, e.fx.formB.ID); err != nil {
			t.Fatal(err)
		}
		fillToQuota(t, e, app, e.fx.formB, quotaBody)
		if resp, _ := submit(t, e.url, submitOpts{path: "/f/" + e.fx.formB.AccessKey, body: quotaBody}); resp.StatusCode != http.StatusInsufficientStorage {
			t.Errorf("statut %d (507 attendu : l'email ne porterait pas la soumission)", resp.StatusCode)
		}
	})
	t.Run("envoi d'email non configuré", func(t *testing.T) {
		e, app := quotaEnv(t, func(a *handlers.App) { a.Mailer = nil })
		fillToQuota(t, e, app, e.fx.formB, quotaBody)
		if resp, _ := submit(t, e.url, submitOpts{path: "/f/" + e.fx.formB.AccessKey, body: quotaBody}); resp.StatusCode != http.StatusInsufficientStorage {
			t.Errorf("statut %d (507 attendu : aucun email ne partirait)", resp.StatusCode)
		}
		if n := countSubmissions(t, e, e.fx.formB); n != 2 {
			t.Errorf("%d soumission(s) conservée(s) (2 attendues)", n)
		}
	})
}

// Concurrent submissions do not all pass under the quota: the space held is read under
// lock at the moment of keeping.
func TestQuotaEnvoisSimultanes(t *testing.T) {
	e, app := quotaEnv(t)
	stored := mustForm(t, e.q, e.fx.siteB, "Conservé seul", false, true)
	path := "/f/" + stored.AccessKey
	if resp, out := submit(t, e.url, submitOpts{path: path, body: quotaBody}); resp.StatusCode != http.StatusOK {
		t.Fatalf("première soumission : statut %d, corps %s", resp.StatusCode, out)
	}
	app.Cfg.MaxFormStorageBytes = storageBytes(t, e, stored) + 1

	var wg sync.WaitGroup
	codes := make([]int, 40)
	for i := range codes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Post(e.url+path, "application/x-www-form-urlencoded", strings.NewReader(quotaBody))
			if err != nil {
				t.Errorf("envoi %d: %v", i, err)
				return
			}
			resp.Body.Close()
			codes[i] = resp.StatusCode
		}()
	}
	wg.Wait()
	accepted := 0
	for _, code := range codes {
		switch code {
		case http.StatusOK:
			accepted++
		case http.StatusInsufficientStorage:
		default:
			t.Errorf("statut inattendu %d", code)
		}
	}
	if n := countSubmissions(t, e, stored); accepted != 1 || n != 2 {
		t.Errorf("%d envoi(s) accepté(s), %d soumission(s) conservée(s) (1 et 2 attendus)", accepted, n)
	}
}

// The measure adds the encrypted content of each submission of the form and the plaintext
// size of all its attachments, and nothing from another form.
func TestMesureDuStockage(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	if n := storageBytes(t, e, e.fx.formA); n != 0 {
		t.Fatalf("formulaire vide : %d octets", n)
	}
	insert := func(form database.Form, payload string, sizes ...int) {
		t.Helper()
		var id string
		if err := e.pool.QueryRow(ctx, `INSERT INTO submissions (form_id, payload) VALUES ($1, $2) RETURNING id::text`, form.ID, payload).Scan(&id); err != nil {
			t.Fatal(err)
		}
		for i, size := range sizes {
			if _, err := e.pool.Exec(ctx, `INSERT INTO attachments (submission_id, position, filename, size, content) VALUES ($1, $2, 'x', $3, 'x')`, id, i, size); err != nil {
				t.Fatal(err)
			}
		}
	}
	insert(e.fx.formA, strings.Repeat("a", 100), 10, 20)
	insert(e.fx.formA, strings.Repeat("é", 100)) // 200 bytes
	insert(e.fx.formB, strings.Repeat("b", 7000), 5000)
	if n := storageBytes(t, e, e.fx.formA); n != 100+10+20+200 {
		t.Errorf("formulaire A : %d octets (330 attendus)", n)
	}
	if n := storageBytes(t, e, e.fx.formB); n != 7000+5000 {
		t.Errorf("formulaire B : %d octets (12000 attendus)", n)
	}
	// A submission the application still keeps is counted separately: the measure leaves
	// it out, attachments included.
	var first uuid.UUID
	if err := e.pool.QueryRow(ctx, `SELECT id FROM submissions WHERE form_id = $1 AND octet_length(payload) = 100`, e.fx.formA.ID).Scan(&first); err != nil {
		t.Fatal(err)
	}
	n, err := e.q.FormStorageBytes(ctx, database.FormStorageBytesParams{FormID: e.fx.formA.ID, Pending: []uuid.UUID{first}})
	if err != nil || n != 200 {
		t.Errorf("formulaire A sans la soumission en cours : %d octets, err %v (200 attendus)", n, err)
	}
}

// A measure taken during submissions does not count them twice: after a burst, the space
// the instance believes held is the one the database holds.
func TestQuotaMesurePendantDesEnvois(t *testing.T) {
	e, app := quotaEnv(t)
	app.Cfg.MaxFormStorageBytes = 1 << 30
	stored := mustForm(t, e.q, e.fx.siteB, "Conservé seul", false, true)
	path := "/f/" + stored.AccessKey
	c := newClient()
	login(t, c, e.url, e.fx.memberB.Email)
	csrf := csrfToken(t, c, e.url+"/account")
	if resp, out := submit(t, e.url, submitOpts{path: path, body: quotaBody}); resp.StatusCode != http.StatusOK {
		t.Fatalf("soumission : statut %d, corps %s", resp.StatusCode, out)
	}
	var doomed string
	if err := e.pool.QueryRow(context.Background(), `SELECT id::text FROM submissions WHERE form_id = $1`, stored.ID).Scan(&doomed); err != nil {
		t.Fatal(err)
	}
	// Deleting makes the form be measured again at the next submission, so in the middle
	// of the burst.
	var wg sync.WaitGroup
	for i := range 30 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Post(e.url+path, "application/x-www-form-urlencoded", strings.NewReader(quotaBody))
			if err != nil {
				t.Errorf("envoi %d: %v", i, err)
				return
			}
			resp.Body.Close()
		}()
	}
	resp := postForm(t, c, e.url+"/submissions/"+doomed+"/delete", url.Values{"csrf_token": {csrf}})
	resp.Body.Close()
	wg.Wait()
	// The form page shows the space the instance believes held.
	inBase := storageBytes(t, e, stored)
	app.Cfg.MaxFormStorageBytes = inBase + 1
	if _, page := get(t, c, e.url+"/forms/"+stored.ID.String()); strings.Contains(page, "sont refusées") {
		t.Errorf("après la rafale, l'instance croit le formulaire plein alors que la base tient %d octets pour un quota de %d", inBase, inBase+1)
	}
}

// A recipient refused by the email server does not trigger the alert again for the owner:
// the owner already received it, and it is not retried.
func TestQuotaAlerteDestinataireRefuse(t *testing.T) {
	e, app := quotaEnv(t)
	fillToQuota(t, e, app, e.fx.formB, quotaBody)
	e.mailer.mu.Lock()
	e.mailer.reject = "dest@exemple.fr"
	e.mailer.mu.Unlock()
	for range 3 {
		submit(t, e.url, submitOpts{path: "/f/" + e.fx.formB.AccessKey, body: quotaBody})
	}
	time.Sleep(250 * time.Millisecond)
	e.mailer.mu.Lock()
	got := alerts(e.mailer.sent)
	e.mailer.mu.Unlock()
	to := map[string]bool{}
	for _, m := range got {
		to[strings.Join(m.To, ",")] = true
	}
	if len(got) != 2 || !to["b@b.test"] || !to["orga@naria.test"] {
		t.Errorf("%d alerte(s) reçue(s) à %v (une par adresse, au propriétaire et à l'administrateur, attendues)", len(got), to)
	}
}

// The retention purge frees space: a full form of expired submissions starts keeping again.
func TestQuotaRepriseApresLaRetention(t *testing.T) {
	e, app := quotaEnv(t)
	stored := mustForm(t, e.q, e.fx.siteB, "Conservé seul", false, true)
	path := "/f/" + stored.AccessKey
	fillToQuota(t, e, app, stored, quotaBody)
	if resp, _ := submit(t, e.url, submitOpts{path: path, body: quotaBody}); resp.StatusCode != http.StatusInsufficientStorage {
		t.Fatalf("formulaire plein : statut %d (507 attendu)", resp.StatusCode)
	}
	ctx := context.Background()
	if _, err := e.pool.Exec(ctx, `UPDATE submissions SET created_at = now() - interval '91 days' WHERE form_id = $1`, stored.ID); err != nil {
		t.Fatal(err)
	}
	app.PurgeRetention(ctx)
	if resp, out := submit(t, e.url, submitOpts{path: path, body: quotaBody}); resp.StatusCode != http.StatusOK || countSubmissions(t, e, stored) != 1 {
		t.Errorf("après la purge : statut %d, corps %s", resp.StatusCode, out)
	}
}

// A failing email server is not hit on every discarded submission: six refusals only
// trigger one alert attempt.
func TestQuotaAlerteEnEchec(t *testing.T) {
	e, app := quotaEnv(t)
	stored := mustForm(t, e.q, e.fx.siteB, "Conservé seul", false, true)
	path := "/f/" + stored.AccessKey
	fillToQuota(t, e, app, stored, quotaBody)
	attempts := func() int {
		e.mailer.mu.Lock()
		defer e.mailer.mu.Unlock()
		return e.mailer.attempts
	}
	e.mailer.mu.Lock()
	e.mailer.err = errors.New("smtp en panne")
	e.mailer.mu.Unlock()

	submit(t, e.url, submitOpts{path: path, body: quotaBody})
	for deadline := time.Now().Add(2 * time.Second); attempts() == 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("aucune tentative d'alerte après un refus")
		}
	}
	for range 5 {
		if resp, _ := submit(t, e.url, submitOpts{path: path, body: quotaBody}); resp.StatusCode != http.StatusInsufficientStorage {
			t.Fatalf("formulaire plein : statut %d (507 attendu)", resp.StatusCode)
		}
	}
	time.Sleep(250 * time.Millisecond)
	if n := attempts(); n != 1 {
		t.Errorf("%d tentative(s) d'envoi pour six refus (1 attendue)", n)
	}
}

// An email-only form keeps nothing: the quota does not concern it, and its page does not
// mention storage.
func TestQuotaIgnoreLEmailSeul(t *testing.T) {
	e, app := quotaEnv(t)
	fillToQuota(t, e, app, e.fx.formB, quotaBody)
	if _, err := e.pool.Exec(context.Background(), `UPDATE forms SET store_submissions = FALSE WHERE id = $1`, e.fx.formB.ID); err != nil {
		t.Fatal(err)
	}
	if resp, out := submit(t, e.url, submitOpts{path: "/f/" + e.fx.formB.AccessKey, body: "name=Grace&message=email+seul"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("email seul : statut %d, corps %s (200 attendu)", resp.StatusCode, out)
	}
	sent := e.mailer.messages(t, 3)
	if strings.Contains(sent[2].HTML, "pas été conservée") || len(alerts(sent)) != 0 {
		t.Errorf("un formulaire en email seul n'a pas de quota à annoncer")
	}
	c := newClient()
	login(t, c, e.url, e.fx.memberB.Email)
	if _, page := get(t, c, e.url+"/forms/"+e.fx.formB.ID.String()); strings.Contains(page, "Stockage : ") || strings.Contains(page, "quota") {
		t.Errorf("la page d'un formulaire en email seul ne doit pas parler de stockage")
	}
}

// The kept size follows the size of the send, including for <, which the HTML escaping
// of JSON would write on six bytes before base64.
func TestPoidsConserveSansEchappementHTML(t *testing.T) {
	e := setup(t)
	body := "message=" + strings.Repeat("<", 16000)
	if resp, out := submit(t, e.url, submitOpts{path: "/f/" + e.fx.formB.AccessKey, body: body}); resp.StatusCode != http.StatusOK {
		t.Fatalf("statut %d, corps %s", resp.StatusCode, out)
	}
	if n := storageBytes(t, e, e.fx.formB); n > int64(2*len(body)) {
		t.Errorf("%d octets conservés pour un corps de %d", n, len(body))
	}
}

func TestSansQuota(t *testing.T) {
	e := setup(t)
	body := "name=Ada&message=" + strings.Repeat("x", 4000)
	for i := range 3 {
		if resp, out := submit(t, e.url, submitOpts{path: "/f/" + e.fx.formB.AccessKey, body: body}); resp.StatusCode != http.StatusOK {
			t.Fatalf("envoi %d : statut %d, corps %s", i+1, resp.StatusCode, out)
		}
	}
	if n := countSubmissions(t, e, e.fx.formB); n != 3 {
		t.Errorf("%d soumission(s) conservée(s) (3 attendues)", n)
	}
	c := newClient()
	login(t, c, e.url, e.fx.memberB.Email)
	if _, page := get(t, c, e.url+"/forms/"+e.fx.formB.ID.String()); strings.Contains(page, "Stockage : ") || strings.Contains(page, "quota") {
		t.Errorf("sans quota, la page du formulaire ne doit pas parler de stockage")
	}
}
