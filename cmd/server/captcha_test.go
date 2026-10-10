package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math/bits"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	naria "gitlab.com/detag_inno/naria"
	"gitlab.com/detag_inno/naria/internal/captcha"
	"gitlab.com/detag_inno/naria/internal/database"
	"gitlab.com/detag_inno/naria/internal/handlers"
	"gitlab.com/detag_inno/naria/internal/web"
)

func requireCaptcha(t *testing.T, e testEnv, form database.Form) {
	t.Helper()
	if _, err := e.pool.Exec(context.Background(), `UPDATE forms SET captcha = TRUE WHERE id = $1`, form.ID); err != nil {
		t.Fatal(err)
	}
}

// challengeFor requests a challenge from the server for the access key, as the script
// installed on the site does.
func challengeFor(t *testing.T, e testEnv, key string) string {
	t.Helper()
	resp, err := http.Get(e.url + "/f/" + key + "/challenge")
	if err != nil {
		t.Fatalf("demande de défi: %v", err)
	}
	defer resp.Body.Close()
	var out struct {
		Challenge  string `json:"challenge"`
		Difficulty int    `json:"difficulty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("demande de défi : statut %d, %v", resp.StatusCode, err)
	}
	if out.Challenge == "" || out.Difficulty != testCaptchaBits {
		t.Fatalf("défi inattendu : %+v", out)
	}
	return out.Challenge
}

// solveChallenge searches for the counter giving the challenge a hash of the wanted
// difficulty (valid), or on the contrary one that is too weak.
func solveChallenge(token string, valid bool) string {
	for n := 0; ; n++ {
		s := token + "." + strconv.Itoa(n)
		sum := sha256.Sum256([]byte(s))
		if (bits.LeadingZeros32(binary.BigEndian.Uint32(sum[:])) >= testCaptchaBits) == valid {
			return s
		}
	}
}

// solved returns the solution of a challenge just issued for the form, ready to be put
// in a urlencoded body.
func solved(t *testing.T, e testEnv, form database.Form) string {
	t.Helper()
	return solveChallenge(challengeFor(t, e, form.AccessKey), true)
}

// A protected form only accepts the solution of a challenge issued for it, not expired
// and never used. Anything else is refused without keeping or notifying anything.
func TestCaptcha(t *testing.T) {
	e := setup(t)
	form := e.fx.formB
	requireCaptcha(t, e, form)
	path := "/f/" + form.AccessKey

	// A challenge signed with the instance key, but issued ten minutes ago.
	past, err := captcha.New(testSecret, testCaptchaBits)
	if err != nil {
		t.Fatal(err)
	}
	expired := past.Challenge(form.AccessKey, time.Now().Add(-10*time.Minute))
	forged := []byte(challengeFor(t, e, form.AccessKey))
	forged[20] = map[bool]byte{true: 'B', false: 'A'}[forged[20] == 'A']

	for _, tc := range []struct {
		name string
		body string
	}{
		{"sans solution", "message=x"},
		{"solution vide", "message=x&naria_captcha="},
		{"solution illisible", "message=x&naria_captcha=pas-une-solution"},
		{"preuve insuffisante", "message=x&naria_captcha=" + solveChallenge(challengeFor(t, e, form.AccessKey), false)},
		{"défi falsifié", "message=x&naria_captcha=" + solveChallenge(string(forged), true)},
		{"défi périmé", "message=x&naria_captcha=" + solveChallenge(expired, true)},
		{"défi d'un autre formulaire", "message=x&naria_captcha=" + solved(t, e, e.fx.formA)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, out := submit(t, e.url, submitOpts{path: path, body: tc.body})
			if resp.StatusCode != http.StatusForbidden || !strings.Contains(out, `"success":false`) {
				t.Errorf("statut %d (403 attendu) : %s", resp.StatusCode, out)
			}
		})
	}
	// Without JavaScript, the visitor reads on the return page what is missing.
	resp, page := submit(t, e.url, submitOpts{path: path, body: "message=x", html: true})
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(page, `role="alert"`) || !strings.Contains(page, "JavaScript") {
		t.Errorf("envoi sans JavaScript : statut %d, page %s", resp.StatusCode, page)
	}
	time.Sleep(50 * time.Millisecond)
	if n := countSubmissions(t, e, form); n != 0 {
		t.Fatalf("%d soumission(s) conservée(s) malgré les refus", n)
	}
	if msgs := e.mailer.messages(t, 0); len(msgs) != 0 {
		t.Fatalf("%d email(s) envoyé(s) malgré les refus", len(msgs))
	}

	solution := solved(t, e, form)
	if resp, out := submit(t, e.url, submitOpts{path: path, body: "message=bonjour&naria_captcha=" + solution}); resp.StatusCode != http.StatusOK {
		t.Fatalf("solution valide : statut %d (%s)", resp.StatusCode, out)
	}
	if resp, out := submit(t, e.url, submitOpts{path: path, body: "message=encore&naria_captcha=" + solution}); resp.StatusCode != http.StatusForbidden {
		t.Errorf("solution déjà utilisée : statut %d (%s)", resp.StatusCode, out)
	}
	body, _ := json.Marshal(map[string]string{"access_key": form.AccessKey, "message": "en json", "naria_captcha": solved(t, e, form)})
	if resp, out := submit(t, e.url, submitOpts{contentType: "application/json", body: string(body)}); resp.StatusCode != http.StatusOK {
		t.Errorf("solution valide en JSON : statut %d (%s)", resp.StatusCode, out)
	}
	if n := countSubmissions(t, e, form); n != 2 {
		t.Errorf("%d soumission(s) conservée(s), 2 attendues", n)
	}
	// The solution drives the processing: it is not part of the content.
	for _, m := range e.mailer.messages(t, 2) {
		if strings.Contains(m.HTML, "naria_captcha") || strings.Contains(m.HTML, solution) {
			t.Errorf("la solution figure dans la notification : %s", m.HTML)
		}
	}
}

// A form without anti-bot verification requests none, and drops the field from the
// content if the site sends it anyway: the script may be installed before the checkbox
// is ticked.
func TestCaptchaNonDemande(t *testing.T) {
	e := setup(t)
	path := "/f/" + e.fx.formB.AccessKey
	if resp, out := submit(t, e.url, submitOpts{path: path, body: "message=sans"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("sans solution : statut %d (%s)", resp.StatusCode, out)
	}
	if resp, out := submit(t, e.url, submitOpts{path: path, body: "message=avec&naria_captcha=pas-une-solution"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("solution sans objet : statut %d (%s)", resp.StatusCode, out)
	}
	// Also in a submission with a file, wherever it is placed.
	ct, body := multipartBody([]string{"message", "multipart"}, []string{"cv", "cv.pdf", "x"}, []string{"naria_captcha", "pas-une-solution"})
	if resp, out := submit(t, e.url, submitOpts{path: path, contentType: ct, body: body}); resp.StatusCode != http.StatusOK {
		t.Fatalf("solution sans objet après un fichier : statut %d (%s)", resp.StatusCode, out)
	}
	for _, m := range e.mailer.messages(t, 3) {
		if strings.Contains(m.HTML, "naria_captcha") || strings.Contains(m.HTML, "pas-une-solution") {
			t.Errorf("le champ de service figure dans le contenu : %s", m.HTML)
		}
	}
}

// The challenge request is open to all sites. It sets no cookie, whether or not the key
// designates a form, and writes no session, audit trace or submission.
func TestCaptchaDemandeDeDefi(t *testing.T) {
	e := setup(t)
	for _, key := range []string{e.fx.formA.AccessKey, "cle-inconnue"} {
		req, _ := http.NewRequest(http.MethodGet, e.url+"/f/"+key+"/challenge", nil)
		req.Header.Set("Origin", "https://autre-site.tld")
		req.Header.Set("Cookie", "lang=en; session=abc")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || resp.Header.Get("Access-Control-Allow-Origin") != "*" ||
			resp.Header.Get("Cache-Control") != "no-store" || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
			t.Errorf("clé %s : statut %d, en-têtes %v", key, resp.StatusCode, resp.Header)
		}
		if len(resp.Header.Values("Set-Cookie")) != 0 || resp.Header.Get("Access-Control-Allow-Credentials") != "" {
			t.Errorf("clé %s : la demande de défi pose un cookie ou en accepte : %v", key, resp.Header)
		}
		if !strings.Contains(string(raw), `"challenge":"`) || !strings.Contains(string(raw), `"difficulty":`+strconv.Itoa(testCaptchaBits)) {
			t.Errorf("clé %s : réponse %s", key, raw)
		}
	}
	if resp, err := http.Get(e.url + "/f/" + strings.Repeat("x", 65) + "/challenge"); err != nil || resp.StatusCode != http.StatusNotFound {
		t.Errorf("clé démesurée : %v, %v", resp, err)
	}
	var rows int
	if err := e.pool.QueryRow(context.Background(),
		`SELECT (SELECT count(*) FROM sessions) + (SELECT count(*) FROM audit_log) + (SELECT count(*) FROM submissions)`).Scan(&rows); err != nil || rows != 0 {
		t.Errorf("la demande de défi a écrit en base : %d ligne(s) (err=%v)", rows, err)
	}
}

// Sent several times at once, a solution only passes once.
func TestCaptchaEnvoisSimultanes(t *testing.T) {
	e := setup(t)
	form := e.fx.formB
	requireCaptcha(t, e, form)
	body := "message=x&naria_captcha=" + solved(t, e, form)
	var accepted, refused, failed atomic.Int32
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			resp, err := http.Post(e.url+"/f/"+form.AccessKey, "application/x-www-form-urlencoded", strings.NewReader(body))
			if err != nil {
				failed.Add(1)
				return
			}
			resp.Body.Close()
			switch resp.StatusCode {
			case http.StatusOK:
				accepted.Add(1)
			case http.StatusForbidden:
				refused.Add(1)
			}
		})
	}
	wg.Wait()
	if failed.Load() != 0 || accepted.Load() != 1 || refused.Load() != 19 {
		t.Errorf("%d envoi(s) accepté(s), %d refusé(s), %d sans réponse ; 1, 19 et 0 attendus", accepted.Load(), refused.Load(), failed.Load())
	}
	if n := countSubmissions(t, e, form); n != 1 {
		t.Errorf("%d soumission(s) conservée(s), 1 attendue", n)
	}
}

// The solution is checked before the first file is read: without it, or if it is placed
// after, the files are not read.
func TestCaptchaAvantLesFichiers(t *testing.T) {
	e := setup(t)
	form := e.fx.formB
	requireCaptcha(t, e, form)
	acceptAttachments(t, e, form)
	path := "/f/" + form.AccessKey
	big := []string{"cv", "gros.bin", strings.Repeat("x", 200<<10)}

	ct, body := multipartBody([]string{"message", "x"}, big)
	if resp, out := submit(t, e.url, submitOpts{path: path, contentType: ct, body: body}); resp.StatusCode != http.StatusForbidden {
		t.Errorf("sans solution : statut %d (%s)", resp.StatusCode, out)
	}
	ct, body = multipartBody([]string{"message", "x"}, big, []string{"naria_captcha", solved(t, e, form)})
	resp, out := submit(t, e.url, submitOpts{path: path, contentType: ct, body: body})
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(out, "naria_captcha") {
		t.Errorf("solution après le fichier : statut %d (%s)", resp.StatusCode, out)
	}
	if n := countSubmissions(t, e, form); n != 0 || countAttachments(t, e) != 0 {
		t.Fatalf("une soumission refusée a été conservée")
	}

	ct, body = multipartBody([]string{"naria_captcha", solved(t, e, form)}, []string{"message", "x"}, []string{"cv", "cv.pdf", "%PDF"})
	if resp, out := submit(t, e.url, submitOpts{path: path, contentType: ct, body: body}); resp.StatusCode != http.StatusOK {
		t.Fatalf("solution avant le fichier : statut %d (%s)", resp.StatusCode, out)
	}
	if n := countSubmissions(t, e, form); n != 1 || countAttachments(t, e) != 1 {
		t.Errorf("la soumission vérifiée et son fichier doivent être conservés")
	}
}

// The check runs before the honeypot field: without a solution the bot is refused, and
// nothing in the response depends on 'botcheck'. With a solution it receives the same fake
// success as elsewhere, and its solution is consumed.
func TestCaptchaPuisChampPiege(t *testing.T) {
	e := setup(t)
	form := e.fx.formB
	requireCaptcha(t, e, form)
	path := "/f/" + form.AccessKey

	_, plain := submit(t, e.url, submitOpts{path: path, body: "message=spam"})
	resp, trapped := submit(t, e.url, submitOpts{path: path, body: "message=spam&botcheck=on"})
	if resp.StatusCode != http.StatusForbidden || trapped != plain {
		t.Errorf("sans solution, la réponse dépend du champ piège : %d %s / %s", resp.StatusCode, trapped, plain)
	}
	solution := solved(t, e, form)
	resp, out := submit(t, e.url, submitOpts{path: path, body: "message=spam&botcheck=on&naria_captcha=" + solution})
	if resp.StatusCode != http.StatusOK || !strings.Contains(out, `"success":true`) {
		t.Errorf("robot avec solution : statut %d (%s)", resp.StatusCode, out)
	}
	if resp, _ := submit(t, e.url, submitOpts{path: path, body: "message=x&naria_captcha=" + solution}); resp.StatusCode != http.StatusForbidden {
		t.Errorf("la solution d'un robot piégé reste utilisable : statut %d", resp.StatusCode)
	}
	time.Sleep(50 * time.Millisecond)
	if n := countSubmissions(t, e, form); n != 0 {
		t.Errorf("la soumission d'un robot a été conservée")
	}
	if msgs := e.mailer.messages(t, 0); len(msgs) != 0 {
		t.Errorf("la soumission d'un robot a été notifiée")
	}
}

// A browser refused for lack of a solution is a visitor the page did not get ready to
// submit: the site owner learns of it by email, once, and on the form page, until the next
// verified submission.
func TestCaptchaAlerteLeProprietaire(t *testing.T) {
	e := setup(t)
	form := e.fx.formB
	requireCaptcha(t, e, form)
	path := "/f/" + form.AccessKey
	browser := http.Header{"Sec-Fetch-Site": {"cross-site"}}
	owner := newClient()
	login(t, owner, e.url, e.fx.memberB.Email)
	const notice = "vérifié : "

	// A submission without a solution that does not come from a browser is a bot: it does not count.
	for range 3 {
		if resp, _ := submit(t, e.url, submitOpts{path: path, body: "message=spam"}); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("robot sans solution : statut %d", resp.StatusCode)
		}
	}
	if _, page := get(t, owner, e.url+"/forms/"+form.ID.String()); strings.Contains(page, notice) {
		t.Fatalf("avis affiché sans refus de navigateur")
	}
	if n := len(e.mailer.messages(t, 0)); n != 0 {
		t.Fatalf("%d alerte(s) pour des robots", n)
	}
	for range 2 {
		if resp, out := submit(t, e.url, submitOpts{path: path, body: "message=secret-visiteur", header: browser}); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("navigateur sans solution : statut %d (%s)", resp.StatusCode, out)
		}
	}
	// A rejected solution is not a sign of a missing script.
	if resp, _ := submit(t, e.url, submitOpts{path: path, body: "message=x&naria_captcha=pas-une-solution", header: browser}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("solution illisible : statut %d", resp.StatusCode)
	}
	time.Sleep(50 * time.Millisecond)
	// One alert per address: the owner and the administrator of their organisation.
	msgs := e.mailer.messages(t, 2)
	if len(msgs) != 2 {
		t.Fatalf("%d alerte(s) pour deux refus, 2 attendues", len(msgs))
	}
	to := map[string]bool{}
	for _, m := range msgs {
		to[strings.Join(m.To, ",")] = true
		if len(m.To) != 1 || !strings.Contains(m.Subject, "anti-robot") ||
			!strings.Contains(m.HTML, "/forms/"+form.ID.String()) || strings.Contains(m.HTML, "secret-visiteur") {
			t.Errorf("alerte inattendue : à %v, sujet %q, corps %s", m.To, m.Subject, m.HTML)
		}
	}
	if !to[e.fx.memberB.Email] || !to[e.fx.orgAdmin.Email] {
		t.Errorf("destinataires des alertes : %v (propriétaire et administrateur attendus)", to)
	}
	if _, page := get(t, owner, e.url+"/forms/"+form.ID.String()); !strings.Contains(page, notice+"2") {
		t.Errorf("la page du formulaire doit compter les deux refus")
	}

	body := "message=bonjour&naria_captcha=" + solved(t, e, form)
	if resp, out := submit(t, e.url, submitOpts{path: path, body: body, header: browser}); resp.StatusCode != http.StatusOK {
		t.Fatalf("envoi vérifié : statut %d (%s)", resp.StatusCode, out)
	}
	if _, page := get(t, owner, e.url+"/forms/"+form.ID.String()); strings.Contains(page, notice) {
		t.Errorf("avis encore affiché après un envoi vérifié")
	}
}

// An alert that could not be sent is not retried at each refusal: a failing email server
// is not hit by every discarded visitor.
func TestCaptchaAlerteEnEchec(t *testing.T) {
	e := setup(t)
	form := e.fx.formB
	requireCaptcha(t, e, form)
	e.mailer.mu.Lock()
	e.mailer.err = errors.New("serveur d'email en panne")
	e.mailer.mu.Unlock()
	attempts := func() int {
		e.mailer.mu.Lock()
		defer e.mailer.mu.Unlock()
		return e.mailer.attempts
	}
	refuse := func() {
		t.Helper()
		opts := submitOpts{path: "/f/" + form.AccessKey, body: "message=x", header: http.Header{"Sec-Fetch-Site": {"cross-site"}}}
		if resp, out := submit(t, e.url, opts); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("navigateur sans solution : statut %d (%s)", resp.StatusCode, out)
		}
	}

	refuse()
	for deadline := time.Now().Add(2 * time.Second); attempts() == 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("aucune alerte tentée")
		}
	}
	for range 3 {
		refuse()
	}
	time.Sleep(50 * time.Millisecond)
	if n := attempts(); n != 1 {
		t.Errorf("%d envois d'alerte tentés pour quatre refus, 1 attendu", n)
	}
}

// The check runs after the rate limit and before the quota: an address that has used up
// its sends no longer triggers any verification, and a bot without a solution neither has
// storage measured nor triggers an alert for a full form.
func TestCaptchaEntreLaLimiteDeDebitEtLeQuota(t *testing.T) {
	e, app := quotaEnv(t, func(a *handlers.App) { a.SubmitLimiter = web.NewRateLimiter(4, time.Minute) })
	form := mustForm(t, e.q, e.fx.siteB, "Listé seulement", false, true)
	path := "/f/" + form.AccessKey
	fillToQuota(t, e, app, form, quotaBody)
	requireCaptcha(t, e, form)

	if resp, out := submit(t, e.url, submitOpts{path: path, body: quotaBody}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("formulaire plein, sans solution : statut %d (%s), 403 attendu", resp.StatusCode, out)
	}
	time.Sleep(50 * time.Millisecond)
	if n := len(alerts(e.mailer.messages(t, 0))); n != 0 {
		t.Fatalf("%d alerte(s) de quota pour un envoi sans solution", n)
	}
	solution := solved(t, e, form)
	if resp, out := submit(t, e.url, submitOpts{path: path, body: quotaBody + "&naria_captcha=" + solution}); resp.StatusCode != http.StatusInsufficientStorage {
		t.Fatalf("formulaire plein, solution valide : statut %d (%s), 507 attendu", resp.StatusCode, out)
	}
	// Four sends have been counted: the fifth is stopped before any verification, whatever its solution.
	if resp, out := submit(t, e.url, submitOpts{path: path, body: quotaBody + "&naria_captcha=" + solved(t, e, form)}); resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("limite de débit atteinte : statut %d (%s), 429 attendu", resp.StatusCode, out)
	}
}

// An access key surrounded by spaces designates the same form at submission: the
// challenge requested with it must be accepted there.
func TestCaptchaCleAvecEspaces(t *testing.T) {
	e := setup(t)
	form := e.fx.formB
	requireCaptcha(t, e, form)
	solution := solveChallenge(challengeFor(t, e, "%20"+form.AccessKey+"%20"), true)
	body := url.Values{"access_key": {" " + form.AccessKey + " "}, "message": {"x"}, "naria_captcha": {solution}}.Encode()
	if resp, out := submit(t, e.url, submitOpts{body: body}); resp.StatusCode != http.StatusOK {
		t.Errorf("statut %d (%s)", resp.StatusCode, out)
	}
}

func TestCaptchaReglageEtCodeDIntegration(t *testing.T) {
	e := setup(t)
	c := newClient()
	login(t, c, e.url, e.fx.memberA.Email)
	formPage := e.url + "/forms/" + e.fx.formA.ID.String()
	const script = `http://naria.test/static/captcha.js`

	if _, page := get(t, c, formPage); strings.Contains(page, script) || strings.Contains(page, "data-naria-captcha") {
		t.Errorf("le code d'intégration ne doit donner le script que si la vérification est activée")
	}
	resp := postForm(t, c, formPage+"/settings", formValues(csrfToken(t, c, e.url+"/account"), url.Values{"captcha": {"1"}}))
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("enregistrement : statut %d", resp.StatusCode)
	}
	// Enabling it reminds that the site must load the script.
	if _, page := get(t, c, formPage+"/settings"); !strings.Contains(page, "script") || !strings.Contains(page, `name="captcha" value="1" checked`) {
		t.Errorf("la page de réglages doit montrer la case cochée et rappeler le script")
	}
	if _, page := get(t, c, formPage); !strings.Contains(page, script) || !strings.Contains(page, "data-naria-captcha") {
		t.Errorf("le code d'intégration doit donner l'attribut et le script")
	}
	if resp, out := submit(t, e.url, submitOpts{path: "/f/" + e.fx.formA.AccessKey, body: "message=x", origin: "https://exemple.fr"}); resp.StatusCode != http.StatusForbidden {
		t.Errorf("formulaire protégé depuis l'interface : statut %d (%s)", resp.StatusCode, out)
	}

	token := createToken(t, e, c, e.fx.siteA, "Agent")
	code, created, raw := api(t, e, http.MethodPost, "/forms", token, `{"name": "Protégé", "captcha": true}`)
	html, _ := created["html"].(string)
	if code != http.StatusCreated || created["captcha"] != true ||
		!strings.Contains(html, " data-naria-captcha>") || !strings.Contains(html, `<script src="`+script+`" defer></script>`) {
		t.Fatalf("création par l'API : statut %d (%s)", code, raw)
	}
	key := created["access_key"].(string)
	if resp, out := submit(t, e.url, submitOpts{path: "/f/" + key, body: "message=x", origin: "https://exemple.fr"}); resp.StatusCode != http.StatusForbidden {
		t.Errorf("formulaire protégé depuis l'API : statut %d (%s)", resp.StatusCode, out)
	}
	if _, _, raw := api(t, e, http.MethodGet, "/forms", token, ""); !strings.Contains(raw, `"captcha":true`) {
		t.Errorf("la liste doit dire quels formulaires demandent la vérification : %s", raw)
	}
}

// The script runs in the pages of client sites: it touches neither cookies nor browser
// storage, and its only request is sent without the page's cookies or address.
func TestCaptchaScriptNeGardeRien(t *testing.T) {
	raw, err := naria.StaticFiles.ReadFile("web/static/captcha.js")
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	for _, banned := range []string{"cookie", "localStorage", "sessionStorage", "indexedDB", "XMLHttpRequest", "sendBeacon", "navigator."} {
		if strings.Contains(script, banned) {
			t.Errorf("le script mentionne %q", banned)
		}
	}
	if strings.Count(script, "fetch(") != 1 || !strings.Contains(script, `credentials: "omit"`) || !strings.Contains(script, `referrerPolicy: "no-referrer"`) {
		t.Errorf("le script doit faire une seule requête, sans cookie ni adresse de la page")
	}
}

// scriptHarness loads the script outside a browser and has it solve the challenge received
// as argument, recording the address it requested it from.
const scriptHarness = `
const [script, challenge, difficulty, endpoint, key] = process.argv.slice(2);
let asked;
globalThis.window = globalThis;
globalThis.HTMLFormElement = class {};
globalThis.document = { baseURI: "https://site.test/contact/", addEventListener() {} };
globalThis.fetch = async (url, options) => {
  asked = { url, credentials: options.credentials };
  return { ok: true, json: async () => ({ challenge, difficulty: Number(difficulty) }) };
};
(0, eval)(require("fs").readFileSync(script, "utf8"));
window.nariaCaptcha(endpoint, key).then(
  (solution) => console.log(JSON.stringify({ solution, ...asked })),
  (err) => { console.error(err); process.exit(1); },
);
`

// The script computes SHA-256 itself: its solutions must be those the instance accepts, at
// the real difficulty. The test requires node, which is absent from the CI image: it does not
// run there.
func TestCaptchaScriptResoutUnDefi(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node absent : script non exécuté")
	}
	harness := filepath.Join(t.TempDir(), "harness.js")
	if err := os.WriteFile(harness, []byte(scriptHarness), 0o600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(t.TempDir(), "captcha.js")
	raw, err := naria.StaticFiles.ReadFile("web/static/captcha.js")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	checker, err := captcha.New(testSecret, captcha.Difficulty)
	if err != nil {
		t.Fatal(err)
	}
	const key = "276b1f4e-8a55-4c8b-9d63-0c1f0f3c2a11" // gitleaks:allow
	for _, tc := range []struct{ endpoint, key, asked string }{
		{"https://forms.test/submit", " " + key + " ", "https://forms.test/f/" + key + "/challenge"},
		{"https://forms.test/prefixe/f/" + key, "", "https://forms.test/prefixe/f/" + key + "/challenge"},
		{"/submit", key, "https://site.test/f/" + key + "/challenge"},
	} {
		now := time.Now()
		cmd := exec.Command(node, harness, script, checker.Challenge(key, now), strconv.Itoa(captcha.Difficulty), tc.endpoint, tc.key)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("node : %v (%s)", err, out)
		}
		var got struct{ Solution, URL, Credentials string }
		if err := json.Unmarshal(out, &got); err != nil {
			t.Fatalf("sortie illisible : %s", out)
		}
		if got.URL != tc.asked || got.Credentials != "omit" {
			t.Errorf("%s : défi demandé à %s (cookies : %s), attendu %s sans cookie", tc.endpoint, got.URL, got.Credentials, tc.asked)
		}
		if err := checker.Check(key, got.Solution, now); err != nil {
			t.Errorf("%s : solution du script refusée (%v) : %s", tc.endpoint, err, got.Solution)
		}
	}
}
