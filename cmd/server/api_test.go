package main

// Integration tests for the API and its tokens, skipped without TEST_DATABASE_URL.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"gitlab.com/detag_inno/naria/internal/auth"
	"gitlab.com/detag_inno/naria/internal/database"
	"gitlab.com/detag_inno/naria/internal/handlers"
	"gitlab.com/detag_inno/naria/internal/web"
	"gitlab.com/detag_inno/naria/ui"
)

var apiTokenRe = regexp.MustCompile(`naria_[A-Za-z0-9_-]{43}`)

// createToken creates a token from the site page, as a logged-in user would.
func createToken(t *testing.T, e testEnv, c *http.Client, site database.Site, name string) string {
	t.Helper()
	return createTokenFor(t, e, c, site, name, "30")
}

func createTokenFor(t *testing.T, e testEnv, c *http.Client, site database.Site, name, days string) string {
	t.Helper()
	sitePath := e.url + "/sites/" + site.ID.String()
	resp := postForm(t, c, sitePath+"/tokens", url.Values{
		"csrf_token": {csrfToken(t, c, e.url+"/account")}, "name": {name}, "expires_in": {days},
	})
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	plain := apiTokenRe.FindString(string(body))
	if resp.StatusCode != http.StatusOK || plain == "" {
		t.Fatalf("création du jeton %q : statut %d, jeton affiché %q", name, resp.StatusCode, plain)
	}
	// The page carries the token in clear text: the browser must not keep it.
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("page du jeton %q : Cache-Control %q (no-store attendu)", name, cc)
	}
	return plain
}

// api calls the API with the given token (no header if empty) and returns the status,
// the decoded body and the raw body.
func api(t *testing.T, e testEnv, method, path, token, body string) (int, map[string]any, string) {
	t.Helper()
	req, err := http.NewRequest(method, e.url+"/api/v1"+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("requête: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := newClient().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("%s %s : Content-Type %q, JSON attendu (statut %d)", method, path, ct, resp.StatusCode)
	}
	if resp.StatusCode == http.StatusUnauthorized && resp.Header.Get("WWW-Authenticate") != "Bearer" {
		t.Errorf("%s %s : 401 sans en-tête WWW-Authenticate", method, path)
	}
	out := map[string]any{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("%s %s : réponse illisible %q", method, path, raw)
	}
	return resp.StatusCode, out, string(raw)
}

func countForms(t *testing.T, e testEnv, site database.Site) int {
	t.Helper()
	forms, err := e.q.ListFormsOfSite(context.Background(), site.ID)
	if err != nil {
		t.Fatalf("liste des formulaires: %v", err)
	}
	return len(forms)
}

// An agent's workflow: a token created from the site page is enough to read the site,
// create a form and get the code to embed, and the created form receives submissions.
func TestAPICreationDeFormulaire(t *testing.T) {
	e := setup(t)
	c := newClient()
	login(t, c, e.url, e.fx.memberA.Email)
	token := createToken(t, e, c, e.fx.siteA, "Agent du site")

	// The token is shown only once, and the database keeps only its fingerprint.
	if _, body := get(t, c, e.url+"/sites/"+e.fx.siteA.ID.String()); strings.Contains(body, token) || !strings.Contains(body, "Agent du site") {
		t.Errorf("la page du site doit lister le jeton par son nom, sans le réafficher")
	}
	var id, hash string
	if err := e.pool.QueryRow(context.Background(), `SELECT id::text, token_hash FROM api_tokens`).Scan(&id, &hash); err != nil {
		t.Fatalf("lecture du jeton: %v", err)
	}
	if hash != auth.HashToken(token) || strings.Contains(hash, token) {
		t.Errorf("la base doit garder l'empreinte du jeton, pas le jeton")
	}
	var leaks int
	if err := e.pool.QueryRow(context.Background(),
		`SELECT (SELECT count(*) FROM sessions WHERE position(convert_to($1, 'UTF8') in data) > 0)
		      + (SELECT count(*) FROM audit_log WHERE detail LIKE '%' || $1 || '%')`, token).Scan(&leaks); err != nil || leaks != 0 {
		t.Errorf("le jeton figure en clair dans la session ou le journal d'audit : %d (err=%v)", leaks, err)
	}

	code, site, _ := api(t, e, http.MethodGet, "/site", token, "")
	if code != http.StatusOK || site["name"] != "Site Alpha" || len(site["domains"].([]any)) != 1 || site["domains"].([]any)[0] != "exemple.fr" {
		t.Errorf("GET /site : statut %d, réponse %v", code, site)
	}

	code, created, raw := api(t, e, http.MethodPost, "/forms", token,
		`{"name": " Devis ", "retention_days": 30, "accept_attachments": true, "redirect_url": "https://exemple.fr/merci/"}`)
	if code != http.StatusCreated {
		t.Fatalf("POST /forms : statut %d (%s)", code, raw)
	}
	key, _ := created["access_key"].(string)
	html, _ := created["html"].(string)
	if created["name"] != "Devis" || created["submit_url"] != "http://naria.test/submit" || created["active"] != true ||
		created["retention_days"] != float64(30) || created["redirect_url"] != "https://exemple.fr/merci/" {
		t.Errorf("formulaire créé inattendu : %s", raw)
	}
	if key == "" || !strings.Contains(html, `value="`+key+`"`) || !strings.Contains(html, "http://naria.test/submit") ||
		!strings.Contains(html, "multipart/form-data") || !strings.Contains(html, "botcheck") {
		t.Errorf("le code d'intégration doit porter l'adresse d'envoi, la clé, l'enctype et le champ piège : %s", html)
	}

	form, err := e.q.GetFormByAccessKey(context.Background(), key)
	if err != nil || form.SiteID != e.fx.siteA.ID || !form.StoreSubmissions || !form.NotifyEmail {
		t.Fatalf("le formulaire créé doit être sur le site du jeton, conservé et notifié : %v", err)
	}
	// The notification goes to the token's creator, and to them only.
	if resp, out := submit(t, e.url, submitOpts{path: "/f/" + key, body: "message=bonjour", origin: "https://exemple.fr"}); resp.StatusCode != http.StatusOK {
		t.Errorf("soumission au formulaire créé : statut %d (%s)", resp.StatusCode, out)
	}
	if to := e.mailer.messages(t, 1)[0].To; len(to) != 1 || to[0] != e.fx.memberA.Email {
		t.Errorf("destinataires de la notification : %v", to)
	}

	// The list gives what is needed to embed each form, not who receives its submissions.
	code, _, raw = api(t, e, http.MethodGet, "/forms", token, "")
	if code != http.StatusOK || !strings.Contains(raw, key) || !strings.Contains(raw, e.fx.formA.AccessKey) {
		t.Errorf("GET /forms : statut %d, les deux formulaires du site sont attendus : %s", code, raw)
	}
	if strings.Contains(raw, "recipients") || strings.Contains(raw, "dest@exemple.fr") || strings.Contains(raw, e.fx.memberA.Email) {
		t.Errorf("GET /forms livre des destinataires : %s", raw)
	}

	// Creation is logged under the token creator's name, along with the token used.
	var actor, detail string
	if err := e.pool.QueryRow(context.Background(),
		`SELECT actor_id::text, detail FROM audit_log WHERE action = 'form.created' AND entity_id = $1`, form.ID).Scan(&actor, &detail); err != nil {
		t.Fatalf("trace de création: %v", err)
	}
	meta := map[string]string{}
	if err := json.Unmarshal([]byte(detail), &meta); err != nil || actor != e.fx.memberA.ID.String() || meta["token"] != id || meta["ip"] == "" {
		t.Errorf("trace de création : acteur %s, détail %s", actor, detail)
	}
	var lastUsed bool
	if err := e.pool.QueryRow(context.Background(), `SELECT last_used_at IS NOT NULL FROM api_tokens`).Scan(&lastUsed); err != nil || !lastUsed {
		t.Errorf("la date du dernier appel doit être tenue : %v (err=%v)", lastUsed, err)
	}
}

// Without a valid token, these calls get a 401: neither an open session in the interface nor
// an expired or revoked token opens anything.
func TestAPIRefuseSansJetonValide(t *testing.T) {
	e := setup(t)
	c := newClient()
	login(t, c, e.url, e.fx.memberA.Email)
	token := createToken(t, e, c, e.fx.siteA, "Agent")
	if code, _, _ := api(t, e, http.MethodGet, "/site", token, ""); code != http.StatusOK {
		t.Fatalf("jeton valide : statut %d", code)
	}

	for _, tc := range []struct{ what, header string }{
		{"aucun en-tête", ""},
		{"jeton sans schéma", token},
		{"autre schéma", "Basic " + token},
		{"jeton inconnu", "Bearer naria_" + strings.Repeat("A", 43)},
		{"jeton tronqué", "Bearer " + token[:len(token)-1]},
		{"sans préfixe", "Bearer " + strings.TrimPrefix(token, auth.APITokenPrefix)},
	} {
		for _, call := range []struct{ method, path string }{{http.MethodGet, "/site"}, {http.MethodGet, "/forms"}, {http.MethodPost, "/forms"}} {
			req, _ := http.NewRequest(call.method, e.url+"/api/v1"+call.path, strings.NewReader(`{"name":"Pirate"}`))
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			// A's session accompanies the call: it must not stand in for a token.
			resp, err := c.Do(req)
			if err != nil {
				t.Fatalf("%s: %v", tc.what, err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s, %s %s : statut %d (401 attendu)", tc.what, call.method, call.path, resp.StatusCode)
			}
			if strings.Contains(string(body), "Site Alpha") || strings.Contains(string(body), e.fx.formA.AccessKey) {
				t.Errorf("%s, %s %s : des données du site fuient : %s", tc.what, call.method, call.path, body)
			}
		}
	}

	ctx := context.Background()
	if _, err := e.pool.Exec(ctx, `UPDATE api_tokens SET expires_at = now() - interval '1 second'`); err != nil {
		t.Fatalf("échéance: %v", err)
	}
	if code, _, _ := api(t, e, http.MethodPost, "/forms", token, `{"name":"Trop tard"}`); code != http.StatusUnauthorized {
		t.Errorf("jeton échu : statut %d (401 attendu)", code)
	}
	if _, body := get(t, c, e.url+"/sites/"+e.fx.siteA.ID.String()); !strings.Contains(body, "Expiré") {
		t.Errorf("la page du site doit signaler le jeton échu")
	}
	if _, err := e.pool.Exec(ctx, `UPDATE api_tokens SET expires_at = NULL`); err != nil {
		t.Fatalf("échéance: %v", err)
	}
	if code, _, _ := api(t, e, http.MethodGet, "/site", token, ""); code != http.StatusOK {
		t.Fatalf("jeton sans échéance : statut %d", code)
	}

	var id string
	if err := e.pool.QueryRow(ctx, `SELECT id::text FROM api_tokens`).Scan(&id); err != nil {
		t.Fatalf("lecture du jeton: %v", err)
	}
	resp := postForm(t, c, e.url+"/sites/"+e.fx.siteA.ID.String()+"/tokens/"+id+"/delete", url.Values{"csrf_token": {csrfToken(t, c, e.url+"/account")}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("révocation : statut %d", resp.StatusCode)
	}
	if code, _, _ := api(t, e, http.MethodGet, "/site", token, ""); code != http.StatusUnauthorized {
		t.Errorf("jeton révoqué : statut %d (401 attendu)", code)
	}
	if n := countForms(t, e, e.fx.siteA); n != 1 {
		t.Errorf("formulaires du site : %d (1 attendu, aucun appel refusé ne doit en créer)", n)
	}
	var created, revoked int
	if err := e.pool.QueryRow(ctx,
		`SELECT count(*) FILTER (WHERE action = 'site.token_created'), count(*) FILTER (WHERE action = 'site.token_revoked')
		 FROM audit_log WHERE entity = 'site' AND entity_id = $1 AND actor_id = $2 AND detail LIKE '%' || $3 || '%'`,
		e.fx.siteA.ID, e.fx.memberA.ID, id).Scan(&created, &revoked); err != nil || created != 1 || revoked != 1 {
		t.Errorf("traces du jeton : %d création(s), %d révocation(s) (err=%v)", created, revoked, err)
	}
}

// A token does not leave the site it was created for, and is only worth its creator's access:
// another member cannot create or revoke one on that site, and the token lapses with its
// creator's access or account.
func TestAPIJetonCloisonneAuSite(t *testing.T) {
	e := setup(t)
	a, b := newClient(), newClient()
	login(t, a, e.url, e.fx.memberA.Email)
	login(t, b, e.url, e.fx.memberB.Email)
	token := createToken(t, e, a, e.fx.siteA, "Agent de A")

	if _, _, raw := api(t, e, http.MethodGet, "/forms", token, ""); strings.Contains(raw, e.fx.formB.AccessKey) || strings.Contains(raw, "Contact Bravo") {
		t.Errorf("le jeton du site A liste un formulaire du site B : %s", raw)
	}
	if code, _, raw := api(t, e, http.MethodPost, "/forms", token, `{"name":"Sur A"}`); code != http.StatusCreated {
		t.Fatalf("création : statut %d (%s)", code, raw)
	}
	if na, nb := countForms(t, e, e.fx.siteA), countForms(t, e, e.fx.siteB); na != 2 || nb != 1 {
		t.Errorf("formulaires : %d sur A, %d sur B (2 et 1 attendus)", na, nb)
	}

	ctx := context.Background()
	var id string
	if err := e.pool.QueryRow(ctx, `SELECT id::text FROM api_tokens`).Scan(&id); err != nil {
		t.Fatalf("lecture du jeton: %v", err)
	}
	csrf := csrfToken(t, b, e.url+"/account")
	for _, path := range []string{
		"/sites/" + e.fx.siteA.ID.String() + "/tokens",
		"/sites/" + e.fx.siteA.ID.String() + "/tokens/" + id + "/delete",
		// A's token designated through B's site.
		"/sites/" + e.fx.siteB.ID.String() + "/tokens/" + id + "/delete",
	} {
		resp := postForm(t, b, e.url+path, url.Values{"csrf_token": {csrf}, "name": {"Pirate"}, "expires_in": {"0"}})
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound || apiTokenRe.Match(body) {
			t.Errorf("POST %s par un autre membre : statut %d (404 attendu)", path, resp.StatusCode)
		}
	}
	if _, body := get(t, b, e.url+"/sites/"+e.fx.siteB.ID.String()); strings.Contains(body, "Agent de A") {
		t.Errorf("la page du site B montre un jeton du site A")
	}
	var n int
	if err := e.pool.QueryRow(ctx, `SELECT count(*) FROM api_tokens`).Scan(&n); err != nil || n != 1 {
		t.Errorf("jetons en base : %d (1 attendu, err=%v)", n, err)
	}
	if code, _, _ := api(t, e, http.MethodGet, "/site", token, ""); code != http.StatusOK {
		t.Fatalf("le jeton de A doit toujours fonctionner : statut %d", code)
	}

	// Account disabled: its token is worthless, then valid again with it.
	if err := e.q.SetUserActive(ctx, database.SetUserActiveParams{ID: e.fx.memberA.ID, Active: false}); err != nil {
		t.Fatalf("désactivation: %v", err)
	}
	if code, _, _ := api(t, e, http.MethodGet, "/site", token, ""); code != http.StatusUnauthorized {
		t.Errorf("créateur désactivé : statut %d (401 attendu)", code)
	}
	if err := e.q.SetUserActive(ctx, database.SetUserActiveParams{ID: e.fx.memberA.ID, Active: true}); err != nil {
		t.Fatalf("réactivation: %v", err)
	}
	if code, _, _ := api(t, e, http.MethodGet, "/site", token, ""); code != http.StatusOK {
		t.Fatalf("créateur réactivé : statut %d", code)
	}

	// Site transferred to B: A's token, which no longer has access, has no effect,
	// and the page says so to the new owner.
	adm := newClient()
	login(t, adm, e.url, e.fx.admin.Email)
	adminToken := createToken(t, e, adm, e.fx.siteA, "Agent de l'administrateur")
	resp := postForm(t, adm, e.url+"/sites/"+e.fx.siteA.ID.String()+"/owner", url.Values{
		"csrf_token": {csrfToken(t, adm, e.url+"/account")}, "owner_id": {e.fx.memberB.ID.String()},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("transfert : statut %d", resp.StatusCode)
	}
	if code, _, _ := api(t, e, http.MethodPost, "/forms", token, `{"name":"Après transfert"}`); code != http.StatusUnauthorized {
		t.Errorf("jeton d'un ancien propriétaire : statut %d (401 attendu)", code)
	}
	if n := countForms(t, e, e.fx.siteA); n != 2 {
		t.Errorf("formulaires du site transféré : %d (2 attendus)", n)
	}
	if _, body := get(t, b, e.url+"/sites/"+e.fx.siteA.ID.String()); !strings.Contains(body, "Agent de A") || !strings.Contains(body, "Sans effet") {
		t.Errorf("le nouveau propriétaire doit voir le jeton de A, signalé sans effet")
	}
	// The administrator's token, which keeps access to all sites, stays valid as long as
	// they are an administrator.
	if code, _, _ := api(t, e, http.MethodGet, "/site", adminToken, ""); code != http.StatusOK {
		t.Errorf("jeton de l'administrateur après transfert : statut %d", code)
	}
	if err := e.q.SetUserRole(ctx, database.SetUserRoleParams{ID: e.fx.admin.ID, Role: auth.RoleMember}); err != nil {
		t.Fatalf("rétrogradation: %v", err)
	}
	if code, _, _ := api(t, e, http.MethodGet, "/site", adminToken, ""); code != http.StatusUnauthorized {
		t.Errorf("jeton d'un administrateur rétrogradé : statut %d (401 attendu)", code)
	}
}

// The API applies the rules of the settings page and refuses what it does not know: an alert
// channel cannot be configured with a token.
func TestAPIValidationDeLaCreation(t *testing.T) {
	e := setup(t)
	c := newClient()
	login(t, c, e.url, e.fx.memberA.Email)
	token := createToken(t, e, c, e.fx.siteA, "Agent")

	for _, tc := range []struct{ what, body string }{
		{"corps vide", ``},
		{"JSON mal formé", `{"name": `},
		{"nom absent", `{}`},
		{"nom trop long", `{"name": "` + strings.Repeat("x", 121) + `"}`},
		{"aucune destination", `{"name": "Vide", "notify_email": false, "store_submissions": false}`},
		{"nom d'un autre type", `{"name": 123}`},
		{"conservation en texte", `{"name": "Contact", "retention_days": "30"}`},
		{"conservation décimale", `{"name": "Contact", "retention_days": 30.5}`},
		{"tableau", `[{"name": "Contact"}]`},
		{"deux objets", `{"name": "Contact"} {"name": "Autre"}`},
		{"reste après l'objet", `{"name": "Contact"} reste`},
		{"destinataires choisis", `{"name": "Contact", "recipients": ["attaquant@evil.tld"]}`},
		{"conservation hors bornes", `{"name": "Contact", "retention_days": 99999}`},
		{"page de retour hors domaine", `{"name": "Contact", "redirect_url": "https://evil.tld/merci"}`},
		{"canal d'alerte", `{"name": "Contact", "slack_webhook_url": "https://hooks.slack.com/services/T/B/X"}`},
		{"jeton Telegram", `{"name": "Contact", "telegram_bot_token": "123456789:AAExample", "telegram_chat_id": "-1001"}`},
		{"clé d'accès choisie", `{"name": "Contact", "access_key": "` + e.fx.formB.AccessKey + `"}`},
		{"site désigné", `{"name": "Contact", "site_id": "` + e.fx.siteB.ID.String() + `"}`},
	} {
		code, out, raw := api(t, e, http.MethodPost, "/forms", token, tc.body)
		if code != http.StatusBadRequest || out["error"] == "" || out["error"] == nil {
			t.Errorf("%s : statut %d, réponse %s (400 et un message attendus)", tc.what, code, raw)
		}
	}
	if na, nb := countForms(t, e, e.fx.siteA), countForms(t, e, e.fx.siteB); na != 1 || nb != 1 {
		t.Errorf("une saisie refusée a créé un formulaire : %d sur A, %d sur B", na, nb)
	}

	if code, _, raw := api(t, e, http.MethodPost, "/forms", token, `{"name": "`+strings.Repeat("x", 2<<20)+`"}`); code != http.StatusRequestEntityTooLarge {
		t.Errorf("corps trop volumineux : statut %d (413 attendu) : %.80s", code, raw)
	}
	// The refusal names the field at fault, without the decoder's text.
	if _, out, raw := api(t, e, http.MethodPost, "/forms", token, `{"name": "Contact", "notify_email": "oui"}`); !strings.Contains(raw, "notify_email") || strings.Contains(raw, "apiFormInput") || strings.Contains(raw, "json:") {
		t.Errorf("message d'un type inattendu : %v", out["error"])
	}
	if _, out, raw := api(t, e, http.MethodPost, "/forms", token, `{"name": "Contact", "recipients": []}`); !strings.Contains(raw, "recipients") || strings.Contains(raw, "json:") {
		t.Errorf("message d'un champ inconnu : %v", out["error"])
	}
	if na, nb := countForms(t, e, e.fx.siteA), countForms(t, e, e.fx.siteB); na != 1 || nb != 1 {
		t.Errorf("une saisie refusée a créé un formulaire : %d sur A, %d sur B", na, nb)
	}

	// An email-only form keeps the content in the email, as in the interface.
	code, created, raw := api(t, e, http.MethodPost, "/forms", token,
		`{"name": "Email seul", "store_submissions": false, "email_include_content": false}`)
	if code != http.StatusCreated {
		t.Fatalf("création : statut %d (%s)", code, raw)
	}
	if created["email_include_content"] != true || created["store_submissions"] != false {
		t.Errorf("mode email seul : %s", raw)
	}

	// Messages follow the requested language.
	req, _ := http.NewRequest(http.MethodPost, e.url+"/api/v1/forms", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept-Language", "en")
	resp, err := newClient().Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "form name is required") {
		t.Errorf("message en anglais attendu : %s", body)
	}
}

func TestAPILimiteDeDebit(t *testing.T) {
	e := setup(t, trustLoopback, func(a *handlers.App) { a.APILimiter = web.NewRateLimiter(2, time.Minute) })
	c := newClient()
	login(t, c, e.url, e.fx.memberA.Email)
	token := createToken(t, e, c, e.fx.siteA, "Agent")
	call := func(token, forwardedFor string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, e.url+"/api/v1/site", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if forwardedFor != "" {
			req.Header.Set("X-Forwarded-For", forwardedFor)
		}
		resp, err := newClient().Do(req)
		if err != nil {
			t.Fatalf("GET /site: %v", err)
		}
		resp.Body.Close()
		return resp
	}
	// Per address: the limit applies before the token is read, and so also counts refused calls.
	for i, tc := range []struct {
		token string
		want  int
	}{{token, http.StatusOK}, {"", http.StatusUnauthorized}, {token, http.StatusTooManyRequests}} {
		resp := call(tc.token, "")
		if resp.StatusCode != tc.want {
			t.Errorf("appel %d : statut %d (%d attendu)", i+1, resp.StatusCode, tc.want)
		}
		if tc.want == http.StatusTooManyRequests && resp.Header.Get("Retry-After") == "" {
			t.Errorf("un appel refusé pour débit doit dire quand réessayer")
		}
	}
	// Per token: the test client is a declared proxy, so each call announces another address.
	// Changing it gives the caller no extra allowance.
	for i, want := range []int{http.StatusOK, http.StatusTooManyRequests, http.StatusTooManyRequests} {
		if resp := call(token, "203.0.113."+string(rune('1'+i))); resp.StatusCode != want {
			t.Errorf("appel %d depuis une autre adresse : statut %d (%d attendu)", i+1, resp.StatusCode, want)
		}
	}
}

// A field missing from the body takes the value of the creation page. The notification goes
// to the token's creator, whose address is nevertheless not returned: they may have handed
// the token to a third party.
func TestAPICreationValeursParDefaut(t *testing.T) {
	e := setup(t)
	adm := newClient()
	login(t, adm, e.url, e.fx.admin.Email)
	token := createToken(t, e, adm, e.fx.siteA, "Agent de l'administrateur")

	code, created, raw := api(t, e, http.MethodPost, "/forms", token, `{"name": "Minimal"}`)
	if code != http.StatusCreated {
		t.Fatalf("création : statut %d (%s)", code, raw)
	}
	if created["retention_days"] != float64(90) || created["store_submissions"] != true || created["notify_email"] != true ||
		created["email_include_content"] != true || created["accept_attachments"] != false || created["captcha"] != false ||
		created["redirect_url"] != "" || strings.Contains(raw, "captcha.js") {
		t.Errorf("valeurs par défaut inattendues : %s", raw)
	}
	if strings.Contains(raw, "recipients") || strings.Contains(raw, e.fx.admin.Email) {
		t.Errorf("la réponse donne un destinataire : %s", raw)
	}
	form, err := e.q.GetFormByAccessKey(context.Background(), created["access_key"].(string))
	if err != nil || len(form.Recipients) != 1 || form.Recipients[0] != e.fx.admin.Email {
		t.Errorf("destinataires du formulaire : %v (err=%v)", form.Recipients, err)
	}
}

// Without email sending configured, a form created through the API keeps submissions without
// notifying, rather than promising an email that will never be sent.
func TestAPICreationSansEnvoiConfigure(t *testing.T) {
	e := setup(t, func(a *handlers.App) { a.Mailer = nil })
	c := newClient()
	login(t, c, e.url, e.fx.memberA.Email)
	token := createToken(t, e, c, e.fx.siteA, "Agent")
	code, created, raw := api(t, e, http.MethodPost, "/forms", token, `{"name": "Minimal"}`)
	if code != http.StatusCreated || created["notify_email"] != false || created["store_submissions"] != true {
		t.Errorf("création sans SMTP : statut %d, %s", code, raw)
	}
}

// What prevents a web page from calling the API on a user's behalf: it sets no cookie or CORS
// header, and refuses the preflight request from another origin.
func TestAPISansCORSNiCookie(t *testing.T) {
	e := setup(t)
	c := newClient()
	login(t, c, e.url, e.fx.memberA.Email)
	token := createToken(t, e, c, e.fx.siteA, "Agent")

	for _, tc := range []struct {
		method, path, token, body string
		preflight                 bool
	}{
		{method: http.MethodGet, path: "/site", token: token},
		{method: http.MethodPost, path: "/forms", token: token, body: `{"name": "Contact"}`},
		{method: http.MethodGet, path: "/site"},
		{method: http.MethodOptions, path: "/forms", preflight: true},
	} {
		req, _ := http.NewRequest(tc.method, e.url+"/api/v1"+tc.path, strings.NewReader(tc.body))
		req.Header.Set("Origin", "https://evil.tld")
		if tc.token != "" {
			req.Header.Set("Authorization", "Bearer "+tc.token)
		}
		if tc.preflight {
			req.Header.Set("Access-Control-Request-Method", http.MethodPost)
			req.Header.Set("Access-Control-Request-Headers", "authorization")
		}
		resp, err := newClient().Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", tc.method, tc.path, err)
		}
		resp.Body.Close()
		for name := range resp.Header {
			if strings.HasPrefix(name, "Access-Control-") || name == "Set-Cookie" {
				t.Errorf("%s %s : en-tête %s posé (%q)", tc.method, tc.path, name, resp.Header.Get(name))
			}
		}
		if tc.preflight && resp.StatusCode < 400 {
			t.Errorf("pré-requête CORS : statut %d (un refus est attendu)", resp.StatusCode)
		}
	}
}

// A token creates and lists forms, nothing else: no other method, no other resource, and it
// does not open the interface.
func TestAPIJetonNeFaitRienDAutre(t *testing.T) {
	e := setup(t)
	sub := storeSubmission(t, e, e.fx.formA, "https://exemple.fr", "message=secret-alpha")
	c := newClient()
	login(t, c, e.url, e.fx.memberA.Email)
	token := createToken(t, e, c, e.fx.siteA, "Agent")
	form := "/forms/" + e.fx.formA.ID.String()

	do := func(method, path string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(method, e.url+path, strings.NewReader(`{"name": "Pirate"}`))
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := newClient().Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}
	for _, call := range []struct{ method, path string }{
		{http.MethodPut, "/forms"}, {http.MethodPatch, "/forms"}, {http.MethodDelete, "/forms"},
		{http.MethodGet, form}, {http.MethodPut, form}, {http.MethodPatch, form}, {http.MethodDelete, form},
		{http.MethodGet, form + "/submissions"}, {http.MethodGet, "/submissions"},
		{http.MethodGet, "/submissions/" + sub.ID.String()},
		{http.MethodPost, "/site"}, {http.MethodDelete, "/site"}, {http.MethodGet, "/tokens"},
	} {
		code, body := do(call.method, "/api/v1"+call.path)
		if code != http.StatusNotFound && code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s : statut %d (404 ou 405 attendu)", call.method, call.path, code)
		}
		if strings.Contains(body, "secret-alpha") {
			t.Errorf("%s %s : une soumission fuit", call.method, call.path)
		}
	}
	// Presented to the interface, the token is not a session.
	for _, call := range []struct{ method, path string }{
		{http.MethodGet, "/sites/" + e.fx.siteA.ID.String()}, {http.MethodGet, form},
		{http.MethodGet, form + "/export.csv"}, {http.MethodGet, "/submissions/" + sub.ID.String()},
		{http.MethodGet, "/account"},
	} {
		if code, body := do(call.method, call.path); code != http.StatusSeeOther || strings.Contains(body, "secret-alpha") {
			t.Errorf("%s %s avec un jeton : statut %d (303 vers la connexion attendu)", call.method, call.path, code)
		}
	}
	form1, err := e.q.GetFormByAccessKey(context.Background(), e.fx.formA.AccessKey)
	if err != nil || form1.Name != "Contact Alpha" || countForms(t, e, e.fx.siteA) != 1 || countSubmissions(t, e, e.fx.formA) != 1 {
		t.Errorf("un appel refusé a modifié le site : %v", err)
	}
}

// Beyond one hundred forms on the site, the API stops creating them: a runaway script
// does not fill the database.
func TestAPIPlafondDeFormulaires(t *testing.T) {
	e := setup(t)
	c := newClient()
	login(t, c, e.url, e.fx.memberA.Email)
	token := createToken(t, e, c, e.fx.siteA, "Agent")
	for range 98 {
		mustForm(t, e.q, e.fx.siteA, "Rempli", false, true)
	}
	if code, _, raw := api(t, e, http.MethodPost, "/forms", token, `{"name": "Centième"}`); code != http.StatusCreated {
		t.Fatalf("centième formulaire : statut %d (%s)", code, raw)
	}
	if code, out, _ := api(t, e, http.MethodPost, "/forms", token, `{"name": "De trop"}`); code != http.StatusConflict || out["error"] == nil {
		t.Errorf("cent unième formulaire : statut %d (409 attendu)", code)
	}
	if n := countForms(t, e, e.fx.siteA); n != 100 {
		t.Errorf("formulaires du site : %d (100 attendus)", n)
	}
}

func TestJetonEcheanceSelonLaDureeChoisie(t *testing.T) {
	e := setup(t)
	c := newClient()
	login(t, c, e.url, e.fx.memberA.Email)
	// The two-hour window absorbs a DST change between today and the deadline, which Go and
	// Postgres do not count the same way.
	for _, days := range ui.TokenLifetimes {
		name := "Jeton " + strconv.Itoa(days)
		token := createTokenFor(t, e, c, e.fx.siteA, name, strconv.Itoa(days))
		var never, onTime bool
		if err := e.pool.QueryRow(context.Background(),
			`SELECT expires_at IS NULL,
			        coalesce(expires_at BETWEEN now() + make_interval(days => $2) - interval '2 hours' AND now() + make_interval(days => $2) + interval '2 hours', false)
			 FROM api_tokens WHERE name = $1`, name, days).Scan(&never, &onTime); err != nil {
			t.Fatalf("lecture du jeton %q: %v", name, err)
		}
		if never != (days == 0) || onTime != (days > 0) {
			t.Errorf("%s : sans échéance=%v, échéance à %d jours=%v", name, never, days, onTime)
		}
		if code, _, _ := api(t, e, http.MethodGet, "/site", token, ""); code != http.StatusOK {
			t.Errorf("%s : statut %d", name, code)
		}
	}
}

func TestJetonsDUnSiteBornes(t *testing.T) {
	e := setup(t)
	c := newClient()
	login(t, c, e.url, e.fx.memberA.Email)
	tokens := e.url + "/sites/" + e.fx.siteA.ID.String() + "/tokens"
	csrf := csrfToken(t, c, e.url+"/account")

	for _, tc := range []struct {
		what string
		vals url.Values
	}{
		{"sans nom", url.Values{"name": {"  "}, "expires_in": {"30"}}},
		{"nom trop long", url.Values{"name": {strings.Repeat("x", 81)}, "expires_in": {"30"}}},
		{"durée absente", url.Values{"name": {"Agent"}}},
		{"durée hors liste", url.Values{"name": {"Agent"}, "expires_in": {"3650"}}},
	} {
		tc.vals.Set("csrf_token", csrf)
		resp := postForm(t, c, tokens, tc.vals)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest || apiTokenRe.Match(body) {
			t.Errorf("%s : statut %d (400 sans jeton attendu)", tc.what, resp.StatusCode)
		}
	}

	for i := range 10 {
		createToken(t, e, c, e.fx.siteA, "Agent "+string(rune('A'+i)))
	}
	resp := postForm(t, c, tokens, url.Values{"csrf_token": {csrf}, "name": {"De trop"}, "expires_in": {"30"}})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || apiTokenRe.Match(body) {
		t.Errorf("onzième jeton : statut %d (400 sans jeton attendu)", resp.StatusCode)
	}
	var n int
	if err := e.pool.QueryRow(context.Background(), `SELECT count(*) FROM api_tokens`).Scan(&n); err != nil || n != 10 {
		t.Errorf("jetons en base : %d (10 attendus, err=%v)", n, err)
	}

	// Deleting the site deletes its tokens.
	resp = postForm(t, c, e.url+"/sites/"+e.fx.siteA.ID.String()+"/delete", url.Values{"csrf_token": {csrf}})
	resp.Body.Close()
	if err := e.pool.QueryRow(context.Background(), `SELECT count(*) FROM api_tokens`).Scan(&n); err != nil || n != 0 {
		t.Errorf("jetons après suppression du site : %d (0 attendu, err=%v)", n, err)
	}
}
