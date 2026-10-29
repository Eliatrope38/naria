package main

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"gitlab.com/detag_inno/naria/internal/database"
)

func setHoneypot(t *testing.T, e testEnv, form database.Form, name string) {
	t.Helper()
	if _, err := e.pool.Exec(context.Background(), `UPDATE forms SET honeypot_field = $2 WHERE id = $1`, form.ID, name); err != nil {
		t.Fatal(err)
	}
}

func honeypotColumn(t *testing.T, e testEnv, form database.Form) *string {
	t.Helper()
	var name *string
	if err := e.pool.QueryRow(context.Background(), `SELECT honeypot_field FROM forms WHERE id = $1`, form.ID).Scan(&name); err != nil {
		t.Fatal(err)
	}
	return name
}

// The form's own trap works like "botcheck", which stays recognised. Left empty, it is
// not part of the visitor's data.
func TestChampPiegeDuFormulaire(t *testing.T) {
	e := setup(t)
	form := e.fx.formB
	setHoneypot(t, e, form, "order_ref")
	path := "/f/" + form.AccessKey

	for _, body := range []string{"message=spam&order_ref=on", "message=spam&botcheck=on"} {
		resp, out := submit(t, e.url, submitOpts{path: path, body: body})
		if resp.StatusCode != http.StatusOK || !strings.Contains(out, `"success":true`) {
			t.Fatalf("%s : statut %d, corps %s", body, resp.StatusCode, out)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if n := countSubmissions(t, e, form); n != 0 {
		t.Fatalf("%d soumission(s) de robot conservée(s)", n)
	}

	if resp, out := submit(t, e.url, submitOpts{path: path, body: "message=bonjour&order_ref="}); resp.StatusCode != http.StatusOK {
		t.Fatalf("visiteur : statut %d, corps %s", resp.StatusCode, out)
	}
	if n := countSubmissions(t, e, form); n != 1 {
		t.Fatalf("visiteur : %d soumission(s), 1 attendue", n)
	}
	msgs := e.mailer.messages(t, 1)
	if len(msgs) != 1 || !strings.Contains(msgs[0].HTML, "bonjour") || strings.Contains(msgs[0].HTML, "order_ref") {
		t.Errorf("la notification doit porter le message sans le champ piège : %v", msgs)
	}

	// Filled alone, the trap does not count as content: the bot gets the visitor's refusal.
	_, plain := submit(t, e.url, submitOpts{path: path, body: "message="})
	if _, trapped := submit(t, e.url, submitOpts{path: path, body: "message=&order_ref=on"}); trapped != plain {
		t.Errorf("la réponse dépend du champ piège : %s, sans piège %s", trapped, plain)
	}
}

// The snippet names the form's trap and does not point it out; a form without one
// keeps "botcheck".
func TestChampPiegeCodeIntegration(t *testing.T) {
	e := setup(t)
	setHoneypot(t, e, e.fx.formA, "order_ref")
	c := newClient()
	login(t, c, e.url, e.fx.memberA.Email)
	_, page := get(t, c, e.url+"/forms/"+e.fx.formA.ID.String())
	if !strings.Contains(page, `name=&#34;order_ref&#34;`) || strings.Contains(page, "botcheck") {
		t.Errorf("le code d'intégration doit porter le champ order_ref, et lui seul")
	}
	if strings.Contains(page, "display:none") {
		t.Errorf("le champ piège est masqué par display:none")
	}

	other := newClient()
	login(t, other, e.url, e.fx.memberB.Email)
	if _, page := get(t, other, e.url+"/forms/"+e.fx.formB.ID.String()); !strings.Contains(page, `name=&#34;botcheck&#34;`) {
		t.Errorf("un formulaire sans champ piège propre doit garder botcheck")
	}
}

// A new form comes with a trap name; the settings page changes or clears it, refuses a
// name that would collide, and the audit log records the change.
func TestChampPiegeReglage(t *testing.T) {
	e := setup(t)
	c := newClient()
	login(t, c, e.url, e.fx.memberA.Email)
	token := csrfToken(t, c, e.url+"/account")

	if _, page := get(t, c, e.url+"/sites/"+e.fx.siteA.ID.String()+"/forms/new"); strings.Contains(page, `name="honeypot_field" value=""`) {
		t.Errorf("la page de création doit proposer un nom de champ piège")
	}

	settings := e.url + "/forms/" + e.fx.formA.ID.String() + "/settings"
	resp := postForm(t, c, settings, formValues(token, url.Values{"honeypot_field": {"promo_code"}}))
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("réglages : statut %d", resp.StatusCode)
	}
	if got := honeypotColumn(t, e, e.fx.formA); got == nil || *got != "promo_code" {
		t.Fatalf("nom non enregistré : %v", got)
	}
	var changed string
	if err := e.pool.QueryRow(context.Background(),
		`SELECT detail::jsonb->>'changed' FROM audit_log WHERE entity_id = $1 AND action = 'form.updated' ORDER BY created_at DESC LIMIT 1`,
		e.fx.formA.ID).Scan(&changed); err != nil || !strings.Contains(changed, "honeypot_field") {
		t.Errorf("journal d'audit : changed=%q (err=%v)", changed, err)
	}

	for _, name := range []string{"Email", "access_key", "1abc", "nom avec espace", strings.Repeat("a", 41)} {
		resp := postForm(t, c, settings, formValues(token, url.Values{"honeypot_field": {name}}))
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%q accepté : statut %d", name, resp.StatusCode)
		}
	}
	if got := honeypotColumn(t, e, e.fx.formA); got == nil || *got != "promo_code" {
		t.Errorf("un nom refusé a remplacé le précédent : %v", got)
	}

	resp = postForm(t, c, settings, formValues(token, nil))
	resp.Body.Close()
	if got := honeypotColumn(t, e, e.fx.formA); resp.StatusCode != http.StatusSeeOther || got != nil {
		t.Errorf("nom vidé : statut %d, valeur %v", resp.StatusCode, got)
	}
}

// Through the API, a form gets a trap name unless the body sets one or clears it.
func TestChampPiegeParLAPI(t *testing.T) {
	e := setup(t)
	adm := newClient()
	login(t, adm, e.url, e.fx.orgAdmin.Email)
	token := createToken(t, e, adm, e.fx.siteA, "Agent")

	code, created, raw := api(t, e, http.MethodPost, "/forms", token, `{"name": "Par défaut"}`)
	name, _ := created["honeypot_field"].(string)
	html, _ := created["html"].(string)
	if code != http.StatusCreated || name == "" || !strings.Contains(html, `name="`+name+`"`) || strings.Contains(html, "botcheck") {
		t.Errorf("nom tiré à la création : statut %d (%s)", code, raw)
	}

	code, created, raw = api(t, e, http.MethodPost, "/forms", token, `{"name": "Choisi", "honeypot_field": "ref-client"}`)
	if html, _ := created["html"].(string); code != http.StatusCreated || created["honeypot_field"] != "ref-client" || !strings.Contains(html, `name="ref-client"`) {
		t.Errorf("nom choisi : statut %d (%s)", code, raw)
	}

	code, created, raw = api(t, e, http.MethodPost, "/forms", token, `{"name": "Sans", "honeypot_field": ""}`)
	if html, _ := created["html"].(string); code != http.StatusCreated || created["honeypot_field"] != "" || !strings.Contains(html, `name="botcheck"`) {
		t.Errorf("sans nom : statut %d (%s)", code, raw)
	}

	if code, _, raw := api(t, e, http.MethodPost, "/forms", token, `{"name": "Collision", "honeypot_field": "message"}`); code != http.StatusBadRequest {
		t.Errorf("nom réservé accepté : statut %d (%s)", code, raw)
	}
}
