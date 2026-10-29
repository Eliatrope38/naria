package main

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestBlocageDExpediteurs(t *testing.T) {
	e := setup(t)
	owner := newClient()
	login(t, owner, e.url, e.fx.memberA.Email)
	token := csrfToken(t, owner, e.url+"/")
	blockedPath := "/sites/" + e.fx.siteA.ID.String() + "/blocked"

	block := func(value string) *http.Response {
		t.Helper()
		resp := postForm(t, owner, e.url+blockedPath, url.Values{"csrf_token": {token}, "value": {value}})
		resp.Body.Close()
		return resp
	}
	send := func(addr string) (*http.Response, string) {
		t.Helper()
		body := url.Values{
			"access_key": {e.fx.formA.AccessKey},
			"name":       {"Visiteur"},
			"email":      {addr},
			"message":    {"Bonjour"},
			"botcheck":   {""},
		}.Encode()
		return submit(t, e.url, submitOpts{body: body, origin: "https://www.exemple.fr"})
	}

	// A domain covers its subdomains; the owner may type it as a URL.
	if resp := block("https://Spam.Test/"); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("blocage du domaine : statut %d", resp.StatusCode)
	}
	if resp, out := send("bot@mail.spam.test"); resp.StatusCode != http.StatusOK || !strings.Contains(out, `"success":true`) {
		t.Fatalf("expéditeur bloqué : statut %d, corps %s", resp.StatusCode, out)
	}
	if n := countSubmissions(t, e, e.fx.formA); n != 0 {
		t.Fatalf("soumission d'un expéditeur bloqué conservée : %d", n)
	}

	// Control: an unblocked sender is stored.
	if _, out := send("ada@exemple.org"); !strings.Contains(out, `"success":true`) {
		t.Fatalf("expéditeur non bloqué refusé : %s", out)
	}
	if n := countSubmissions(t, e, e.fx.formA); n != 1 {
		t.Fatalf("soumission non bloquée : %d conservée(s), 1 attendue", n)
	}

	// An address blocks only that address, not its domain.
	block("Ada@exemple.org")
	send("ada@exemple.org")
	send("autre@exemple.org")
	if n := countSubmissions(t, e, e.fx.formA); n != 2 {
		t.Fatalf("après blocage de l'adresse : %d soumissions, 2 attendues", n)
	}

	// Another account cannot change this site's blocklist.
	other := newClient()
	login(t, other, e.url, e.fx.memberB.Email)
	otherToken := csrfToken(t, other, e.url+"/")
	resp := postForm(t, other, e.url+blockedPath, url.Values{"csrf_token": {otherToken}, "value": {"intrus.test"}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("blocage par un autre compte : statut %d (404 attendu)", resp.StatusCode)
	}

	// A value that is neither an address nor a domain is refused.
	resp = postForm(t, owner, e.url+blockedPath, url.Values{"csrf_token": {token}, "value": {"pas une adresse"}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("valeur invalide : statut %d (400 attendu)", resp.StatusCode)
	}

	// The reply address is a sender too, even when the form has no email field.
	body := url.Values{
		"access_key": {e.fx.formA.AccessKey},
		"name":       {"Visiteur"},
		"replyto":    {"bot@mail.spam.test"},
		"message":    {"Bonjour"},
		"botcheck":   {""},
	}.Encode()
	if _, out := submit(t, e.url, submitOpts{body: body, origin: "https://www.exemple.fr"}); !strings.Contains(out, `"success":true`) {
		t.Fatalf("reply-to bloqué : %s", out)
	}
	if n := countSubmissions(t, e, e.fx.formA); n != 2 {
		t.Fatalf("reply-to bloqué conservé : %d soumissions, 2 attendues", n)
	}

	// Unblocking lets the sender through again.
	var entry string
	if err := e.pool.QueryRow(context.Background(),
		`SELECT id::text FROM site_blocked_senders WHERE value = 'spam.test'`).Scan(&entry); err != nil {
		t.Fatalf("lecture de l'entrée : %v", err)
	}
	resp = postForm(t, owner, e.url+blockedPath+"/"+entry+"/delete", url.Values{"csrf_token": {token}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("déblocage : statut %d", resp.StatusCode)
	}
	send("bot@mail.spam.test")
	if n := countSubmissions(t, e, e.fx.formA); n != 3 {
		t.Fatalf("après déblocage : %d soumissions, 3 attendues", n)
	}
}

func TestBlocageDesAdressesJetables(t *testing.T) {
	e := setup(t)
	owner := newClient()
	login(t, owner, e.url, e.fx.memberA.Email)
	token := csrfToken(t, owner, e.url+"/")
	disposablePath := e.url + "/sites/" + e.fx.siteA.ID.String() + "/blocked/disposable"

	setOption := func(c *http.Client, csrf string, on bool) int {
		t.Helper()
		v := url.Values{"csrf_token": {csrf}}
		if on {
			v.Set("block_disposable", "1")
		}
		resp := postForm(t, c, disposablePath, v)
		resp.Body.Close()
		return resp.StatusCode
	}
	send := func(field, addr string) {
		t.Helper()
		body := url.Values{
			"access_key": {e.fx.formA.AccessKey},
			"name":       {"Visiteur"},
			field:        {addr},
			"message":    {"Bonjour"},
			"botcheck":   {""},
		}.Encode()
		if resp, out := submit(t, e.url, submitOpts{body: body, origin: "https://www.exemple.fr"}); resp.StatusCode != http.StatusOK || !strings.Contains(out, `"success":true`) {
			t.Fatalf("soumission de %s : statut %d, corps %s", addr, resp.StatusCode, out)
		}
	}
	optionOn := func() bool {
		t.Helper()
		var on bool
		if err := e.pool.QueryRow(context.Background(),
			`SELECT block_disposable FROM sites WHERE id = $1`, e.fx.siteA.ID).Scan(&on); err != nil {
			t.Fatalf("lecture de l'option : %v", err)
		}
		return on
	}

	// Off by default: a disposable address is stored like any other.
	send("email", "bot@yopmail.com")
	if n := countSubmissions(t, e, e.fx.formA); n != 1 {
		t.Fatalf("option désactivée : %d soumission(s), 1 attendue", n)
	}

	if code := setOption(owner, token, true); code != http.StatusSeeOther {
		t.Fatalf("activation : statut %d", code)
	}
	var kind string
	if err := e.pool.QueryRow(context.Background(),
		`SELECT detail::jsonb->>'kind' FROM audit_log WHERE entity_id = $1 AND action = 'site.sender_blocked' ORDER BY created_at DESC LIMIT 1`,
		e.fx.siteA.ID).Scan(&kind); err != nil || kind != "disposable" {
		t.Errorf("journal d'audit : kind=%q (err=%v)", kind, err)
	}

	// The visitor gets a success, and nothing is stored, for the address, a
	// subdomain of the listed domain, or the reply address.
	send("email", "bot@yopmail.com")
	send("email", "Bot@Mail.YopMail.com")
	send("replyto", "bot@mailinator.com")
	if n := countSubmissions(t, e, e.fx.formA); n != 1 {
		t.Fatalf("adresses jetables conservées : %d soumission(s), 1 attendue", n)
	}

	// Control: an ordinary address still goes through.
	send("email", "ada@exemple.org")
	if n := countSubmissions(t, e, e.fx.formA); n != 2 {
		t.Fatalf("adresse ordinaire : %d soumission(s), 2 attendues", n)
	}

	// Neither another account nor a reader of the site can turn the option off.
	if resp := grantRead(t, e, e.fx.orgAdmin, e.fx.siteA, e.fx.memberB); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("accord de lecture : statut %d", resp.StatusCode)
	}
	reader := newClient()
	login(t, reader, e.url, e.fx.memberB.Email)
	if code := setOption(reader, csrfToken(t, reader, e.url+"/"), false); code != http.StatusNotFound {
		t.Errorf("désactivation par un lecteur : statut %d (404 attendu)", code)
	}
	outsider := newClient()
	login(t, outsider, e.url, e.fx.memberC.Email)
	if code := setOption(outsider, csrfToken(t, outsider, e.url+"/"), false); code != http.StatusNotFound {
		t.Errorf("désactivation par un autre compte : statut %d (404 attendu)", code)
	}
	orgBAdmin := newClient()
	login(t, orgBAdmin, e.url, e.fx.orgBAdmin.Email)
	if code := setOption(orgBAdmin, csrfToken(t, orgBAdmin, e.url+"/account"), false); code != http.StatusNotFound {
		t.Errorf("désactivation par l'administrateur d'une autre organisation : statut %d (404 attendu)", code)
	}
	if !optionOn() {
		t.Fatal("l'option a été désactivée par un compte sans droit d'écriture")
	}

	// The administrator of the owner's organisation can change it.
	orgAdmin := newClient()
	login(t, orgAdmin, e.url, e.fx.orgAdmin.Email)
	adminToken := csrfToken(t, orgAdmin, e.url+"/account")
	if code := setOption(orgAdmin, adminToken, false); code != http.StatusSeeOther || optionOn() {
		t.Fatalf("désactivation par l'administrateur de l'organisation : statut %d", code)
	}
	if code := setOption(orgAdmin, adminToken, true); code != http.StatusSeeOther || !optionOn() {
		t.Fatalf("activation par l'administrateur de l'organisation : statut %d", code)
	}

	// The option belongs to siteA: siteB still stores disposable addresses.
	body := url.Values{
		"access_key": {e.fx.formB.AccessKey},
		"email":      {"bot@yopmail.com"},
		"message":    {"Bonjour"},
	}.Encode()
	if _, out := submit(t, e.url, submitOpts{body: body, origin: "https://www.exemple.fr"}); !strings.Contains(out, `"success":true`) {
		t.Fatalf("soumission sur un autre site : %s", out)
	}
	if n := countSubmissions(t, e, e.fx.formB); n != 1 {
		t.Fatalf("autre site : %d soumission(s), 1 attendue", n)
	}

	// Turned off, a disposable address is stored again.
	if code := setOption(owner, token, false); code != http.StatusSeeOther || optionOn() {
		t.Fatalf("désactivation : statut %d, option encore active : %v", code, optionOn())
	}
	send("email", "bot@yopmail.com")
	if n := countSubmissions(t, e, e.fx.formA); n != 3 {
		t.Fatalf("après désactivation : %d soumission(s), 3 attendues", n)
	}

	// Saving the same state again records nothing.
	setOption(owner, token, false)
	var actions string
	if err := e.pool.QueryRow(context.Background(),
		`SELECT string_agg(action, ',' ORDER BY created_at) FROM audit_log WHERE entity_id = $1 AND detail::jsonb->>'kind' = 'disposable'`,
		e.fx.siteA.ID).Scan(&actions); err != nil || actions != "site.sender_blocked,site.sender_unblocked,site.sender_blocked,site.sender_unblocked" {
		t.Errorf("journal d'audit : %q (err=%v)", actions, err)
	}
}
