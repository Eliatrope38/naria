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
