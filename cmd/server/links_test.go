package main

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"gitlab.com/detag_inno/naria/internal/antivirus/clamdtest"
	"gitlab.com/detag_inno/naria/internal/database"
)

// A phishing message: a quote request whose link leads to a lookalike page.
const phishing = "Un devis pour cinq PC Latitude 5430 est-il envisageable ? Le projet est précisé ici : https://shareits.online/fr/net/detag-informatique"

func refuseLinks(t *testing.T, e testEnv, form database.Form) {
	t.Helper()
	if _, err := e.pool.Exec(context.Background(), `UPDATE forms SET refuse_links = TRUE WHERE id = $1`, form.ID); err != nil {
		t.Fatal(err)
	}
}

func phishingBody(form database.Form, extra url.Values) string {
	v := url.Values{
		"access_key": {form.AccessKey},
		"name":       {"Nicolas Hocquet"},
		"email":      {"nicolas.hocquet7880@prodmail.online"},
		"message":    {phishing},
	}
	for k, vals := range extra {
		v[k] = vals
	}
	return v.Encode()
}

// With the option, a submission holding a link gets the success of any other, but is
// neither stored nor sent. The form page counts it, and one alert goes to the owner
// and one to the organisation administrator.
func TestLiensEcartes(t *testing.T) {
	e := setup(t)
	form := e.fx.formB
	refuseLinks(t, e, form)
	owner := newClient()
	login(t, owner, e.url, e.fx.memberB.Email)
	const notice = "contenaient un lien"

	_, valid := submit(t, e.url, submitOpts{body: "access_key=" + form.AccessKey + "&message=bonjour"})
	for _, extra := range []url.Values{
		nil,
		{"subject": {"voir www.shareits.online"}, "message": {"bonjour"}},
		{"https://shareits.online/x": {"oui"}, "message": {"bonjour"}},
	} {
		resp, out := submit(t, e.url, submitOpts{body: phishingBody(form, extra)})
		if resp.StatusCode != http.StatusOK || out != valid {
			t.Fatalf("envoi avec un lien : statut %d, %s (réponse d'un envoi valide : %s)", resp.StatusCode, out, valid)
		}
	}
	// The honeypot does not change the response either.
	if _, out := submit(t, e.url, submitOpts{body: phishingBody(form, url.Values{"botcheck": {"on"}})}); out != valid {
		t.Errorf("lien et champ piège : %s", out)
	}
	time.Sleep(50 * time.Millisecond)
	if n := countSubmissions(t, e, form); n != 1 {
		t.Fatalf("%d soumission(s) conservée(s), seule celle sans lien attendue", n)
	}

	// One alert per address, without the visitor's content, then nothing for a day.
	msgs := e.mailer.messages(t, 3)
	alerts := map[string]bool{}
	for _, m := range msgs {
		if strings.Contains(m.HTML, "shareits") || strings.Contains(m.HTML, "Hocquet") {
			t.Errorf("email avec le contenu écarté : à %v, sujet %q", m.To, m.Subject)
		}
		if strings.Contains(m.Subject, "lien") {
			alerts[strings.Join(m.To, ",")] = true
			if !strings.Contains(m.HTML, "/forms/"+form.ID.String()) {
				t.Errorf("alerte sans lien vers le formulaire : %s", m.HTML)
			}
		}
	}
	if len(alerts) != 2 || !alerts[e.fx.memberB.Email] || !alerts[e.fx.orgAdmin.Email] {
		t.Errorf("alertes : %v (propriétaire et administrateur attendus, une fois chacun)", alerts)
	}
	if len(msgs) != 3 {
		t.Errorf("%d email(s) : la notification de l'envoi valide et deux alertes attendues", len(msgs))
	}
	if _, page := get(t, owner, e.url+"/forms/"+form.ID.String()); !strings.Contains(page, notice) || !strings.Contains(page, "instance : 3.") {
		t.Errorf("la page du formulaire doit compter les trois envois écartés")
	}

	// A bare domain name is not a link written as one: the message is kept.
	submit(t, e.url, submitOpts{body: "access_key=" + form.AccessKey + "&message=" + url.QueryEscape("écrivez sur shareits.online, ASP.NET")})
	if n := countSubmissions(t, e, form); n != 2 {
		t.Errorf("domaine nu : %d soumission(s), 2 attendues", n)
	}

	// Without the option, the same message is kept.
	if _, out := submit(t, e.url, submitOpts{path: "/f/" + e.fx.formA.AccessKey, body: phishingBody(e.fx.formA, nil), origin: "https://www.exemple.fr"}); !strings.Contains(out, `"success":true`) {
		t.Fatalf("formulaire sans l'option : %s", out)
	}
	if n := countSubmissions(t, e, e.fx.formA); n != 1 {
		t.Errorf("formulaire sans l'option : %d soumission(s), 1 attendue", n)
	}
}

// The option is set from the settings page and recorded in the audit log.
func TestLiensReglage(t *testing.T) {
	e := setup(t)
	c := newClient()
	login(t, c, e.url, e.fx.memberA.Email)
	token := csrfToken(t, c, e.url+"/account")
	settings := e.url + "/forms/" + e.fx.formA.ID.String() + "/settings"

	resp := postForm(t, c, settings, formValues(token, url.Values{"refuse_links": {"1"}}))
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("réglages : statut %d", resp.StatusCode)
	}
	form, err := e.q.GetFormByAccessKey(context.Background(), e.fx.formA.AccessKey)
	if err != nil || !form.RefuseLinks {
		t.Fatalf("option non enregistrée (err=%v)", err)
	}
	if _, page := get(t, c, settings); !strings.Contains(page, `name="refuse_links" value="1" checked`) {
		t.Errorf("case non cochée sur la page des réglages")
	}
	var changed string
	if err := e.pool.QueryRow(context.Background(),
		`SELECT detail::jsonb->>'changed' FROM audit_log WHERE entity_id = $1 AND action = 'form.updated' ORDER BY created_at DESC LIMIT 1`,
		e.fx.formA.ID).Scan(&changed); err != nil || !strings.Contains(changed, "refuse_links") {
		t.Errorf("journal d'audit : changed=%q (err=%v)", changed, err)
	}
}

// The notification never carries a clickable link written by the visitor; what is
// stored stays as it was sent.
func TestLiensNeutralisesDansLaNotification(t *testing.T) {
	hook := newChatHook(t)
	e := setup(t, hook.trust)
	c := newClient()
	login(t, c, e.url, e.fx.memberA.Email)
	token := csrfToken(t, c, e.url+"/account")
	resp := postForm(t, c, e.url+"/forms/"+e.fx.formA.ID.String()+"/settings", formValues(token, url.Values{
		"notify_email": {"1"}, "recipients": {e.fx.memberA.Email}, "email_include_content": {"1"},
		"slack_webhook_url": {hook.url("/slack")}, "discord_webhook_url": {hook.url("/discord")},
		"telegram_bot_token": {telegramToken}, "telegram_chat_id": {"-100123"}, "chat_include_content": {"1"},
	}))
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("réglages : statut %d", resp.StatusCode)
	}

	body := phishingBody(e.fx.formA, url.Values{"subject": {"Devis https://evil.online/x"}, "voir www.evil.online": {"oui"}})
	sub := storeSubmission(t, e, e.fx.formA, "https://www.exemple.fr", body)
	const defanged = "hxxps://shareits[.]online/fr/net/detag-informatique"

	msg := e.mailer.messages(t, 1)[0]
	if !strings.Contains(msg.HTML, defanged) || strings.Contains(msg.HTML, "https://shareits.online") {
		t.Errorf("lien non neutralisé dans l'email : %s", msg.HTML)
	}
	if !strings.Contains(msg.Subject, "hxxps://evil[.]online/x") {
		t.Errorf("objet : %q", msg.Subject)
	}
	if !strings.Contains(msg.HTML, "www[.]evil[.]online") || strings.Contains(msg.HTML, "www.evil.online") {
		t.Errorf("lien non neutralisé dans un nom de champ : %s", msg.HTML)
	}
	// The visitor's address stays usable for the reply.
	if msg.ReplyTo != "nicolas.hocquet7880@prodmail.online" || !strings.Contains(msg.HTML, "nicolas.hocquet7880@prodmail.online") {
		t.Errorf("adresse du visiteur altérée : reply-to %q", msg.ReplyTo)
	}
	for _, path := range []string{"/slack", "/discord", "/bot" + telegramToken + "/sendMessage"} {
		alert := hook.received(t, path, 1)[0]
		if !strings.Contains(alert, defanged) || strings.Contains(alert, "https://shareits.online") ||
			!strings.Contains(alert, "www[.]evil[.]online") || strings.Contains(alert, "www.evil.online") {
			t.Errorf("%s : lien non neutralisé dans l'alerte : %s", path, alert)
		}
	}
	if _, page := get(t, c, e.url+"/submissions/"+sub.ID.String()); !strings.Contains(page, "https://shareits.online/fr/net/detag-informatique") {
		t.Errorf("la soumission conservée doit garder le texte envoyé")
	}
}

// A blocked domain also covers the links of a message, and an extension covers every
// domain that ends with it, sender or link.
func TestBlocageDesLiensEtDesExtensions(t *testing.T) {
	e := setup(t)
	owner := newClient()
	login(t, owner, e.url, e.fx.memberB.Email)
	token := csrfToken(t, owner, e.url+"/")
	blockedPath := "/sites/" + e.fx.siteB.ID.String() + "/blocked"
	form := e.fx.formB
	block := func(value string) {
		t.Helper()
		resp := postForm(t, owner, e.url+blockedPath, url.Values{"csrf_token": {token}, "value": {value}})
		resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("blocage de %q : statut %d", value, resp.StatusCode)
		}
	}
	send := func(message string) {
		t.Helper()
		body := url.Values{"access_key": {form.AccessKey}, "email": {"ada@exemple.org"}, "message": {message}}.Encode()
		if _, out := submit(t, e.url, submitOpts{body: body}); !strings.Contains(out, `"success":true`) {
			t.Fatalf("envoi : %s", out)
		}
	}

	block("shareits.online")
	send(phishing)
	send("le lien : https://ｓｈａｒｅｉｔｓ．online/x")
	send("écrivez sur fr.shareits.online.")
	if n := countSubmissions(t, e, form); n != 0 {
		t.Fatalf("lien vers un domaine bloqué : %d soumission(s) conservée(s)", n)
	}
	send("rien à voir : https://exemple.org/")
	if n := countSubmissions(t, e, form); n != 1 {
		t.Fatalf("lien vers un autre domaine : %d soumission(s), 1 attendue", n)
	}
	// The subject reaches the owner too.
	body := url.Values{"access_key": {form.AccessKey}, "subject": {"voir https://shareits.online/x"}, "message": {"bonjour"}}.Encode()
	submit(t, e.url, submitOpts{body: body})
	if n := countSubmissions(t, e, form); n != 1 {
		t.Fatalf("lien bloqué dans l'objet : %d soumission(s), 1 attendue", n)
	}

	block("*.online")
	var stored string
	if err := e.pool.QueryRow(context.Background(),
		`SELECT value FROM site_blocked_senders WHERE site_id = $1 AND value LIKE '.%'`, e.fx.siteB.ID).Scan(&stored); err != nil || stored != ".online" {
		t.Fatalf("extension enregistrée : %q (err=%v)", stored, err)
	}
	body = url.Values{"access_key": {form.AccessKey}, "email": {"nicolas@prodmail.online"}, "message": {"bonjour"}}.Encode()
	submit(t, e.url, submitOpts{body: body})
	send("https://autre.online/")
	if n := countSubmissions(t, e, form); n != 1 {
		t.Fatalf("extension bloquée : %d soumission(s), 1 attendue", n)
	}
	var kind string
	if err := e.pool.QueryRow(context.Background(),
		`SELECT detail::jsonb->>'kind' FROM audit_log WHERE entity_id = $1 AND action = 'site.sender_blocked' ORDER BY created_at DESC LIMIT 1`,
		e.fx.siteB.ID).Scan(&kind); err != nil || kind != "tld" {
		t.Errorf("journal d'audit : kind=%q (err=%v)", kind, err)
	}
}

// A submission dropped for its link, or for a link to a blocked domain, never
// reaches the antivirus: its files are neither scanned nor kept.
func TestLiensAvantLAntivirus(t *testing.T) {
	clamd := clamdtest.Start(t)
	e := setup(t, withAntivirus(clamd))
	form := e.fx.formB
	acceptAttachments(t, e, form)
	owner := newClient()
	login(t, owner, e.url, e.fx.memberB.Email)
	resp := postForm(t, owner, e.url+"/sites/"+e.fx.siteB.ID.String()+"/blocked",
		url.Values{"csrf_token": {csrfToken(t, owner, e.url+"/")}, "value": {"shareits.online"}})
	resp.Body.Close()

	send := func() {
		t.Helper()
		ct, body := multipartBody([]string{"message", phishing}, []string{"cv", "cv.pdf", clamdtest.Marker})
		if resp, out := submit(t, e.url, submitOpts{path: "/f/" + form.AccessKey, contentType: ct, body: body}); resp.StatusCode != http.StatusOK {
			t.Fatalf("statut %d, corps %s", resp.StatusCode, out)
		}
	}
	send() // blocked domain
	refuseLinks(t, e, form)
	send() // link refused
	if got := clamd.Streams(); len(got) != 0 {
		t.Errorf("%d flux envoyé(s) à l'antivirus", len(got))
	}
	if n := countSubmissions(t, e, form); n != 0 {
		t.Errorf("%d soumission(s) conservée(s)", n)
	}
}

// The option is part of the form an API token creates.
func TestLiensParLAPI(t *testing.T) {
	e := setup(t)
	adm := newClient()
	login(t, adm, e.url, e.fx.orgAdmin.Email)
	token := createToken(t, e, adm, e.fx.siteA, "Agent")
	code, created, raw := api(t, e, http.MethodPost, "/forms", token, `{"name": "Sans liens", "refuse_links": true}`)
	if code != http.StatusCreated || created["refuse_links"] != true {
		t.Fatalf("création : statut %d (%s)", code, raw)
	}
	form, err := e.q.GetFormByAccessKey(context.Background(), created["access_key"].(string))
	if err != nil || !form.RefuseLinks {
		t.Errorf("option non enregistrée (err=%v)", err)
	}
}
