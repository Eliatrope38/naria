package main

// Integration tests for the language of a form's notifications, skipped without TEST_DATABASE_URL.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"gitlab.com/detag_inno/naria/internal/database"
	"gitlab.com/detag_inno/naria/internal/email"
)

// notificationTexts: what each notification says in one language, and what the other
// language does not say. No text contains an apostrophe, which the HTML of an email escapes.
type notificationTexts struct{ mail, noContent, notStored, chat, test, quota, captcha []string }

var notificationsIn = map[string]notificationTexts{
	"fr": {
		mail:      []string{"] Nouvelle soumission : Contact", "Nouvelle soumission du formulaire", "Voir la soumission", "Envoyé par Test."},
		noContent: []string{"] Nouvelle soumission : Contact", "consultez-le dans", "Voir la soumission", "Envoyé par Test."},
		notStored: []string{"] Nouvelle soumission : Contact", "pas été conservée", "Envoyé par Test."},
		chat:      []string{"Nouvelle soumission : Contact", "Consultez-la dans", "Voir la soumission"},
		test:      []string{"Message de test : Contact", "Ce canal recevra une alerte"},
		quota:     []string{"] Quota de stockage atteint : Contact", "a atteint son quota de stockage", "que par email", "Ouvrir le formulaire", "Envoyé par Test."},
		captcha:   []string{"] Envoi refusé faute de vérification anti-robot : Contact", "son navigateur", "Ouvrir le formulaire", "Envoyé par Test."},
	},
	"en": {
		mail:      []string{"] New submission: Contact", "New submission of the form", "View submission", "Sent by Test."},
		noContent: []string{"] New submission: Contact", "read it in the interface", "View submission", "Sent by Test."},
		notStored: []string{"] New submission: Contact", "was not kept", "Sent by Test."},
		chat:      []string{"New submission: Contact", "Read it in the interface", "View submission"},
		test:      []string{"Test message: Contact", "This channel will receive an alert"},
		quota:     []string{"] Storage quota reached: Contact", "has reached its storage quota", "only arrive by email", "Open the form", "Sent by Test."},
		captcha:   []string{"] Submission refused for lack of the anti-bot check: Contact", "their browser", "Open the form", "Sent by Test."},
	},
}

// otherLang: the language the form does not speak, and the visitor requests.
var otherLang = map[string]string{"fr": "en", "en": "fr"}

// visitorSpeaks: the headers of a visitor whose browser requests a language, interface
// cookie included.
func visitorSpeaks(lang string) http.Header {
	return http.Header{"Accept-Language": {lang}, "Cookie": {"lang=" + lang}}
}

// written checks that a text contains all the expected sentences, and none of those of the
// other language.
func written(t *testing.T, what, text string, want, unwanted []string) {
	t.Helper()
	for _, s := range want {
		if !strings.Contains(text, s) {
			t.Errorf("%s : %q attendu dans %s", what, s, text)
		}
	}
	for _, s := range unwanted {
		if strings.Contains(text, s) {
			t.Errorf("%s : %q dans une notification qui ne doit pas être dans cette langue : %s", what, s, text)
		}
	}
}

func mailText(m email.Message) string { return m.Subject + "\n" + m.HTML }

func setNotificationLang(t *testing.T, e testEnv, form database.Form, lang string) {
	t.Helper()
	if _, err := e.pool.Exec(context.Background(), `UPDATE forms SET notification_lang = $2 WHERE id = $1`, form.ID, lang); err != nil {
		t.Fatal(err)
	}
}

func notificationLang(t *testing.T, e testEnv, formID any) (lang string) {
	t.Helper()
	if err := e.pool.QueryRow(context.Background(), `SELECT notification_lang FROM forms WHERE id = $1`, formID).Scan(&lang); err != nil {
		t.Fatalf("lecture de la langue: %v", err)
	}
	return lang
}

// The email of a submission and the discussion alert are written in the language set on
// the form, and the message of the 'Tester' button in the language shown on the settings
// page. The language requested by the visitor's browser changes nothing.
func TestLangueDesNotifications(t *testing.T) {
	for lang, other := range otherLang {
		t.Run(lang, func(t *testing.T) {
			hook := newChatHook(t)
			e := setup(t, hook.trust)
			want, unwanted := notificationsIn[lang], notificationsIn[other]
			c := newClient()
			login(t, c, e.url, e.fx.memberA.Email)
			base := e.url + "/forms/" + e.fx.formA.ID.String()
			vals := formValues(csrfToken(t, c, e.url+"/account"), url.Values{
				"notification_lang": {lang}, "notify_email": {"1"}, "recipients": {"dest@exemple.fr"},
				"email_include_content": {"1"}, "slack_webhook_url": {hook.url("/slack")},
			})
			save := func() {
				t.Helper()
				resp := postForm(t, c, base+"/settings", vals)
				resp.Body.Close()
				if resp.StatusCode != http.StatusSeeOther {
					t.Fatalf("enregistrement : statut %d", resp.StatusCode)
				}
			}
			send := func() {
				t.Helper()
				resp, out := submit(t, e.url, submitOpts{
					path: "/f/" + e.fx.formA.AccessKey, body: "message=bonjour", origin: "https://exemple.fr", header: visitorSpeaks(other),
				})
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("soumission : statut %d (%s)", resp.StatusCode, out)
				}
			}

			save()
			if got := notificationLang(t, e, e.fx.formA.ID); got != lang {
				t.Fatalf("langue enregistrée = %q", got)
			}
			if _, page := get(t, c, base+"/settings"); !strings.Contains(page, `<option value="`+lang+`" selected>`) {
				t.Errorf("la page de réglages doit réafficher la langue enregistrée")
			}

			send()
			written(t, "email", mailText(e.mailer.messages(t, 1)[0]), want.mail, unwanted.mail)
			written(t, "alerte", hook.received(t, "/slack", 1)[0], want.chat, unwanted.chat)

			// The test message follows the language entered on the page, saved or not.
			for i, tested := range []string{lang, other} {
				test := url.Values{"channel": {"slack"}}
				for k, v := range vals {
					test[k] = v
				}
				test.Set("notification_lang", tested)
				resp := postForm(t, c, base+"/webhooks/test", test)
				resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("test en %s : statut %d", tested, resp.StatusCode)
				}
				written(t, "message de test en "+tested, hook.received(t, "/slack", 2+i)[1+i],
					notificationsIn[tested].test, notificationsIn[otherLang[tested]].test)
			}
			if got := notificationLang(t, e, e.fx.formA.ID); got != lang {
				t.Errorf("le test a changé la langue enregistrée : %q", got)
			}

			// A request that gives no language keeps the form's language.
			vals.Del("notification_lang")
			save()
			if got := notificationLang(t, e, e.fx.formA.ID); got != lang {
				t.Errorf("réglages enregistrés sans la langue : %q", got)
			}
			test := url.Values{"channel": {"slack"}}
			for k, v := range vals {
				test[k] = v
			}
			resp := postForm(t, c, base+"/webhooks/test", test)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("test sans la langue : statut %d", resp.StatusCode)
			}
			written(t, "message de test sans la langue", hook.received(t, "/slack", 4)[3], want.test, unwanted.test)

			// The email without the content has its own text.
			vals.Del("email_include_content")
			save()
			send()
			written(t, "email sans contenu", mailText(e.mailer.messages(t, 2)[1]), want.noContent, unwanted.noContent)
		})
	}
}

// The alerts the form sends to its owner and recipients follow the same language.
func TestLangueDeLAlerteDeQuota(t *testing.T) {
	for lang, other := range otherLang {
		t.Run(lang, func(t *testing.T) {
			e, app := quotaEnv(t)
			setNotificationLang(t, e, e.fx.formB, lang)
			fillToQuota(t, e, app, e.fx.formB, quotaBody)
			resp, out := submit(t, e.url, submitOpts{path: "/f/" + e.fx.formB.AccessKey, body: quotaBody, header: visitorSpeaks(other)})
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("soumission sur le formulaire plein : statut %d (%s)", resp.StatusCode, out)
			}
			// Two regular notifications, the one for the submission not kept, which has no link, and
			// the alert to the owner, then to the recipients.
			want, unwanted := notificationsIn[lang], notificationsIn[other]
			var alerts, notStored int
			for _, m := range e.mailer.messages(t, 6) {
				switch {
				case strings.Contains(m.HTML, "/forms/"+e.fx.formB.ID.String()):
					written(t, "alerte de quota", mailText(m), want.quota, unwanted.quota)
					alerts++
				case !strings.Contains(m.HTML, "/submissions/"):
					written(t, "email d'une soumission non conservée", mailText(m), want.notStored, unwanted.notStored)
					notStored++
				}
			}
			if alerts != 3 || notStored != 1 {
				t.Errorf("%d alerte(s) de quota et %d email(s) sans conservation, 3 et 1 attendus", alerts, notStored)
			}
		})
	}
}

func TestLangueDeLAlerteAntiRobot(t *testing.T) {
	for lang, other := range otherLang {
		t.Run(lang, func(t *testing.T) {
			e := setup(t)
			setNotificationLang(t, e, e.fx.formB, lang)
			requireCaptcha(t, e, e.fx.formB)
			header := visitorSpeaks(other)
			header.Set("Sec-Fetch-Site", "cross-site")
			if resp, out := submit(t, e.url, submitOpts{path: "/f/" + e.fx.formB.AccessKey, body: "message=bonjour", header: header}); resp.StatusCode != http.StatusForbidden {
				t.Fatalf("navigateur sans solution : statut %d (%s)", resp.StatusCode, out)
			}
			written(t, "alerte anti-robot", mailText(e.mailer.messages(t, 1)[0]), notificationsIn[lang].captcha, notificationsIn[other].captcha)
		})
	}
}

// A form created before the language could be set keeps French: it sends nothing beyond
// what it used to send. The test does not replay the migration: it sets the column default
// on existing rows, which is what a row inserted here without naming the column receives.
func TestLangueDUnFormulaireExistant(t *testing.T) {
	e := setup(t)
	var id string
	if err := e.pool.QueryRow(context.Background(),
		`INSERT INTO forms (site_id, name, access_key, recipients) VALUES ($1, 'Contact ancien', 'cle-ancienne', '{dest@exemple.fr}') RETURNING id::text`,
		e.fx.siteB.ID).Scan(&id); err != nil {
		t.Fatalf("insertion: %v", err)
	}
	if got := notificationLang(t, e, id); got != "fr" {
		t.Fatalf("langue d'un formulaire existant = %q", got)
	}
	if resp, out := submit(t, e.url, submitOpts{path: "/f/cle-ancienne", body: "message=bonjour", header: visitorSpeaks("en")}); resp.StatusCode != http.StatusOK {
		t.Fatalf("soumission : statut %d (%s)", resp.StatusCode, out)
	}
	written(t, "email", mailText(e.mailer.messages(t, 1)[0]), notificationsIn["fr"].mail, notificationsIn["en"].mail)

	// A settings page loaded before the update does not send the language: saving it does not change it.
	c := newClient()
	login(t, c, e.url, e.fx.memberB.Email)
	vals := formValues(csrfToken(t, c, e.url+"/account"), url.Values{"name": {"Contact renommé"}})
	resp := postForm(t, c, e.url+"/forms/"+id+"/settings", vals)
	resp.Body.Close()
	if got := notificationLang(t, e, id); resp.StatusCode != http.StatusSeeOther || got != "fr" {
		t.Errorf("réglages sans le champ : statut %d, langue %q", resp.StatusCode, got)
	}
}

// A new form takes the interface language of whoever creates it, which the creation page
// offers and they can change. Through the API it is a body field, and French when absent:
// the language of the API error messages (Accept-Language) plays no part.
func TestLangueDUnNouveauFormulaire(t *testing.T) {
	e := setup(t)
	c := newClient()
	login(t, c, e.url, e.fx.memberA.Email)
	newForm := e.url + "/sites/" + e.fx.siteA.ID.String() + "/forms/new"
	create := func(name, lang string) string {
		t.Helper()
		vals := url.Values{"csrf_token": {csrfToken(t, c, e.url+"/account")}, "name": {name}, "store_submissions": {"1"}}
		if lang != "" {
			vals.Set("notification_lang", lang)
		}
		resp := postForm(t, c, e.url+"/sites/"+e.fx.siteA.ID.String()+"/forms", vals)
		resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("création de %q : statut %d", name, resp.StatusCode)
		}
		return notificationLang(t, e, strings.TrimPrefix(resp.Header.Get("Location"), "/forms/"))
	}

	if _, page := get(t, c, newForm); !strings.Contains(page, `<option value="fr" selected>`) {
		t.Errorf("interface en français : la page de création doit proposer le français")
	}
	resp, err := c.Get(e.url + "/lang?to=en")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if _, page := get(t, c, newForm); !strings.Contains(page, `<option value="en" selected>`) || strings.Contains(page, `<option value="fr" selected>`) {
		t.Errorf("interface en anglais : la page de création doit proposer l'anglais")
	}
	if got := create("Proposée", "en"); got != "en" {
		t.Errorf("langue proposée gardée : %q", got)
	}
	if got := create("Changée", "fr"); got != "fr" {
		t.Errorf("langue changée à la création : %q", got)
	}

	token := createToken(t, e, c, e.fx.siteA, "Agent")
	post := func(body string) (int, map[string]any) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, e.url+"/api/v1/forms", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept-Language", "en")
		resp, err := newClient().Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		out := map[string]any{}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("réponse illisible: %v", err)
		}
		return resp.StatusCode, out
	}
	for body, want := range map[string]string{
		`{"name": "Sans langue"}`:                            "fr",
		`{"name": "En anglais", "notification_lang": "en"}`:  "en",
		`{"name": "En français", "notification_lang": "fr"}`: "fr",
	} {
		code, created := post(body)
		if code != http.StatusCreated || created["notification_lang"] != want {
			t.Errorf("%s : statut %d, notification_lang = %v (%q attendu)", body, code, created["notification_lang"], want)
			continue
		}
		if got := notificationLang(t, e, created["id"]); got != want {
			t.Errorf("%s : langue enregistrée = %q", body, got)
		}
	}
	code, list, raw := api(t, e, http.MethodGet, "/forms", token, "")
	if code != http.StatusOK || strings.Count(raw, `"notification_lang":"en"`) != 2 || len(list["forms"].([]any)) != 6 {
		t.Errorf("GET /forms doit donner la langue de chaque formulaire : statut %d, %s", code, raw)
	}
}

// The language comes from an HTML form or a JSON body: only the languages the instance can
// write are accepted.
func TestLangueDesNotificationsInconnue(t *testing.T) {
	e := setup(t)
	c := newClient()
	login(t, c, e.url, e.fx.memberA.Email)
	token := csrfToken(t, c, e.url+"/account")
	const reason = "Langue des notifications inconnue"

	for _, lang := range []string{"es", "EN", "fr-FR", "français", "fr,en", "../en"} {
		for what, target := range map[string]string{
			"réglages": e.url + "/forms/" + e.fx.formA.ID.String() + "/settings",
			"création": e.url + "/sites/" + e.fx.siteA.ID.String() + "/forms",
		} {
			resp := postForm(t, c, target, formValues(token, url.Values{"notification_lang": {lang}}))
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), reason) {
				t.Errorf("%s en %q : statut %d, refus motivé attendu", what, lang, resp.StatusCode)
			}
		}
	}

	apiToken := createToken(t, e, c, e.fx.siteA, "Agent")
	for _, value := range []string{`"es"`, `"EN"`, `""`, `" en"`, `"fr-FR"`} {
		code, out, raw := api(t, e, http.MethodPost, "/forms", apiToken, `{"name": "Contact", "notification_lang": `+value+`}`)
		if code != http.StatusBadRequest || !strings.Contains(raw, reason) {
			t.Errorf("API en %s : statut %d, réponse %v", value, code, out)
		}
	}
	for _, value := range []string{`12`, `true`, `["en"]`} {
		if code, _, raw := api(t, e, http.MethodPost, "/forms", apiToken, `{"name": "Contact", "notification_lang": `+value+`}`); code != http.StatusBadRequest {
			t.Errorf("API avec %s : statut %d (%s)", value, code, raw)
		}
	}

	if n := countForms(t, e, e.fx.siteA); n != 1 {
		t.Errorf("une langue refusée a créé un formulaire : %d sur le site", n)
	}
	if got := notificationLang(t, e, e.fx.formA.ID); got != "fr" {
		t.Errorf("une langue refusée a été enregistrée : %q", got)
	}
	var others int
	if err := e.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM forms WHERE notification_lang NOT IN ('fr', 'en', 'it', 'de')`).Scan(&others); err != nil || others != 0 {
		t.Errorf("%d formulaire(s) dans une langue inconnue (err=%v)", others, err)
	}
	// The database also refuses what the instance cannot write.
	if _, err := e.pool.Exec(context.Background(), `UPDATE forms SET notification_lang = 'es' WHERE id = $1`, e.fx.formA.ID); err == nil {
		t.Errorf("la base a accepté une langue inconnue")
	}
}
