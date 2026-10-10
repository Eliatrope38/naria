package main

// Integration tests against a real Postgres, on the real router (session, CSRF, roles):
// isolation and privacy of submissions. Skipped without TEST_DATABASE_URL.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"maps"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alexedwards/scs/pgxstore"
	"github.com/alexedwards/scs/v2"
	"github.com/jackc/pgx/v5/pgxpool"

	naria "gitlab.com/detag_inno/naria"
	"gitlab.com/detag_inno/naria/internal/auth"
	"gitlab.com/detag_inno/naria/internal/captcha"
	"gitlab.com/detag_inno/naria/internal/chat"
	"gitlab.com/detag_inno/naria/internal/config"
	"gitlab.com/detag_inno/naria/internal/crypto"
	"gitlab.com/detag_inno/naria/internal/database"
	"gitlab.com/detag_inno/naria/internal/email"
	"gitlab.com/detag_inno/naria/internal/email/graphtest"
	"gitlab.com/detag_inno/naria/internal/handlers"
	"gitlab.com/detag_inno/naria/internal/web"
	"gitlab.com/detag_inno/naria/ui"
)

const (
	testPassword = "motdepasse-test"
	testSecret   = "cle-de-test"
	// testCaptchaBits: difficulty of the anti-bot challenges of the test server, so that a
	// test solves one without waiting.
	testCaptchaBits = 8
)

var (
	migrateOnce sync.Once
	migrateErr  error
)

func TestMain(m *testing.M) {
	ui.SetBrand(ui.Brand{Name: "Test", Company: "Test", Color: "#000000"})
	ui.SetVersion("test")
	os.Exit(m.Run())
}

// fakeMailer captures emails instead of sending them. err simulates an SMTP server that is down.
type fakeMailer struct {
	mu       sync.Mutex
	sent     []email.Message
	err      error
	attempts int
	// reject simulates a recipient the server refuses: any message sent to it fails.
	reject string
	// refuse, if it returns an error, makes sending that message fail: a sender that
	// cannot carry everything.
	refuse func(email.Message) error
}

func (f *fakeMailer) Send(_ context.Context, m email.Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attempts++
	if f.reject != "" && slices.Contains(m.To, f.reject) {
		return errors.New("destinataire refusé")
	}
	if f.err != nil {
		return f.err
	}
	if f.refuse != nil {
		if err := f.refuse(m); err != nil {
			return err
		}
	}
	f.sent = append(f.sent, m)
	return nil
}

// messages waits until at least n emails have been sent (sending is asynchronous when the
// submission is kept), then returns them.
func (f *fakeMailer) messages(t *testing.T, n int) []email.Message {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		f.mu.Lock()
		got := append([]email.Message(nil), f.sent...)
		f.mu.Unlock()
		if len(got) >= n || time.Now().After(deadline) {
			if len(got) < n {
				t.Fatalf("%d email(s) envoyé(s), %d attendu(s)", len(got), n)
			}
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type fixtures struct {
	admin   database.User
	memberA database.User
	memberB database.User
	siteA   database.Site // domains: exemple.fr
	siteB   database.Site // no domain restriction
	formA   database.Form // kept + email
	formB   database.Form // kept + email
}

type testEnv struct {
	url    string
	q      *database.Queries
	pool   *pgxpool.Pool
	mailer *fakeMailer
	fx     fixtures
}

// setup starts a full server on a throwaway database. The options modify the App
// before the router is built.
func setup(t *testing.T, opts ...func(*handlers.App)) testEnv {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL non défini : test d'intégration ignoré")
	}

	migrateOnce.Do(func() { migrateErr = migrate(dsn) })
	if migrateErr != nil {
		t.Fatalf("migrations: %v", migrateErr)
	}

	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connexion db: %v", err)
	}
	t.Cleanup(pool.Close)
	resetDB(t, pool)

	q := database.New(pool)
	cfg := config.Config{
		Secure:             false,
		BaseURL:            "http://naria.test",
		SessionLifetime:    time.Hour,
		MaxBodyBytes:       1 << 20,
		MaxSubmissionBytes: 16 << 10,
		MaxAttachmentBytes: 64 << 10,
		PasswordMinLength:  config.DefaultPasswordMinLength,
		Brand:              config.Branding{Name: "Test", Company: "Test", Color: "#000000"},
	}
	sm := scs.New()
	sm.Store = pgxstore.New(pool)
	sm.Lifetime = cfg.SessionLifetime
	sm.Cookie.HttpOnly = true
	sm.Cookie.SameSite = http.SameSiteLaxMode

	cipher, err := crypto.New(testSecret, crypto.PurposeSubmission)
	if err != nil {
		t.Fatalf("chiffrement: %v", err)
	}
	attachmentCipher, err := crypto.New(testSecret, crypto.PurposeAttachment)
	if err != nil {
		t.Fatalf("chiffrement: %v", err)
	}
	webhookCipher, err := crypto.New(testSecret, crypto.PurposeWebhook)
	if err != nil {
		t.Fatalf("chiffrement: %v", err)
	}
	botTokenCipher, err := crypto.New(testSecret, crypto.PurposeBotToken)
	if err != nil {
		t.Fatalf("chiffrement: %v", err)
	}
	challenges, err := captcha.New(testSecret, testCaptchaBits)
	if err != nil {
		t.Fatalf("vérification anti-robot: %v", err)
	}
	mailer := &fakeMailer{}
	app := &handlers.App{
		Cfg: cfg, Q: q, Pool: pool, Sessions: sm, Mailer: mailer,
		Limiter:          web.NewRateLimiter(10, 5*time.Minute),
		SubmissionCrypto: cipher,
		AttachmentCrypto: attachmentCipher,
		Captcha:          challenges,
		Chat:             chat.New(nil),
		WebhookCrypto:    webhookCipher,
		BotTokenCrypto:   botTokenCipher,
	}
	for _, o := range opts {
		o(app)
	}
	staticFS, err := fs.Sub(naria.StaticFiles, "web/static")
	if err != nil {
		t.Fatalf("static fs: %v", err)
	}
	srv := httptest.NewServer(buildRouter(app, app.Cfg, staticFS))
	t.Cleanup(srv.Close)

	return testEnv{url: srv.URL, q: q, pool: pool, mailer: mailer, fx: seed(t, q)}
}

// resetDB empties the application tables between two tests (except the migration log).
func resetDB(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	rows, err := pool.Query(ctx,
		`SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename <> 'goose_db_version'`)
	if err != nil {
		t.Fatalf("liste des tables: %v", err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			t.Fatalf("scan table: %v", err)
		}
		tables = append(tables, `"`+name+`"`)
	}
	rows.Close()
	if len(tables) == 0 {
		return
	}
	if _, err := pool.Exec(ctx, "TRUNCATE "+strings.Join(tables, ", ")+" RESTART IDENTITY CASCADE"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

func seed(t *testing.T, q *database.Queries) fixtures {
	t.Helper()
	hash, err := auth.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	fx := fixtures{
		admin:   mustUser(t, q, "admin@naria.test", auth.RoleAdmin, hash),
		memberA: mustUser(t, q, "a@a.test", auth.RoleMember, hash),
		memberB: mustUser(t, q, "b@b.test", auth.RoleMember, hash),
	}
	fx.siteA = mustSite(t, q, fx.memberA, "Site Alpha", []string{"exemple.fr"})
	fx.siteB = mustSite(t, q, fx.memberB, "Site Bravo", []string{})
	fx.formA = mustForm(t, q, fx.siteA, "Contact Alpha", true, true)
	fx.formB = mustForm(t, q, fx.siteB, "Contact Bravo", true, true)
	return fx
}

func mustUser(t *testing.T, q *database.Queries, addr, role, hash string) database.User {
	t.Helper()
	u, err := q.CreateUser(context.Background(), database.CreateUserParams{
		Email: addr, Name: addr, Role: role, PasswordHash: hash,
	})
	if err != nil {
		t.Fatalf("création compte %q: %v", addr, err)
	}
	return u
}

func mustSite(t *testing.T, q *database.Queries, owner database.User, name string, domains []string) database.Site {
	t.Helper()
	s, err := q.CreateSite(context.Background(), database.CreateSiteParams{OwnerID: owner.ID, Name: name, Domains: domains})
	if err != nil {
		t.Fatalf("création site %q: %v", name, err)
	}
	return s
}

func mustForm(t *testing.T, q *database.Queries, site database.Site, name string, notify, store bool) database.Form {
	t.Helper()
	key, err := auth.GenerateAccessKey()
	if err != nil {
		t.Fatalf("clé d'accès: %v", err)
	}
	f, err := q.CreateForm(context.Background(), database.CreateFormParams{
		SiteID: site.ID, Name: name, AccessKey: key,
		NotifyEmail: notify, Recipients: []string{"dest@exemple.fr"}, EmailIncludeContent: true,
		StoreSubmissions: store, RetentionDays: 90, NotificationLang: "fr",
	})
	if err != nil {
		t.Fatalf("création formulaire %q: %v", name, err)
	}
	return f
}

func newClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

var csrfRe = regexp.MustCompile(`name="csrf_token"[^>]*value="([^"]+)"`)

func csrfToken(t *testing.T, c *http.Client, target string) string {
	t.Helper()
	resp, err := c.Get(target)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	m := csrfRe.FindSubmatch(body)
	if m == nil {
		t.Fatalf("jeton CSRF introuvable à %s (statut %d)", target, resp.StatusCode)
	}
	return string(m[1])
}

// postForm emulates a same-origin form POST. nosurf v1.2 requires an origin proof
// (Sec-Fetch-Site / Origin / Referer) that a browser sends automatically but
// http.Client does not, so the request would be rejected before the token check.
func postForm(t *testing.T, c *http.Client, target string, vals url.Values) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(vals.Encode()))
	if err != nil {
		t.Fatalf("requête POST %s: %v", target, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", target, err)
	}
	return resp
}

func login(t *testing.T, c *http.Client, base, addr string) {
	t.Helper()
	token := csrfToken(t, c, base+"/login")
	resp := postForm(t, c, base+"/login", url.Values{
		"email": {addr}, "password": {testPassword}, "csrf_token": {token},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login %s: statut %d (303 attendu)", addr, resp.StatusCode)
	}
}

func get(t *testing.T, c *http.Client, target string) (int, string) {
	t.Helper()
	resp, err := c.Get(target)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// submitOpts describes a submission to the public entry point.
type submitOpts struct {
	path        string // default /submit
	contentType string // default urlencoded
	body        string
	origin      string
	html        bool // classic form submission (no Accept JSON)
	header      http.Header
}

func submit(t *testing.T, base string, o submitOpts) (*http.Response, string) {
	t.Helper()
	if o.path == "" {
		o.path = "/submit"
	}
	if o.contentType == "" {
		o.contentType = "application/x-www-form-urlencoded"
	}
	req, err := http.NewRequest(http.MethodPost, base+o.path, strings.NewReader(o.body))
	if err != nil {
		t.Fatalf("requête: %v", err)
	}
	maps.Copy(req.Header, o.header)
	req.Header.Set("Content-Type", o.contentType)
	if o.origin != "" {
		req.Header.Set("Origin", o.origin)
	}
	if o.html {
		req.Header.Set("Sec-Fetch-Mode", "navigate")
	} else {
		req.Header.Set("Accept", "application/json")
	}
	resp, err := newClient().Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", o.path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

func countSubmissions(t *testing.T, e testEnv, form database.Form) int64 {
	t.Helper()
	n, err := e.q.CountSubmissionsByForm(context.Background(), form.ID)
	if err != nil {
		t.Fatalf("comptage: %v", err)
	}
	return n
}

// storeSubmission sends a valid submission to the form and returns its row.
func storeSubmission(t *testing.T, e testEnv, form database.Form, origin, body string) database.Submission {
	t.Helper()
	resp, out := submit(t, e.url, submitOpts{path: "/f/" + form.AccessKey, body: body, origin: origin})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("soumission: statut %d (%s)", resp.StatusCode, out)
	}
	list, err := e.q.ListSubmissionsByForm(context.Background(), database.ListSubmissionsByFormParams{FormID: form.ID, PageLimit: 1})
	if err != nil || len(list) != 1 {
		t.Fatalf("soumission introuvable en base: %v", err)
	}
	return list[0]
}

func TestNonAuthentifieRedirigeVersLogin(t *testing.T) {
	e := setup(t)
	for _, path := range []string{"/", "/sites/" + e.fx.siteA.ID.String(), "/forms/" + e.fx.formA.ID.String(), "/users", "/account"} {
		resp, err := newClient().Get(e.url + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
			t.Errorf("%s : attendu 303 vers /login, obtenu %d %q", path, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
}

// A member neither sees nor changes anything that belongs to another account: site, form,
// settings, submissions, export. Out of scope means 404, as for a nonexistent resource.
func TestMembreCloisonneASesSites(t *testing.T) {
	e := setup(t)
	subA := storeSubmission(t, e, e.fx.formA, "https://exemple.fr", "name=Ada&message=secret-alpha")

	b := newClient()
	login(t, b, e.url, e.fx.memberB.Email)

	if _, body := get(t, b, e.url+"/"); strings.Contains(body, "Site Alpha") || !strings.Contains(body, "Site Bravo") {
		t.Errorf("la liste de B doit montrer son site et pas celui de A")
	}

	siteA, formA := "/sites/"+e.fx.siteA.ID.String(), "/forms/"+e.fx.formA.ID.String()
	for _, path := range []string{
		siteA, siteA + "/forms/new", formA, formA + "/settings", formA + "/export.csv",
		"/submissions/" + subA.ID.String(),
	} {
		code, body := get(t, b, e.url+path)
		if code != http.StatusNotFound {
			t.Errorf("GET %s par un autre membre : statut %d (404 attendu)", path, code)
		}
		if strings.Contains(body, "secret-alpha") || strings.Contains(body, e.fx.formA.AccessKey) {
			t.Errorf("GET %s : des données de A fuient vers B", path)
		}
	}

	token := csrfToken(t, b, e.url+"/account")
	for _, path := range []string{
		siteA, siteA + "/delete", siteA + "/forms",
		formA + "/settings", formA + "/key", formA + "/delete", formA + "/purge", formA + "/read",
		"/submissions/" + subA.ID.String() + "/delete",
	} {
		resp := postForm(t, b, e.url+path, url.Values{
			"csrf_token": {token}, "name": {"piraté"}, "store_submissions": {"1"},
		})
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("POST %s par un autre membre : statut %d (404 attendu)", path, resp.StatusCode)
		}
	}

	// Nothing changed for A.
	ctx := context.Background()
	site, err := e.q.GetSiteScoped(ctx, database.GetSiteScopedParams{ID: e.fx.siteA.ID, IsAdmin: true})
	if err != nil || site.Name != "Site Alpha" {
		t.Errorf("site A altéré ou supprimé : %v %q", err, site.Name)
	}
	form, err := e.q.GetFormByAccessKey(ctx, e.fx.formA.AccessKey)
	if err != nil || form.Name != "Contact Alpha" {
		t.Errorf("formulaire A altéré, supprimé ou clé régénérée : %v", err)
	}
	if n := countSubmissions(t, e, e.fx.formA); n != 1 {
		t.Errorf("soumissions de A : %d (1 attendue)", n)
	}
	if list, _ := e.q.ListSubmissionsByForm(ctx, database.ListSubmissionsByFormParams{FormID: e.fx.formA.ID, PageLimit: 1}); len(list) == 1 && list[0].ReadAt.Valid {
		t.Errorf("la soumission de A a été marquée lue par B")
	}

	a := newClient()
	login(t, a, e.url, e.fx.memberA.Email)
	if code, body := get(t, a, e.url+"/submissions/"+subA.ID.String()); code != http.StatusOK || !strings.Contains(body, "secret-alpha") {
		t.Errorf("le propriétaire doit lire sa soumission : statut %d", code)
	}
}

func TestAdminVoitToutEtMembreNAdministrePas(t *testing.T) {
	e := setup(t)

	adm := newClient()
	login(t, adm, e.url, e.fx.admin.Email)
	if _, body := get(t, adm, e.url+"/"); !strings.Contains(body, "Site Alpha") || !strings.Contains(body, "Site Bravo") {
		t.Errorf("l'administrateur doit voir tous les sites")
	}
	if code, _ := get(t, adm, e.url+"/users"); code != http.StatusOK {
		t.Errorf("/users pour l'administrateur : statut %d", code)
	}

	a := newClient()
	login(t, a, e.url, e.fx.memberA.Email)
	if code, _ := get(t, a, e.url+"/users"); code != http.StatusForbidden {
		t.Errorf("/users pour un membre : statut %d (403 attendu)", code)
	}
	// A member cannot take over a site by naming themselves owner, nor promote themselves
	// to administrator.
	token := csrfToken(t, a, e.url+"/account")
	for _, path := range []string{
		"/sites/" + e.fx.siteB.ID.String() + "/owner",
		"/sites/" + e.fx.siteA.ID.String() + "/owner",
		"/users/" + e.fx.memberA.ID.String() + "/role",
	} {
		resp := postForm(t, a, e.url+path, url.Values{
			"csrf_token": {token}, "owner_id": {e.fx.memberA.ID.String()}, "role": {auth.RoleAdmin},
		})
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("POST %s par un membre : statut %d (403 attendu)", path, resp.StatusCode)
		}
	}
	site, _ := e.q.GetSiteScoped(context.Background(), database.GetSiteScopedParams{ID: e.fx.siteB.ID, IsAdmin: true})
	if site.OwnerID != e.fx.memberB.ID {
		t.Errorf("le site B a changé de propriétaire")
	}
	if u, _ := e.q.GetUserByID(context.Background(), e.fx.memberA.ID); u.Role != auth.RoleMember {
		t.Errorf("le membre A a changé de rôle : %s", u.Role)
	}
}

func TestParcoursCreationSiteEtFormulaire(t *testing.T) {
	e := setup(t)
	c := newClient()
	login(t, c, e.url, e.fx.memberA.Email)
	token := csrfToken(t, c, e.url+"/")

	resp := postForm(t, c, e.url+"/sites", url.Values{
		"csrf_token": {token}, "name": {"Nouveau site"}, "domains": {"https://www.Nouveau.fr/contact, *.nouveau.fr"},
	})
	resp.Body.Close()
	sitePath := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(sitePath, "/sites/") {
		t.Fatalf("création du site : statut %d, Location %q", resp.StatusCode, sitePath)
	}
	if _, body := get(t, c, e.url+sitePath); !strings.Contains(body, "www.nouveau.fr · *.nouveau.fr") {
		t.Errorf("les domaines normalisés devraient s'afficher sur la page du site")
	}

	// No destination: refused (the submission would lead nowhere).
	resp = postForm(t, c, e.url+sitePath+"/forms", url.Values{"csrf_token": {token}, "name": {"Vide"}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("formulaire sans destination : statut %d (400 attendu)", resp.StatusCode)
	}
	// Return page outside the site's domains: refused.
	resp = postForm(t, c, e.url+sitePath+"/forms", url.Values{
		"csrf_token": {token}, "name": {"Contact"}, "store_submissions": {"1"}, "redirect_url": {"https://evil.tld/merci"},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("page de retour hors domaine : statut %d (400 attendu)", resp.StatusCode)
	}

	resp = postForm(t, c, e.url+sitePath+"/forms", url.Values{
		"csrf_token": {token}, "name": {"Contact"},
		"notify_email": {"1"}, "recipients": {"Equipe@Nouveau.fr; autre@nouveau.fr"},
		"retention_days": {"30"}, "redirect_url": {"https://www.nouveau.fr/merci"},
		"accept_attachments": {"1"},
	})
	resp.Body.Close()
	formPath := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(formPath, "/forms/") {
		t.Fatalf("création du formulaire : statut %d, Location %q", resp.StatusCode, formPath)
	}
	code, body := get(t, c, e.url+formPath)
	if code != http.StatusOK || !strings.Contains(body, "http://naria.test/submit") {
		t.Errorf("la page du formulaire doit donner l'adresse d'envoi (statut %d)", code)
	}
	// Email-only mode: the content is necessarily included in the email, otherwise the
	// submission would be lost.
	var include, attachments bool
	var recipients []string
	if err := e.pool.QueryRow(context.Background(),
		`SELECT email_include_content, accept_attachments, recipients FROM forms WHERE id = $1`, strings.TrimPrefix(formPath, "/forms/")).
		Scan(&include, &attachments, &recipients); err != nil {
		t.Fatalf("lecture du formulaire: %v", err)
	}
	if !attachments || !strings.Contains(body, "multipart/form-data") {
		t.Errorf("pièces jointes demandées à la création : réglage %v, et le code d'intégration doit porter l'enctype multipart", attachments)
	}
	if !include {
		t.Errorf("mode email seul : email_include_content doit rester vrai")
	}
	if strings.Join(recipients, ",") != "equipe@nouveau.fr,autre@nouveau.fr" {
		t.Errorf("destinataires normalisés inattendus : %v", recipients)
	}
}

func TestSoumissionConserveeChiffreeEtNotifiee(t *testing.T) {
	e := setup(t)
	body := url.Values{
		"access_key": {e.fx.formA.AccessKey},
		"name":       {"Ada Lovelace"},
		"email":      {"ada@exemple.org"},
		"message":    {"contenu-tres-confidentiel"},
		"subject":    {"Demande de devis"},
		"botcheck":   {""},
	}.Encode()
	resp, out := submit(t, e.url, submitOpts{body: body, origin: "https://www.exemple.fr"})
	if resp.StatusCode != http.StatusOK || !strings.Contains(out, `"success":true`) {
		t.Fatalf("statut %d, corps %s", resp.StatusCode, out)
	}
	// A visitor on a client site is not a user: no cookie.
	if len(resp.Cookies()) != 0 {
		t.Errorf("le point d'entrée public a posé un cookie : %v", resp.Cookies())
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Access-Control-Allow-Origin = %q", got)
	}

	// In the database: the content is encrypted, nothing is readable.
	var payload string
	if err := e.pool.QueryRow(context.Background(), `SELECT payload FROM submissions WHERE form_id = $1`, e.fx.formA.ID).Scan(&payload); err != nil {
		t.Fatalf("lecture: %v", err)
	}
	if !strings.HasPrefix(payload, "enc1:") {
		t.Errorf("payload non chiffré : %.30q", payload)
	}
	for _, clear := range []string{"contenu-tres-confidentiel", "Ada", "ada@exemple.org"} {
		if strings.Contains(payload, clear) {
			t.Errorf("%q lisible en clair dans la base", clear)
		}
	}

	msgs := e.mailer.messages(t, 1)
	m := msgs[0]
	if len(m.To) != 1 || m.To[0] != "dest@exemple.fr" {
		t.Errorf("destinataires = %v", m.To)
	}
	if m.Subject != "[Site Alpha] Demande de devis" {
		t.Errorf("sujet = %q", m.Subject)
	}
	if m.ReplyTo != "ada@exemple.org" {
		t.Errorf("Reply-To = %q", m.ReplyTo)
	}
	if !strings.Contains(m.HTML, "contenu-tres-confidentiel") || !strings.Contains(m.HTML, "http://naria.test/submissions/") {
		t.Errorf("l'email doit porter le contenu et le lien vers la soumission")
	}
	// Service fields are not visitor data.
	for _, service := range []string{e.fx.formA.AccessKey, "botcheck"} {
		if strings.Contains(m.HTML, service) {
			t.Errorf("champ de service %q présent dans l'email", service)
		}
	}
}

// The promise of 'neither IP nor browser' rests on the schema: the table has no column to
// store them in. This test fails if a migration adds one.
func TestTableSoumissionsSansDonneeDeTracage(t *testing.T) {
	e := setup(t)
	for table, want := range map[string]string{
		"submissions": "created_at,form_id,id,payload,read_at",
		"attachments": "content,filename,id,position,size,submission_id",
	} {
		rows, err := e.pool.Query(context.Background(),
			`SELECT column_name FROM information_schema.columns WHERE table_name = $1 ORDER BY column_name`, table)
		if err != nil {
			t.Fatalf("lecture du schéma: %v", err)
		}
		var cols []string
		for rows.Next() {
			var c string
			_ = rows.Scan(&c)
			cols = append(cols, c)
		}
		rows.Close()
		if got := strings.Join(cols, ","); got != want {
			t.Errorf("colonnes de %s = %s ; attendu %s", table, got, want)
		}
	}
}

func TestSoumissionRefusee(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	inactive := mustForm(t, e.q, e.fx.siteB, "Fermé", true, true)
	if _, err := e.pool.Exec(ctx, `UPDATE forms SET active = FALSE WHERE id = $1`, inactive.ID); err != nil {
		t.Fatal(err)
	}
	keyA := "/f/" + e.fx.formA.AccessKey

	cases := []struct {
		name string
		o    submitOpts
		want int
	}{
		{"origine non autorisée", submitOpts{path: keyA, body: "message=x", origin: "https://evil.tld"}, http.StatusForbidden},
		{"origine au suffixe trompeur", submitOpts{path: keyA, body: "message=x", origin: "https://exemple.fr.evil.tld"}, http.StatusForbidden},
		{"origine opaque", submitOpts{path: keyA, body: "message=x", origin: "null"}, http.StatusForbidden},
		{"clé inconnue", submitOpts{path: "/f/00000000-0000-4000-8000-000000000000", body: "message=x"}, http.StatusNotFound},
		{"clé absente", submitOpts{body: "message=x"}, http.StatusBadRequest},
		{"formulaire inactif", submitOpts{path: "/f/" + inactive.AccessKey, body: "message=x"}, http.StatusForbidden},
		{"aucun contenu", submitOpts{path: keyA, body: "name=&message=", origin: "https://exemple.fr"}, http.StatusBadRequest},
		{"type non pris en charge", submitOpts{path: keyA, contentType: "text/plain", body: "x", origin: "https://exemple.fr"}, http.StatusUnsupportedMediaType},
		{"json invalide", submitOpts{path: keyA, contentType: "application/json", body: "[1]", origin: "https://exemple.fr"}, http.StatusBadRequest},
		{"corps trop gros", submitOpts{path: keyA, body: "message=" + strings.Repeat("x", 20<<10), origin: "https://exemple.fr"}, http.StatusRequestEntityTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, out := submit(t, e.url, tc.o)
			if resp.StatusCode != tc.want {
				t.Errorf("statut %d (%d attendu) : %s", resp.StatusCode, tc.want, out)
			}
			if !strings.Contains(out, `"success":false`) {
				t.Errorf("réponse JSON d'échec attendue, obtenu %s", out)
			}
		})
	}
	if n := countSubmissions(t, e, e.fx.formA) + countSubmissions(t, e, inactive); n != 0 {
		t.Errorf("%d soumission(s) conservée(s) malgré les refus", n)
	}
	time.Sleep(50 * time.Millisecond)
	if msgs := e.mailer.messages(t, 0); len(msgs) != 0 {
		t.Errorf("%d email(s) envoyé(s) malgré les refus", len(msgs))
	}
}

// multipartBody builds a multipart submission: a field (name, value) or a file (field, name, content).
func multipartBody(parts ...[]string) (contentType, body string) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for _, p := range parts {
		if len(p) == 2 {
			_ = mw.WriteField(p[0], p[1])
			continue
		}
		fw, _ := mw.CreateFormFile(p[0], p[1])
		_, _ = fw.Write([]byte(p[2]))
	}
	_ = mw.Close()
	return mw.FormDataContentType(), buf.String()
}

func acceptAttachments(t *testing.T, e testEnv, form database.Form) {
	t.Helper()
	if _, err := e.pool.Exec(context.Background(), `UPDATE forms SET accept_attachments = TRUE WHERE id = $1`, form.ID); err != nil {
		t.Fatal(err)
	}
}

func countAttachments(t *testing.T, e testEnv) int {
	t.Helper()
	var n int
	if err := e.pool.QueryRow(context.Background(), `SELECT count(*) FROM attachments`).Scan(&n); err != nil {
		t.Fatalf("comptage des pièces jointes: %v", err)
	}
	return n
}

// Files follow the submission: encrypted, attached to the email, deleted with it.
func TestPiecesJointes(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	owner := newClient()
	login(t, owner, e.url, e.fx.memberA.Email)
	if _, page := get(t, owner, e.url+"/forms/"+e.fx.formA.ID.String()); strings.Contains(page, "multipart/form-data") {
		t.Errorf("le code d'intégration ne doit proposer l'envoi de fichiers que si le formulaire les accepte")
	}
	acceptAttachments(t, e, e.fx.formA)
	const pdf = "%PDF-1.7 contenu-tres-confidentiel\x00\xff\r\n"
	ct, body := multipartBody(
		[]string{"access_key", e.fx.formA.AccessKey},
		[]string{"name", "Ada"},
		[]string{"cv", "cv-secret.pdf", pdf},
		[]string{"notes", "notes été.txt", "deuxième fichier"},
	)
	resp, out := submit(t, e.url, submitOpts{contentType: ct, body: body, origin: "https://exemple.fr"})
	if resp.StatusCode != http.StatusOK || !strings.Contains(out, `"success":true`) {
		t.Fatalf("statut %d, corps %s", resp.StatusCode, out)
	}

	rows, err := e.pool.Query(ctx, `SELECT id::text, submission_id::text, filename, size, content FROM attachments ORDER BY position`)
	if err != nil {
		t.Fatalf("lecture: %v", err)
	}
	var ids []string
	var subID string
	for rows.Next() {
		var id, filename string
		var size int64
		var content []byte
		if err := rows.Scan(&id, &subID, &filename, &size, &content); err != nil {
			t.Fatalf("scan: %v", err)
		}
		ids = append(ids, id)
		if !strings.HasPrefix(filename, "enc1:") || !bytes.HasPrefix(content, []byte("enc1:")) {
			t.Errorf("pièce jointe non chiffrée en base : nom %.20q, contenu %.20q", filename, content)
		}
		if bytes.Contains(content, []byte("confidentiel")) || bytes.Contains(content, []byte("deuxième")) {
			t.Errorf("contenu d'un fichier lisible en clair dans la base")
		}
	}
	rows.Close()
	if len(ids) != 2 {
		t.Fatalf("%d pièce(s) jointe(s) en base, 2 attendues", len(ids))
	}
	var size int64
	_ = e.pool.QueryRow(ctx, `SELECT size FROM attachments WHERE id::text = $1`, ids[0]).Scan(&size)
	if size != int64(len(pdf)) {
		t.Errorf("taille enregistrée = %d, attendu %d", size, len(pdf))
	}

	m := e.mailer.messages(t, 1)[0]
	if len(m.Attachments) != 2 || m.Attachments[0].Name != "cv-secret.pdf" || string(m.Attachments[0].Data) != pdf ||
		m.Attachments[1].Name != "notes été.txt" || string(m.Attachments[1].Data) != "deuxième fichier" {
		t.Errorf("l'email doit porter les deux fichiers, intacts et dans l'ordre : %d reçu(s)", len(m.Attachments))
	}
	if !strings.Contains(m.HTML, "cv-secret.pdf") {
		t.Errorf("le champ du fichier doit porter son nom dans l'email")
	}

	code, page := get(t, owner, e.url+"/submissions/"+subID)
	if code != http.StatusOK || !strings.Contains(page, "/attachments/"+ids[0]) || !strings.Contains(page, "cv-secret.pdf") {
		t.Errorf("la fiche de la soumission doit lister ses pièces jointes (statut %d)", code)
	}
	if _, page := get(t, owner, e.url+"/forms/"+e.fx.formA.ID.String()); !strings.Contains(page, "multipart/form-data") {
		t.Errorf("le code d'intégration d'un formulaire à pièces jointes doit porter l'enctype multipart")
	}

	dl, err := owner.Get(e.url + "/attachments/" + ids[0])
	if err != nil {
		t.Fatalf("téléchargement: %v", err)
	}
	got, _ := io.ReadAll(dl.Body)
	dl.Body.Close()
	if dl.StatusCode != http.StatusOK || string(got) != pdf {
		t.Errorf("téléchargement : statut %d, %d octet(s) (%d attendus)", dl.StatusCode, len(got), len(pdf))
	}
	// A visitor's file is never rendered by the browser.
	if cd := dl.Header.Get("Content-Disposition"); cd != "attachment; filename=cv-secret.pdf" {
		t.Errorf("Content-Disposition = %q", cd)
	}
	if ct := dl.Header.Get("Content-Type"); ct != "application/octet-stream" || dl.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("Content-Type = %q, nosniff = %q", ct, dl.Header.Get("X-Content-Type-Options"))
	}

	// Account isolation: another member gets the same 404 as for a nonexistent file.
	other := newClient()
	login(t, other, e.url, e.fx.memberB.Email)
	for _, path := range []string{"/attachments/" + ids[0], "/attachments/00000000-0000-4000-8000-000000000000", "/attachments/x"} {
		if code, page := get(t, other, e.url+path); code != http.StatusNotFound || strings.Contains(page, "confidentiel") {
			t.Errorf("GET %s par un autre membre : statut %d (404 attendu)", path, code)
		}
	}
	admin := newClient()
	login(t, admin, e.url, e.fx.admin.Email)
	dl, err = admin.Get(e.url + "/attachments/" + ids[1])
	if err != nil {
		t.Fatalf("téléchargement: %v", err)
	}
	got, _ = io.ReadAll(dl.Body)
	dl.Body.Close()
	if dl.StatusCode != http.StatusOK || string(got) != "deuxième fichier" {
		t.Errorf("téléchargement par l'administrateur : statut %d", dl.StatusCode)
	}
	if disposition, params, err := mime.ParseMediaType(dl.Header.Get("Content-Disposition")); err != nil || disposition != "attachment" || params["filename"] != "notes été.txt" {
		t.Errorf("Content-Disposition = %q (%v)", dl.Header.Get("Content-Disposition"), err)
	}

	// Content altered in the database is not served.
	if _, err := e.pool.Exec(ctx, `UPDATE attachments SET content = 'enc1:altéré'::bytea WHERE id::text = $1`, ids[1]); err != nil {
		t.Fatal(err)
	}
	if code, _ := get(t, admin, e.url+"/attachments/"+ids[1]); code != http.StatusInternalServerError {
		t.Errorf("pièce jointe altérée : statut %d (500 attendu)", code)
	}
	if code, _ := get(t, newClient(), e.url+"/attachments/"+ids[0]); code != http.StatusSeeOther {
		t.Errorf("téléchargement sans session : statut %d (303 attendu)", code)
	}

	token := csrfToken(t, owner, e.url+"/account")
	del := postForm(t, owner, e.url+"/submissions/"+subID+"/delete", url.Values{"csrf_token": {token}})
	del.Body.Close()
	if n := countAttachments(t, e); del.StatusCode != http.StatusSeeOther || n != 0 {
		t.Errorf("suppression de la soumission : statut %d, %d pièce(s) jointe(s) restante(s)", del.StatusCode, n)
	}
}

// Without the setting nothing changes: files are ignored and do not raise the submission
// size limit.
func TestPiecesJointesIgnoreesParDefaut(t *testing.T) {
	e := setup(t)
	path := "/f/" + e.fx.formB.AccessKey
	ct, body := multipartBody([]string{"name", "Ada"}, []string{"cv", "cv-secret.pdf", "contenu-confidentiel"})
	if resp, out := submit(t, e.url, submitOpts{path: path, contentType: ct, body: body}); resp.StatusCode != http.StatusOK {
		t.Fatalf("statut %d, corps %s", resp.StatusCode, out)
	}
	if n := countAttachments(t, e); n != 0 {
		t.Errorf("%d pièce(s) jointe(s) conservée(s) par un formulaire qui n'en accepte pas", n)
	}
	m := e.mailer.messages(t, 1)[0]
	if len(m.Attachments) != 0 || strings.Contains(m.HTML, "cv-secret") {
		t.Errorf("le fichier ou son nom a atteint l'email")
	}

	// A file field placed before the key does not bother a form that expects no file.
	ct, body = multipartBody([]string{"cv", "cv-secret.pdf", "contenu-confidentiel"}, []string{"access_key", e.fx.formB.AccessKey}, []string{"name", "Ada"})
	if resp, out := submit(t, e.url, submitOpts{contentType: ct, body: body}); resp.StatusCode != http.StatusOK || countAttachments(t, e) != 0 {
		t.Errorf("fichier avant la clé, formulaire sans pièces jointes : statut %d, corps %s", resp.StatusCode, out)
	}

	ct, body = multipartBody([]string{"name", "Ada"}, []string{"cv", "gros.bin", strings.Repeat("x", 20<<10)})
	if resp, _ := submit(t, e.url, submitOpts{path: path, contentType: ct, body: body}); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("fichier au-delà du plafond de la soumission : statut %d (413 attendu)", resp.StatusCode)
	}
}

func TestPiecesJointesHorsLimites(t *testing.T) {
	e := setup(t)
	acceptAttachments(t, e, e.fx.formB)
	key := []string{"access_key", e.fx.formB.AccessKey}
	file := func(name string, size int) []string { return []string{name, name + ".bin", strings.Repeat("x", size)} }

	for _, tc := range []struct {
		name    string
		parts   [][]string
		want    int
		message string
	}{
		{"fichiers trop volumineux", [][]string{key, file("a", 40<<10), file("b", 30<<10)}, http.StatusRequestEntityTooLarge, "fichiers joints sont trop volumineux"},
		{"trop de fichiers", [][]string{key, file("a", 1), file("b", 1), file("c", 1), file("d", 1), file("e", 1), file("f", 1)}, http.StatusRequestEntityTooLarge, "Trop de fichiers joints : 5"},
		// Accepting the submission without its files would lose them silently.
		{"fichier avant la clé", [][]string{file("a", 1), key, {"name", "Ada"}}, http.StatusBadRequest, "access_key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ct, body := multipartBody(tc.parts...)
			resp, out := submit(t, e.url, submitOpts{contentType: ct, body: body})
			if resp.StatusCode != tc.want || !strings.Contains(out, `"success":false`) || !strings.Contains(out, tc.message) {
				t.Errorf("statut %d (%d attendu) : %s", resp.StatusCode, tc.want, out)
			}
		})
	}
	if n := countSubmissions(t, e, e.fx.formB); n != 0 || countAttachments(t, e) != 0 {
		t.Errorf("%d soumission(s) conservée(s) malgré les refus", n)
	}

	// At the exact limit, regardless of field order when the key is in the address.
	parts := [][]string{file("a", 60<<10), {"name", "Ada"}, file("b", 1<<10), file("c", 1<<10), file("d", 1<<10), file("e", 1<<10)}
	ct, body := multipartBody(parts...)
	if resp, out := submit(t, e.url, submitOpts{path: "/f/" + e.fx.formB.AccessKey, contentType: ct, body: body}); resp.StatusCode != http.StatusOK {
		t.Errorf("cinq fichiers à la limite de taille : statut %d, corps %s", resp.StatusCode, out)
	}
	if n := countAttachments(t, e); n != 5 {
		t.Errorf("%d pièce(s) jointe(s) conservée(s), 5 attendues", n)
	}
}

// A refused submission is refused before any file is read. This case exceeds every limit:
// if it were read, the response would be a 413.
func TestPiecesJointesRefuseesAvantLecture(t *testing.T) {
	e := setup(t, func(a *handlers.App) { a.SubmitLimiter = web.NewRateLimiter(1, time.Minute) })
	inactive := mustForm(t, e.q, e.fx.siteB, "Fermé", true, true)
	for _, f := range []database.Form{e.fx.formA, e.fx.formB, inactive} {
		acceptAttachments(t, e, f)
	}
	if _, err := e.pool.Exec(context.Background(), `UPDATE forms SET active = FALSE WHERE id = $1`, inactive.ID); err != nil {
		t.Fatal(err)
	}
	if resp, _ := submit(t, e.url, submitOpts{path: "/f/" + e.fx.formB.AccessKey, body: "message=x"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("premier envoi : statut %d", resp.StatusCode)
	}
	big := []string{"cv", "gros.bin", strings.Repeat("x", 200<<10)}

	for _, tc := range []struct {
		name  string
		path  string
		parts [][]string
		want  int
	}{
		{"origine non autorisée", "/f/" + e.fx.formA.AccessKey, [][]string{big}, http.StatusForbidden},
		{"origine non autorisée, clé dans un champ", "", [][]string{{"access_key", e.fx.formA.AccessKey}, big}, http.StatusForbidden},
		{"clé inconnue", "/f/00000000-0000-4000-8000-000000000000", [][]string{big}, http.StatusNotFound},
		{"formulaire inactif", "/f/" + inactive.AccessKey, [][]string{big}, http.StatusForbidden},
		{"limite de débit atteinte", "/f/" + e.fx.formB.AccessKey, [][]string{big}, http.StatusTooManyRequests},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ct, body := multipartBody(tc.parts...)
			resp, out := submit(t, e.url, submitOpts{path: tc.path, contentType: ct, body: body, origin: "https://evil.tld"})
			if resp.StatusCode != tc.want {
				t.Errorf("statut %d (%d attendu) : %s", resp.StatusCode, tc.want, out)
			}
		})
	}
	if n := countAttachments(t, e); n != 0 {
		t.Errorf("%d pièce(s) jointe(s) conservée(s) malgré les refus", n)
	}
}

// Each file upload takes several times its size in memory: their simultaneous number is
// bounded, whatever the number of addresses they come from. Beyond that, the visitor is asked
// to retry, and the slot is freed as soon as an upload ends.
func TestPiecesJointesEnvoisSimultanesBornes(t *testing.T) {
	e := setup(t)
	acceptAttachments(t, e, e.fx.formB)
	path := "/f/" + e.fx.formB.AccessKey
	host := strings.TrimPrefix(e.url, "http://")

	// Four uploads (handlers.maxUploads) stay pending: the start of a file, then nothing.
	stalled := "POST " + path + " HTTP/1.1\r\nHost: " + host + "\r\n" +
		"Content-Type: multipart/form-data; boundary=B\r\nContent-Length: 50000\r\n\r\n" +
		"--B\r\nContent-Disposition: form-data; name=\"cv\"; filename=\"cv.pdf\"\r\n\r\ndébut"
	var conns []net.Conn
	stall := func() {
		t.Helper()
		c, err := net.Dial("tcp", host)
		if err != nil {
			t.Fatalf("connexion: %v", err)
		}
		t.Cleanup(func() { c.Close() })
		if _, err := c.Write([]byte(stalled)); err != nil {
			t.Fatalf("envoi: %v", err)
		}
		conns = append(conns, c)
	}
	for range 4 {
		stall()
	}

	ct, body := multipartBody([]string{"name", "Ada"}, []string{"cv", "cv.pdf", "x"})
	// await repeats a file upload until the expected status, calling between (if given)
	// after each other response.
	await := func(want int, between func()) *http.Response {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for {
			resp, out := submit(t, e.url, submitOpts{path: path, contentType: ct, body: body})
			if resp.StatusCode == want {
				return resp
			}
			if time.Now().After(deadline) {
				t.Fatalf("statut %d (%d attendu) : %s", resp.StatusCode, want, out)
			}
			if between != nil {
				between()
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	// The probing upload itself holds a slot while it is processed. If it overtakes one of the
	// pending uploads, it is this one that is refused, and it keeps nothing: the probe would
	// otherwise go on indefinitely. One more pending upload takes the slot it just released,
	// and has no effect if all four are already held.
	if resp := await(http.StatusServiceUnavailable, stall); resp.Header.Get("Retry-After") == "" {
		t.Errorf("un envoi refusé faute de place doit dire quand réessayer")
	}
	// An upload without a file is not affected.
	if resp, out := submit(t, e.url, submitOpts{path: path, body: "name=Ada"}); resp.StatusCode != http.StatusOK {
		t.Errorf("envoi sans fichier pendant la saturation : statut %d, corps %s", resp.StatusCode, out)
	}
	for _, c := range conns {
		c.Close()
	}
	await(http.StatusOK, nil)
}

// Files never go to a chat service. When the alert carries the content, only their name
// appears there, as the value of their field.
func TestPiecesJointesJamaisVersLesServicesDeDiscussion(t *testing.T) {
	hook := newChatHook(t)
	e := setup(t, hook.trust)
	c := newClient()
	login(t, c, e.url, e.fx.memberA.Email)
	resp := postForm(t, c, e.url+"/forms/"+e.fx.formA.ID.String()+"/settings", formValues(csrfToken(t, c, e.url+"/account"), url.Values{
		"slack_webhook_url": {hook.url("/slack/S")}, "teams_webhook_url": {hook.url("/teams/T")}, "discord_webhook_url": {hook.url("/discord/D")},
		"telegram_bot_token": {telegramToken}, "telegram_chat_id": {"-100123"},
		"chat_include_content": {"1"}, "accept_attachments": {"1"},
	}))
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("enregistrement des réglages : statut %d", resp.StatusCode)
	}

	ct, body := multipartBody([]string{"name", "Ada"}, []string{"cv", "cv.pdf", "CONTENU-DU-FICHIER"})
	if resp, out := submit(t, e.url, submitOpts{path: "/f/" + e.fx.formA.AccessKey, contentType: ct, body: body, origin: "https://exemple.fr"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("statut %d, corps %s", resp.StatusCode, out)
	}
	if n := countAttachments(t, e); n != 1 {
		t.Fatalf("%d pièce(s) jointe(s) conservée(s), 1 attendue", n)
	}
	for _, path := range []string{"/slack/S", "/teams/T", "/discord/D", "/bot" + telegramToken + "/sendMessage"} {
		msg := hook.received(t, path, 1)[0]
		if strings.Contains(msg, "CONTENU-DU-FICHIER") {
			t.Errorf("%s : le contenu d'un fichier a été transmis au service de discussion", path)
		}
		if !strings.Contains(msg, "Ada") || !strings.Contains(msg, "cv.pdf") {
			t.Errorf("%s : l'alerte avec contenu doit porter les champs, dont le nom du fichier : %s", path, msg)
		}
	}
}

// In email-only mode, files live only in the email; without the content in the email, they
// never leave the instance.
func TestPiecesJointesSelonLesDestinations(t *testing.T) {
	e := setup(t)
	emailOnly := mustForm(t, e.q, e.fx.siteB, "Email seul", true, false)
	acceptAttachments(t, e, emailOnly)
	ct, body := multipartBody([]string{"name", "Ada"}, []string{"cv", "cv.pdf", "contenu-du-cv"})
	if resp, out := submit(t, e.url, submitOpts{path: "/f/" + emailOnly.AccessKey, contentType: ct, body: body}); resp.StatusCode != http.StatusOK {
		t.Fatalf("email seul : statut %d, corps %s", resp.StatusCode, out)
	}
	m := e.mailer.messages(t, 1)[0]
	if len(m.Attachments) != 1 || string(m.Attachments[0].Data) != "contenu-du-cv" {
		t.Errorf("email seul : l'email doit porter le fichier")
	}
	if n := countAttachments(t, e); n != 0 {
		t.Errorf("email seul : %d pièce(s) jointe(s) stockée(s)", n)
	}

	acceptAttachments(t, e, e.fx.formB)
	if _, err := e.pool.Exec(context.Background(), `UPDATE forms SET email_include_content = FALSE WHERE id = $1`, e.fx.formB.ID); err != nil {
		t.Fatal(err)
	}
	if resp, out := submit(t, e.url, submitOpts{path: "/f/" + e.fx.formB.AccessKey, contentType: ct, body: body}); resp.StatusCode != http.StatusOK {
		t.Fatalf("email sans contenu : statut %d, corps %s", resp.StatusCode, out)
	}
	m = e.mailer.messages(t, 2)[1]
	if len(m.Attachments) != 0 || strings.Contains(m.HTML, "cv.pdf") {
		t.Errorf("email sans contenu : le fichier ou son nom a quitté l'instance")
	}
	if n := countAttachments(t, e); n != 1 {
		t.Errorf("email sans contenu : %d pièce(s) jointe(s) conservée(s), 1 attendue", n)
	}
}

// A bot that fills the honeypot field gets a success, but nothing is processed.
func TestChampPiege(t *testing.T) {
	e := setup(t)
	resp, out := submit(t, e.url, submitOpts{path: "/f/" + e.fx.formB.AccessKey, body: "message=spam&botcheck=on"})
	if resp.StatusCode != http.StatusOK || !strings.Contains(out, `"success":true`) {
		t.Fatalf("statut %d, corps %s", resp.StatusCode, out)
	}
	acceptAttachments(t, e, e.fx.formB)
	ct, body := multipartBody([]string{"botcheck", "on"}, []string{"cv", "spam.bin", "spam"})
	if resp, out := submit(t, e.url, submitOpts{path: "/f/" + e.fx.formB.AccessKey, contentType: ct, body: body}); resp.StatusCode != http.StatusOK {
		t.Fatalf("robot avec fichier : statut %d, corps %s", resp.StatusCode, out)
	}
	time.Sleep(50 * time.Millisecond)
	if n := countSubmissions(t, e, e.fx.formB); n != 0 || countAttachments(t, e) != 0 {
		t.Errorf("la soumission d'un robot a été conservée")
	}
	if msgs := e.mailer.messages(t, 0); len(msgs) != 0 {
		t.Errorf("la soumission d'un robot a été notifiée")
	}
}

// A form refusal does not depend on the honeypot field: the bot receives the same response
// as the visitor, status and body, and nothing is processed.
func TestChampPiegeMemeRefusQueSansLui(t *testing.T) {
	e := setup(t)
	path := "/f/" + e.fx.formB.AccessKey
	plainCT, plainBody := multipartBody([]string{"message", ""})
	trapCT, trapBody := multipartBody([]string{"message", ""}, []string{"botcheck", "on"})
	for _, c := range []struct {
		name        string
		plain, trap submitOpts
	}{
		{"urlencoded", submitOpts{path: path, body: "message="}, submitOpts{path: path, body: "message=&botcheck=on"}},
		{"json", submitOpts{path: path, contentType: "application/json", body: `{"message":""}`}, submitOpts{path: path, contentType: "application/json", body: `{"message":"","botcheck":"on"}`}},
		{"multipart", submitOpts{path: path, contentType: plainCT, body: plainBody}, submitOpts{path: path, contentType: trapCT, body: trapBody}},
	} {
		t.Run(c.name, func(t *testing.T) {
			for _, html := range []bool{false, true} {
				plain, trap := c.plain, c.trap
				plain.html, trap.html = html, html
				resp, plainOut := submit(t, e.url, plain)
				if resp.StatusCode != http.StatusBadRequest {
					t.Fatalf("contenu vide sans piège (html %v) : statut %d, corps %s", html, resp.StatusCode, plainOut)
				}
				trapResp, trapOut := submit(t, e.url, trap)
				if trapResp.StatusCode != resp.StatusCode || trapOut != plainOut {
					t.Errorf("la réponse dépend du champ piège (html %v) : %d %s, sans piège %d %s", html, trapResp.StatusCode, trapOut, resp.StatusCode, plainOut)
				}
			}
		})
	}
	if n := countSubmissions(t, e, e.fx.formB); n != 0 {
		t.Errorf("%d soumission(s) conservée(s)", n)
	}
}

func TestLimiteDeDebit(t *testing.T) {
	e := setup(t, func(a *handlers.App) { a.SubmitLimiter = web.NewRateLimiter(2, time.Minute) })
	path := "/f/" + e.fx.formB.AccessKey
	for i, want := range []int{http.StatusOK, http.StatusOK, http.StatusTooManyRequests} {
		if resp, _ := submit(t, e.url, submitOpts{path: path, body: "message=x"}); resp.StatusCode != want {
			t.Errorf("envoi %d : statut %d (%d attendu)", i+1, resp.StatusCode, want)
		}
	}
	// The limit is per form: another form remains reachable.
	if resp, _ := submit(t, e.url, submitOpts{path: "/f/" + e.fx.formA.AccessKey, body: "message=x", origin: "https://exemple.fr"}); resp.StatusCode != http.StatusOK {
		t.Errorf("autre formulaire : statut %d (200 attendu)", resp.StatusCode)
	}
}

// Email-only mode: nothing is stored, and the visitor only gets a success if the email has
// really left, otherwise the submission would be lost silently. The commitment holds for each sender.
func TestModeEmailSeul(t *testing.T) {
	t.Run("expéditeur des tests", func(t *testing.T) {
		e := setup(t)
		modeEmailSeul(t, e,
			func() string { return e.mailer.messages(t, 1)[0].HTML },
			func() {
				e.mailer.mu.Lock()
				e.mailer.err = errors.New("smtp en panne")
				e.mailer.mu.Unlock()
			})
	})
	t.Run("Microsoft Graph", func(t *testing.T) {
		ms := graphtest.Start(t)
		e := setup(t, withGraph(ms))
		modeEmailSeul(t, e,
			func() string {
				mails := ms.Mails()
				if len(mails) != 1 {
					t.Fatalf("%d email(s) reçu(s) par Graph, 1 attendu", len(mails))
				}
				// The instance keeps nothing, and the sending mailbox must not keep anything either.
				if mails[0].Saved {
					t.Errorf("l'email serait gardé dans les éléments envoyés de la boîte")
				}
				return mails[0].HTML
			},
			func() { ms.RefuseSend(http.StatusForbidden, `{"error":{"code":"ErrorAccessDenied"}}`, "") })
		if n := len(ms.Mails()); n != 1 {
			t.Errorf("%d email(s) reçu(s) par Graph après le refus, 1 attendu", n)
		}
	})
}

// modeEmailSeul runs the email-only scenario. sent returns the HTML of the only email sent,
// breakSender makes the sender fail.
func modeEmailSeul(t *testing.T, e testEnv, sent func() string, breakSender func()) {
	t.Helper()
	form := mustForm(t, e.q, e.fx.siteB, "Email seul", true, false)
	path := "/f/" + form.AccessKey

	resp, out := submit(t, e.url, submitOpts{path: path, contentType: "application/json", body: `{"name":"Ada","message":"bonjour"}`})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("statut %d, corps %s", resp.StatusCode, out)
	}
	if n := countSubmissions(t, e, form); n != 0 {
		t.Errorf("mode email seul : %d soumission(s) stockée(s)", n)
	}
	html := sent()
	if !strings.Contains(html, "bonjour") {
		t.Errorf("l'email doit porter le contenu")
	}
	if strings.Contains(html, "/submissions/") {
		t.Errorf("rien n'est conservé : l'email ne doit pas pointer vers une soumission")
	}

	breakSender()
	resp, out = submit(t, e.url, submitOpts{path: path, body: "message=perdu"})
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(out, `"success":false`) {
		t.Errorf("email non remis : statut %d (502 attendu), corps %s", resp.StatusCode, out)
	}
}

func TestModeEmailSeulSansEnvoiConfigure(t *testing.T) {
	e := setup(t, func(a *handlers.App) { a.Mailer = nil })
	form := mustForm(t, e.q, e.fx.siteB, "Email seul", true, false)
	if resp, _ := submit(t, e.url, submitOpts{path: "/f/" + form.AccessKey, body: "message=x"}); resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("statut %d (503 attendu)", resp.StatusCode)
	}
	// A kept form, on the other hand, works without email: nothing is lost.
	if resp, _ := submit(t, e.url, submitOpts{path: "/f/" + e.fx.formB.AccessKey, body: "message=x"}); resp.StatusCode != http.StatusOK {
		t.Errorf("formulaire conservé sans email : statut %d (200 attendu)", resp.StatusCode)
	}
}

// 'Do not include the content': the email carries no visitor data: neither its fields, nor its
// subject, nor its address in Reply-To.
func TestEmailSansContenu(t *testing.T) {
	e := setup(t)
	if _, err := e.pool.Exec(context.Background(), `UPDATE forms SET email_include_content = FALSE WHERE id = $1`, e.fx.formB.ID); err != nil {
		t.Fatal(err)
	}
	body := url.Values{"email": {"ada@exemple.org"}, "message": {"donnee-privee"}, "subject": {"sujet-prive"}}.Encode()
	if resp, out := submit(t, e.url, submitOpts{path: "/f/" + e.fx.formB.AccessKey, body: body}); resp.StatusCode != http.StatusOK {
		t.Fatalf("statut %d, corps %s", resp.StatusCode, out)
	}
	m := e.mailer.messages(t, 1)[0]
	for _, private := range []string{"donnee-privee", "sujet-prive", "ada@exemple.org"} {
		if strings.Contains(m.HTML, private) || strings.Contains(m.Subject, private) {
			t.Errorf("%q présent dans l'email sans contenu", private)
		}
	}
	if m.ReplyTo != "" {
		t.Errorf("Reply-To = %q : l'adresse du visiteur ne doit pas voyager", m.ReplyTo)
	}
	if !strings.Contains(m.HTML, "/submissions/") {
		t.Errorf("l'email doit renvoyer vers la soumission dans l'interface")
	}
}

// Classic form submission (without JavaScript): redirect to the return page, never to a
// domain foreign to the site.
func TestRetourApresEnvoiHTML(t *testing.T) {
	e := setup(t)
	path := "/f/" + e.fx.formA.AccessKey
	post := func(redirect string) (*http.Response, string) {
		body := url.Values{"message": {"x"}, "redirect": {redirect}}.Encode()
		return submit(t, e.url, submitOpts{path: path, body: body, origin: "https://exemple.fr", html: true})
	}

	resp, _ := post("https://www.exemple.fr/merci")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "https://www.exemple.fr/merci" {
		t.Errorf("page de retour du site : statut %d, Location %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	for _, evil := range []string{"https://evil.tld/phishing", "//evil.tld", "javascript:alert(1)"} {
		resp, body := post(evil)
		if resp.StatusCode != http.StatusOK || resp.Header.Get("Location") != "" || !strings.Contains(body, "Message envoyé") {
			t.Errorf("redirect=%q : attendu la page intégrée, obtenu %d Location %q", evil, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
	// Failure in HTML: a readable page, not JSON.
	resp, body := submit(t, e.url, submitOpts{path: path, body: "message=x", origin: "https://evil.tld", html: true})
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "<html") {
		t.Errorf("échec HTML : statut %d", resp.StatusCode)
	}
}

func TestPreflightCORS(t *testing.T) {
	e := setup(t)
	req, _ := http.NewRequest(http.MethodOptions, e.url+"/submit", nil)
	req.Header.Set("Origin", "https://exemple.fr")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "content-type")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent || resp.Header.Get("Access-Control-Allow-Origin") != "*" ||
		!strings.Contains(resp.Header.Get("Access-Control-Allow-Headers"), "Content-Type") {
		t.Errorf("pré-requête : statut %d, en-têtes %v", resp.StatusCode, resp.Header)
	}
}

func TestLectureExportEtSuppression(t *testing.T) {
	e := setup(t)
	storeSubmission(t, e, e.fx.formA, "https://exemple.fr",
		"name="+url.QueryEscape(`=HYPERLINK("http://evil.tld")`)+"&message="+url.QueryEscape("<script>alert(1)</script>"))
	sub := storeSubmission(t, e, e.fx.formA, "https://exemple.fr", "name=Grace&message=second")

	c := newClient()
	login(t, c, e.url, e.fx.memberA.Email)

	formPath := "/forms/" + e.fx.formA.ID.String()
	code, body := get(t, c, e.url+formPath)
	if code != http.StatusOK || !strings.Contains(body, "Grace") {
		t.Fatalf("liste des soumissions : statut %d", code)
	}
	// A visitor's content is escaped on display.
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Errorf("contenu d'une soumission rendu sans échappement")
	}

	// Opening a submission marks it as read.
	if code, _ := get(t, c, e.url+"/submissions/"+sub.ID.String()); code != http.StatusOK {
		t.Fatalf("détail : statut %d", code)
	}
	var unread int
	_ = e.pool.QueryRow(context.Background(), `SELECT count(*) FROM submissions WHERE form_id = $1 AND read_at IS NULL`, e.fx.formA.ID).Scan(&unread)
	if unread != 1 {
		t.Errorf("%d soumission(s) non lue(s) après ouverture d'une sur deux (1 attendue)", unread)
	}

	code, csv := get(t, c, e.url+formPath+"/export.csv")
	if code != http.StatusOK || !strings.Contains(csv, "Grace,second") {
		t.Errorf("export CSV : statut %d, contenu %q", code, csv)
	}
	// A cell starting with '=' would be run by a spreadsheet.
	if !strings.Contains(csv, `"'=HYPERLINK(`) {
		t.Errorf("formule non neutralisée dans l'export : %q", csv)
	}

	token := csrfToken(t, c, e.url+"/account")
	resp := postForm(t, c, e.url+"/submissions/"+sub.ID.String()+"/delete", url.Values{"csrf_token": {token}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || countSubmissions(t, e, e.fx.formA) != 1 {
		t.Errorf("suppression d'une soumission : statut %d, reste %d", resp.StatusCode, countSubmissions(t, e, e.fx.formA))
	}
	resp = postForm(t, c, e.url+formPath+"/purge", url.Values{"csrf_token": {token}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || countSubmissions(t, e, e.fx.formA) != 0 {
		t.Errorf("vidage : statut %d, reste %d", resp.StatusCode, countSubmissions(t, e, e.fx.formA))
	}
}

// The retention period applies per form; 0 means no limit.
func TestRetentionDesSoumissions(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	forever := mustForm(t, e.q, e.fx.siteB, "Sans limite", false, true)
	if _, err := e.pool.Exec(ctx, `UPDATE forms SET retention_days = 0 WHERE id = $1`, forever.ID); err != nil {
		t.Fatal(err)
	}
	insert := func(form database.Form, age string) {
		if _, err := e.pool.Exec(ctx,
			`WITH sub AS (INSERT INTO submissions (form_id, payload, created_at) VALUES ($1, 'x', now() - $2::interval) RETURNING id)
			 INSERT INTO attachments (submission_id, position, filename, size, content) SELECT id, 0, 'x', 1, 'x' FROM sub`, form.ID, age); err != nil {
			t.Fatal(err)
		}
	}
	insert(e.fx.formA, "91 days") // expired (90 days)
	insert(e.fx.formA, "89 days") // still within the period
	insert(forever, "900 days")   // kept with no limit

	n, err := e.q.PurgeExpiredSubmissions(ctx)
	if err != nil || n != 1 {
		t.Fatalf("purge : %d supprimée(s), err %v (1 attendue)", n, err)
	}
	if got := countSubmissions(t, e, e.fx.formA); got != 1 {
		t.Errorf("formulaire à 90 jours : %d restante(s) (1 attendue)", got)
	}
	if got := countSubmissions(t, e, forever); got != 1 {
		t.Errorf("formulaire sans limite : %d restante(s) (1 attendue)", got)
	}
	// An attachment does not outlive its submission.
	if got := countAttachments(t, e); got != 2 {
		t.Errorf("%d pièce(s) jointe(s) après la purge (2 attendues)", got)
	}
}

// Deleting a site deletes its forms and their submissions: nothing survives beyond the
// reach of its owner.
func TestSuppressionDuSiteEmporteLesDonnees(t *testing.T) {
	e := setup(t)
	sub := storeSubmission(t, e, e.fx.formA, "https://exemple.fr", "message=x")
	if _, err := e.pool.Exec(context.Background(),
		`INSERT INTO attachments (submission_id, position, filename, size, content) VALUES ($1, 0, 'x', 1, 'x')`, sub.ID); err != nil {
		t.Fatal(err)
	}
	c := newClient()
	login(t, c, e.url, e.fx.memberA.Email)
	token := csrfToken(t, c, e.url+"/account")
	resp := postForm(t, c, e.url+"/sites/"+e.fx.siteA.ID.String()+"/delete", url.Values{"csrf_token": {token}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("suppression du site : statut %d", resp.StatusCode)
	}
	var forms, subs int
	_ = e.pool.QueryRow(context.Background(), `SELECT count(*) FROM forms WHERE site_id = $1`, e.fx.siteA.ID).Scan(&forms)
	_ = e.pool.QueryRow(context.Background(), `SELECT count(*) FROM submissions WHERE form_id = $1`, e.fx.formA.ID).Scan(&subs)
	if files := countAttachments(t, e); forms != 0 || subs != 0 || files != 0 {
		t.Errorf("après suppression du site : %d formulaire(s), %d soumission(s), %d pièce(s) jointe(s) restants", forms, subs, files)
	}
	if resp, _ := submit(t, e.url, submitOpts{path: "/f/" + e.fx.formA.AccessKey, body: "message=x", origin: "https://exemple.fr"}); resp.StatusCode != http.StatusNotFound {
		t.Errorf("envoi vers un formulaire supprimé : statut %d (404 attendu)", resp.StatusCode)
	}
}

// chatHook is a fake chat service (HTTPS) that keeps what it receives.
type chatHook struct {
	srv    *httptest.Server
	mu     sync.Mutex
	got    map[string][]string // bodies received, by path
	status int                 // status returned (default 200)
	down   map[string]bool     // paths that answer 500 whatever the status
}

func newChatHook(t *testing.T) *chatHook {
	t.Helper()
	h := &chatHook{got: map[string][]string{}, down: map[string]bool{}}
	h.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		h.mu.Lock()
		h.got[r.URL.Path] = append(h.got[r.URL.Path], string(body))
		status := h.status
		if h.down[r.URL.Path] {
			status = http.StatusInternalServerError
		}
		h.mu.Unlock()
		if status != 0 {
			w.WriteHeader(status)
		}
	}))
	t.Cleanup(h.srv.Close)
	return h
}

// trust makes the application accept this fake service (host added by the operator,
// plus the test certificate).
func (h *chatHook) trust(a *handlers.App) {
	u, _ := url.Parse(h.srv.URL)
	n := chat.New([]string{u.Hostname()})
	client := h.srv.Client()
	client.CheckRedirect = n.Client.CheckRedirect
	n.Client = client
	n.TelegramAPI = h.srv.URL
	a.Chat = n
}

func (h *chatHook) url(path string) string { return h.srv.URL + path }

func (h *chatHook) received(t *testing.T, path string, n int) []string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		h.mu.Lock()
		got := append([]string(nil), h.got[path]...)
		h.mu.Unlock()
		if len(got) >= n || time.Now().After(deadline) {
			if len(got) < n {
				t.Fatalf("%s : %d message(s) reçu(s), %d attendu(s)", path, len(got), n)
			}
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// formValues: full input of the settings page (kept form).
func formValues(token string, extra url.Values) url.Values {
	v := url.Values{
		"csrf_token": {token}, "name": {"Contact Alpha"}, "active": {"1"},
		"store_submissions": {"1"}, "retention_days": {"90"},
	}
	for k, vals := range extra {
		v[k] = vals
	}
	return v
}

func webhookColumns(t *testing.T, e testEnv, form database.Form) (slack, teams *string) {
	t.Helper()
	if err := e.pool.QueryRow(context.Background(),
		`SELECT slack_webhook_url, teams_webhook_url FROM forms WHERE id = $1`, form.ID).Scan(&slack, &teams); err != nil {
		t.Fatalf("lecture des webhooks: %v", err)
	}
	return slack, teams
}

// webhookColumn reads a webhook column as stored (encrypted).
func webhookColumn(t *testing.T, e testEnv, form database.Form, column string) (stored *string) {
	t.Helper()
	if err := e.pool.QueryRow(context.Background(),
		`SELECT `+column+` FROM forms WHERE id = $1`, form.ID).Scan(&stored); err != nil {
		t.Fatalf("lecture de %s: %v", column, err)
	}
	return stored
}

func TestAlertesSlackTeamsEtDiscord(t *testing.T) {
	hook := newChatHook(t)
	e := setup(t, hook.trust)
	c := newClient()
	login(t, c, e.url, e.fx.memberA.Email)
	token := csrfToken(t, c, e.url+"/account")
	settings := e.url + "/forms/" + e.fx.formA.ID.String() + "/settings"

	resp := postForm(t, c, settings, formValues(token, url.Values{
		"slack_webhook_url": {hook.url("/slack/SECRET-S")}, "teams_webhook_url": {hook.url("/teams/SECRET-T")},
		"discord_webhook_url": {hook.url("/discord/SECRET-D")},
	}))
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("enregistrement des webhooks : statut %d", resp.StatusCode)
	}
	// A webhook address is a secret: encrypted in the database.
	slack, teams := webhookColumns(t, e, e.fx.formA)
	discord := webhookColumn(t, e, e.fx.formA, "discord_webhook_url")
	for name, col := range map[string]*string{"slack": slack, "teams": teams, "discord": discord} {
		if col == nil || !strings.HasPrefix(*col, "enc1:") || strings.Contains(*col, "SECRET") {
			t.Errorf("webhook %s non chiffré en base : %v", name, col)
		}
	}
	// Its owner finds it in their settings.
	if _, body := get(t, c, settings); !strings.Contains(body, "/slack/SECRET-S") || !strings.Contains(body, "/teams/SECRET-T") || !strings.Contains(body, "/discord/SECRET-D") {
		t.Errorf("les réglages doivent réafficher les adresses enregistrées")
	}

	// By default the alert carries nothing of what the visitor wrote.
	storeSubmission(t, e, e.fx.formA, "https://exemple.fr", "name=Zorglub&email=zorglub%40exemple.org&message=donnee-privee")
	paths := []string{"/slack/SECRET-S", "/teams/SECRET-T", "/discord/SECRET-D"}
	for _, path := range paths {
		msg := hook.received(t, path, 1)[0]
		for _, private := range []string{"donnee-privee", "Zorglub", "zorglub@exemple.org"} {
			if strings.Contains(msg, private) {
				t.Errorf("%s : %q transmis au service de discussion sans que ce soit demandé", path, private)
			}
		}
		if !strings.Contains(msg, "Contact Alpha") || !strings.Contains(msg, "http://naria.test/submissions/") {
			t.Errorf("%s : l'alerte doit nommer le formulaire et pointer vers la soumission : %s", path, msg)
		}
	}
	// Each address receives the format of its service: a column crossed with another would show here.
	for path, marker := range map[string]string{
		"/slack/SECRET-S": `"blocks"`, "/teams/SECRET-T": "AdaptiveCard", "/discord/SECRET-D": `"allowed_mentions":{"parse":[]}`,
	} {
		if msg := hook.received(t, path, 1)[0]; !strings.Contains(msg, marker) {
			t.Errorf("%s : %s attendu dans le message : %s", path, marker, msg)
		}
	}
	if _, body := get(t, c, e.url+"/forms/"+e.fx.formA.ID.String()); !strings.Contains(body, ">Discord<") {
		t.Errorf("la page du formulaire doit afficher le badge Discord")
	}

	// On explicit request, the content is attached.
	resp = postForm(t, c, settings, formValues(token, url.Values{
		"slack_webhook_url": {hook.url("/slack/SECRET-S")}, "teams_webhook_url": {hook.url("/teams/SECRET-T")},
		"discord_webhook_url": {hook.url("/discord/SECRET-D")}, "chat_include_content": {"1"},
	}))
	resp.Body.Close()
	resp2, out := submit(t, e.url, submitOpts{path: "/f/" + e.fx.formA.AccessKey, body: "message=contenu-voulu", origin: "https://exemple.fr"})
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("soumission : statut %d (%s)", resp2.StatusCode, out)
	}
	for _, path := range paths {
		if msg := hook.received(t, path, 2)[1]; !strings.Contains(msg, "contenu-voulu") {
			t.Errorf("%s : le contenu demandé manque : %s", path, msg)
		}
	}

	resp = postForm(t, c, settings, formValues(token, url.Values{"teams_webhook_url": {hook.url("/teams/SECRET-T")}}))
	resp.Body.Close()
	if slack, teams := webhookColumns(t, e, e.fx.formA); slack != nil || teams == nil {
		t.Errorf("après retrait de Slack : slack=%v teams=%v", slack, teams)
	}
	if discord := webhookColumn(t, e, e.fx.formA, "discord_webhook_url"); discord != nil {
		t.Errorf("après retrait de Discord : discord=%v", discord)
	}
}

// A chat service that is down neither fails nor loses a submission, and does not deprive
// the other channels of their alert.
func TestAlerteEnPanneNeBloquePasLaSoumission(t *testing.T) {
	hook := newChatHook(t)
	hook.down["/slack"] = true
	e := setup(t, hook.trust)
	c := newClient()
	login(t, c, e.url, e.fx.memberA.Email)
	token := csrfToken(t, c, e.url+"/account")
	resp := postForm(t, c, e.url+"/forms/"+e.fx.formA.ID.String()+"/settings",
		formValues(token, url.Values{"slack_webhook_url": {hook.url("/slack")}, "discord_webhook_url": {hook.url("/discord")}}))
	resp.Body.Close()

	// The sending order between channels is not fixed: several submissions, so that the outage
	// comes before the healthy channel at least once.
	const n = 5
	for range n {
		storeSubmission(t, e, e.fx.formA, "https://exemple.fr", "message=x") // exige un 200
	}
	hook.received(t, "/slack", n)
	hook.received(t, "/discord", n)
	if got := countSubmissions(t, e, e.fx.formA); got != n {
		t.Errorf("%d soumission(s) conservée(s) (%d attendues)", got, n)
	}
}

// One channel configured: only it is called, and only its column is filled.
// No channel: nothing is called.
func TestAlerteDiscordSeulPuisAucunCanal(t *testing.T) {
	hook := newChatHook(t)
	e := setup(t, hook.trust)
	c := newClient()
	login(t, c, e.url, e.fx.memberA.Email)
	token := csrfToken(t, c, e.url+"/account")
	settings := e.url + "/forms/" + e.fx.formA.ID.String() + "/settings"

	resp := postForm(t, c, settings, formValues(token, url.Values{"discord_webhook_url": {hook.url("/discord")}}))
	resp.Body.Close()
	if slack, teams := webhookColumns(t, e, e.fx.formA); slack != nil || teams != nil {
		t.Errorf("Discord seul : slack=%v teams=%v", slack, teams)
	}
	if webhookColumn(t, e, e.fx.formA, "discord_webhook_url") == nil {
		t.Fatal("Discord seul : adresse non enregistrée")
	}
	storeSubmission(t, e, e.fx.formA, "https://exemple.fr", "message=x")
	if msg := hook.received(t, "/discord", 1)[0]; !strings.Contains(msg, `"allowed_mentions"`) {
		t.Errorf("message Discord inattendu : %s", msg)
	}

	resp = postForm(t, c, settings, formValues(token, nil))
	resp.Body.Close()
	storeSubmission(t, e, e.fx.formA, "https://exemple.fr", "message=y")
	time.Sleep(100 * time.Millisecond) // the alert, if any, would leave in the background
	hook.mu.Lock()
	defer hook.mu.Unlock()
	if len(hook.got) != 1 || len(hook.got["/discord"]) != 1 {
		t.Errorf("appels reçus : %v (un seul attendu, sur /discord)", hook.got)
	}
}

// The server calls the entered address: it must not be able to point to its internal network
// or to just any host.
func TestWebhookRefuseLesAdressesNonAutorisees(t *testing.T) {
	e := setup(t)
	c := newClient()
	login(t, c, e.url, e.fx.memberA.Email)
	token := csrfToken(t, c, e.url+"/account")
	base := e.url + "/forms/" + e.fx.formA.ID.String()

	for _, bad := range []url.Values{
		{"slack_webhook_url": {"https://127.0.0.1:5432/"}},
		{"slack_webhook_url": {"https://169.254.169.254/latest/meta-data/"}},
		{"slack_webhook_url": {"http://hooks.slack.com/services/T/B/X"}},
		{"slack_webhook_url": {"https://hooks.slack.com.evil.tld/services/T/B/X"}},
		{"teams_webhook_url": {"https://evil.tld/workflows"}},
		{"teams_webhook_url": {"https://hooks.slack.com/services/T/B/X"}},
		{"discord_webhook_url": {"https://127.0.0.1/api/webhooks/1/T"}},
		{"discord_webhook_url": {"https://discord.com.evil.tld/api/webhooks/1/T"}},
		{"discord_webhook_url": {"http://discord.com/api/webhooks/1/T"}},
		{"discord_webhook_url": {"https://discord.com/api/v10/auth/login"}},
	} {
		for _, path := range []string{"/settings", "/webhooks/test"} {
			vals := formValues(token, bad)
			vals.Set("channel", "slack")
			if bad.Get("teams_webhook_url") != "" {
				vals.Set("channel", "teams")
			}
			if bad.Get("discord_webhook_url") != "" {
				vals.Set("channel", "discord")
			}
			resp := postForm(t, c, base+path, vals)
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("POST %s %v : statut %d (400 attendu)", path, bad, resp.StatusCode)
			}
			// The refusal must come from the address, not from a channel the route would ignore.
			if bad.Get("discord_webhook_url") != "" && !strings.Contains(string(body), "Webhook Discord invalide") {
				t.Errorf("POST %s %v : le refus ne vient pas de la validation de l'adresse", path, bad)
			}
		}
	}
	if slack, teams := webhookColumns(t, e, e.fx.formA); slack != nil || teams != nil {
		t.Errorf("une adresse refusée a été enregistrée : slack=%v teams=%v", slack, teams)
	}
	if discord := webhookColumn(t, e, e.fx.formA, "discord_webhook_url"); discord != nil {
		t.Errorf("une adresse Discord refusée a été enregistrée : %v", discord)
	}
	// An official address is accepted (nothing is called at save time).
	resp := postForm(t, c, base+"/settings", formValues(token, url.Values{
		"slack_webhook_url":   {"https://hooks.slack.com/services/T000/B000/XXXX"},
		"teams_webhook_url":   {"https://abc.de.environment.api.powerplatform.com:443/powerautomate/automations/direct/workflows/w/triggers/manual/paths/invoke?api-version=1&sig=s"},
		"discord_webhook_url": {"https://discord.com/api/webhooks/123456789/TOKEN"},
	}))
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("adresses officielles : statut %d (303 attendu)", resp.StatusCode)
	}
}

// The 'Test' button sends a message to the entered address without saving it, and stays
// isolated like the rest of the form.
func TestBoutonTesterLeWebhook(t *testing.T) {
	hook := newChatHook(t)
	e := setup(t, hook.trust)
	testURL := e.url + "/forms/" + e.fx.formA.ID.String() + "/webhooks/test"

	b := newClient()
	login(t, b, e.url, e.fx.memberB.Email)
	resp := postForm(t, b, testURL, formValues(csrfToken(t, b, e.url+"/account"), url.Values{
		"channel": {"slack"}, "slack_webhook_url": {hook.url("/slack")},
	}))
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("test du webhook d'un autre membre : statut %d (404 attendu)", resp.StatusCode)
	}
	resp = postForm(t, b, testURL, formValues(csrfToken(t, b, e.url+"/account"), url.Values{
		"channel": {"telegram"}, "telegram_bot_token": {telegramToken}, "telegram_chat_id": {"-100123"},
	}))
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("test Telegram sur le formulaire d'un autre membre : statut %d (404 attendu)", resp.StatusCode)
	}

	a := newClient()
	login(t, a, e.url, e.fx.memberA.Email)
	token := csrfToken(t, a, e.url+"/account")
	resp = postForm(t, a, testURL, formValues(token, url.Values{"channel": {"teams"}, "teams_webhook_url": {hook.url("/teams")}}))
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("test Teams : statut %d", resp.StatusCode)
	}
	if msgs := hook.received(t, "/teams", 1); !strings.Contains(msgs[0], "Message de test") || !strings.Contains(msgs[0], "AdaptiveCard") {
		t.Errorf("message de test inattendu : %s", msgs[0])
	}
	if !strings.Contains(string(body), hook.url("/teams")) {
		t.Errorf("la page doit conserver l'adresse saisie")
	}
	if slack, teams := webhookColumns(t, e, e.fx.formA); slack != nil || teams != nil {
		t.Errorf("le test a enregistré une adresse : slack=%v teams=%v", slack, teams)
	}
	// Discord: same button, and the message forbids any mention.
	resp = postForm(t, a, testURL, formValues(token, url.Values{"channel": {"discord"}, "discord_webhook_url": {hook.url("/discord")}}))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("test Discord : statut %d", resp.StatusCode)
	}
	if msgs := hook.received(t, "/discord", 1); !strings.Contains(msgs[0], "Message de test") || !strings.Contains(msgs[0], `"allowed_mentions":{"parse":[]}`) {
		t.Errorf("message de test Discord inattendu : %s", msgs[0])
	}
	if discord := webhookColumn(t, e, e.fx.formA, "discord_webhook_url"); discord != nil {
		t.Errorf("le test a enregistré l'adresse Discord : %v", discord)
	}
	hook.mu.Lock()
	leaked := len(hook.got["/slack"]) + len(hook.got["/bot"+telegramToken+"/sendMessage"])
	hook.mu.Unlock()
	if leaked != 0 {
		t.Errorf("le test refusé de B a tout de même appelé le webhook")
	}

	// Service in error: the failure is shown, without quoting the address in the logs.
	hook.mu.Lock()
	hook.status = http.StatusNotFound
	hook.mu.Unlock()
	resp = postForm(t, a, testURL, formValues(token, url.Values{"channel": {"slack"}, "slack_webhook_url": {hook.url("/slack")}}))
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("webhook en erreur : statut %d (502 attendu)", resp.StatusCode)
	}
	resp = postForm(t, a, testURL, formValues(token, url.Values{"channel": {"slack"}}))
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("test sans adresse : statut %d (400 attendu)", resp.StatusCode)
	}
}

// The 'Test' button makes the server call a third party: it is limited per account, so that a
// member cannot get the instance address blocked by the service through repeated refused calls.
func TestBoutonTesterEstLimiteParCompte(t *testing.T) {
	hook := newChatHook(t)
	e := setup(t, hook.trust, func(a *handlers.App) { a.WebhookTestLimiter = web.NewRateLimiter(2, time.Minute) })
	c := newClient()
	login(t, c, e.url, e.fx.memberA.Email)
	token := csrfToken(t, c, e.url+"/account")
	testURL := e.url + "/forms/" + e.fx.formA.ID.String() + "/webhooks/test"
	vals := formValues(token, url.Values{"channel": {"discord"}, "discord_webhook_url": {hook.url("/discord")}})

	for i, want := range []int{http.StatusOK, http.StatusOK, http.StatusTooManyRequests} {
		resp := postForm(t, c, testURL, vals)
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("test n°%d : statut %d (%d attendu)", i+1, resp.StatusCode, want)
		}
	}
	if got := hook.received(t, "/discord", 2); len(got) != 2 {
		t.Errorf("%d appels sortants (2 attendus) : le test refusé ne doit rien envoyer", len(got))
	}

	// The limit is per account: the administrator still tests the same form.
	adm := newClient()
	login(t, adm, e.url, e.fx.admin.Email)
	vals.Set("csrf_token", csrfToken(t, adm, e.url+"/account"))
	resp := postForm(t, adm, testURL, vals)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("test par un autre compte : statut %d (200 attendu)", resp.StatusCode)
	}
}

const telegramToken = "123456789:AAExampleExampleExampleExampleExample"

func TestAlerteTelegram(t *testing.T) {
	hook := newChatHook(t)
	e := setup(t, hook.trust)
	c := newClient()
	login(t, c, e.url, e.fx.memberA.Email)
	token := csrfToken(t, c, e.url+"/account")
	base := e.url + "/forms/" + e.fx.formA.ID.String()
	api := "/bot" + telegramToken + "/sendMessage"

	// The token and the identifier go together, and their format is checked: the token goes into
	// the address the server calls.
	const pair, empty = "vont ensemble", "Saisissez d&#39;abord le jeton"
	for _, bad := range []struct {
		vals             url.Values
		onSave, onTester string // reason shown on save, then on test
	}{
		{url.Values{"telegram_bot_token": {telegramToken}}, pair, empty},
		{url.Values{"telegram_chat_id": {"-100123"}}, pair, empty},
		{url.Values{"telegram_bot_token": {"pas-un-jeton"}, "telegram_chat_id": {"-100123"}}, "Jeton Telegram invalide", "Jeton Telegram invalide"},
		{url.Values{"telegram_bot_token": {telegramToken + "/../getMe"}, "telegram_chat_id": {"-100123"}}, "Jeton Telegram invalide", "Jeton Telegram invalide"},
		{url.Values{"telegram_bot_token": {telegramToken}, "telegram_chat_id": {"mon groupe"}}, "Identifiant Telegram invalide", "Identifiant Telegram invalide"},
	} {
		for path, reason := range map[string]string{"/settings": bad.onSave, "/webhooks/test": bad.onTester} {
			vals := formValues(token, bad.vals)
			vals.Set("channel", "telegram")
			resp := postForm(t, c, base+path, vals)
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), reason) {
				t.Errorf("POST %s %v : statut %d, raison %q attendue", path, bad.vals, resp.StatusCode, reason)
			}
		}
	}
	if stored := webhookColumn(t, e, e.fx.formA, "telegram_bot_token"); stored != nil {
		t.Errorf("un réglage refusé a été enregistré : %v", stored)
	}

	resp := postForm(t, c, base+"/settings", formValues(token, url.Values{
		"telegram_bot_token": {telegramToken}, "telegram_chat_id": {"-100123"},
	}))
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("enregistrement : statut %d", resp.StatusCode)
	}
	// The token is a secret, encrypted in the database; the identifier is not one.
	stored := webhookColumn(t, e, e.fx.formA, "telegram_bot_token")
	if stored == nil || !strings.HasPrefix(*stored, "enc1:") || strings.Contains(*stored, "AAExample") {
		t.Fatalf("jeton non chiffré en base : %v", stored)
	}
	// It has its own key: the one for webhook addresses does not open it.
	for purpose, readable := range map[string]bool{crypto.PurposeBotToken: true, crypto.PurposeWebhook: false} {
		cipher, _ := crypto.New(testSecret, purpose)
		if plain, err := cipher.Decrypt(*stored); (err == nil && plain == telegramToken) != readable {
			t.Errorf("clé %q : lisible=%v attendu, err=%v", purpose, readable, err)
		}
	}
	if chatID := webhookColumn(t, e, e.fx.formA, "telegram_chat_id"); chatID == nil || *chatID != "-100123" {
		t.Errorf("identifiant de discussion = %v", chatID)
	}
	if _, body := get(t, c, base+"/settings"); !strings.Contains(body, telegramToken) || !strings.Contains(body, "-100123") {
		t.Errorf("les réglages doivent réafficher le jeton et l'identifiant")
	}
	for _, page := range []string{base, e.url + "/sites/" + e.fx.siteA.ID.String()} {
		if _, body := get(t, c, page); !strings.Contains(body, ">Telegram<") || strings.Contains(body, ">Discord<") {
			t.Errorf("%s doit afficher le badge Telegram, et lui seul", page)
		}
	}

	// By default the alert carries nothing of what the visitor wrote.
	storeSubmission(t, e, e.fx.formA, "https://exemple.fr", "name=Zorglub&email=zorglub%40exemple.org&message=donnee-privee")
	msg := hook.received(t, api, 1)[0]
	for _, private := range []string{"donnee-privee", "Zorglub", "zorglub@exemple.org"} {
		if strings.Contains(msg, private) {
			t.Errorf("%q transmis à Telegram sans que ce soit demandé", private)
		}
	}
	for _, want := range []string{"Contact Alpha", "http://naria.test/submissions/", `"chat_id":"-100123"`, `"parse_mode":"HTML"`, `"is_disabled":true`} {
		if !strings.Contains(msg, want) {
			t.Errorf("%s attendu dans l'alerte : %s", want, msg)
		}
	}

	resp = postForm(t, c, base+"/settings", formValues(token, url.Values{
		"telegram_bot_token": {telegramToken}, "telegram_chat_id": {"-100123"}, "chat_include_content": {"1"},
	}))
	resp.Body.Close()
	storeSubmission(t, e, e.fx.formA, "https://exemple.fr", "message=contenu-voulu")
	if msg := hook.received(t, api, 2)[1]; !strings.Contains(msg, "contenu-voulu") {
		t.Errorf("le contenu demandé manque : %s", msg)
	}

	vals := formValues(token, url.Values{"channel": {"telegram"}, "telegram_bot_token": {telegramToken}, "telegram_chat_id": {"@canal_public"}})
	resp = postForm(t, c, base+"/webhooks/test", vals)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("test Telegram : statut %d", resp.StatusCode)
	}
	if msg := hook.received(t, api, 3)[2]; !strings.Contains(msg, "Message de test") || !strings.Contains(msg, `"chat_id":"@canal_public"`) {
		t.Errorf("message de test inattendu : %s", msg)
	}
	if chatID := webhookColumn(t, e, e.fx.formA, "telegram_chat_id"); chatID == nil || *chatID != "-100123" {
		t.Errorf("le test a modifié le réglage enregistré : %v", chatID)
	}
	hook.mu.Lock()
	hook.down[api] = true
	hook.mu.Unlock()
	resp = postForm(t, c, base+"/webhooks/test", vals)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("Telegram en erreur : statut %d (502 attendu)", resp.StatusCode)
	}
	storeSubmission(t, e, e.fx.formA, "https://exemple.fr", "message=x")
	hook.received(t, api, 5)
	if n := countSubmissions(t, e, e.fx.formA); n != 3 {
		t.Errorf("%d soumission(s) conservée(s) (3 attendues)", n)
	}

	resp = postForm(t, c, base+"/settings", formValues(token, nil))
	resp.Body.Close()
	if tok, chatID := webhookColumn(t, e, e.fx.formA, "telegram_bot_token"), webhookColumn(t, e, e.fx.formA, "telegram_chat_id"); tok != nil || chatID != nil {
		t.Errorf("après retrait : jeton=%v identifiant=%v", tok, chatID)
	}
}

// Telegram alongside another channel: each receives its message in its own format, and the
// failure of one does not deprive the other.
func TestAlerteTelegramAvecUnAutreCanal(t *testing.T) {
	hook := newChatHook(t)
	e := setup(t, hook.trust)
	c := newClient()
	login(t, c, e.url, e.fx.memberA.Email)
	token := csrfToken(t, c, e.url+"/account")
	api := "/bot" + telegramToken + "/sendMessage"
	resp := postForm(t, c, e.url+"/forms/"+e.fx.formA.ID.String()+"/settings", formValues(token, url.Values{
		"discord_webhook_url": {hook.url("/discord")}, "telegram_bot_token": {telegramToken}, "telegram_chat_id": {"-100123"},
	}))
	resp.Body.Close()

	// The sending order between channels is not fixed: several submissions per case.
	const n = 5
	sent := 0
	for _, down := range []string{"", api, "/discord"} {
		hook.mu.Lock()
		hook.down = map[string]bool{down: true}
		hook.mu.Unlock()
		for range n {
			storeSubmission(t, e, e.fx.formA, "https://exemple.fr", "message=x")
		}
		sent += n
		hook.received(t, api, sent)
		hook.received(t, "/discord", sent)
	}
	for path, marker := range map[string]string{api: `"parse_mode":"HTML"`, "/discord": `"allowed_mentions"`} {
		for _, msg := range hook.received(t, path, sent) {
			if !strings.Contains(msg, marker) {
				t.Fatalf("%s a reçu un message qui n'est pas le sien : %s", path, msg)
			}
		}
	}
	if got := countSubmissions(t, e, e.fx.formA); got != int64(sent) {
		t.Errorf("%d soumission(s) conservée(s) (%d attendues)", got, sent)
	}
}

func TestCreationDeFormulaireAvecTelegram(t *testing.T) {
	e := setup(t)
	c := newClient()
	login(t, c, e.url, e.fx.memberA.Email)
	token := csrfToken(t, c, e.url+"/account")
	create := e.url + "/sites/" + e.fx.siteA.ID.String() + "/forms"
	columns := func(name string) (count int, tok, chatID *string) {
		t.Helper()
		if err := e.pool.QueryRow(context.Background(),
			`SELECT count(*), min(telegram_bot_token), min(telegram_chat_id) FROM forms WHERE name = $1`, name).Scan(&count, &tok, &chatID); err != nil {
			t.Fatalf("lecture du formulaire %q: %v", name, err)
		}
		return count, tok, chatID
	}

	resp := postForm(t, c, create, url.Values{
		"csrf_token": {token}, "name": {"Sans identifiant"}, "store_submissions": {"1"}, "telegram_bot_token": {telegramToken},
	})
	resp.Body.Close()
	if count, _, _ := columns("Sans identifiant"); resp.StatusCode != http.StatusBadRequest || count != 0 {
		t.Errorf("jeton sans identifiant : statut %d, %d formulaire(s) créé(s)", resp.StatusCode, count)
	}

	resp = postForm(t, c, create, url.Values{
		"csrf_token": {token}, "name": {"Avec Telegram"}, "store_submissions": {"1"},
		"telegram_bot_token": {telegramToken}, "telegram_chat_id": {"@canal_public"},
	})
	resp.Body.Close()
	count, tok, chatID := columns("Avec Telegram")
	if resp.StatusCode != http.StatusSeeOther || count != 1 {
		t.Fatalf("création : statut %d, %d formulaire(s)", resp.StatusCode, count)
	}
	if tok == nil || !strings.HasPrefix(*tok, "enc1:") || chatID == nil || *chatID != "@canal_public" {
		t.Errorf("réglages Telegram à la création : jeton=%v identifiant=%v", tok, chatID)
	}
	// A channel set at creation appears in the audit log.
	var formID string
	if err := e.pool.QueryRow(context.Background(), `SELECT id::text FROM forms WHERE name = 'Avec Telegram'`).Scan(&formID); err != nil {
		t.Fatalf("lecture du formulaire créé: %v", err)
	}
	want := map[string]string{"telegram": "added", "chat_content": "false", "name": "Avec Telegram", "site": e.fx.siteA.ID.String()}
	if got := auditEntries(t, e, formID, "form.created", telegramToken, "canal_public"); len(got) != 1 || !maps.Equal(got[0], want) {
		t.Errorf("trace de création = %v, attendu %v", got, want)
	}
}

// The token and the identifier are useless without each other: the database itself refuses
// a write that would separate them.
func TestContrainteTelegramEnBase(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	for _, half := range []string{
		`UPDATE forms SET telegram_bot_token = 'x' WHERE id = $1`,
		`UPDATE forms SET telegram_chat_id = '-100' WHERE id = $1`,
	} {
		if _, err := e.pool.Exec(ctx, half, e.fx.formA.ID); err == nil || !strings.Contains(err.Error(), "forms_telegram_pair") {
			t.Errorf("%s : refus par forms_telegram_pair attendu, got %v", half, err)
		}
	}
	for _, whole := range []string{
		`UPDATE forms SET telegram_bot_token = 'x', telegram_chat_id = '-100' WHERE id = $1`,
		`UPDATE forms SET telegram_bot_token = NULL, telegram_chat_id = NULL WHERE id = $1`,
	} {
		if _, err := e.pool.Exec(ctx, whole, e.fx.formA.ID); err != nil {
			t.Errorf("%s : %v", whole, err)
		}
	}
}

// auditEntries returns the audit entries of an action, from oldest to newest, without their
// 'ip' key. It also checks that no entry contains a secret.
func auditEntries(t *testing.T, e testEnv, formID, action string, secrets ...string) []map[string]string {
	t.Helper()
	rows, err := e.pool.Query(context.Background(),
		`SELECT detail FROM audit_log WHERE action = $1 AND entity = 'form' AND entity_id::text = $2 ORDER BY created_at, id`, action, formID)
	if err != nil {
		t.Fatalf("lecture de l'audit: %v", err)
	}
	defer rows.Close()
	known := []string{"slack", "teams", "discord", "telegram", "changed", "name", "site", "chat_content", "ip"}
	var out []map[string]string
	for rows.Next() {
		var detail string
		if err := rows.Scan(&detail); err != nil {
			t.Fatalf("scan audit: %v", err)
		}
		for _, secret := range append(secrets, "SECRET", "AAExample", "@", "://") {
			if strings.Contains(detail, secret) {
				t.Errorf("la trace d'audit contient %q : %s", secret, detail)
			}
		}
		meta := map[string]string{}
		if err := json.Unmarshal([]byte(detail), &meta); err != nil {
			t.Fatalf("détail illisible: %v", err)
		}
		for key, value := range meta {
			if !slices.Contains(known, key) {
				t.Errorf("clé inattendue %q dans la trace : %s", key, detail)
			}
			if slices.Contains(known[:4], key) && !slices.Contains([]string{"added", "removed", "replaced"}, value) {
				t.Errorf("état de canal inattendu %s=%q", key, value)
			}
		}
		if meta["ip"] == "" {
			t.Errorf("trace sans adresse IP : %s", detail)
		}
		delete(meta, "ip")
		out = append(out, meta)
	}
	return out
}

// A form's settings decide where submission content goes: each change leaves an audit entry
// that names what changed and nothing else.
func TestAuditDesReglagesDuFormulaire(t *testing.T) {
	hook := newChatHook(t)
	e := setup(t, hook.trust)
	c := newClient()
	login(t, c, e.url, e.fx.memberA.Email)
	settings := e.url + "/forms/" + e.fx.formA.ID.String() + "/settings"
	const otherToken = "987654321:BBAutreAutreAutreAutreAutreAutreAutre"
	entries := func() []map[string]string {
		t.Helper()
		return auditEntries(t, e, e.fx.formA.ID.String(), "form.updated", telegramToken, otherToken, "BBAutre", "100123", "100999", "merci")
	}
	cur := formValues(csrfToken(t, c, e.url+"/account"), nil)
	save := func(want int) {
		t.Helper()
		resp := postForm(t, c, settings, cur)
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("enregistrement : statut %d (%d attendu)", resp.StatusCode, want)
		}
	}
	save(http.StatusSeeOther) // ramène le formulaire de test à la saisie de départ
	seen := len(entries())

	set := func(pairs ...string) func() {
		return func() {
			for i := 0; i < len(pairs); i += 2 {
				cur.Set(pairs[i], pairs[i+1])
			}
		}
	}
	del := func(keys ...string) func() {
		return func() {
			for _, k := range keys {
				cur.Del(k)
			}
		}
	}
	const alpha, beta = "Contact Alpha", "Contact Beta"
	for _, tc := range []struct {
		what   string
		change func()
		want   map[string]string // nil: no entry expected
	}{
		{"Slack ajouté", set("slack_webhook_url", hook.url("/slack/SECRET-S")), map[string]string{"slack": "added", "name": alpha, "chat_content": "false"}},
		{"Teams ajouté", set("teams_webhook_url", hook.url("/teams/SECRET-T")), map[string]string{"teams": "added", "name": alpha, "chat_content": "false"}},
		{"Slack remplacé", set("slack_webhook_url", hook.url("/slack/SECRET-S2")), map[string]string{"slack": "replaced", "name": alpha, "chat_content": "false"}},
		{"Slack retiré", del("slack_webhook_url"), map[string]string{"slack": "removed", "name": alpha, "chat_content": "false"}},
		{"Teams retiré, Discord ajouté", func() { cur.Del("teams_webhook_url"); cur.Set("discord_webhook_url", hook.url("/discord/SECRET-D")) },
			map[string]string{"teams": "removed", "discord": "added", "name": alpha, "chat_content": "false"}},
		{"Telegram ajouté", set("telegram_bot_token", telegramToken, "telegram_chat_id", "-100123"), map[string]string{"telegram": "added", "name": alpha, "chat_content": "false"}},
		{"jeton Telegram remplacé", set("telegram_bot_token", otherToken), map[string]string{"telegram": "replaced", "name": alpha, "chat_content": "false"}},
		{"discussion Telegram remplacée", set("telegram_chat_id", "-100999"), map[string]string{"telegram": "replaced", "name": alpha, "chat_content": "false"}},
		// The '-' moves from the identifier to the token: end to end, the two settings are the same.
		{"jeton et discussion décalés", set("telegram_bot_token", otherToken+"-", "telegram_chat_id", "100999"), map[string]string{"telegram": "replaced", "name": alpha, "chat_content": "false"}},
		{"rien ne change", func() {}, nil},
		{"contenu joint aux alertes", set("chat_include_content", "1"), map[string]string{"changed": "chat_content", "name": alpha, "chat_content": "true"}},
		{"nom", set("name", beta), map[string]string{"changed": "name", "name": beta, "chat_content": "true"}},
		{"désactivé", del("active"), map[string]string{"changed": "active", "name": beta, "chat_content": "true"}},
		{"email activé", set("notify_email", "1", "recipients", "equipe@exemple.org"), map[string]string{"changed": "notify_email,recipients", "name": beta, "chat_content": "true"}},
		{"autre destinataire", set("recipients", "autre@exemple.org"), map[string]string{"changed": "recipients", "name": beta, "chat_content": "true"}},
		{"contenu dans l'email", set("email_include_content", "1"), map[string]string{"changed": "email_content", "name": beta, "chat_content": "true"}},
		{"conservation", set("retention_days", "30"), map[string]string{"changed": "retention", "name": beta, "chat_content": "true"}},
		{"pièces jointes acceptées", set("accept_attachments", "1"), map[string]string{"changed": "attachments", "name": beta, "chat_content": "true"}},
		{"pièces jointes refusées", del("accept_attachments"), map[string]string{"changed": "attachments", "name": beta, "chat_content": "true"}},
		{"vérification anti-robot activée", set("captcha", "1"), map[string]string{"changed": "captcha", "name": beta, "chat_content": "true"}},
		{"vérification anti-robot retirée", del("captcha"), map[string]string{"changed": "captcha", "name": beta, "chat_content": "true"}},
		{"notifications en anglais", set("notification_lang", "en"), map[string]string{"changed": "notification_lang", "name": beta, "chat_content": "true"}},
		{"langue inchangée", func() {}, nil},
		{"notifications en français", set("notification_lang", "fr"), map[string]string{"changed": "notification_lang", "name": beta, "chat_content": "true"}},
		{"page de retour posée", set("redirect_url", "https://exemple.fr/merci"), map[string]string{"changed": "redirect", "name": beta, "chat_content": "true"}},
		{"page de retour retirée", del("redirect_url"), map[string]string{"changed": "redirect", "name": beta, "chat_content": "true"}},
		{"plus conservé", del("store_submissions"), map[string]string{"changed": "store", "name": beta, "chat_content": "true"}},
		{"contenu retiré des alertes", del("chat_include_content"), map[string]string{"changed": "chat_content", "name": beta, "chat_content": "false"}},
		{"Discord et Telegram retirés", del("discord_webhook_url", "telegram_bot_token", "telegram_chat_id"),
			map[string]string{"discord": "removed", "telegram": "removed", "name": beta, "chat_content": "false"}},
	} {
		tc.change()
		save(http.StatusSeeOther)
		got := entries()
		if tc.want == nil {
			if len(got) != seen {
				t.Errorf("%s : une trace a été écrite : %v", tc.what, got[len(got)-1])
			}
			continue
		}
		if len(got) != seen+1 {
			t.Fatalf("%s : %d trace(s) de plus (1 attendue)", tc.what, len(got)-seen)
		}
		seen++
		if last := got[len(got)-1]; !maps.Equal(last, tc.want) {
			t.Errorf("%s : trace = %v, attendu %v", tc.what, last, tc.want)
		}
	}

	// A refused input changes nothing and leaves no trace.
	cur.Set("discord_webhook_url", "https://evil.tld/x")
	save(http.StatusBadRequest)
	if n := len(entries()); n != seen {
		t.Errorf("saisie refusée : %d trace(s) de plus", n-seen)
	}

	// The author of each audit entry is the account that saved it.
	var others int
	if err := e.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_log WHERE action = 'form.updated' AND actor_id IS DISTINCT FROM $1`, e.fx.memberA.ID).Scan(&others); err != nil || others != 0 {
		t.Errorf("traces attribuées à un autre compte : %d (err=%v)", others, err)
	}
}
