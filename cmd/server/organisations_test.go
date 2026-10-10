package main

// Organisations and roles: what each of the three roles reaches, and what a read grant
// allows. Integration tests, skipped without TEST_DATABASE_URL.

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"gitlab.com/detag_inno/naria/internal/auth"
	"gitlab.com/detag_inno/naria/internal/database"
)

// grantRead lets the organisation administrator of e read a site to target.
func grantRead(t *testing.T, e testEnv, admin database.User, site database.Site, target database.User) *http.Response {
	t.Helper()
	c := newClient()
	login(t, c, e.url, admin.Email)
	resp := postForm(t, c, e.url+"/sites/"+site.ID.String()+"/readers", url.Values{
		"csrf_token": {csrfToken(t, c, e.url+"/account")}, "user_id": {target.ID.String()},
	})
	resp.Body.Close()
	return resp
}

// readerCount returns the number of read grants on a site.
func readerCount(t *testing.T, e testEnv, site database.Site) int {
	t.Helper()
	var n int
	if err := e.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM site_read_grants WHERE site_id = $1`, site.ID).Scan(&n); err != nil {
		t.Fatalf("comptage des lectures: %v", err)
	}
	return n
}

// TestAdminOrgaVoitEtGereSonOrganisation: the administrator of an organisation sees and
// changes all its sites, and gets 404 on the other organisation's.
func TestAdminOrgaVoitEtGereSonOrganisation(t *testing.T) {
	e := setup(t)
	c := newClient()
	login(t, c, e.url, e.fx.orgAdmin.Email)

	if _, body := get(t, c, e.url+"/"); !strings.Contains(body, "Site Alpha") || !strings.Contains(body, "Site Bravo") {
		t.Errorf("l'administrateur d'organisation doit voir les sites de son organisation")
	}
	if _, body := get(t, c, e.url+"/"); strings.Contains(body, "Site Charlie") {
		t.Errorf("un site de l'autre organisation apparaît dans la liste")
	}
	if code, _ := get(t, c, e.url+"/users"); code != http.StatusOK {
		t.Errorf("/users pour l'administrateur d'organisation : statut %d", code)
	}

	token := csrfToken(t, c, e.url+"/account")
	resp := postForm(t, c, e.url+"/sites/"+e.fx.siteB.ID.String(), url.Values{
		"csrf_token": {token}, "name": {"Site Bravo modifié"}, "domains": {""},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("modification du site d'un autre compte de l'organisation : statut %d", resp.StatusCode)
	}

	for _, path := range []string{
		"/sites/" + e.fx.siteC.ID.String(), "/forms/" + e.fx.formC.ID.String(),
		"/forms/" + e.fx.formC.ID.String() + "/export.csv", "/forms/" + e.fx.formC.ID.String() + "/settings",
	} {
		if code, _ := get(t, c, e.url+path); code != http.StatusNotFound {
			t.Errorf("GET %s pour un autre organisation : statut %d (404 attendu)", path, code)
		}
	}
	resp = postForm(t, c, e.url+"/sites/"+e.fx.siteC.ID.String()+"/delete", url.Values{"csrf_token": {token}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("suppression d'un site d'une autre organisation : statut %d (404 attendu)", resp.StatusCode)
	}
	var n int
	if err := e.pool.QueryRow(context.Background(), `SELECT count(*) FROM sites`).Scan(&n); err != nil || n != 3 {
		t.Errorf("sites en base : %d (3 attendus, err=%v)", n, err)
	}
}

// TestUtilisateurNAdministreRien: a user manages their own sites only, and cannot reach
// the organisation's accounts.
func TestUtilisateurNAdministreRien(t *testing.T) {
	e := setup(t)
	c := newClient()
	login(t, c, e.url, e.fx.memberA.Email)
	if code, _ := get(t, c, e.url+"/users"); code != http.StatusForbidden {
		t.Errorf("/users pour un utilisateur : statut %d (403 attendu)", code)
	}
	if code, _ := get(t, c, e.url+"/organisations"); code != http.StatusForbidden {
		t.Errorf("/organisations pour un utilisateur : statut %d (403 attendu)", code)
	}
	token := csrfToken(t, c, e.url+"/account")
	for _, path := range []string{"/sites/" + e.fx.siteB.ID.String() + "/owner", "/users/" + e.fx.memberB.ID.String() + "/toggle"} {
		resp := postForm(t, c, e.url+path, url.Values{"csrf_token": {token}, "owner_id": {e.fx.memberA.ID.String()}})
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusNotFound {
			t.Errorf("POST %s par un utilisateur : statut %d", path, resp.StatusCode)
		}
	}
	site, _ := e.q.GetSiteScoped(context.Background(), database.GetSiteScopedParams{ID: e.fx.siteB.ID, ViewerID: e.fx.memberB.ID})
	if site.OwnerID != e.fx.memberB.ID {
		t.Errorf("le site B a changé de propriétaire")
	}
	if u, _ := e.q.GetUserByID(context.Background(), e.fx.memberA.ID); u.Role != auth.RoleUser {
		t.Errorf("l'utilisateur A a changé de rôle : %s", u.Role)
	}
}

// TestAdminPlateformeNeVoitAucunContenu: the platform administrator reaches no content.
// Every route answers 404, even with the exact identifier of an existing object.
func TestAdminPlateformeNeVoitAucunContenu(t *testing.T) {
	e := setup(t)
	sub := storeSubmission(t, e, e.fx.formA, "https://exemple.fr", "name=Ada&message=secret-alpha")
	adm := newClient()
	login(t, adm, e.url, e.fx.admin.Email)

	if resp, err := adm.Get(e.url + "/"); err != nil || resp.Header.Get("Location") != "/organisations" {
		t.Errorf("l'accueil de l'administrateur de plateforme doit mener aux organisations")
	}
	for _, path := range []string{
		"/sites/" + e.fx.siteA.ID.String(), "/sites/" + e.fx.siteC.ID.String() + "/forms/new",
		"/forms/" + e.fx.formA.ID.String(), "/forms/" + e.fx.formA.ID.String() + "/settings",
		"/forms/" + e.fx.formA.ID.String() + "/export.csv", "/forms/" + e.fx.formA.ID.String() + "/export.zip",
		"/submissions/" + sub.ID.String(),
	} {
		if code, body := get(t, adm, e.url+path); code != http.StatusNotFound || strings.Contains(body, "secret-alpha") {
			t.Errorf("GET %s pour l'administrateur de plateforme : statut %d (404 attendu)", path, code)
		}
	}

	token := csrfToken(t, adm, e.url+"/account")
	for _, path := range []string{
		"/sites", "/sites/" + e.fx.siteA.ID.String() + "/tokens", "/sites/" + e.fx.siteA.ID.String() + "/delete",
		"/forms/" + e.fx.formA.ID.String() + "/read", "/submissions/" + sub.ID.String() + "/delete",
	} {
		resp := postForm(t, adm, e.url+path, url.Values{"csrf_token": {token}, "name": {"x"}})
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("POST %s pour l'administrateur de plateforme : statut %d (404 attendu)", path, resp.StatusCode)
		}
	}
	if n := countSubmissions(t, e, e.fx.formA); n != 1 {
		t.Errorf("soumissions de A : %d (1 attendue)", n)
	}
	if code, _ := get(t, adm, e.url+"/users"); code != http.StatusForbidden {
		t.Errorf("/users pour l'administrateur de plateforme : statut %d (403 attendu)", code)
	}
	if code, body := get(t, adm, e.url+"/organisations"); code != http.StatusOK || strings.Contains(body, "Site Alpha") || !strings.Contains(body, "Orga") {
		t.Errorf("/organisations : statut %d, la liste doit nommer les organisations et rien d'autre", code)
	}
}

// TestLectureAccordeeParLAdministrateurDOrganisation: a read grant opens the submissions of
// the site, and nothing that changes it.
func TestLectureAccordeeParLAdministrateurDOrganisation(t *testing.T) {
	e := setup(t)
	sub := storeSubmission(t, e, e.fx.formA, "https://exemple.fr", "name=Ada&message=secret-alpha")

	// Not a user of the organisation, nor an administrator: refused, nothing stored.
	if resp := grantRead(t, e, e.fx.orgAdmin, e.fx.siteA, e.fx.memberC); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("accord hors organisation : statut %d", resp.StatusCode)
	}
	grantRead(t, e, e.fx.orgAdmin, e.fx.siteA, e.fx.orgAdmin)
	grantRead(t, e, e.fx.orgAdmin, e.fx.siteA, e.fx.memberA) // the owner
	if n := readerCount(t, e, e.fx.siteA); n != 0 {
		t.Fatalf("lectures accordées à tort : %d", n)
	}

	grantRead(t, e, e.fx.orgAdmin, e.fx.siteA, e.fx.memberB)
	if n := readerCount(t, e, e.fx.siteA); n != 1 {
		t.Fatalf("lectures sur A : %d (1 attendue)", n)
	}

	b := newClient()
	login(t, b, e.url, e.fx.memberB.Email)
	siteA, formA := "/sites/"+e.fx.siteA.ID.String(), "/forms/"+e.fx.formA.ID.String()
	for _, path := range []string{siteA, formA, formA + "/export.csv", "/submissions/" + sub.ID.String()} {
		if code, _ := get(t, b, e.url+path); code != http.StatusOK {
			t.Errorf("GET %s avec lecture : statut %d (200 attendu)", path, code)
		}
	}
	if _, body := get(t, b, e.url+"/submissions/"+sub.ID.String()); !strings.Contains(body, "secret-alpha") {
		t.Errorf("le lecteur doit voir le contenu de la soumission")
	}
	if list, _ := e.q.ListSubmissionsByForm(context.Background(), database.ListSubmissionsByFormParams{FormID: e.fx.formA.ID, PageLimit: 1}); len(list) == 1 && list[0].ReadAt.Valid {
		t.Errorf("le lecteur a marqué la soumission comme lue")
	}

	// Read-only: no write route answers to it.
	token := csrfToken(t, b, e.url+"/account")
	for _, path := range []string{
		siteA + "/forms", siteA + "/tokens", siteA + "/delete", formA + "/settings", formA + "/read",
		formA + "/key", formA + "/purge", formA + "/delete", "/submissions/" + sub.ID.String() + "/delete",
	} {
		resp := postForm(t, b, e.url+path, url.Values{"csrf_token": {token}, "name": {"piraté"}})
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("POST %s avec lecture seule : statut %d (404 attendu)", path, resp.StatusCode)
		}
	}
	if code, _ := get(t, b, e.url+formA+"/settings"); code != http.StatusNotFound {
		t.Errorf("GET réglages avec lecture seule : statut %d (404 attendu)", code)
	}
	if _, body := get(t, b, e.url+siteA); strings.Contains(body, e.fx.formA.AccessKey) || strings.Contains(body, "Agent") {
		t.Errorf("la page du site en lecture seule montre une clé ou des jetons")
	}
	if n := countSubmissions(t, e, e.fx.formA); n != 1 {
		t.Errorf("soumissions de A : %d (1 attendue)", n)
	}

	// Another user, not granted, still sees nothing of A.
	c := newClient()
	login(t, c, e.url, e.fx.memberC.Email)
	if code, _ := get(t, c, e.url+"/submissions/"+sub.ID.String()); code != http.StatusNotFound {
		t.Errorf("soumission de A pour un compte sans lecture : statut %d", code)
	}
}

// TestRetraitDeLaLectureCoupeLAcces: once withdrawn, the reader gets 404 on the submission,
// the attachments and the export.
func TestRetraitDeLaLectureCoupeLAcces(t *testing.T) {
	e := setup(t)
	sub := storeSubmission(t, e, e.fx.formA, "https://exemple.fr", "name=Ada&message=secret-alpha")
	grantRead(t, e, e.fx.orgAdmin, e.fx.siteA, e.fx.memberB)

	b := newClient()
	login(t, b, e.url, e.fx.memberB.Email)
	if code, _ := get(t, b, e.url+"/submissions/"+sub.ID.String()); code != http.StatusOK {
		t.Fatalf("avant le retrait : statut %d", code)
	}

	adm := newClient()
	login(t, adm, e.url, e.fx.orgAdmin.Email)
	resp := postForm(t, adm, e.url+"/sites/"+e.fx.siteA.ID.String()+"/readers/"+e.fx.memberB.ID.String()+"/delete", url.Values{
		"csrf_token": {csrfToken(t, adm, e.url+"/account")},
	})
	resp.Body.Close()
	if n := readerCount(t, e, e.fx.siteA); n != 0 {
		t.Fatalf("lecture encore présente après retrait : %d", n)
	}
	for _, path := range []string{"/sites/" + e.fx.siteA.ID.String(), "/forms/" + e.fx.formA.ID.String(), "/forms/" + e.fx.formA.ID.String() + "/export.csv", "/submissions/" + sub.ID.String()} {
		if code, body := get(t, b, e.url+path); code != http.StatusNotFound || strings.Contains(body, "secret-alpha") {
			t.Errorf("GET %s après retrait : statut %d (404 attendu)", path, code)
		}
	}
}

// TestTransfertRetireLaLectureEtLAncienProprietaire: transferring a site ends the former
// owner's access, and the new owner's grant is dropped. A target from another organisation
// is refused.
func TestTransfertRetireLaLectureEtLAncienProprietaire(t *testing.T) {
	e := setup(t)
	grantRead(t, e, e.fx.orgAdmin, e.fx.siteA, e.fx.memberB)
	if n := readerCount(t, e, e.fx.siteA); n != 1 {
		t.Fatalf("lecture non accordée : %d", n)
	}

	adm := newClient()
	login(t, adm, e.url, e.fx.orgAdmin.Email)
	token := csrfToken(t, adm, e.url+"/account")
	resp := postForm(t, adm, e.url+"/sites/"+e.fx.siteA.ID.String()+"/owner", url.Values{
		"csrf_token": {token}, "owner_id": {e.fx.memberC.ID.String()},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("transfert hors organisation : statut %d (400 attendu)", resp.StatusCode)
	}

	resp = postForm(t, adm, e.url+"/sites/"+e.fx.siteA.ID.String()+"/owner", url.Values{
		"csrf_token": {token}, "owner_id": {e.fx.memberB.ID.String()},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("transfert : statut %d", resp.StatusCode)
	}
	if n := readerCount(t, e, e.fx.siteA); n != 0 {
		t.Errorf("la lecture du nouveau propriétaire est restée : %d", n)
	}
	a := newClient()
	login(t, a, e.url, e.fx.memberA.Email)
	if code, _ := get(t, a, e.url+"/sites/"+e.fx.siteA.ID.String()); code != http.StatusNotFound {
		t.Errorf("l'ancien propriétaire garde l'accès au site : statut %d", code)
	}
}

// TestOrganisationsPlateforme: the platform administrator creates an organisation with its
// administrator, and replaces that administrator. An organisation has one at a time.
func TestOrganisationsPlateforme(t *testing.T) {
	e := setup(t)
	adm := newClient()
	login(t, adm, e.url, e.fx.admin.Email)
	token := csrfToken(t, adm, e.url+"/organisations")

	resp := postForm(t, adm, e.url+"/organisations", url.Values{
		"csrf_token": {token}, "org_name": {"Orgc"}, "name": {"Admin C"},
		"email": {"adminc@naria.test"}, "password": {testPassword},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("création d'organisation : statut %d", resp.StatusCode)
	}
	created, err := e.q.GetUserByEmail(context.Background(), "adminc@naria.test")
	if err != nil || created.Role != auth.RoleOrgAdmin || !created.OrgID.Valid {
		t.Fatalf("administrateur créé : %+v (err=%v)", created, err)
	}

	// A second administrator for the same organisation cannot be inserted.
	if _, err := e.q.CreateUser(context.Background(), database.CreateUserParams{
		Email: "second@naria.test", Name: "Second", Role: auth.RoleOrgAdmin,
		PasswordHash: created.PasswordHash, OrgID: created.OrgID,
	}); err == nil {
		t.Errorf("deux administrateurs pour une même organisation acceptés")
	}

	resp = postForm(t, adm, e.url+"/organisations/"+e.fx.orgA.ID.String()+"/admin", url.Values{
		"csrf_token": {token}, "name": {"Nouvel admin"}, "email": {"nouvel@naria.test"}, "password": {testPassword},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("remplacement : statut %d", resp.StatusCode)
	}
	old, _ := e.q.GetUserByID(context.Background(), e.fx.orgAdmin.ID)
	replacement, _ := e.q.GetUserByEmail(context.Background(), "nouvel@naria.test")
	if old.Role != auth.RoleUser || replacement.Role != auth.RoleOrgAdmin {
		t.Errorf("remplacement : ancien %s, nouveau %s", old.Role, replacement.Role)
	}

	// The former administrator now a user: no more administration of the organisation.
	former := newClient()
	login(t, former, e.url, e.fx.orgAdmin.Email)
	if code, _ := get(t, former, e.url+"/users"); code != http.StatusForbidden {
		t.Errorf("ancien administrateur : /users statut %d (403 attendu)", code)
	}
	if code, _ := get(t, former, e.url+"/organisations"); code != http.StatusForbidden {
		t.Errorf("administrateur d'organisation : /organisations statut %d (403 attendu)", code)
	}
}

// TestComptesDOrganisation: the administrator of an organisation creates users of its own
// organisation only, and cannot manage an account of another one.
func TestComptesDOrganisation(t *testing.T) {
	e := setup(t)
	c := newClient()
	login(t, c, e.url, e.fx.orgAdmin.Email)
	token := csrfToken(t, c, e.url+"/users")

	resp := postForm(t, c, e.url+"/users", url.Values{
		"csrf_token": {token}, "name": {"Nouveau"}, "email": {"nouveau@naria.test"},
		"password": {testPassword}, "role": {auth.RoleOrgAdmin},
	})
	resp.Body.Close()
	created, err := e.q.GetUserByEmail(context.Background(), "nouveau@naria.test")
	if err != nil || created.Role != auth.RoleUser || created.OrgID.Bytes != e.fx.orgA.ID {
		// The role field is ignored: an administrator is never created here.
		t.Fatalf("compte créé : %+v (err=%v)", created, err)
	}

	resp = postForm(t, c, e.url+"/users/"+e.fx.memberC.ID.String()+"/toggle", url.Values{"csrf_token": {token}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("désactivation d'un compte d'une autre organisation : statut %d (404 attendu)", resp.StatusCode)
	}
	if u, _ := e.q.GetUserByID(context.Background(), e.fx.memberC.ID); !u.Active {
		t.Errorf("le compte d'une autre organisation a été désactivé")
	}
	resp = postForm(t, c, e.url+"/users/"+e.fx.orgBAdmin.ID.String()+"/password", url.Values{"csrf_token": {token}, "password": {"nouveau-mot-de-passe"}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("mot de passe d'un administrateur d'une autre organisation : statut %d (404 attendu)", resp.StatusCode)
	}
}
