package main

// Integration tests for the archive export, skipped without TEST_DATABASE_URL.

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

// exportZIP returns the content of each file in the archive, by name.
func exportZIP(t *testing.T, c *http.Client, target string) map[string]string {
	t.Helper()
	return exportZIPIn(t, c, target, "")
}

// exportZIPIn requests the archive in a given language ("" for the default).
func exportZIPIn(t *testing.T, c *http.Client, target, lang string) map[string]string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("requête: %v", err)
	}
	if lang != "" {
		req.Header.Set("Accept-Language", lang)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/zip" ||
		!strings.HasPrefix(resp.Header.Get("Content-Disposition"), "attachment;") || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("export ZIP : statut %d, en-têtes %v", resp.StatusCode, resp.Header)
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("archive illisible: %v", err)
	}
	files := map[string]string{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("ouverture de %q: %v", f.Name, err)
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("lecture de %q: %v", f.Name, err)
		}
		if _, dup := files[f.Name]; dup {
			t.Errorf("deux fichiers de l'archive portent le nom %q", f.Name)
		}
		files[f.Name] = string(data)
	}
	return files
}

// The CSV links each submission to its file folder.
func TestExportZIP(t *testing.T) {
	e := setup(t)
	acceptAttachments(t, e, e.fx.formA)
	path := "/f/" + e.fx.formA.AccessKey
	send := func(parts ...[]string) {
		t.Helper()
		ct, body := multipartBody(parts...)
		if resp, out := submit(t, e.url, submitOpts{path: path, contentType: ct, body: body, origin: "https://exemple.fr"}); resp.StatusCode != http.StatusOK {
			t.Fatalf("soumission : statut %d, corps %s", resp.StatusCode, out)
		}
	}
	const pdf = "%PDF-1.7 contenu-binaire\x00\xff\r\n"
	// Two files with the same name in the first submission, none in the second, one in the third.
	send([]string{"name", "Ada"}, []string{"cv", "cv.pdf", pdf}, []string{"autre", "cv.pdf", "second cv"})
	send([]string{"name", "Grace"}, []string{"message", `=HYPERLINK("http://evil.tld")`})
	send([]string{"name", "Linus"}, []string{"notes", "notes été.txt", "troisième"})

	c := newClient()
	login(t, c, e.url, e.fx.memberA.Email)
	formPath := "/forms/" + e.fx.formA.ID.String()
	if _, page := get(t, c, e.url+formPath); !strings.Contains(page, formPath+"/export.zip") {
		t.Errorf("la page du formulaire doit proposer l'export avec les pièces jointes")
	}
	files := exportZIP(t, c, e.url+formPath+"/export.zip")

	for name, want := range map[string]string{
		"pieces-jointes/0001/1-cv.pdf":        pdf,
		"pieces-jointes/0001/2-cv.pdf":        "second cv",
		"pieces-jointes/0003/1-notes été.txt": "troisième",
	} {
		if got, ok := files[name]; !ok || got != want {
			t.Errorf("fichier %q : présent=%v, contenu %q (%q attendu)", name, ok, got, want)
		}
	}
	if len(files) != 4 {
		t.Errorf("l'archive contient %d fichiers (le CSV et trois pièces jointes attendus)", len(files))
	}
	csv := files["soumissions.csv"]
	lines := strings.Split(strings.TrimSpace(csv), "\n")
	if len(lines) != 4 || !strings.Contains(lines[0], "Reçue le,Dossier des pièces jointes,name,") {
		t.Fatalf("CSV de l'archive inattendu : %q", csv)
	}
	// The folder follows the date, at a fixed place.
	for i, want := range []struct{ name, folder string }{{"Ada", "pieces-jointes/0001"}, {"Grace", ""}, {"Linus", "pieces-jointes/0003"}} {
		cells := strings.SplitN(lines[i+1], ",", 4)
		if len(cells) != 4 || cells[1] != want.folder || cells[2] != want.name {
			t.Errorf("ligne %d du CSV : %q (dossier %q et nom %q attendus)", i+1, lines[i+1], want.folder, want.name)
		}
	}
	// A cell starting with '=' would be run by a spreadsheet.
	if !strings.Contains(csv, `"'=HYPERLINK(`) {
		t.Errorf("formule non neutralisée dans le CSV de l'archive : %q", csv)
	}
	// The CSV export alone has no folder column.
	if _, plain := get(t, c, e.url+formPath+"/export.csv"); strings.Contains(plain, "Dossier") || strings.Contains(plain, "pieces-jointes") {
		t.Errorf("l'export CSV seul ne doit pas renvoyer à un dossier : %q", plain)
	}

	// In English, the archive names change together: the CSV still points
	// to a folder that exists.
	en := exportZIPIn(t, c, e.url+formPath+"/export.zip", "en")
	if _, ok := en["attachments/0001/1-cv.pdf"]; !ok || !strings.Contains(en["submissions.csv"], ",attachments/0001,Ada,") || !strings.Contains(en["submissions.csv"], ",Attachments folder,") {
		t.Errorf("archive en anglais inattendue : %v", en["submissions.csv"])
	}

	// The export is logged, with the number of files exported and without their names.
	var detail string
	if err := e.pool.QueryRow(context.Background(),
		`SELECT detail FROM audit_log WHERE action = 'form.submissions_exported' AND entity_id = $1 AND actor_id = $2 AND detail LIKE '%attachments%' LIMIT 1`,
		e.fx.formA.ID, e.fx.memberA.ID).Scan(&detail); err != nil {
		t.Fatalf("trace de l'export: %v", err)
	}
	if !strings.Contains(detail, `"attachments":"3"`) || strings.Contains(detail, "cv.pdf") {
		t.Errorf("trace de l'export inattendue : %s", detail)
	}
}

// A file name comes from a visitor: inside the archive, it must not make extraction
// write anywhere outside its folder.
func TestExportZIPNomsDeFichiersHostiles(t *testing.T) {
	e := setup(t)
	acceptAttachments(t, e, e.fx.formB)
	ct, body := multipartBody(
		[]string{"name", "Mallory"},
		[]string{"a", `..\..\Windows\evil.bat`, "un"},
		[]string{"b", "..", "deux"},
		[]string{"c", `C:\Users\Public\x.txt`, "trois"},
		[]string{"d", `a<b>c|d?e*f.txt. `, "quatre"},
		// The longest name a submission accepts: with its number, it would exceed
		// what a file system can write.
		[]string{"e", strings.Repeat("é", 125) + ".pdf", "cinq"},
	)
	if resp, out := submit(t, e.url, submitOpts{path: "/f/" + e.fx.formB.AccessKey, contentType: ct, body: body}); resp.StatusCode != http.StatusOK {
		t.Fatalf("soumission : statut %d, corps %s", resp.StatusCode, out)
	}
	c := newClient()
	login(t, c, e.url, e.fx.memberB.Email)
	files := exportZIP(t, c, e.url+"/forms/"+e.fx.formB.ID.String()+"/export.zip")
	var contents []string
	for name, content := range files {
		if name == "soumissions.csv" {
			continue
		}
		contents = append(contents, content)
		rest, ok := strings.CutPrefix(name, "pieces-jointes/0001/")
		if !ok || rest == "" || rest == "." || rest == ".." || strings.ContainsAny(rest, `/\:<>"|?*`) ||
			strings.HasSuffix(rest, ".") || strings.HasSuffix(rest, " ") || len(rest) > 255 {
			t.Errorf("nom de fichier dangereux ou inextractible dans l'archive : %q", name)
		}
	}
	slices.Sort(contents)
	if got := strings.Join(contents, ","); got != "cinq,deux,quatre,trois,un" {
		t.Errorf("les cinq fichiers doivent être dans l'archive, chacun sous son nom : %s", got)
	}
}

// A submission that became unreadable is absent from the CSV, and its files from the
// archive. Folders follow the row rank in the CSV, not the rank of submissions in the database.
func TestExportZIPSoumissionIllisible(t *testing.T) {
	e := setup(t)
	acceptAttachments(t, e, e.fx.formB)
	for _, who := range []string{"Ada", "Grace", "Linus"} {
		ct, body := multipartBody([]string{"name", who}, []string{"cv", "cv-" + who + ".pdf", "fichier de " + who})
		if resp, out := submit(t, e.url, submitOpts{path: "/f/" + e.fx.formB.AccessKey, contentType: ct, body: body}); resp.StatusCode != http.StatusOK {
			t.Fatalf("soumission : statut %d, corps %s", resp.StatusCode, out)
		}
	}
	if _, err := e.pool.Exec(context.Background(),
		`UPDATE submissions SET payload = 'enc1:AAAA' WHERE id = (SELECT id FROM submissions ORDER BY created_at, id OFFSET 1 LIMIT 1)`); err != nil {
		t.Fatal(err)
	}
	c := newClient()
	login(t, c, e.url, e.fx.memberB.Email)
	files := exportZIP(t, c, e.url+"/forms/"+e.fx.formB.ID.String()+"/export.zip")
	if len(files) != 3 || files["pieces-jointes/0001/1-cv-Ada.pdf"] != "fichier de Ada" || files["pieces-jointes/0002/1-cv-Linus.pdf"] != "fichier de Linus" {
		t.Errorf("archive inattendue : %d fichiers", len(files))
	}
	csv := files["soumissions.csv"]
	if lines := strings.Split(strings.TrimSpace(csv), "\n"); len(lines) != 3 || !strings.Contains(lines[2], ",pieces-jointes/0002,Linus,") || strings.Contains(csv, "Grace") {
		t.Errorf("CSV inattendu : %q", csv)
	}
	// The log counts the exported files, not those of the discarded submission.
	var detail string
	if err := e.pool.QueryRow(context.Background(), `SELECT detail FROM audit_log WHERE action = 'form.submissions_exported'`).Scan(&detail); err != nil || !strings.Contains(detail, `"attachments":"2"`) {
		t.Errorf("trace de l'export : %s (err=%v)", detail, err)
	}
}

func TestExportZIPIsoleParFormulaire(t *testing.T) {
	e := setup(t)
	acceptAttachments(t, e, e.fx.formA)
	acceptAttachments(t, e, e.fx.formB)
	ct, body := multipartBody([]string{"name", "Ada"}, []string{"cv", "alpha.pdf", "fichier-alpha"})
	if resp, out := submit(t, e.url, submitOpts{path: "/f/" + e.fx.formA.AccessKey, contentType: ct, body: body, origin: "https://exemple.fr"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("soumission A : statut %d, corps %s", resp.StatusCode, out)
	}
	ct, body = multipartBody([]string{"name", "Bob"}, []string{"cv", "bravo.pdf", "fichier-bravo"})
	if resp, out := submit(t, e.url, submitOpts{path: "/f/" + e.fx.formB.AccessKey, contentType: ct, body: body}); resp.StatusCode != http.StatusOK {
		t.Fatalf("soumission B : statut %d, corps %s", resp.StatusCode, out)
	}
	adm := newClient()
	login(t, adm, e.url, e.fx.orgAdmin.Email)
	files := exportZIP(t, adm, e.url+"/forms/"+e.fx.formA.ID.String()+"/export.zip")
	if len(files) != 2 || files["pieces-jointes/0001/1-alpha.pdf"] != "fichier-alpha" {
		t.Errorf("l'export de A doit porter son CSV et son fichier : %d fichiers", len(files))
	}
	for name, content := range files {
		if strings.Contains(name, "bravo") || strings.Contains(content, "bravo") || strings.Contains(content, "Bob") {
			t.Errorf("l'export de A porte des données de B : %q", name)
		}
	}
	var detail string
	if err := e.pool.QueryRow(context.Background(), `SELECT detail FROM audit_log WHERE action = 'form.submissions_exported'`).Scan(&detail); err != nil || !strings.Contains(detail, `"attachments":"1"`) {
		t.Errorf("trace de l'export : %s (err=%v)", detail, err)
	}
}

// An export holds a file in memory until its reader has received it: their number at
// once is bounded, and the slot is freed when a reader leaves.
func TestExportZIPSimultanesBornes(t *testing.T) {
	e := setup(t)
	acceptAttachments(t, e, e.fx.formB)
	// Enough files for an export not to fit in the network buffers: it stays in progress
	// as long as nobody reads it.
	ct, body := multipartBody([]string{"name", "Ada"}, []string{"cv", "cv.bin", strings.Repeat("x", 60<<10)})
	for range 400 {
		if resp, out := submit(t, e.url, submitOpts{path: "/f/" + e.fx.formB.AccessKey, contentType: ct, body: body}); resp.StatusCode != http.StatusOK {
			t.Fatalf("soumission : statut %d, corps %s", resp.StatusCode, out)
		}
	}
	c := newClient()
	login(t, c, e.url, e.fx.memberB.Email)
	target := e.url + "/forms/" + e.fx.formB.ID.String() + "/export.zip"
	u, _ := url.Parse(target)
	var cookies []string
	for _, ck := range c.Jar.Cookies(u) {
		cookies = append(cookies, ck.Name+"="+ck.Value)
	}
	request := "GET " + u.Path + " HTTP/1.1\r\nHost: " + u.Host + "\r\nCookie: " + strings.Join(cookies, "; ") + "\r\n\r\n"
	var conns []net.Conn
	stall := func() {
		t.Helper()
		conn, err := net.Dial("tcp", u.Host)
		if err != nil {
			t.Fatalf("connexion: %v", err)
		}
		t.Cleanup(func() { conn.Close() })
		if _, err := conn.Write([]byte(request)); err != nil {
			t.Fatalf("envoi: %v", err)
		}
		conns = append(conns, conn)
	}
	// Two exports (handlers.maxExports) requested, never read.
	stall()
	stall()
	await := func(want int, between func()) *http.Response {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			resp, err := c.Get(target)
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == want {
				return resp
			}
			if time.Now().After(deadline) {
				t.Fatalf("statut %d (%d attendu)", resp.StatusCode, want)
			}
			if between != nil {
				between()
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	// Same precaution as for file uploads: a probing export holds a slot while it is served.
	// If it overtakes one of the pending exports, it is this one that is refused; another
	// then takes the slot.
	if resp := await(http.StatusServiceUnavailable, stall); resp.Header.Get("Retry-After") == "" {
		t.Errorf("un export refusé faute de place doit dire quand réessayer")
	}
	// The CSV export alone, which carries no file, is not affected.
	if code, _ := get(t, c, e.url+"/forms/"+e.fx.formB.ID.String()+"/export.csv"); code != http.StatusOK {
		t.Errorf("export CSV pendant la saturation : statut %d", code)
	}
	for _, conn := range conns {
		conn.Close()
	}
	await(http.StatusOK, nil)
}

// The archive follows the account isolation of the other exports, and is only offered
// when the form keeps files.
func TestExportZIPCloisonne(t *testing.T) {
	e := setup(t)
	acceptAttachments(t, e, e.fx.formA)
	ct, body := multipartBody([]string{"name", "Ada"}, []string{"cv", "cv-secret.pdf", "contenu-tres-confidentiel"})
	if resp, out := submit(t, e.url, submitOpts{path: "/f/" + e.fx.formA.AccessKey, contentType: ct, body: body, origin: "https://exemple.fr"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("soumission : statut %d, corps %s", resp.StatusCode, out)
	}
	target := e.url + "/forms/" + e.fx.formA.ID.String() + "/export.zip"

	resp, err := newClient().Get(target)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("export sans session : statut %d (303 attendu)", resp.StatusCode)
	}
	b := newClient()
	login(t, b, e.url, e.fx.memberB.Email)
	if code, out := get(t, b, target); code != http.StatusNotFound || strings.Contains(out, "confidentiel") {
		t.Errorf("export par un autre membre : statut %d (404 attendu)", code)
	}
	// Form B keeps no files: no button.
	if _, page := get(t, b, e.url+"/forms/"+e.fx.formB.ID.String()); strings.Contains(page, "export.zip") {
		t.Errorf("l'export avec pièces jointes est proposé pour un formulaire sans fichier")
	}
	var traced int
	if err := e.pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_log WHERE action = 'form.submissions_exported'`).Scan(&traced); err != nil || traced != 0 {
		t.Errorf("%d export(s) tracé(s) alors qu'aucun n'a abouti (err=%v)", traced, err)
	}

	adm := newClient()
	login(t, adm, e.url, e.fx.orgAdmin.Email)
	if files := exportZIP(t, adm, target); files["pieces-jointes/0001/1-cv-secret.pdf"] != "contenu-tres-confidentiel" {
		t.Errorf("l'administrateur doit pouvoir exporter les fichiers de tout formulaire")
	}
}

// A file that became unreadable does not take the rest of the export with it: it is
// missing from the archive, which says so.
func TestExportZIPFichierIllisible(t *testing.T) {
	e := setup(t)
	acceptAttachments(t, e, e.fx.formB)
	ct, body := multipartBody([]string{"name", "Ada"}, []string{"cv", "cv.pdf", "contenu-du-cv"}, []string{"notes", "notes.txt", "contenu-des-notes"})
	if resp, out := submit(t, e.url, submitOpts{path: "/f/" + e.fx.formB.AccessKey, contentType: ct, body: body}); resp.StatusCode != http.StatusOK {
		t.Fatalf("soumission : statut %d, corps %s", resp.StatusCode, out)
	}
	// The prefix of an encrypted content, followed by bytes that do not decrypt.
	if _, err := e.pool.Exec(context.Background(), `UPDATE attachments SET content = convert_to('enc1:', 'UTF8') || '\x00010203'::bytea WHERE position = 0`); err != nil {
		t.Fatal(err)
	}
	c := newClient()
	login(t, c, e.url, e.fx.memberB.Email)
	files := exportZIP(t, c, e.url+"/forms/"+e.fx.formB.ID.String()+"/export.zip")
	if files["pieces-jointes/0001/2-notes.txt"] != "contenu-des-notes" {
		t.Errorf("le fichier lisible doit rester dans l'archive")
	}
	if _, present := files["pieces-jointes/0001/1-cv.pdf"]; present {
		t.Errorf("un fichier illisible ne doit pas figurer dans l'archive")
	}
	if missing := files["fichiers-manquants.txt"]; !strings.Contains(missing, "pieces-jointes/0001/1-cv.pdf") || strings.Contains(missing, "notes.txt") {
		t.Errorf("l'archive doit nommer le fichier manquant, et lui seul : %q", missing)
	}
}
