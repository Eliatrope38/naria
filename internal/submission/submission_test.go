package submission

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"reflect"
	"strings"
	"testing"
	"testing/iotest"
)

func request(contentType, body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader(body))
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	return r
}

func TestParseKeepsFieldOrder(t *testing.T) {
	want := []Field{{"zeta", "1"}, {"alpha", "deux mots"}, {"message", "ligne 1\nligne 2"}}

	urlenc := "zeta=1&alpha=deux+mots&message=ligne+1%0D%0Aligne+2"
	got, _, err := Parse(request("application/x-www-form-urlencoded", urlenc), DefaultLimits, nil)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("urlencoded: got %v, %v ; want %v", got, err, want)
	}

	jsonBody := `{"zeta": 1, "alpha": "deux mots", "message": "ligne 1\nligne 2"}`
	got, _, err = Parse(request("application/json; charset=utf-8", jsonBody), DefaultLimits, nil)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("json: got %v, %v ; want %v", got, err, want)
	}

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for _, f := range want {
		_ = mw.WriteField(f.Name, f.Value)
	}
	_ = mw.Close()
	got, _, err = Parse(request(mw.FormDataContentType(), buf.String()), DefaultLimits, nil)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("multipart: got %v, %v ; want %v", got, err, want)
	}
}

// upload builds a multipart submission. A two-element entry is a field (name, value);
// a three-element one is a file (field name, file name, content).
func upload(parts ...[]string) *http.Request {
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
	return request(mw.FormDataContentType(), buf.String())
}

func TestParseMultipartIgnoresFiles(t *testing.T) {
	want := []Field{{"name", "Ada"}, {"message", "bonjour"}}
	for name, gate := range map[string]FileGate{
		"sans gate":      nil,
		"limites nulles": func(Meta) (FileLimits, error) { return FileLimits{}, nil },
	} {
		t.Run(name, func(t *testing.T) {
			r := upload([]string{"name", "Ada"}, []string{"cv", "cv-secret.pdf", "%PDF contenu confidentiel"}, []string{"message", "bonjour"})
			got, files, err := Parse(r, DefaultLimits, gate)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if !reflect.DeepEqual(got, want) || len(files) != 0 {
				t.Fatalf("got %v et %d fichier(s), want %v sans fichier", got, len(files), want)
			}
		})
	}
}

// The gate decision is requested only once, at the first file, with the service fields read so far.
func TestParseMultipartFiles(t *testing.T) {
	var seen []Meta
	gate := func(m Meta) (FileLimits, error) {
		seen = append(seen, m)
		return FileLimits{MaxFiles: 3, MaxBytes: 64}, nil
	}
	r := upload(
		[]string{"access_key", "cle-1"},
		[]string{"naria_captcha", "defi.42"},
		[]string{"name", "Ada"},
		[]string{"pieces[]", "cv.pdf", "%PDF\x00\xff"},
		[]string{"pieces[]", "lettre de motivation.txt", "bonjour"},
		[]string{"message", "ci-joint"},
		[]string{"photo", "../../etc/passwd", ""},
	)
	fields, files, err := Parse(r, DefaultLimits, gate)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	wantFields := []Field{{"access_key", "cle-1"}, {"naria_captcha", "defi.42"}, {"name", "Ada"}, {"pieces", "cv.pdf, lettre de motivation.txt"}, {"message", "ci-joint"}, {"photo", "passwd"}}
	if !reflect.DeepEqual(fields, wantFields) {
		t.Errorf("champs = %v, want %v", fields, wantFields)
	}
	wantFiles := []File{{"cv.pdf", []byte("%PDF\x00\xff")}, {"lettre de motivation.txt", []byte("bonjour")}, {"passwd", []byte{}}}
	if !reflect.DeepEqual(files, wantFiles) {
		t.Errorf("fichiers = %q, want %q", files, wantFiles)
	}
	if want := []Meta{{AccessKey: "cle-1", Captcha: "defi.42"}}; !reflect.DeepEqual(seen, want) {
		t.Errorf("gate appelée avec %+v, want %+v", seen, want)
	}
}

func TestFileName(t *testing.T) {
	for in, want := range map[string]string{
		"cv.pdf":                        "cv.pdf",
		" rapport\tannuel\r\n2026.pdf ": "rapport annuel 2026.pdf",
		"a\x00b\x1b.txt":                "ab.txt",
		"\x01\n":                        "sans-nom",
		"facture\u202efdp.exe":          "facturefdp.exe",
		"a\u200b\u2066b\u009b.txt":      "ab.txt",
	} {
		if got := fileName(in); got != want {
			t.Errorf("fileName(%q) = %q, want %q", in, got, want)
		}
	}
}

// An empty file field is not a file: the gate is not consulted.
func TestParseMultipartEmptyFileInput(t *testing.T) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("name", "Ada")
	_, _ = mw.CreatePart(textproto.MIMEHeader{
		"Content-Disposition": {`form-data; name="cv"; filename=""`},
		"Content-Type":        {"application/octet-stream"},
	})
	_ = mw.Close()
	fields, files, err := Parse(request(mw.FormDataContentType(), buf.String()), DefaultLimits, func(Meta) (FileLimits, error) {
		t.Error("gate appelée pour un champ de fichier vide")
		return FileLimits{MaxFiles: 1, MaxBytes: 64}, nil
	})
	want := []Field{{"name", "Ada"}, {"cv", ""}}
	if err != nil || !reflect.DeepEqual(fields, want) || len(files) != 0 {
		t.Fatalf("got %v, %d fichier(s), %v ; want %v sans fichier", fields, len(files), err, want)
	}
}

// The read timeout surfaces as is, as a 408 and not "invalid request".
func TestParseSurfacesReadTimeout(t *testing.T) {
	timeout := fmt.Errorf("read tcp: %w", os.ErrDeadlineExceeded)
	multi := upload([]string{"cv", "cv.pdf", strings.Repeat("x", 4096)})
	whole, _ := io.ReadAll(multi.Body)
	for ct, start := range map[string]string{
		"application/json":                  `{"a":"`,
		"application/x-www-form-urlencoded": "a=1&b=",
		multi.Header.Get("Content-Type"):    string(whole[:len(whole)/2]),
	} {
		r := request(ct, "")
		r.Body = io.NopCloser(io.MultiReader(strings.NewReader(start), iotest.ErrReader(timeout)))
		_, _, err := Parse(r, DefaultLimits, func(Meta) (FileLimits, error) {
			return FileLimits{MaxFiles: 1, MaxBytes: 1 << 20}, nil
		})
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Errorf("%.30s: got %v, want le délai dépassé", ct, err)
		}
	}
}

// The gate receives an empty key: the caller decides.
func TestParseMultipartFileBeforeKey(t *testing.T) {
	got := "non appelée"
	r := upload([]string{"cv", "cv.pdf", "x"}, []string{"access_key", "cle-1"})
	_, _, err := Parse(r, DefaultLimits, func(seen Meta) (FileLimits, error) {
		got = seen.AccessKey
		return FileLimits{}, nil
	})
	if err != nil || got != "" {
		t.Fatalf("gate appelée avec %q, err %v ; want une clé vide", got, err)
	}
}

func TestParseMultipartFileLimits(t *testing.T) {
	refused := errors.New("refus de l'appelant")
	allow := func(lim FileLimits) FileGate {
		return func(Meta) (FileLimits, error) { return lim, nil }
	}
	cases := []struct {
		name  string
		gate  FileGate
		parts [][]string
		want  error
	}{
		{"trop de fichiers", allow(FileLimits{MaxFiles: 1, MaxBytes: 64}), [][]string{{"a", "a.txt", "x"}, {"b", "b.txt", "x"}}, ErrTooManyFiles},
		{"fichier trop gros", allow(FileLimits{MaxFiles: 2, MaxBytes: 4}), [][]string{{"a", "a.txt", "12345"}}, ErrFilesTooLarge},
		{"cumul trop gros", allow(FileLimits{MaxFiles: 2, MaxBytes: 4}), [][]string{{"a", "a.txt", "123"}, {"b", "b.txt", "45"}}, ErrFilesTooLarge},
		{"cumul à la limite", allow(FileLimits{MaxFiles: 2, MaxBytes: 4}), [][]string{{"a", "a.txt", "12"}, {"b", "b.txt", "34"}}, nil},
		{"nom trop long", allow(FileLimits{MaxFiles: 1, MaxBytes: 4}), [][]string{{"a", strings.Repeat("n", 256), "x"}}, ErrFieldTooLong},
		{"refus de l'appelant", func(Meta) (FileLimits, error) { return FileLimits{}, refused }, [][]string{{"a", "a.txt", "x"}}, refused},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := Parse(upload(tc.parts...), DefaultLimits, tc.gate)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestParseMergesRepeatedNames(t *testing.T) {
	got, _, err := Parse(request("application/x-www-form-urlencoded", "topics%5B%5D=a&name=x&topics%5B%5D=b&topics%5B%5D="), DefaultLimits, nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := []Field{{"topics", "a, b"}, {"name", "x"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseJSONValues(t *testing.T) {
	body := `{"s":"texte","n":12.5,"b":true,"nul":null,"list":["a",2,false],"obj":{"k": [1, 2]}}`
	got, _, err := Parse(request("application/json", body), DefaultLimits, nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := []Field{{"s", "texte"}, {"n", "12.5"}, {"b", "true"}, {"nul", ""}, {"list", "a, 2, false"}, {"obj", `{"k":[1,2]}`}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseRejects(t *testing.T) {
	small := Limits{MaxFields: 2, MaxNameLen: 5, MaxValueLen: 10}
	cases := []struct {
		name, contentType, body string
		lim                     Limits
		want                    error
	}{
		{"type inconnu", "text/plain", "a=b", DefaultLimits, ErrUnsupportedType},
		{"xml", "application/xml", "<a/>", DefaultLimits, ErrUnsupportedType},
		{"json tableau", "application/json", `["a"]`, DefaultLimits, ErrMalformed},
		{"json tronqué", "application/json", `{"a":`, DefaultLimits, ErrMalformed},
		{"urlencoded invalide", "application/x-www-form-urlencoded", "a=%zz", DefaultLimits, ErrMalformed},
		{"trop de champs", "application/x-www-form-urlencoded", "a=1&b=2&c=3", small, ErrTooManyFields},
		{"nom trop long", "application/x-www-form-urlencoded", "abcdef=1", small, ErrFieldTooLong},
		{"valeur trop longue", "application/json", `{"a":"12345678901"}`, small, ErrFieldTooLong},
		{"valeur fusionnée trop longue", "application/x-www-form-urlencoded", "a=123456&a=123456", small, ErrFieldTooLong},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := Parse(request(tc.contentType, tc.body), tc.lim, nil)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

// So that the handler answers 413 and not "invalid request".
func TestParseSurfacesBodyLimit(t *testing.T) {
	for _, ct := range []string{"application/x-www-form-urlencoded", "application/json"} {
		body := `{"a":"` + strings.Repeat("x", 4096) + `"}`
		r := request(ct, body)
		r.Body = http.MaxBytesReader(httptest.NewRecorder(), r.Body, 64)
		_, _, err := Parse(r, DefaultLimits, nil)
		var tooLarge *http.MaxBytesError
		if !errors.As(err, &tooLarge) {
			t.Fatalf("%s: got %v, want *http.MaxBytesError", ct, err)
		}
	}
}

func TestParseCleansValues(t *testing.T) {
	got, _, err := Parse(request("application/json", `{" nom ":"  a\u0000b\u0007\tc\r\nd\re  "}`), DefaultLimits, nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := []Field{{"nom", "ab\tc\nd\ne"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestSplit(t *testing.T) {
	meta, data := Split([]Field{
		{"access_key", "KEY"}, {"name", "Ada"}, {"subject", "Devis"}, {"redirect", "https://exemple.fr/merci"},
		{"replyto", "ada@exemple.fr"}, {"botcheck", ""}, {"cf-turnstile-response", "tok"}, {"naria_captcha", "defi.42"}, {"message", "bonjour"},
	})
	wantMeta := Meta{AccessKey: "KEY", Redirect: "https://exemple.fr/merci", Subject: "Devis", ReplyTo: "ada@exemple.fr", Captcha: "defi.42"}
	if meta != wantMeta {
		t.Fatalf("meta = %+v, want %+v", meta, wantMeta)
	}
	wantData := []Field{{"name", "Ada"}, {"message", "bonjour"}}
	if !reflect.DeepEqual(data, wantData) {
		t.Fatalf("data = %v, want %v", data, wantData)
	}
}

func TestSplitBotcheck(t *testing.T) {
	for value, want := range map[string]bool{"": false, "false": false, "0": false, "on": true, "true": true, "spam": true} {
		meta, _ := Split([]Field{{"botcheck", value}})
		if meta.Bot != want {
			t.Errorf("botcheck=%q : Bot = %v, want %v", value, meta.Bot, want)
		}
	}
}

func TestValidEmail(t *testing.T) {
	valid := []string{"ada@exemple.fr", "  ada.lovelace+tag@sub.exemple.co.uk  "}
	for _, s := range valid {
		if _, ok := ValidEmail(s); !ok {
			t.Errorf("%q devrait être valide", s)
		}
	}
	invalid := []string{
		"", "ada", "ada@", "@exemple.fr", "Ada <ada@exemple.fr>", "a@b.fr, c@d.fr",
		"ada@exemple.fr\r\nBcc: x@evil.tld", "ada@exemple.fr\nBcc: x@evil.tld", strings.Repeat("a", 250) + "@b.fr",
	}
	for _, s := range invalid {
		if got, ok := ValidEmail(s); ok {
			t.Errorf("%q ne devrait pas être valide (got %q)", s, got)
		}
	}
}

func TestReplyAddress(t *testing.T) {
	data := []Field{{"Email", "visiteur@exemple.org"}, {"message", "x"}}
	if got := ReplyAddress(Meta{}, data); got != "visiteur@exemple.org" {
		t.Errorf("repli sur le champ email : got %q", got)
	}
	if got := ReplyAddress(Meta{ReplyTo: "autre@exemple.org"}, data); got != "autre@exemple.org" {
		t.Errorf("replyto explicite prioritaire : got %q", got)
	}
	if got := ReplyAddress(Meta{ReplyTo: "x\r\nBcc: a@b.c"}, []Field{{"email", "pas une adresse"}}); got != "" {
		t.Errorf("aucune adresse valide : got %q, want vide", got)
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	in := []Field{
		{"nom", "Ada « Lovelace »"},
		{"message", "ligne 1\nligne 2\t<script>alert(\"x\")</script> & 'fin' \\ 日本語 " + string(rune(0x2028)) + " 🙂"},
		{"a<b>&c", "</textarea>"},
		{"vide", ""},
	}
	s, err := Encode(in)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if strings.ContainsAny(s, "\n\r") {
		t.Errorf("la sortie d'Encode tient sur une ligne, sans saut final : %q", s)
	}
	out, err := Decode(s)
	if err != nil || !reflect.DeepEqual(in, out) {
		t.Fatalf("round-trip: got %v, %v", out, err)
	}
	if _, err := Decode("pas du json"); err == nil {
		t.Fatal("Decode d'une valeur invalide aurait dû échouer")
	}
}

// Submissions stored before HTML escaping was turned off are read back unchanged.
func TestDecodeReadsHTMLEscapedForm(t *testing.T) {
	want := []Field{{"message", "<b>A & B</b> \"cité\"\nfin"}, {"a<b", "é"}}
	stored, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if bytes.ContainsAny(stored, "<>&") {
		t.Fatalf("l'ancienne forme devrait échapper <, > et & : %s", stored)
	}
	got, err := Decode(string(stored))
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("Decode: got %v, %v ; want %v", got, err, want)
	}
}

func TestEncodeDoesNotInflateHTMLChars(t *testing.T) {
	for _, c := range []string{"<", ">", "&"} {
		value := strings.Repeat(c, 16002)
		s, err := Encode([]Field{{"message", value}})
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		if limit := len(value) + 64; len(s) > limit {
			t.Errorf("%d octets de %q sérialisés en %d octets, borne %d", len(value), c, len(s), limit)
		}
	}
}

func TestNormalizeDomains(t *testing.T) {
	got, err := NormalizeDomains(" Exemple.FR, https://www.autre.fr/contact?x=1\n*.Client.com ; localhost:3000 exemple.fr ")
	if err != nil {
		t.Fatalf("NormalizeDomains: %v", err)
	}
	want := []string{"exemple.fr", "www.autre.fr", "*.client.com", "localhost"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if got, err := NormalizeDomains("  "); err != nil || len(got) != 0 {
		t.Fatalf("saisie vide : got %v, %v", got, err)
	}
	for _, bad := range []string{"exemple", "exa mple.fr,bad_host.fr", "http://", "*.", "exemple<script>.fr", "[::1]"} {
		if got, err := NormalizeDomains(bad); err == nil {
			t.Errorf("%q aurait dû être refusé (got %v)", bad, got)
		}
	}
}

func TestOriginAllowed(t *testing.T) {
	domains := []string{"exemple.fr", "*.client.com", "localhost"}
	cases := []struct {
		origin, referer string
		want            bool
	}{
		{"https://exemple.fr", "", true},
		{"https://www.exemple.fr", "", true},
		{"https://EXEMPLE.fr:8443", "", true},
		{"http://localhost:3000", "", true},
		{"https://app.client.com", "", true},
		{"https://a.b.client.com", "", true},
		{"https://client.com", "", false}, // le joker ne couvre pas le domaine nu
		{"https://exemple.fr.evil.tld", "", false},
		{"https://evilexemple.fr", "", false},
		{"https://notclient.com", "", false},
		{"https://sub.exemple.fr", "", false},
		{"null", "", false}, // opaque origin (sandboxed iframe, local file)
		{"", "https://exemple.fr/contact", true},
		{"", "https://evil.tld/contact", false},
		{"https://evil.tld", "https://exemple.fr/contact", false}, // Origin prime sur Referer
		{"", "", true}, // not a browser: see OriginAllowed
	}
	for _, tc := range cases {
		if got := OriginAllowed(domains, tc.origin, tc.referer); got != tc.want {
			t.Errorf("OriginAllowed(origin=%q, referer=%q) = %v, want %v", tc.origin, tc.referer, got, tc.want)
		}
	}
	if !OriginAllowed(nil, "https://nimporte.ou", "") {
		t.Error("sans domaine déclaré, toute origine doit être acceptée")
	}
}

func TestURLAllowed(t *testing.T) {
	domains := []string{"exemple.fr"}
	for raw, want := range map[string]bool{
		"https://exemple.fr/merci":       true,
		"https://www.exemple.fr/merci":   true,
		"https://evil.tld/merci":         false,
		"javascript:alert(1)":            false,
		"//evil.tld/merci":               false,
		"/merci":                         false,
		"https://exemple.fr@evil.tld/":   false,
		"https://evil.tld/?x=exemple.fr": false,
	} {
		if got := URLAllowed(domains, raw); got != want {
			t.Errorf("URLAllowed(%q) = %v, want %v", raw, got, want)
		}
	}
	if URLAllowed(nil, "javascript:alert(1)") {
		t.Error("même sans domaine déclaré, seule une URL http(s) est acceptée")
	}
}
