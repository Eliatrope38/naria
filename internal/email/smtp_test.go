package email

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
	"time"
)

func TestSanitizeHeader(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "valeur simple inchangée", in: "contact@exemple.fr", want: "contact@exemple.fr"},
		{name: "CR retiré", in: "a\rb", want: "ab"},
		{name: "LF retiré", in: "a\nb", want: "ab"},
		{name: "injection d'en-tête CRLF neutralisée", in: "victime@x.tld\r\nBcc: attaquant@evil.tld", want: "victime@x.tldBcc: attaquant@evil.tld"},
		{name: "plusieurs CRLF retirés", in: "Sujet\r\n\r\nCorps injecté", want: "SujetCorps injecté"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeHeader(tc.in); got != tc.want {
				t.Fatalf("sanitizeHeader(%q) = %q, attendu %q", tc.in, got, tc.want)
			}
		})
	}
}

// The content comes from a visitor: neither subject nor reply address may add a header,
// and no line may exceed the SMTP limit.
func TestBuildMIME(t *testing.T) {
	body := "<p>" + strings.Repeat("é", 3000) + "</p>"
	raw := string(buildMIME("naria@exemple.fr", Message{
		To:      []string{"dest@exemple.fr"},
		ReplyTo: "visiteur@exemple.org\r\nBcc: attaquant@evil.tld",
		Subject: "Contact\r\nBcc: attaquant@evil.tld",
		HTML:    body,
	}, time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)))

	head, encoded, ok := strings.Cut(raw, "\r\n\r\n")
	if !ok {
		t.Fatal("séparateur en-têtes/corps introuvable")
	}
	for _, line := range strings.Split(head, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "bcc:") {
			t.Fatalf("en-tête injecté : %q", line)
		}
	}
	if !strings.Contains(head, "Reply-To: visiteur@exemple.orgBcc: attaquant@evil.tld\r\n") {
		t.Errorf("Reply-To absent ou non assaini :\n%s", head)
	}
	for _, line := range strings.Split(raw, "\r\n") {
		if len(line) > 78 {
			t.Fatalf("ligne de %d octets (limite 78) : %.40q…", len(line), line)
		}
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(encoded, "\r\n", ""))
	if err != nil {
		t.Fatalf("corps base64 invalide : %v", err)
	}
	if string(decoded) != body {
		t.Fatal("le corps décodé ne correspond pas au HTML d'origine")
	}
}

func TestBuildMIMEOmitsEmptyReplyTo(t *testing.T) {
	raw := string(buildMIME("naria@exemple.fr", Message{To: []string{"dest@exemple.fr"}, Subject: "s", HTML: "x"}, time.Now()))
	if strings.Contains(raw, "Reply-To:") {
		t.Fatal("Reply-To présent alors qu'aucune adresse de réponse n'est fournie")
	}
}

// Files arrive byte for byte under their name, in a multipart/mixed. This name comes
// from a visitor: it must not add a header.
func TestBuildMIMEAttachments(t *testing.T) {
	binary := bytes.Repeat([]byte{0x00, 0xff, '\r', '\n', 0x80}, 1000)
	files := []Attachment{
		{Name: "devis été 2026.pdf", Data: binary},
		{Name: "a.txt\r\nBcc: attaquant@evil.tld", Data: []byte("x")},
		{Name: strings.Repeat("é", 127) + ".pdf", Data: nil},
	}
	raw := buildMIME("naria@exemple.fr", Message{
		To: []string{"dest@exemple.fr"}, Subject: "s", HTML: "<p>bonjour</p>", Attachments: files,
	}, time.Now())

	for _, line := range strings.Split(string(raw), "\r\n") {
		if len(line) > 998 {
			t.Fatalf("ligne de %d octets (limite SMTP 998) : %.40q…", len(line), line)
		}
		if strings.HasPrefix(strings.ToLower(line), "bcc:") {
			t.Fatalf("en-tête injecté : %q", line)
		}
	}

	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("message illisible : %v", err)
	}
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/mixed" {
		t.Fatalf("Content-Type = %q (%v), multipart/mixed attendu", msg.Header.Get("Content-Type"), err)
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	decode := func(p *multipart.Part) []byte {
		t.Helper()
		if enc := p.Header.Get("Content-Transfer-Encoding"); enc != "base64" {
			t.Fatalf("encodage %q, base64 attendu", enc)
		}
		data, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, p))
		if err != nil {
			t.Fatalf("partie illisible : %v", err)
		}
		return data
	}

	part, err := mr.NextPart()
	if err != nil {
		t.Fatalf("première partie : %v", err)
	}
	if ct := part.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") || string(decode(part)) != "<p>bonjour</p>" {
		t.Errorf("la première partie doit être le HTML (Content-Type %q)", ct)
	}
	for _, want := range files {
		part, err := mr.NextPart()
		if err != nil {
			t.Fatalf("pièce jointe %q : %v", want.Name, err)
		}
		disposition, params, err := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
		if err != nil || disposition != "attachment" || params["filename"] != want.Name {
			t.Errorf("Content-Disposition = %q (%v), fichier %q attendu", part.Header.Get("Content-Disposition"), err, want.Name)
		}
		if ct := part.Header.Get("Content-Type"); ct != "application/octet-stream" {
			t.Errorf("Content-Type = %q", ct)
		}
		if got := decode(part); !bytes.Equal(got, want.Data) {
			t.Errorf("%q : %d octet(s) relus, %d attendus", want.Name, len(got), len(want.Data))
		}
	}
	if _, err := mr.NextPart(); err != io.EOF {
		t.Errorf("partie en trop, ou message mal terminé : %v", err)
	}
}
