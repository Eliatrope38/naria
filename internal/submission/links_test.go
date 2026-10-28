package submission

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestDefang(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"phishing message", "Le projet est précisé ici : https://shareits.online/fr/net/detag-informatique",
			"Le projet est précisé ici : hxxps://shareits[.]online/fr/net/detag-informatique"},
		{"http", "http://exemple.fr", "hxxp://exemple[.]fr"},
		{"uppercase scheme", "HTTPS://Evil.Online/", "HxxPS://Evil[.]Online/"},
		{"sentence punctuation", "voir https://evil.online, merci", "voir hxxps://evil[.]online, merci"},
		{"end of sentence", "(https://evil.online).", "(hxxps://evil[.]online)."},
		{"userinfo", "https://google.com@evil.online/", "hxxps://google[.]com@evil[.]online/"},
		{"backslash ends the authority", `https://evil.online\@google.com`, `hxxps://evil[.]online\@google[.]com`},
		{"extra slashes", "https:///evil.online/x", "hxxps:///evil[.]online/x"},
		{"no slash", "https:evil.online", "hxxps:evil[.]online"},
		{"backslashes", `https:\\evil.online`, `hxxps:\\evil[.]online`},
		{"scheme glued to a word", "xhttps://evil.online", "xhxxps://evil[.]online"},
		{"port", "https://evil.online:8443/x", "hxxps://evil[.]online:8443/x"},
		{"percent-encoded dot", "https://evil%2Eonline/", "hxxps://evil[.]online/"},
		{"fullwidth dot", "https://evil．online/", "hxxps://evil[.]online/"},
		{"ip address", "http://192.168.1.1/admin", "hxxp://192[.]168[.]1[.]1/admin"},
		{"other scheme", "smb://evil.online/share", "smb[:]//evil[.]online/share"},
		{"file without a host", "file:///etc/passwd", "file[:]///etc/passwd"},
		{"unc path", `\\evil.online\share`, `\\evil[.]online\share`},
		{"www", "www.exemple.fr", "www[.]exemple[.]fr"},
		{"host and path", "shareits.online/fr/net", "shareits[.]online/fr/net"},
		{"bare domain", "écrivez sur shareits.online", "écrivez sur shareits[.]online"},
		{"link in a query", "https://bon.fr/?u=https://evil.online/", "hxxps://bon[.]fr/?u=hxxps://evil[.]online/"},
		{"www in a path", "https://bon.fr/www.evil.online", "hxxps://bon[.]fr/www[.]evil[.]online"},
		{"address left alone", "nicolas.hocquet7880@prodmail.online", "nicolas.hocquet7880@prodmail.online"},
		{"address on www left alone", "x@www.exemple.fr", "x@www.exemple.fr"},
		{"numbers left alone", "3.14 ou 1.5/2", "3.14 ou 1.5/2"},
		{"file name left alone", "cv.pdf, devis.docx", "cv.pdf, devis.docx"},
		{"circled letters", "https://ⓢhareits.ⓞnline/fr", "hxxps://ⓢhareits[.]ⓞnline/fr"},
		{"one dot leader", "https://evil․online/fr", "hxxps://evil[.]online/fr"},
		{"percent-encoded ideographic dot", "https://evil%E3%80%82online/x", "hxxps://evil[%]E3[%]80[%]82online/x"},
		{"name glued to a scheme", "evil.online.http://x.fr", "evil[.]online.hxxp://x[.]fr"},
		{"word before a colon left alone", "File:rapport, ws:x", "File:rapport, ws:x"},
		{"extension that is a domain", "photo.zip", "photo[.]zip"},
		{"drive letter left alone", `C:\Users\ada`, `C:\Users\ada`},
		{"text left alone", "Bonjour, un devis pour cinq PC ?", "Bonjour, un devis pour cinq PC ?"},
		{"http alone left alone", "le protocole http: est ancien", "le protocole http: est ancien"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Defang(tt.in); got != tt.want {
				t.Fatalf("Defang(%q)\n got %q\nwant %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestHasLink(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{"https", "voir https://shareits.online/fr", true},
		{"three slashes", "https:///evil.online/x", true},
		{"www", "notre site www.exemple.fr", true},
		{"host and path", "shareits.online/fr/net", true},
		{"host, port and path", "shareits.online:8443/x", true},
		{"unc", `\\evil.online\share`, true},
		{"file", "file:///etc/passwd", true},
		{"circled letters", "https://ⓢhareits.ⓞnline/fr", true},
		{"host of invisible characters", "https://\u00ad\u00ad/x", true},
		{"special scheme without slashes", "ftp:evil.online", true},
		{"word before a colon is not one", "File:rapport", false},
		{"bare domain is not one", "écrivez sur shareits.online", false},
		{"address is not one", "ada@exemple.fr", false},
		{"framework name is not one", "ASP.NET et Node.js", false},
		{"file path is not one", "Node.js/React, src/main.go/", false},
		{"plain text", "Un devis pour cinq PC Latitude 5430 ?", false},
		{"phone number", "06 60 82 67 32", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HasLink([]Field{{Name: "message", Value: tt.value}}); got != tt.want {
				t.Fatalf("HasLink(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
	if !HasLink([]Field{{Name: "https://evil.online/", Value: "x"}}) {
		t.Fatal("a link in a field name is not seen")
	}
}

func TestBlockKeysFromLinks(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  []string
	}{
		{"https link", "ici : https://shareits.online/fr", []string{"shareits.online", ".online"}},
		{"subdomain", "https://a.b.evil.online", []string{"a.b.evil.online", "b.evil.online", "evil.online", ".online"}},
		{"userinfo", "https://google.com@evil.online/", []string{"evil.online", ".online"}},
		{"fullwidth letters", "https://ｓｈａｒｅｉｔｓ.online/", []string{"shareits.online", ".online"}},
		{"ideographic dot", "https://shareits。online/", []string{"shareits.online", ".online"}},
		{"soft hyphen", "https://share\u00adits.online/", []string{"shareits.online", ".online"}},
		{"percent-encoded", "https://%73hareits%2Eonline/", []string{"shareits.online", ".online"}},
		{"idn keeps its ascii parents", "https://évil.prodmail.online/", []string{"prodmail.online", ".online"}},
		{"bare domain", "écrivez sur shareits.online.", []string{"shareits.online", ".online"}},
		{"circled letters", "https://ⓢhareits.ⓞnline/", []string{"shareits.online", ".online"}},
		{"one dot leader", "https://shareits․online/", []string{"shareits.online", ".online"}},
		{"deep host keeps its short parents", "https://a.b.c.d.e.f.g.evil.online/",
			[]string{"a.b.c.d.e.f.g.evil.online", "d.e.f.g.evil.online", "e.f.g.evil.online",
				"f.g.evil.online", "g.evil.online", "evil.online", ".online"}},
		{"ip address has no key", "http://192.168.1.1/", nil},
		{"address in a message is not a sender", "écrire à contact@exemple.fr", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BlockKeys([]Field{{Name: "message", Value: tt.value}})
			if !slices.Equal(got, tt.want) {
				t.Fatalf("BlockKeys(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

// A few deep hosts cannot use up the keys before a blocked link.
func TestBlockKeysDeepHosts(t *testing.T) {
	deep := "https://" + strings.Repeat("a.", 120) + "com/ "
	keys := BlockKeys([]Field{{Name: "message", Value: deep + deep + deep + "https://shareits.online/x"}})
	if !slices.Contains(keys, "shareits.online") {
		t.Fatalf("lien bloqué hors des %d clés : %q", len(keys), keys)
	}
}

// The sender's keys come first: links cannot push them past the bound.
func TestBlockKeysSenderFirst(t *testing.T) {
	var msg strings.Builder
	for i := range 1000 {
		fmt.Fprintf(&msg, "https://h%d.exemple%d.zz/ ", i, i)
	}
	keys := BlockKeys([]Field{{Name: "message", Value: msg.String()}, {Name: "email", Value: "bot@spam.online"}})
	if len(keys) != maxBlockKeys {
		t.Fatalf("%d clés, %d attendues", len(keys), maxBlockKeys)
	}
	if !slices.Equal(keys[:3], []string{"bot@spam.online", "spam.online", ".online"}) {
		t.Fatalf("clés de l'expéditeur absentes en tête : %q", keys[:3])
	}
}

// A visitor controls the text: scanning must stay linear on hostile input, up to
// the 60 fields of 20000 bytes that DefaultLimits admits.
func TestLinksLinearOnHostileInput(t *testing.T) {
	const size = 1200 << 10
	inputs := map[string]string{
		"labels":         strings.Repeat("a.", size/2),
		"schemes":        strings.Repeat("https://", size/8),
		"schemes no end": strings.Repeat("https:a.b:", size/10),
		"at signs":       "https://" + strings.Repeat("@", size),
		"www":            strings.Repeat("www.a", size/5),
		"colons":         strings.Repeat("a:", size/2),
		"backslashes":    strings.Repeat(`\\a.b`, size/5),
		"long scheme":    strings.Repeat("a", size) + "://x.y",
		// Every scheme before one "@" points to the same host, read once.
		"shared host invisible": strings.Repeat("ws:", size/6) + "@" + strings.Repeat("\u00ad", size/4),
		"shared host dots":      strings.Repeat("ws:", size/6) + "@" + strings.Repeat(".", size/2),
		"shared bracket":        strings.Repeat("http:x@", size/14) + "[" + strings.Repeat("a", size/2),
		"compat characters":     strings.Repeat("ⓐ.", size/4),
	}
	var many strings.Builder
	for i := 0; many.Len() < size; i++ {
		fmt.Fprintf(&many, "https://h%d.e%d.zz/ ", i, i)
	}
	inputs["distinct links"] = many.String()
	for name, in := range inputs {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			Defang(in)
			HasLink([]Field{{Name: "message", Value: in}})
			BlockKeys([]Field{{Name: "message", Value: in}})
			if d := time.Since(start); d > 2*time.Second {
				t.Fatalf("%s pour %d octets", d, len(in))
			}
		})
	}
}

// Once defanged, a text holds no web link, "www." name or bare domain that the
// scanner itself would find. Only special schemes followed by "//" are checked:
// a made-up scheme ("a0:/x") or "http:x" may still read a host out of the
// rewritten text.
func FuzzDefang(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := Defang(s)
		for _, l := range scanLinks(out) {
			if l.schemeEnd > l.start && (!specialSchemes[strings.ToLower(out[l.start:l.schemeEnd])] ||
				!strings.HasPrefix(out[l.schemeEnd:], "://")) {
				continue
			}
			dot := strings.LastIndexByte(l.host, '.')
			if dot >= 0 && isTLD(l.host[dot+1:]) && !strings.HasPrefix(out[l.authStart:], "[") {
				t.Fatalf("Defang(%q) = %q leaves the host %q", s, out, l.host)
			}
		}
	})
}

// Independent of the scanner: once defanged, a text holds no web scheme followed
// by "//" and a host.
func FuzzDefangSchemes(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := Defang(s)
		// ASCII only, so that offsets in lower are offsets in out.
		lower := []byte(out)
		for i, c := range lower {
			if c >= 'A' && c <= 'Z' {
				lower[i] = c + 'a' - 'A'
			}
		}
		for _, scheme := range []string{"http://", "https://", "ftp://", "ws://", "wss://", "file://"} {
			for k := 0; ; {
				i := strings.Index(string(lower[k:]), scheme)
				if i < 0 {
					break
				}
				k += i + len(scheme)
				rest := strings.TrimLeft(out[k:], `/\@`)
				if r, _ := utf8.DecodeRuneInString(rest); rest != "" && (isHostRune(r) || r == '[') {
					t.Fatalf("Defang(%q) = %q keeps %q", s, out, scheme)
				}
			}
		}
	})
}

var fuzzSeeds = []string{
	"https://shareits.online/fr", "www.exemple.fr", "a.b/c", `\\h.x\s`, "https://g.com@e.online",
	"https:///e.online", "x@www.e.fr", "https://e%2Eonline", "e．online/x", "https://ⓢhareits.ⓞnline/fr",
	"ws:x@\u00ad\u00ad", "evil.online.http://x.fr", "https://\u00ad/x",
}
