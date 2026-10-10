package handlers

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// The name comes from a visitor: it must neither leave its folder nor make extraction fail.
func TestZipEntryName(t *testing.T) {
	long := strings.Repeat("é", 120) // 240 bytes
	for _, tc := range []struct {
		position int16
		name     string
		want     string // "" means only the common rules are checked
	}{
		{0, "cv.pdf", "1-cv.pdf"},
		{4, "cv.pdf", "5-cv.pdf"},
		{0, "../../etc/passwd", "1-.._.._etc_passwd"},
		{0, "a/b", "1-a_b"},
		{0, `..\..\Windows\evil.bat`, "1-.._.._Windows_evil.bat"},
		{0, `C:\Users\x.txt`, "1-C__Users_x.txt"},
		{0, "..", "1-"},
		{0, ".", "1-"},
		{0, "", "1-"},
		{0, "CON", "1-CON"},
		{1, `a<b>c|d?e*f".txt`, "2-a_b_c_d_e_f_.txt"},
		{0, "fin.txt. . ", "1-fin.txt"},
		{0, "=cmd.txt", "1-=cmd.txt"},
		{0, long + ".pdf", ""},
		{0, long, ""},
		{0, "x." + long, ""},
	} {
		got := zipEntryName(tc.position, tc.name)
		if tc.want != "" && got != tc.want {
			t.Errorf("zipEntryName(%d, %q) = %q, attendu %q", tc.position, tc.name, got, tc.want)
		}
		if strings.ContainsAny(got, `/\:<>"|?*`) || strings.HasSuffix(got, ".") || strings.HasSuffix(got, " ") {
			t.Errorf("zipEntryName(%d, %q) = %q : caractère ou fin de nom refusés à l'extraction", tc.position, tc.name, got)
		}
		if len(got) > maxZipName || !utf8.ValidString(got) {
			t.Errorf("zipEntryName(%d, %q) : %d octets, UTF-8 valide=%v", tc.position, tc.name, len(got), utf8.ValidString(got))
		}
		if !strings.HasPrefix(got, "1-") && !strings.HasPrefix(got, "2-") && !strings.HasPrefix(got, "5-") {
			t.Errorf("zipEntryName(%d, %q) = %q : le numéro du fichier doit venir en tête", tc.position, tc.name, got)
		}
	}
	// A shortened name keeps its extension, which says what to open it with.
	if got := zipEntryName(0, long+".pdf"); !strings.HasSuffix(got, ".pdf") {
		t.Errorf("nom raccourci sans son extension : %q", got)
	}
}
