package submission

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestNormalizeSender(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"address is lowercased", " Bot@Spam.TEST ", "bot@spam.test", false},
		{"domain", "Spam.Test", "spam.test", false},
		{"domain typed as a URL", "https://spam.test/contact", "spam.test", false},
		{"wildcard is refused: subdomains are already covered", "*.spam.test", "", true},
		{"display name is refused", "Bot <bot@spam.test>", "", true},
		{"address without a domain dot", "bot@localhost", "bot@localhost", false},
		{"single label domain is refused", "localhost", "", true},
		{"text is refused", "pas une adresse", "", true},
		{"empty is refused", "  ", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeSender(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NormalizeSender(%q) erreur = %v, erreur attendue : %v", tt.input, err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("NormalizeSender(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestSenderKeys(t *testing.T) {
	data := []Field{
		{Name: "name", Value: "Visiteur"},
		{Name: "email", Value: "Bot@Mail.Spam.Test"},
		{Name: "message", Value: "écrire à contact@exemple.fr"},
		{Name: "other", Value: "bot@mail.spam.test"},
	}
	got := SenderKeys(data)
	want := []string{"bot@mail.spam.test", "mail.spam.test", "spam.test"}
	if !slices.Equal(got, want) {
		t.Fatalf("SenderKeys = %q, want %q", got, want)
	}
	if keys := SenderKeys([]Field{{Name: "message", Value: "rien à voir"}}); len(keys) != 0 {
		t.Fatalf("SenderKeys sans adresse = %q", keys)
	}
}

// A visitor controls every field: a long domain must not multiply the keys.
func TestSenderKeysBornees(t *testing.T) {
	long := "x@" + strings.Repeat("a.", 200) + "zz"
	if keys := SenderKeys([]Field{{Name: "email", Value: long}}); len(keys) != 0 {
		t.Fatalf("adresse de plus de %d octets : %d clés", maxSenderLen, len(keys))
	}
	var data []Field
	for i := range 60 {
		data = append(data, Field{Name: "f" + strconv.Itoa(i), Value: fmt.Sprintf("u%d@%sexemple.zz", i, strings.Repeat("l.", 60))})
	}
	if keys := SenderKeys(data); len(keys) != maxSenderKeys {
		t.Fatalf("%d clés, %d attendues", len(keys), maxSenderKeys)
	}
}
