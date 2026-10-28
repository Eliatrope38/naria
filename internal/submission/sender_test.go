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
		{"wildcard is dropped: subdomains are already covered", "*.spam.test", "spam.test", false},
		{"display name is refused", "Bot <bot@spam.test>", "", true},
		{"address without a domain dot", "bot@localhost", "bot@localhost", false},
		{"extension", "Online", ".online", false},
		{"extension with its dot", ".online", ".online", false},
		{"extension as a wildcard", "*.online", ".online", false},
		{"idn extension", ".xn--p1ai", ".xn--p1ai", false},
		{"numeric label is refused", "123", "", true},
		{"extension typed as a URL is refused", "https://online", "", true},
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

func TestBlockKeys(t *testing.T) {
	data := []Field{
		{Name: "name", Value: "Visiteur"},
		{Name: "email", Value: "Bot@Mail.Spam.Test"},
		{Name: "message", Value: "écrire à contact@exemple.fr"},
		{Name: "other", Value: "bot@mail.spam.test"},
	}
	got := BlockKeys(data)
	// ".test" is reserved, not an extension: it has no key.
	want := []string{"bot@mail.spam.test", "mail.spam.test", "spam.test"}
	if !slices.Equal(got, want) {
		t.Fatalf("BlockKeys = %q, want %q", got, want)
	}
	if keys := BlockKeys([]Field{{Name: "message", Value: "rien à voir"}}); len(keys) != 0 {
		t.Fatalf("BlockKeys sans adresse = %q", keys)
	}
}

// A visitor controls every field: a long domain must not multiply the keys.
func TestBlockKeysBornees(t *testing.T) {
	long := "x@" + strings.Repeat("a.", 200) + "zz"
	if keys := BlockKeys([]Field{{Name: "email", Value: long}}); len(keys) != 0 {
		t.Fatalf("adresse de plus de %d octets : %d clés", maxSenderLen, len(keys))
	}
	var data []Field
	for i := range 60 {
		data = append(data, Field{Name: "f" + strconv.Itoa(i), Value: fmt.Sprintf("u@%sexemple%d.zz", strings.Repeat("l.", 60), i)})
	}
	if keys := BlockKeys(data); len(keys) != maxBlockKeys {
		t.Fatalf("%d clés, %d attendues", len(keys), maxBlockKeys)
	}
}
