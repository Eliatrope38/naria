package submission

import (
	"slices"
	"strings"
	"testing"
)

func TestHasDisposableAddress(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{"listed domain", "bot@yopmail.com", true},
		{"case does not matter", " Bot@YopMail.COM ", true},
		{"subdomain of a listed domain", "bot@mail.yopmail.com", true},
		{"ordinary provider", "ada@gmail.com", false},
		{"listed name inside another domain", "bot@yopmail.com.exemple.fr", false},
		{"listed name as a suffix of a label", "bot@notyopmail.com", false},
		{"address quoted in a message", "écrire à bot@yopmail.com", false},
		{"link to a listed domain", "https://yopmail.com/", false},
		{"local part that grows in lower case", strings.Repeat("Ⱥ", 120) + "@yopmail.com", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fields := []Field{{Name: "name", Value: "Visiteur"}, {Name: "email", Value: tt.value}}
			if got := HasDisposableAddress(fields); got != tt.want {
				t.Fatalf("HasDisposableAddress(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestDisposableListLoaded(t *testing.T) {
	if n := len(disposableDomains); n < 5000 {
		t.Fatalf("liste des domaines jetables : %d entrées, le fichier embarqué est-il tronqué ?", n)
	}
	// hostKeys yields only ASCII labels, and never a bare extension: an entry
	// outside that shape would never match.
	for d := range disposableDomains {
		labels := strings.Split(d, ".")
		if len(labels) < 2 || slices.ContainsFunc(labels, func(l string) bool { return !asciiLabel(l) }) {
			t.Fatalf("entrée qui ne peut jamais correspondre dans la liste des domaines jetables : %q", d)
		}
	}
}
