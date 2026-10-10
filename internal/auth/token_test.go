package auth

import (
	"regexp"
	"testing"
)

func TestGenerateAPIToken(t *testing.T) {
	format := regexp.MustCompile(`^naria_[A-Za-z0-9_-]{43}$`)
	plain, hash, err := GenerateAPIToken()
	if err != nil {
		t.Fatalf("GenerateAPIToken: %v", err)
	}
	if !format.MatchString(plain) {
		t.Errorf("jeton %q : préfixe naria_ puis 32 octets en base64url attendus", plain)
	}
	if hash != HashToken(plain) || len(hash) != 64 {
		t.Errorf("l'empreinte doit être le SHA-256 du jeton entier, préfixe compris")
	}
	if other, _, _ := GenerateAPIToken(); other == plain {
		t.Errorf("deux jetons identiques")
	}
}

// The password reset link sent by email keeps its format: no prefix.
func TestGenerateResetToken(t *testing.T) {
	plain, hash, err := GenerateResetToken()
	if err != nil {
		t.Fatalf("GenerateResetToken: %v", err)
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`).MatchString(plain) || hash != HashToken(plain) {
		t.Errorf("jeton de réinitialisation %q inattendu", plain)
	}
}
