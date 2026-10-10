package crypto

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	c, err := New("une-clé-de-test-suffisamment-longue", PurposeSubmission)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !c.Enabled() {
		t.Fatal("le chiffreur devrait être actif avec une clé non vide")
	}

	for _, plain := range []string{"", "secret-totp", "valeur avec accents éàü et espaces", strings.Repeat("x", 4096)} {
		ct, err := c.Encrypt(plain)
		if err != nil {
			t.Fatalf("Encrypt(%q): %v", plain, err)
		}
		if !strings.HasPrefix(ct, prefix) {
			t.Fatalf("valeur chiffrée sans préfixe %s: %q", prefix, ct)
		}
		if plain != "" && strings.Contains(ct, plain) {
			t.Fatalf("le clair apparaît dans la valeur chiffrée: %q", ct)
		}
		got, err := c.Decrypt(ct)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		if got != plain {
			t.Fatalf("round-trip: got %q, want %q", got, plain)
		}
	}
}

// A fixed nonce would reveal identical submissions.
func TestEncryptIsRandomized(t *testing.T) {
	c, _ := New("clé", PurposeSubmission)
	a, _ := c.Encrypt("même contenu")
	b, _ := c.Encrypt("même contenu")
	if a == b {
		t.Fatal("deux chiffrements identiques : le nonce n'est pas aléatoire")
	}
}

func TestPurposeAndSecretSeparation(t *testing.T) {
	sub, _ := New("clé", PurposeSubmission)
	totp, _ := New("clé", PurposeTOTP)
	other, _ := New("autre-clé", PurposeSubmission)

	ct, err := sub.Encrypt("contenu")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := totp.Decrypt(ct); err == nil {
		t.Fatal("déchiffrement réussi avec la clé d'un autre usage")
	}
	if _, err := other.Decrypt(ct); err == nil {
		t.Fatal("déchiffrement réussi avec un autre secret")
	}
}

func TestTamperedCiphertextIsRejected(t *testing.T) {
	c, _ := New("clé", PurposeSubmission)
	ct, _ := c.Encrypt("contenu")
	b := []byte(ct)
	i := len(b) - 3
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	if _, err := c.Decrypt(string(b)); err == nil {
		t.Fatal("une valeur altérée a été déchiffrée sans erreur")
	}
}

// An encrypted value read without a key must fail, not be returned as plaintext.
func TestNilCipher(t *testing.T) {
	c, err := New("", PurposeSubmission)
	if err != nil || c != nil {
		t.Fatalf("New(\"\") = %v, %v ; attendu nil, nil", c, err)
	}
	if c.Enabled() {
		t.Fatal("un chiffreur nil ne doit pas être actif")
	}
	got, err := c.Encrypt("clair")
	if err != nil || got != "clair" {
		t.Fatalf("Encrypt sans clé = %q, %v", got, err)
	}
	if got, err := c.Decrypt("clair"); err != nil || got != "clair" {
		t.Fatalf("Decrypt d'un clair sans clé = %q, %v", got, err)
	}
	if _, err := c.Decrypt(prefix + "AAAA"); err == nil {
		t.Fatal("Decrypt d'une valeur chiffrée sans clé aurait dû échouer")
	}
}

func TestEncryptBytes(t *testing.T) {
	c, _ := New("clé", PurposeSubmission)
	for _, plain := range [][]byte{{}, []byte("%PDF-1.7 contenu"), {0x00, 0xff, 0x80, '\n', 0x00}, bytes.Repeat([]byte{0xab}, 1<<16)} {
		ct, err := c.EncryptBytes(plain)
		if err != nil {
			t.Fatalf("EncryptBytes: %v", err)
		}
		if !bytes.HasPrefix(ct, []byte(prefix)) {
			t.Fatalf("contenu chiffré sans préfixe %s", prefix)
		}
		if len(plain) > 0 && bytes.Contains(ct, plain) {
			t.Fatal("le clair apparaît dans le contenu chiffré")
		}
		got, err := c.DecryptBytes(ct)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("round-trip: %d octet(s) relus, err %v ; %d attendus", len(got), err, len(plain))
		}
		ct[len(ct)-1] ^= 1
		if _, err := c.DecryptBytes(ct); err == nil {
			t.Fatal("un contenu altéré a été déchiffré sans erreur")
		}
	}
	if _, err := c.DecryptBytes([]byte(prefix + "court")); err == nil {
		t.Fatal("un contenu chiffré tronqué a été accepté")
	}
}

func TestNilCipherBytes(t *testing.T) {
	var c *Cipher
	plain := []byte{0x00, 0x01, 0x02}
	if got, err := c.EncryptBytes(plain); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("EncryptBytes sans clé = %v, %v", got, err)
	}
	if got, err := c.DecryptBytes(plain); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("DecryptBytes d'un clair sans clé = %v, %v", got, err)
	}
	keyed, _ := New("clé", PurposeSubmission)
	ct, _ := keyed.EncryptBytes(plain)
	if _, err := c.DecryptBytes(ct); err == nil {
		t.Fatal("DecryptBytes d'un contenu chiffré sans clé aurait dû échouer")
	}
}

// The derivation is a contract: the vectors come from an HKDF-SHA256 computation outside this package.
func TestKeyVecteursFixes(t *testing.T) {
	for _, tc := range []struct{ purpose, hex string }{
		{PurposeSubmission, "bcd3451d22cd1e3d3ccf524ccb931b33356ca8067248c2025d30f293cf7ee3e3"},
		{PurposeCaptcha, "7ffbbd31193fb9b0b16a85989ca9755b5f1d45257fee8a040a098c557d40c341"},
	} {
		got, err := Key("secret-de-test", tc.purpose)
		if err != nil {
			t.Fatalf("Key(%s): %v", tc.purpose, err)
		}
		if hex.EncodeToString(got) != tc.hex {
			t.Errorf("Key(%s) = %x, attendu %s", tc.purpose, got, tc.hex)
		}
	}
	if _, err := Key("", PurposeCaptcha); err == nil {
		t.Error("un secret vide doit être refusé")
	}
}

// Values actually stored: a change to the derivation would make them unreadable.
func TestDechiffreLesValeursDejaConservees(t *testing.T) {
	c, err := New("secret-de-test", PurposeSubmission)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const stored = "enc1:485lHIbyzf2QUiFrLEY+X7Wkn92q4qzBuhqtpHBcs4LT6WuPx67df2V0MfrZYV9CSIQGpW5WNPIgP4s/vEBf4C4="
	if got, err := c.Decrypt(stored); err != nil || got != "contenu conservé avant le changement" {
		t.Errorf("Decrypt = %q, %v", got, err)
	}
	file, _ := hex.DecodeString("656e63313a00cb9a41f74d78dfb79e877b5b8a03130c6e4b1f92373518ddfbc68c97028943d6f8309a1bcc3084d4")
	if got, err := c.DecryptBytes(file); err != nil || string(got) != "pièce jointe" {
		t.Errorf("DecryptBytes = %q, %v", got, err)
	}
}
