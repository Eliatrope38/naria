package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"

	"github.com/google/uuid"
)

// HashToken hashes a token. The token is a random 256-bit secret, so a fast hash is enough.
func HashToken(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

// GenerateResetToken: only the hash is stored; the plain token travels only in the emailed link.
func GenerateResetToken() (plain, hash string, err error) {
	return newToken("")
}

// APITokenPrefix makes the token recognizable to secret scanners. A header without it is rejected before any database query.
const APITokenPrefix = "naria_"

func GenerateAPIToken() (plain, hash string, err error) {
	return newToken(APITokenPrefix)
}

func newToken(prefix string) (plain, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	plain = prefix + base64.RawURLEncoding.EncodeToString(b)
	return plain, HashToken(plain), nil
}

// GenerateAccessKey produces the public key embedded in the site's HTML. It identifies the form without authenticating anyone.
func GenerateAccessKey() (string, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}
	return id.String(), nil
}
