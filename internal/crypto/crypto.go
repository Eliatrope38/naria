// Package crypto encrypts sensitive data at rest (AES-256-GCM).
package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"strings"

	"golang.org/x/crypto/hkdf"
)

// prefix marks an encrypted value. Without it, the value is read as plaintext (instance without a key).
const prefix = "enc1:"

// HKDF contexts: one APP_SECRET_KEY yields a distinct key per purpose. These strings are stable,
// since changing them makes existing data unreadable.
const (
	PurposeTOTP       = "naria/totp-secret/v1"
	PurposeSubmission = "naria/submission/v1"
	PurposeAttachment = "naria/attachment/v1"
	PurposeWebhook    = "naria/webhook-url/v1"
	PurposeBotToken   = "naria/telegram-bot-token/v1"
	// Nothing is stored under this key: changing it only invalidates challenges in progress.
	PurposeCaptcha = "naria/captcha/v1"
)

// Cipher encrypts and decrypts with a key derived from a secret. A nil Cipher passes data through unchanged.
type Cipher struct {
	gcm cipher.AEAD
}

// Key derives the 256-bit key for the given purpose. An empty secret is refused, since the key would be the same for everyone.
func Key(secret, purpose string) ([]byte, error) {
	if secret == "" {
		return nil, errors.New("dérivation de clé sans secret")
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, []byte(secret), nil, []byte(purpose)), key); err != nil {
		return nil, err
	}
	return key, nil
}

// New returns nil if the secret is empty, which disables encryption.
func New(secret, purpose string) (*Cipher, error) {
	if secret == "" {
		return nil, nil
	}
	key, err := Key(secret, purpose)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Cipher{gcm: gcm}, nil
}

func (c *Cipher) Enabled() bool { return c != nil }

func (c *Cipher) Encrypt(plain string) (string, error) {
	if c == nil {
		return plain, nil
	}
	nonce := make([]byte, c.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := c.gcm.Seal(nonce, nonce, []byte(plain), nil)
	return prefix + base64.StdEncoding.EncodeToString(ct), nil
}

// A value without the prefix is plaintext written without a key, so it is returned as is.
func (c *Cipher) Decrypt(s string) (string, error) {
	if !strings.HasPrefix(s, prefix) {
		return s, nil
	}
	if c == nil {
		return "", errors.New("valeur chiffrée mais aucune clé (APP_SECRET_KEY)")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, prefix))
	if err != nil {
		return "", err
	}
	ns := c.gcm.NonceSize()
	if len(raw) < ns {
		return "", errors.New("donnée chiffrée invalide")
	}
	pt, err := c.gcm.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// EncryptBytes uses the Encrypt format without base64: the content is stored as-is in a BYTEA column.
func (c *Cipher) EncryptBytes(plain []byte) ([]byte, error) {
	if c == nil {
		return plain, nil
	}
	ns := c.gcm.NonceSize()
	out := make([]byte, len(prefix)+ns, len(prefix)+ns+len(plain)+c.gcm.Overhead())
	copy(out, prefix)
	nonce := out[len(prefix):]
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return c.gcm.Seal(out, nonce, plain, nil), nil
}

// A plaintext file starting with the prefix would be taken for encrypted. This only happens on an instance without a key.
func (c *Cipher) DecryptBytes(b []byte) ([]byte, error) {
	raw, ok := bytes.CutPrefix(b, []byte(prefix))
	if !ok {
		return b, nil
	}
	if c == nil {
		return nil, errors.New("valeur chiffrée mais aucune clé (APP_SECRET_KEY)")
	}
	ns := c.gcm.NonceSize()
	if len(raw) < ns {
		return nil, errors.New("donnée chiffrée invalide")
	}
	return c.gcm.Open(nil, raw[:ns], raw[ns:], nil)
}
