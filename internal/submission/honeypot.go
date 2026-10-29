package submission

import (
	"crypto/rand"
	"errors"
	"regexp"
	"strings"
)

// honeypotNames look like fields a form could ask for, yet a contact form rarely does:
// a real field under the trap's name would have its submissions dropped. None of them is
// one that browsers or password managers autofill, for the same reason.
var honeypotNames = []string{"fax", "fax_number", "referral_code", "promo_code", "coupon_code"}

// NewHoneypotName picks the honeypot field of a new form.
// The modulo bias does not matter: the name is published in the page, it is not a secret.
func NewHoneypotName() string {
	var b [1]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never returns an error since Go 1.24
	return honeypotNames[int(b[0])%len(honeypotNames)]
}

var honeypotPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,39}$`)

// Names a honeypot cannot take: service fields, whose value would be lost, and the
// fields of the integration snippet, which would hold the same name twice. They are
// compared without case, which refuses a little more than matching requires.
var reservedNames = []string{
	fieldAccessKey, fieldRedirect, fieldSubject, fieldReplyTo, fieldBotcheck, fieldCaptcha,
	"cf-turnstile-response", "g-recaptcha-response", "h-captcha-response",
	"name", "email", "message", "attachment",
}

var (
	ErrHoneypotFormat   = errors.New("honeypot field: invalid name")
	ErrHoneypotReserved = errors.New("honeypot field: reserved name")
)

// HoneypotNameError reports why name cannot be a honeypot field: ErrHoneypotFormat,
// ErrHoneypotReserved, or nil.
func HoneypotNameError(name string) error {
	if !honeypotPattern.MatchString(name) {
		return ErrHoneypotFormat
	}
	for _, r := range reservedNames {
		if strings.EqualFold(name, r) {
			return ErrHoneypotReserved
		}
	}
	return nil
}

// TakeHoneypot removes the fields named name from data, in place, and reports whether
// one of them was filled. With an empty name, data is returned unchanged.
func TakeHoneypot(data []Field, name string) ([]Field, bool) {
	if name == "" {
		return data, false
	}
	filled := false
	out := data[:0]
	for _, f := range data {
		if f.Name != name {
			out = append(out, f)
		} else if trapFilled(f.Value) {
			filled = true
		}
	}
	return out, filled
}

// trapFilled follows Web3Forms, where a checkbox trap may post "false" or "0".
func trapFilled(v string) bool {
	return v != "" && v != "false" && v != "0"
}
