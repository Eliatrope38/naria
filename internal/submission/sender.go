package submission

import (
	"errors"
	"net/mail"
	"strings"
)

var errSenderInvalid = errors.New("expected a bare e-mail address or a domain name")

// maxSenderLen is the longest address the SMTP path allows (RFC 5321). A longer
// value is not an address, and its labels would multiply the keys below.
const maxSenderLen = 254

// maxSenderKeys bounds the keys of one submission. A visitor controls every field,
// so the cost of matching must not depend on what they send.
const maxSenderKeys = 64

// NormalizeSender turns an address or a domain typed by the site owner into the
// value stored in the blocklist. An address must have no display name, and a
// domain is kept without its subdomain wildcard: blocking a domain already covers
// its subdomains (see SenderKeys). A single label such as "localhost" is refused,
// since no submission would ever match it.
func NormalizeSender(input string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(input))
	if strings.Contains(v, "@") {
		addr, err := mail.ParseAddress(v)
		if err != nil || addr.Name != "" || addr.Address != v {
			return "", errSenderInvalid
		}
		return v, nil
	}
	d, ok := normalizeDomain(v)
	if !ok || strings.HasPrefix(d, "*.") || !strings.Contains(d, ".") {
		return "", errSenderInvalid
	}
	return d, nil
}

// SenderKeys returns the blocklist values a submission matches: each e-mail address
// found in a field, then its domain and the parent domains down to the second
// level. A blocked "example.fr" thus also covers "mail.example.fr". Fields are
// matched on their whole value, so a sender named in a free-text message is not
// taken for one.
func SenderKeys(data []Field) []string {
	var keys []string
	seen := map[string]bool{}
	add := func(k string) {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	for _, f := range data {
		v := strings.ToLower(strings.TrimSpace(f.Value))
		if !strings.Contains(v, "@") || len(v) > maxSenderLen {
			continue
		}
		addr, err := mail.ParseAddress(v)
		if err != nil || addr.Name != "" || addr.Address != v {
			continue
		}
		add(v)
		_, domain, _ := strings.Cut(v, "@")
		for d := domain; strings.Contains(d, "."); {
			add(d)
			_, d, _ = strings.Cut(d, ".")
		}
		if len(keys) >= maxSenderKeys {
			return keys[:maxSenderKeys]
		}
	}
	return keys
}
