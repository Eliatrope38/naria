package submission

import (
	"errors"
	"net/mail"
	"strings"
)

var errSenderInvalid = errors.New("expected a bare e-mail address, a domain name or an extension")

// maxSenderLen is the longest address the SMTP path allows (RFC 5321). A longer
// value is not an address, and its labels would multiply the keys below.
const maxSenderLen = 254

// maxBlockKeys bounds the keys of one submission. A visitor controls every field,
// so the cost of matching must not depend on what they send. Past the bound, the
// links that follow are not compared: with maxSuffixLabels, a message needs some
// forty distinct hosts before a blocked one to slip through.
const maxBlockKeys = 256

// NormalizeSender turns an address, a domain or an extension typed by the site
// owner into the value stored in the blocklist. An address must have no display
// name. A domain is kept without its subdomain wildcard: blocking a domain
// already covers its subdomains (see BlockKeys). An extension, typed "online",
// ".online" or "*.online", is stored with its leading dot.
func NormalizeSender(input string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(input))
	if strings.Contains(v, "@") {
		addr, err := mail.ParseAddress(v)
		if err != nil || addr.Name != "" || addr.Address != v {
			return "", errSenderInvalid
		}
		return v, nil
	}
	// Kept apart from normalizeDomain, which also reads a site's allowed origins:
	// an origin must never be a whole extension.
	if tld := strings.TrimPrefix(strings.TrimPrefix(v, "*"), "."); tld != "" && asciiLabel(tld) && isTLD(tld) {
		return "." + tld, nil
	}
	d, ok := normalizeDomain(v)
	d = strings.TrimPrefix(d, "*.")
	if !ok || !strings.Contains(d, ".") {
		return "", errSenderInvalid
	}
	return d, nil
}

// BlockKeys returns the blocklist values a submission matches. First each e-mail
// address found in a field, with its domain, the parent domains and the extension:
// a blocked "example.fr" thus also covers "mail.example.fr". Fields are matched on
// their whole value, so an address quoted in a message is not taken for its sender.
// Then the same keys for the host of each link found in a name or a value,
// bare domain names included.
func BlockKeys(fields []Field) []string {
	var keys []string
	seen := map[string]bool{}
	add := func(k string) bool {
		if len(keys) >= maxBlockKeys {
			return false
		}
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
		return true
	}
	for _, f := range fields {
		v, ok := fieldAddress(f.Value)
		if !ok {
			continue
		}
		add(v)
		_, domain, _ := strings.Cut(v, "@")
		hostKeys(normalizeHost(domain), add)
	}
	for _, f := range fields {
		for _, text := range [2]string{f.Name, f.Value} {
			for _, l := range scanLinks(text) {
				if len(keys) >= maxBlockKeys {
					return keys
				}
				hostKeys(l.host, add)
			}
		}
	}
	return keys
}

// fieldAddress returns a field's value, lower-cased, when the whole value is a bare
// e-mail address. The length is measured before lower-casing, as ValidEmail does:
// some letters grow in lower case, and an address accepted as the reply address
// must not escape the check.
func fieldAddress(value string) (string, bool) {
	v := strings.TrimSpace(value)
	if !strings.Contains(v, "@") || len(v) > maxSenderLen {
		return "", false
	}
	v = strings.ToLower(v)
	addr, err := mail.ParseAddress(v)
	if err != nil || addr.Name != "" || addr.Address != v {
		return "", false
	}
	return v, true
}
