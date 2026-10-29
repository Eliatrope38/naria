package submission

import (
	_ "embed"
	"strings"
)

// disposableList is the community list of disposable e-mail domains
// (https://github.com/disposable-email-domains/disposable-email-domains, CC0).
// It ships with the binary so that checking an address calls no outside service.
//
//go:embed disposable-domains.txt
var disposableList string

var disposableDomains = func() map[string]bool {
	m := map[string]bool{}
	for _, line := range strings.Split(disposableList, "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			m[strings.ToLower(line)] = true
		}
	}
	return m
}()

// HasDisposableAddress reports whether a field holds an address at a disposable
// domain or one of its subdomains. As with BlockKeys, only a field whose whole
// value is an address counts, and links are not looked at: a message may point to
// such a service without coming from it.
func HasDisposableAddress(fields []Field) bool {
	for _, f := range fields {
		v, ok := fieldAddress(f.Value)
		if !ok {
			continue
		}
		_, domain, _ := strings.Cut(v, "@")
		found := false
		hostKeys(normalizeHost(domain), func(k string) bool {
			found = disposableDomains[k]
			return !found
		})
		if found {
			return true
		}
	}
	return false
}
