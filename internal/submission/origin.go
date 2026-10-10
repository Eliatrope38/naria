package submission

import (
	"fmt"
	"net/url"
	"strings"
)

const MaxDomains = 20

// NormalizeDomains turns free-form input into a deduplicated list of normalized hosts. An entry can be
// a full URL (only the host is kept). The prefix "*." covers subdomains.
func NormalizeDomains(input string) ([]string, error) {
	tokens := strings.FieldsFunc(input, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\r' || r == '\t'
	})
	seen := map[string]bool{}
	out := []string{}
	for _, tok := range tokens {
		d, ok := normalizeDomain(tok)
		if !ok {
			return nil, fmt.Errorf("%q", tok)
		}
		if seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	if len(out) > MaxDomains {
		return nil, fmt.Errorf("%d > %d", len(out), MaxDomains)
	}
	return out, nil
}

func normalizeDomain(tok string) (string, bool) {
	d := strings.ToLower(strings.TrimSpace(tok))
	if i := strings.Index(d, "://"); i >= 0 {
		d = d[i+3:]
	}
	if i := strings.IndexAny(d, "/?#"); i >= 0 {
		d = d[:i]
	}
	wildcard := strings.HasPrefix(d, "*.")
	d = strings.TrimPrefix(d, "*.")
	if i := strings.LastIndexByte(d, ':'); i >= 0 {
		d = d[:i] // port: the origin is compared on the host only
	}
	d = strings.Trim(d, ".")
	if d == "" || len(d) > 253 {
		return "", false
	}
	for _, r := range d {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '.' && r != '-' {
			return "", false
		}
	}
	if d != "localhost" && !strings.Contains(d, ".") {
		return "", false
	}
	if wildcard {
		return "*." + d, true
	}
	return d, true
}

// HostAllowed: an empty list imposes no restriction. "example.fr" also covers www; "*.example.fr" covers
// all subdomains.
func HostAllowed(domains []string, host string) bool {
	if len(domains) == 0 {
		return true
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return false
	}
	for _, d := range domains {
		if suffix, ok := strings.CutPrefix(d, "*"); ok {
			if strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
				return true
			}
			continue
		}
		if host == d || host == "www."+d {
			return true
		}
	}
	return false
}

// OriginAllowed enforces the domain restriction from the Origin header, falling back to Referer.
// A browser always sends Origin on a cross-origin POST: its absence means a client outside a browser,
// which can forge the header anyway, so it is accepted. An opaque origin ("null")
// is refused.
func OriginAllowed(domains []string, origin, referer string) bool {
	if len(domains) == 0 {
		return true
	}
	src := origin
	if src == "" {
		src = referer
	}
	if src == "" {
		return true
	}
	return URLAllowed(domains, src)
}

func URLAllowed(domains []string, raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return false
	}
	return HostAllowed(domains, u.Hostname())
}
