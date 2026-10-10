package web

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

// Each xff value is one header line.
func resolve(t *testing.T, trusted []netip.Prefix, remoteAddr string, headers map[string]string, xff ...string) (ip, key string) {
	t.Helper()
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { ip, key = ClientIP(r), RateLimitKey(r) })
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remoteAddr
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	for _, line := range xff {
		req.Header.Add("X-Forwarded-For", line)
	}
	TrustedRealIP(trusted)(next).ServeHTTP(httptest.NewRecorder(), req)
	return ip, key
}

func mustPrefixes(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	var out []netip.Prefix
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			t.Fatalf("CIDR %q: %v", c, err)
		}
		out = append(out, p)
	}
	return out
}

func TestTrustedRealIP(t *testing.T) {
	const proxy = "10.0.0.2:4567"
	for _, tc := range []struct {
		name    string
		trusted []string
		remote  string
		xff     []string
		want    string
	}{
		{"sans proxy déclaré, l'en-tête est ignoré", nil, "10.1.2.3:4567", []string{"203.0.113.9"}, "10.1.2.3"},
		{"pair non déclaré, l'en-tête est ignoré", []string{"10.0.0.2/32"}, "198.51.100.1:4567", []string{"203.0.113.9"}, "198.51.100.1"},
		{"voisin du proxy sur le même réseau, non déclaré", []string{"10.0.0.2/32"}, "10.0.0.1:4567", []string{"203.0.113.9"}, "10.0.0.1"},
		{"proxy déclaré", []string{"10.0.0.2/32"}, proxy, []string{"203.0.113.9"}, "203.0.113.9"},
		{"proxy déclaré sans en-tête", []string{"10.0.0.2/32"}, proxy, nil, "10.0.0.2"},
		{"en-tête forgé que le proxy prolonge", []string{"10.0.0.2/32"}, proxy, []string{"6.6.6.6, 203.0.113.9"}, "203.0.113.9"},
		{"adresse du proxy forgée à gauche", []string{"10.0.0.2/32"}, proxy, []string{"6.6.6.6, 10.0.0.2, 203.0.113.9"}, "203.0.113.9"},
		{"ligne forgée, puis ligne du proxy", []string{"10.0.0.2/32"}, proxy, []string{"6.6.6.6", "203.0.113.9"}, "203.0.113.9"},
		{"deux proxys déclarés en chaîne", []string{"10.0.0.0/24"}, proxy, []string{"6.6.6.6, 203.0.113.9, 10.0.0.7"}, "203.0.113.9"},
		{"deux proxys déclarés, une ligne chacun", []string{"10.0.0.0/24"}, proxy, []string{"6.6.6.6, 203.0.113.9", "10.0.0.7"}, "203.0.113.9"},
		{"tous déclarés : le plus éloigné", []string{"10.0.0.0/24"}, proxy, []string{"10.0.0.9, 10.0.0.7"}, "10.0.0.9"},
		{"valeur illisible écrite par le proxy", []string{"10.0.0.2/32"}, proxy, []string{"203.0.113.9, unknown"}, "10.0.0.2"},
		{"valeur illisible après un proxy déclaré", []string{"10.0.0.0/24"}, proxy, []string{"203.0.113.9, unknown, 10.0.0.7"}, "10.0.0.7"},
		{"élément vide", []string{"10.0.0.2/32"}, proxy, []string{"203.0.113.9,"}, "10.0.0.2"},
		{"ligne vide", []string{"10.0.0.2/32"}, proxy, []string{"203.0.113.9", ""}, "10.0.0.2"},
		{"élément avec port", []string{"10.0.0.2/32"}, proxy, []string{"6.6.6.6, 203.0.113.9:51234"}, "203.0.113.9"},
		{"client IPv6", []string{"10.0.0.2/32"}, proxy, []string{"6.6.6.6, 2001:db8:1:2:3:4:5:6"}, "2001:db8:1:2:3:4:5:6"},
		{"client IPv6 avec port", []string{"10.0.0.2/32"}, proxy, []string{"[2001:db8::1]:51234"}, "2001:db8::1"},
		{"proxy IPv6", []string{"fd00::/64"}, "[fd00::2]:4567", []string{"203.0.113.9"}, "203.0.113.9"},
		{"proxy en IPv4 encapsulée", []string{"10.0.0.2/32"}, "[::ffff:10.0.0.2]:4567", []string{"::ffff:203.0.113.9"}, "203.0.113.9"},
		{"connexion directe en IPv6", nil, "[2001:db8::1]:4567", []string{"203.0.113.9"}, "2001:db8::1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, _ := resolve(t, mustPrefixes(t, tc.trusted...), tc.remote, nil, tc.xff...); got != tc.want {
				t.Errorf("adresse retenue %q, attendu %q", got, tc.want)
			}
		})
	}
}

// Caddy forwards X-Real-IP and True-Client-IP as the client sent them: they must not change the result.
func TestTrustedRealIPIgnoreLesAutresEnTetes(t *testing.T) {
	forged := map[string]string{"X-Real-Ip": "6.6.6.6", "True-Client-Ip": "7.7.7.7", "Forwarded": "for=8.8.8.8"}
	if got, _ := resolve(t, nil, "198.51.100.1:4567", forged); got != "198.51.100.1" {
		t.Errorf("sans proxy déclaré : adresse retenue %q", got)
	}
	trusted := mustPrefixes(t, "10.0.0.2/32")
	if got, _ := resolve(t, trusted, "10.0.0.2:4567", forged, "203.0.113.9"); got != "203.0.113.9" {
		t.Errorf("derrière un proxy déclaré : adresse retenue %q", got)
	}
	if got, _ := resolve(t, trusted, "10.0.0.2:4567", forged); got != "10.0.0.2" {
		t.Errorf("derrière un proxy déclaré, sans X-Forwarded-For : adresse retenue %q", got)
	}
}

// Whatever the client writes before the address added by the proxy never counts.
func TestTrustedRealIPPrefixeForgeSansEffet(t *testing.T) {
	trusted := mustPrefixes(t, "10.0.0.0/24")
	for i, forged := range []string{
		"6.6.6.6", "10.0.0.2", "10.0.0.2, 10.0.0.7", "unknown", "", ",", " , ,", "6.6.6.6:80", "::1", "[::1]:80",
		"2001:db8::1%eth0", "::ffff:10.0.0.2", "203.0.113.9", "6.6.6.6,10.0.0.2,10.0.0.7,10.0.0.9",
		"6.6.6.6, " + strings.Repeat("10.0.0.7, ", 100_000) + "10.0.0.2",
	} {
		for _, lines := range [][]string{
			{forged + ", 203.0.113.9"},
			{forged, "203.0.113.9"},
			{forged + ", 203.0.113.9, 10.0.0.7"},
			{forged, "203.0.113.9", "10.0.0.7"},
		} {
			if got, _ := resolve(t, trusted, "10.0.0.2:4567", nil, lines...); got != "203.0.113.9" {
				t.Errorf("préfixe %d : adresse retenue %q", i, got)
			}
		}
	}
}

func TestRateLimitKey(t *testing.T) {
	for _, tc := range []struct{ remote, want string }{
		{"203.0.113.9:4567", "203.0.113.9"},
		{"203.0.113.9", "203.0.113.9"},
		{"[::ffff:203.0.113.9]:4567", "203.0.113.9"},
		{"[2001:db8:1:2:3:4:5:6]:4567", "2001:db8:1:2::/64"},
		{"[2001:db8:1:2::1]:4567", "2001:db8:1:2::/64"},
		{"2001:db8:1:2:ffff:ffff:ffff:ffff", "2001:db8:1:2::/64"},
		{"[2001:db8:1:3::1]:4567", "2001:db8:1:3::/64"},
	} {
		if _, got := resolve(t, nil, tc.remote, nil); got != tc.want {
			t.Errorf("clé de %s : %q, attendu %q", tc.remote, got, tc.want)
		}
	}
	// Behind a declared proxy, the key follows the address found.
	trusted := mustPrefixes(t, "10.0.0.2/32")
	if ip, key := resolve(t, trusted, "10.0.0.2:4567", nil, "2001:db8:1:2:3:4:5:6"); ip != "2001:db8:1:2:3:4:5:6" || key != "2001:db8:1:2::/64" {
		t.Errorf("derrière un proxy : adresse %q, clé %q", ip, key)
	}
}
