package main

// A client's address comes from the connection or a declared proxy, never from a forged header.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"gitlab.com/detag_inno/naria/internal/handlers"
	"gitlab.com/detag_inno/naria/internal/web"
)

// trustLoopback declares the test client as a proxy: what it writes in X-Forwarded-For
// then stands for what a reverse proxy would have written.
func trustLoopback(a *handlers.App) {
	a.Cfg.TrustedProxyCIDRs = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}
}

// addressModes covers both deployments. In the second, real is the visitor's address,
// which the proxy appends to X-Forwarded-For.
var addressModes = []struct {
	name    string
	declare func(*handlers.App)
	real    string
}{
	{name: "sans proxy déclaré", declare: func(*handlers.App) {}},
	{name: "derrière un proxy déclaré", declare: trustLoopback, real: "203.0.113.7"},
}

// forgeries returns nine header sets from one client that announces a different address
// each time, cycling through the three headers. Behind a proxy, X-Forwarded-For ends with
// the address the proxy saw.
func forgeries(real string) []http.Header {
	var out []http.Header
	for range 3 {
		for _, name := range []string{"X-Forwarded-For", "X-Real-Ip", "True-Client-Ip"} {
			forged := fmt.Sprintf("198.51.100.%d", len(out)+1)
			h := http.Header{}
			switch {
			case real == "":
				h.Set(name, forged)
			case name == "X-Forwarded-For":
				h.Set(name, forged+", "+real)
			default:
				h.Set(name, forged)
				h.Set("X-Forwarded-For", real)
			}
			out = append(out, h)
		}
	}
	return out
}

// checkForgedAddresses exercises a limit of two per address through send: passed is the
// status of a send the limit lets through. A client that changes its announced address on
// each send gets no extra one. Behind a proxy, another visitor keeps its own counter, and
// clients within the same IPv6 /64 share one.
func checkForgedAddresses(t *testing.T, real string, passed int, send func(http.Header) int) {
	t.Helper()
	for i, h := range forgeries(real) {
		want := passed
		if i >= 2 {
			want = http.StatusTooManyRequests
		}
		if got := send(h); got != want {
			t.Errorf("envoi %d avec %v : statut %d (%d attendu)", i+1, h, got, want)
		}
	}
	if real == "" {
		return
	}
	for _, tc := range []struct {
		forwarded string
		want      int
	}{
		// An address already announced by the first client, then another one.
		{"198.51.100.1, 203.0.113.8", passed},
		{"2001:db8:1:2::1", passed},
		{"2001:db8:1:2::2", passed},
		{"2001:db8:1:2:ffff:ffff:ffff:3", http.StatusTooManyRequests},
		{"2001:db8:1:3::1", passed},
	} {
		if got := send(http.Header{"X-Forwarded-For": {tc.forwarded}}); got != tc.want {
			t.Errorf("envoi annoncé par le proxy comme %q : statut %d (%d attendu)", tc.forwarded, got, tc.want)
		}
	}
}

func TestAdresseForgeeLimiteDesSoumissions(t *testing.T) {
	for _, mode := range addressModes {
		t.Run(mode.name, func(t *testing.T) {
			e := setup(t, mode.declare, func(a *handlers.App) { a.SubmitLimiter = web.NewRateLimiter(2, time.Minute) })
			checkForgedAddresses(t, mode.real, http.StatusOK, func(h http.Header) int {
				resp, _ := submit(t, e.url, submitOpts{path: "/f/" + e.fx.formB.AccessKey, body: "message=x", header: h})
				return resp.StatusCode
			})
		})
	}
}

func TestAdresseForgeeLimiteDeLaConnexion(t *testing.T) {
	for _, mode := range addressModes {
		t.Run(mode.name, func(t *testing.T) {
			e := setup(t, mode.declare, func(a *handlers.App) { a.Limiter = web.NewRateLimiter(2, time.Minute) })
			c := newClient()
			token := csrfToken(t, c, e.url+"/login")
			checkForgedAddresses(t, mode.real, http.StatusUnauthorized, func(h http.Header) int {
				vals := url.Values{"email": {e.fx.memberA.Email}, "password": {"mauvais"}, "csrf_token": {token}}
				req, err := http.NewRequest(http.MethodPost, e.url+"/login", strings.NewReader(vals.Encode()))
				if err != nil {
					t.Fatalf("requête: %v", err)
				}
				req.Header = h.Clone()
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.Header.Set("Sec-Fetch-Site", "same-origin")
				resp, err := c.Do(req)
				if err != nil {
					t.Fatalf("POST /login: %v", err)
				}
				resp.Body.Close()
				return resp.StatusCode
			})

			// The audit log keeps the address that was retained, not the announced one: the first
			// two failures are those of the client that kept changing it.
			want := mode.real
			if want == "" {
				u, err := url.Parse(e.url)
				if err != nil {
					t.Fatalf("adresse du serveur: %v", err)
				}
				if want, _, err = net.SplitHostPort(u.Host); err != nil {
					t.Fatalf("adresse du serveur: %v", err)
				}
			}
			rows, err := e.pool.Query(context.Background(),
				`SELECT detail FROM audit_log WHERE action = 'auth.login_failed' ORDER BY created_at, id LIMIT 2`)
			if err != nil {
				t.Fatalf("lecture de l'audit: %v", err)
			}
			details, err := pgx.CollectRows(rows, pgx.RowTo[string])
			if err != nil || len(details) != 2 {
				t.Fatalf("échecs de connexion tracés : %d, 2 attendus (%v)", len(details), err)
			}
			for _, detail := range details {
				var meta map[string]string
				if err := json.Unmarshal([]byte(detail), &meta); err != nil {
					t.Fatalf("détail illisible: %v", err)
				}
				if meta["ip"] != want {
					t.Errorf("adresse dans l'audit %q, attendu %q", meta["ip"], want)
				}
			}
		})
	}
}

// A call without a token is counted per address before being refused.
func TestAdresseForgeeLimiteDeLAPI(t *testing.T) {
	for _, mode := range addressModes {
		t.Run(mode.name, func(t *testing.T) {
			e := setup(t, mode.declare, func(a *handlers.App) { a.APILimiter = web.NewRateLimiter(2, time.Minute) })
			checkForgedAddresses(t, mode.real, http.StatusUnauthorized, func(h http.Header) int {
				req, err := http.NewRequest(http.MethodGet, e.url+"/api/v1/site", nil)
				if err != nil {
					t.Fatalf("requête: %v", err)
				}
				req.Header = h.Clone()
				resp, err := newClient().Do(req)
				if err != nil {
					t.Fatalf("GET /site: %v", err)
				}
				resp.Body.Close()
				return resp.StatusCode
			})
		})
	}
}
