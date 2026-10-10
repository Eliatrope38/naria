package web

import (
	"log"
	"net/http"
	"net/netip"
	"strings"
	"sync"
)

const hdrXForwardedFor = "X-Forwarded-For"

// Replaces RemoteAddr with the client address when the peer is a proxy in TRUSTED_PROXY_CIDRS. The result is
// the key for rate limiters and the audit log, so nothing the client chooses may feed into it. Only
// X-Forwarded-For is read; X-Real-IP and True-Client-IP never are, since Caddy forwards them as the client sent them.
func TrustedRealIP(trusted []netip.Prefix) func(http.Handler) http.Handler {
	var undeclared sync.Once
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			peer, ok := parseAddr(r.RemoteAddr)
			switch {
			case ok && isTrusted(peer, trusted):
				r.RemoteAddr = forwardedClient(peer, r.Header.Values(hdrXForwardedFor), trusted).String()
			case r.Header.Get(hdrXForwardedFor) != "":
				// An undeclared proxy makes all its visitors share one counter.
				// The peer address is not logged, since it may belong to a visitor.
				undeclared.Do(func() {
					log.Print("ATTENTION: X-Forwarded-For reçu d'un pair absent de TRUSTED_PROXY_CIDRS, en-tête ignoré. Si l'instance est derrière un reverse proxy, déclarez son adresse : sinon tous les visiteurs partagent la même limite de débit")
				})
			}
			next.ServeHTTP(w, r)
		})
	}
}

// forwardedClient walks X-Forwarded-For from the right and stops at the first address that is not a declared
// proxy: anything to its left may have been written by the client.
func forwardedClient(peer netip.Addr, lines []string, trusted []netip.Prefix) netip.Addr {
	client := peer
	for i := len(lines) - 1; i >= 0; i-- {
		// No pre-splitting: the header can be long, and only its end matters.
		rest := lines[i]
		for {
			j := strings.LastIndexByte(rest, ',')
			addr, ok := parseAddr(strings.TrimSpace(rest[j+1:]))
			if !ok {
				return client
			}
			if client = addr; !isTrusted(addr, trusted) {
				return client
			}
			if j < 0 {
				break
			}
			rest = rest[:j]
		}
	}
	return client
}

// parseAddr accepts an address with or without a port, as some proxies write it in X-Forwarded-For
// (Azure Application Gateway, IIS). The result is IPv4 when the address is IPv4-mapped IPv6.
func parseAddr(s string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		ap, err := netip.ParseAddrPort(s)
		if err != nil {
			return netip.Addr{}, false
		}
		addr = ap.Addr()
	}
	return addr.Unmap().WithZone(""), true
}

func isTrusted(addr netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
