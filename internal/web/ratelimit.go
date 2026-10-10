package web

import (
	"net/http"
	"net/netip"
	"sync"
	"time"
)

type RateLimiter struct {
	mu     sync.Mutex
	hits   map[string][]time.Time
	limit  int
	window time.Duration
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{hits: make(map[string][]time.Time), limit: limit, window: window}
	go rl.sweepLoop()
	return rl
}

// Bounds memory: without purging, every IP would keep its entry forever.
func (rl *RateLimiter) sweepLoop() {
	t := time.NewTicker(rl.window)
	defer t.Stop()
	for range t.C {
		cutoff := time.Now().Add(-rl.window)
		rl.mu.Lock()
		for k, ts := range rl.hits {
			kept := ts[:0]
			for _, t := range ts {
				if t.After(cutoff) {
					kept = append(kept, t)
				}
			}
			if len(kept) == 0 {
				delete(rl.hits, k)
			} else {
				rl.hits[k] = kept
			}
		}
		rl.mu.Unlock()
	}
}

func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := time.Now().Add(-rl.window)

	kept := rl.hits[key][:0]
	for _, t := range rl.hits[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= rl.limit {
		rl.hits[key] = kept
		return false
	}
	rl.hits[key] = append(kept, time.Now())
	return true
}

// ClientIP returns the address set by TrustedRealIP. For rate limiting, use RateLimitKey.
func ClientIP(r *http.Request) string {
	if addr, ok := parseAddr(r.RemoteAddr); ok {
		return addr.String()
	}
	return r.RemoteAddr
}

// RateLimitKey returns the rate-limit key: the address for IPv4, the /64 prefix for IPv6, since a subscriber often owns a whole /64.
func RateLimitKey(r *http.Request) string {
	addr, ok := parseAddr(r.RemoteAddr)
	if !ok {
		return r.RemoteAddr
	}
	if addr.Is6() {
		return netip.PrefixFrom(addr, 64).Masked().String()
	}
	return addr.String()
}
