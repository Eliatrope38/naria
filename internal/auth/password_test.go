package auth

import (
	"testing"
	"time"
)

// bestOf returns the shortest duration over n runs: the minimum filters noise better than an average.
func bestOf(n int, fn func()) time.Duration {
	best := time.Duration(1<<63 - 1)
	for i := 0; i < n; i++ {
		start := time.Now()
		fn()
		if d := time.Since(start); d < best {
			best = d
		}
	}
	return best
}

// No absolute threshold, which is too sensitive to CI load: compare against a real verification instead.
func TestFakeVerifyDoesRealArgon2Work(t *testing.T) {
	realHash, err := HashPassword("le-vrai-mot-de-passe")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	const iters = 5
	realDur := bestOf(iters, func() { _, _ = VerifyPassword("mauvais-mot-de-passe", realHash) })
	fakeDur := bestOf(iters, func() { FakeVerify() })

	// An argon2id at 64 MiB takes tens of milliseconds; a short-circuit would measure in microseconds.
	if fakeDur < time.Millisecond {
		t.Fatalf("FakeVerify trop rapide (%s) : semble court-circuiter le calcul argon2", fakeDur)
	}

	// Factor of 8: tolerates a loaded machine while still catching a FakeVerify without the real cost.
	if fakeDur > 8*realDur {
		t.Fatalf("FakeVerify (%s) beaucoup plus lent que la vérif réelle (%s)", fakeDur, realDur)
	}
	if realDur > 8*fakeDur {
		t.Fatalf("vérif réelle (%s) beaucoup plus lente que FakeVerify (%s) : le timing n'est pas égalisé", realDur, fakeDur)
	}
}
