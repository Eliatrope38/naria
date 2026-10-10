package captcha

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math/bits"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testDifficulty keeps solving a challenge under a millisecond.
const testDifficulty = 8

func newChecker(t *testing.T, secret string, difficulty int) *Checker {
	t.Helper()
	c, err := New(secret, difficulty)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// noncanonical rewrites the last character: its two low bits encode nothing, and a lenient decoder
// would read the same challenge.
func noncanonical(solution string) string {
	token, _, _ := strings.Cut(solution, ".")
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, token[len(token)-1])
	return solve(token[:len(token)-1]+string(alphabet[last^1]), testDifficulty, true)
}

// solve searches for the counter giving the challenge a digest of the wanted difficulty (valid), or
// on the contrary a too weak one.
func solve(token string, difficulty int, valid bool) string {
	for n := 0; ; n++ {
		s := token + "." + strconv.Itoa(n)
		sum := sha256.Sum256([]byte(s))
		if (bits.LeadingZeros32(binary.BigEndian.Uint32(sum[:])) >= difficulty) == valid {
			return s
		}
	}
}

func TestCheck(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	c := newChecker(t, "secret", testDifficulty)
	other := newChecker(t, "autre-secret", testDifficulty)
	const key = "cle-du-formulaire"

	altered := func(at int) string {
		raw, _ := base64.RawURLEncoding.DecodeString(c.Challenge(key, now))
		raw[at] ^= 1
		return solve(base64.RawURLEncoding.EncodeToString(raw), testDifficulty, true)
	}
	valid := solve(c.Challenge(key, now), testDifficulty, true)

	for _, tc := range []struct {
		name     string
		key      string
		solution string
		at       time.Time
		want     error
	}{
		{"absente", key, "", now, ErrMissing},
		{"sans compteur", key, c.Challenge(key, now), now, ErrInvalid},
		{"compteur vide", key, c.Challenge(key, now) + ".", now, ErrInvalid},
		{"illisible", key, "pas-un-défi.12", now, ErrInvalid},
		{"tronquée", key, valid[:20] + ".12", now, ErrInvalid},
		{"démesurée", key, valid + strings.Repeat("0", maxSolutionLen), now, ErrInvalid},
		{"preuve insuffisante", key, solve(c.Challenge(key, now), testDifficulty, false), now, ErrInvalid},
		{"échéance repoussée", key, altered(7), now, ErrInvalid},
		{"nonce modifié", key, altered(8), now, ErrInvalid},
		{"signature modifiée", key, altered(tokenLen - 1), now, ErrInvalid},
		{"autre écriture du même défi", key, noncanonical(valid), now, ErrInvalid},
		{"défi coupé d'un saut de ligne", key, solve(valid[:10]+"\n"+valid[10:strings.IndexByte(valid, '.')], testDifficulty, true), now, ErrInvalid},
		{"autre formulaire", "autre-cle", solve(c.Challenge(key, now), testDifficulty, true), now, ErrInvalid},
		{"autre instance", key, solve(other.Challenge(key, now), testDifficulty, true), now, ErrInvalid},
		{"périmée", key, solve(c.Challenge(key, now), testDifficulty, true), now.Add(ttl + time.Second), ErrInvalid},
		{"à l'échéance", key, solve(c.Challenge(key, now), testDifficulty, true), now.Add(ttl), nil},
		{"valide", key, valid, now.Add(time.Minute), nil},
		{"déjà utilisée", key, valid, now.Add(2 * time.Minute), ErrInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := c.Check(tc.key, tc.solution, tc.at); !errors.Is(err, tc.want) {
				t.Errorf("Check = %v, attendu %v", err, tc.want)
			}
		})
	}
}

// A refusal does not consume the challenge: presented under another key, the solution stays usable
// by the right form.
func TestRefusNeConsommePasLeDefi(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	c := newChecker(t, "secret", testDifficulty)
	solution := solve(c.Challenge("cle", now), testDifficulty, true)
	if err := c.Check("autre-cle", solution, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("mauvaise clé : %v", err)
	}
	if err := c.Check("cle", solution, now); err != nil {
		t.Errorf("la solution a été consommée par un refus : %v", err)
	}
}

// Two instances sharing APP_SECRET_KEY accept each other's challenges. Without a secret, each start
// has its own key.
func TestCleDeSignature(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	a, b := newChecker(t, "secret", testDifficulty), newChecker(t, "secret", testDifficulty)
	if err := b.Check("cle", solve(a.Challenge("cle", now), testDifficulty, true), now); err != nil {
		t.Errorf("même secret : %v", err)
	}
	x, y := newChecker(t, "", testDifficulty), newChecker(t, "", testDifficulty)
	if err := y.Check("cle", solve(x.Challenge("cle", now), testDifficulty, true), now); !errors.Is(err, ErrInvalid) {
		t.Errorf("sans secret, deux instances ne doivent pas partager leur clé : %v", err)
	}
	if err := x.Check("cle", solve(x.Challenge("cle", now), testDifficulty, true), now); err != nil {
		t.Errorf("sans secret : %v", err)
	}
}

// The used-challenge memory does not survive a restart: a challenge issued before it is refused,
// rather than accepted a second time.
func TestDefiEmisAvantLeDemarrage(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	before := newChecker(t, "secret", testDifficulty)
	solution := solve(before.Challenge("cle", now), testDifficulty, true)
	if err := before.Check("cle", solution, now); err != nil {
		t.Fatalf("avant le redémarrage : %v", err)
	}
	after := newChecker(t, "secret", testDifficulty)
	after.started = now.Unix() + 1
	if err := after.Check("cle", solution, now.Add(2*time.Second)); !errors.Is(err, ErrInvalid) {
		t.Errorf("solution rejouée après le redémarrage : %v", err)
	}
	fresh := solve(after.Challenge("cle", now.Add(time.Second)), testDifficulty, true)
	if err := after.Check("cle", fresh, now.Add(2*time.Second)); err != nil {
		t.Errorf("défi émis après le redémarrage : %v", err)
	}
}

// The script assumes the end of the challenge and the counter fit in the last SHA-256 block, which
// holds as long as the challenge keeps this length.
func TestLongueurDuDefi(t *testing.T) {
	c := newChecker(t, "secret", testDifficulty)
	if n := len(c.Challenge("cle", time.Unix(1_800_000_000, 0))); n != 75 {
		t.Errorf("défi de %d caractères : web/static/captcha.js est écrit pour 75", n)
	}
}

func TestUsageUniqueSousEnvoisSimultanes(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	c := newChecker(t, "secret", testDifficulty)
	solution := solve(c.Challenge("cle", now), testDifficulty, true)
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			if c.Check("cle", solution, now) == nil {
				accepted.Add(1)
			}
		})
	}
	wg.Wait()
	if n := accepted.Load(); n != 1 {
		t.Errorf("%d envois acceptés avec la même solution (1 attendu)", n)
	}
}

// Replayed at the second of its expiry, after a sweep run the next second has already passed, the
// solution is still refused.
func TestPurgeAvecMarge(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	c := newChecker(t, "secret", testDifficulty)
	solution := solve(c.Challenge("cle", now), testDifficulty, true)
	if err := c.Check("cle", solution, now.Add(ttl)); err != nil {
		t.Fatalf("solution refusée à son échéance : %v", err)
	}
	c.sweep(now.Add(ttl + time.Second))
	if err := c.Check("cle", solution, now.Add(ttl)); !errors.Is(err, ErrInvalid) {
		t.Errorf("solution rejouée après une purge : %v", err)
	}
}

// Issuing challenges retains nothing. Only used challenges stay in memory, up to a fixed limit, and
// leave at their expiry.
func TestMemoireBornee(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	c := newChecker(t, "secret", 0)
	spent := func() int {
		c.mu.Lock()
		defer c.mu.Unlock()
		return len(c.spent)
	}

	for range 2 * maxSpent {
		c.Challenge("cle", now)
	}
	if n := spent(); n != 0 {
		t.Fatalf("%d défi(s) retenu(s) après leur seule émission", n)
	}

	late := now.Add(time.Minute)
	for i := range maxSpent + 500 {
		at := now
		if i >= maxSpent/2 {
			at = late
		}
		if err := c.Check("cle", c.Challenge("cle", at)+".0", late); err != nil {
			t.Fatalf("solution %d refusée : %v", i, err)
		}
	}
	if n := spent(); n != maxSpent {
		t.Fatalf("%d défis retenus, %d au plus attendus", n, maxSpent)
	}

	c.sweep(now.Add(ttl + sweepEvery + time.Second))
	if n := spent(); n != maxSpent/2 {
		t.Errorf("%d défis retenus après l'échéance des premiers, %d attendus", n, maxSpent/2)
	}
	c.sweep(late.Add(ttl + sweepEvery + time.Second))
	if n := spent(); n != 0 {
		t.Errorf("%d défis retenus après leur échéance", n)
	}
}
