// Package captcha issues and verifies anti-bot proof-of-work challenges for forms, solved by the
// browser alone. Nothing is kept per visitor: challenges are signed rather than remembered, and only
// used ones stay in memory until they expire.
package captcha

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"log"
	"math/bits"
	"strings"
	"sync"
	"time"

	"gitlab.com/detag_inno/naria/internal/crypto"
)

const (
	// One try in 2^Difficulty is enough: at 18 it takes a tenth of a second on a recent computer,
	// several times that on a phone. The script refuses to search past its own ceiling
	// (MAX_BITS in web/static/captcha.js).
	Difficulty = 18
	// ttl leaves time to solve the challenge and submit the form. The solution is checked as soon
	// as it is read, before the files, so their upload does not count.
	ttl        = 5 * time.Minute
	maxSpent   = 100_000
	sweepEvery = time.Minute

	nonceLen       = 16
	headLen        = 8 + nonceLen
	tokenLen       = headLen + sha256.Size
	maxSolutionLen = 128
)

var (
	ErrMissing = errors.New("captcha: solution absente")
	// ErrInvalid: malformed, forged, expired, insufficient, already used, or issued for another form.
	ErrInvalid = errors.New("captcha: solution refusée")
)

type Checker struct {
	key        []byte
	difficulty int
	// Process start time (Unix seconds). Challenges issued before it are refused, since the
	// used-challenge memory does not survive a restart.
	started int64

	mu    sync.Mutex
	spent map[[nonceLen]byte]int64
	// Log only once per full episode.
	full bool
}

// New returns a Checker whose signing key is derived from the secret. Without a secret the key is
// random, so a challenge is only valid for the process that issued it.
func New(secret string, difficulty int) (*Checker, error) {
	key := make([]byte, sha256.Size)
	if secret == "" {
		_, _ = rand.Read(key) // never fails (Go 1.24)
	} else {
		var err error
		if key, err = crypto.Key(secret, crypto.PurposeCaptcha); err != nil {
			return nil, err
		}
	}
	c := &Checker{key: key, difficulty: difficulty, started: time.Now().Unix(), spent: make(map[[nonceLen]byte]int64)}
	go func() {
		t := time.NewTicker(sweepEvery)
		defer t.Stop()
		for now := range t.C {
			c.sweep(now)
		}
	}()
	return c, nil
}

func (c *Checker) Difficulty() int { return c.difficulty }

// Challenge issues a challenge for the form accessKey, valid until now + ttl. Nothing is stored:
// the challenge carries its expiry and its signature.
func (c *Checker) Challenge(accessKey string, now time.Time) string {
	head := make([]byte, headLen, tokenLen)
	binary.BigEndian.PutUint64(head, uint64(now.Add(ttl).Unix())) // #nosec G115 -- a timestamp after 1970
	_, _ = rand.Read(head[8:])                                    // never fails (Go 1.24)
	return base64.RawURLEncoding.EncodeToString(append(head, c.sign(head, accessKey)...))
}

// sign returns the signature of the expiry and nonce, bound to the access key. The length is fixed:
// the key is appended without a separator, so it cannot run into them.
func (c *Checker) sign(head []byte, accessKey string) []byte {
	mac := hmac.New(sha256.New, c.key)
	mac.Write(head)
	mac.Write([]byte(accessKey))
	return mac.Sum(nil)
}

// Check verifies the solution "challenge.counter" for the form accessKey, then consumes the challenge,
// so the same solution is refused afterwards. The challenge must have been signed by this Checker,
// for this form, since its start, and must not have expired. The SHA-256 digest of the solution must
// start with difficulty zero bits.
func (c *Checker) Check(accessKey, solution string, now time.Time) error {
	if solution == "" {
		return ErrMissing
	}
	encoded, counter, ok := strings.Cut(solution, ".")
	if !ok || len(solution) > maxSolutionLen || counter == "" {
		return ErrInvalid
	}
	// Only one encoding per challenge: the decoder would otherwise ignore line breaks, and unused bits
	// in the last character.
	if len(encoded) != base64.RawURLEncoding.EncodedLen(tokenLen) {
		return ErrInvalid
	}
	token, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return ErrInvalid
	}
	if !hmac.Equal(token[headLen:], c.sign(token[:headLen], accessKey)) {
		return ErrInvalid
	}
	expiry := int64(binary.BigEndian.Uint64(token)) // #nosec G115 -- written by Challenge, signature verified
	if now.Unix() > expiry || expiry-int64(ttl/time.Second) < c.started {
		return ErrInvalid
	}
	sum := sha256.Sum256([]byte(solution))
	if bits.LeadingZeros32(binary.BigEndian.Uint32(sum[:])) < c.difficulty {
		return ErrInvalid
	}

	nonce := [nonceLen]byte(token[8:headLen])
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, used := c.spent[nonce]; used {
		return ErrInvalid
	}
	// Memory full: the solution passes without being recorded, so it stays replayable until it
	// expires. Refusing it would let anyone with enough machines shut down every protected form.
	if len(c.spent) < maxSpent {
		c.spent[nonce] = expiry
	} else if !c.full {
		c.full = true
		log.Printf("ATTENTION: captcha, %d défis utilisés en mémoire, les suivants restent rejouables jusqu'à leur échéance", maxSpent)
	}
	return nil
}

// sweep removes challenges past their expiry, with a one-minute margin for a Check whose time is
// slightly behind the sweep.
func (c *Checker) sweep(now time.Time) {
	limit := now.Add(-sweepEvery).Unix()
	c.mu.Lock()
	defer c.mu.Unlock()
	for nonce, expiry := range c.spent {
		if expiry < limit {
			delete(c.spent, nonce)
		}
	}
	c.full = c.full && len(c.spent) >= maxSpent
}
