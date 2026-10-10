package handlers

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/iotest"
)

// The cap bounds an anonymous visitor's memory: it holds to the byte, whatever the reads.
func TestSubmitBody(t *testing.T) {
	newBody := func(size int, limit int64) *submitBody {
		return &submitBody{ReadCloser: io.NopCloser(strings.NewReader(strings.Repeat("x", size))), limit: limit, left: limit}
	}
	drain := func(b *submitBody, chunk int) (int, error) {
		p := make([]byte, chunk)
		total := 0
		for {
			n, err := b.Read(p)
			total += n
			if err != nil {
				return total, err
			}
		}
	}
	tooLarge := func(err error, limit int64) bool {
		var e *http.MaxBytesError
		return errors.As(err, &e) && e.Limit == limit
	}

	for _, chunk := range []int{1, 3, 10, 11, 12, 64} {
		if n, err := drain(newBody(10, 10), chunk); n != 10 || err != io.EOF {
			t.Errorf("lectures de %d, corps à la limite : %d octet(s), %v ; 10 et EOF attendus", chunk, n, err)
		}
		if n, err := drain(newBody(11, 10), chunk); n != 10 || !tooLarge(err, 10) {
			t.Errorf("lectures de %d, un octet de trop : %d octet(s), %v ; 10 et un dépassement attendus", chunk, n, err)
		}

		b := newBody(25, 10)
		first, _ := b.Read(make([]byte, 4))
		b.raise(15)
		if n, err := drain(b, chunk); first+n != 25 || err != io.EOF {
			t.Errorf("lectures de %d, plafond relevé : %d octet(s), %v ; 25 et EOF attendus", chunk, first+n, err)
		}
		b = newBody(26, 10)
		b.raise(15)
		if n, err := drain(b, chunk); n != 25 || !tooLarge(err, 25) {
			t.Errorf("lectures de %d, un octet au-delà du plafond relevé : %d octet(s), %v", chunk, n, err)
		}
	}

	// The overflow stays recorded, even once the body is exhausted: a reader
	// that ignored the first error must not believe in a normal end.
	b := newBody(11, 10)
	_, _ = drain(b, 64)
	if n, err := b.Read(make([]byte, 8)); n != 0 || !tooLarge(err, 10) {
		t.Errorf("lecture après dépassement : %d octet(s), %v ; le dépassement attendu", n, err)
	}

	boom := errors.New("connexion coupée")
	b = &submitBody{ReadCloser: io.NopCloser(iotest.ErrReader(boom)), limit: 10, left: 10}
	if _, err := b.Read(make([]byte, 8)); !errors.Is(err, boom) {
		t.Errorf("erreur de lecture = %v ; celle du corps attendue", err)
	}
}
