package antivirus_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"gitlab.com/detag_inno/naria/internal/antivirus"
	"gitlab.com/detag_inno/naria/internal/antivirus/clamdtest"
)

func ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	return c
}

func TestNew(t *testing.T) {
	for _, addr := range []string{"", "   "} {
		if antivirus.New(addr) != nil {
			t.Errorf("New(%q) : nil attendu, l'instance n'a pas d'antivirus", addr)
		}
	}
	for _, addr := range []string{"clamav:3310", " 127.0.0.1:3310 ", "/run/clamav/clamd.sock"} {
		if antivirus.New(addr) == nil {
			t.Errorf("New(%q) : un Scanner est attendu", addr)
		}
	}
}

func TestScan(t *testing.T) {
	srv := clamdtest.Start(t)
	s := antivirus.New(srv.Addr)
	if err := s.Ping(ctx(t)); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	// Neither a multiple of the block size nor smaller: the content must arrive whole and in order.
	big := bytes.Repeat([]byte("0123456789abcdef"), 150_000/16*2+1)
	for _, tc := range []struct {
		what string
		data []byte
		want string
	}{
		{"fichier sain", []byte("bonjour"), ""},
		{"fichier vide", nil, ""},
		{"fichier de plusieurs blocs", big, ""},
		{"fichier infecté", []byte("avant " + clamdtest.Marker + " après"), clamdtest.Signature},
		{"marqueur en fin de gros fichier", append(bytes.Clone(big), clamdtest.Marker...), clamdtest.Signature},
	} {
		got, err := s.Scan(ctx(t), tc.data)
		if err != nil || got != tc.want {
			t.Errorf("%s : signature %q, erreur %v (%q attendu)", tc.what, got, err, tc.want)
		}
		streams := srv.Streams()
		if last := streams[len(streams)-1]; !bytes.Equal(last, tc.data) {
			t.Errorf("%s : clamd a reçu %d octets, %d envoyés", tc.what, len(last), len(tc.data))
		}
	}
}

// CLAMAV_ADDR may point to the Unix socket of a clamd installed on the machine.
func TestScanSocketUnix(t *testing.T) {
	srv := clamdtest.StartUnix(t)
	s := antivirus.New(srv.Addr)
	if err := s.Ping(ctx(t)); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if got, err := s.Scan(ctx(t), []byte("bonjour")); err != nil || got != "" {
		t.Errorf("fichier sain : signature %q, erreur %v", got, err)
	}
	if got, err := s.Scan(ctx(t), []byte(clamdtest.Marker)); err != nil || got != clamdtest.Signature {
		t.Errorf("fichier infecté : signature %q, erreur %v", got, err)
	}
}

// respond starts a daemon that sends answer on the first connection, without waiting for the
// stream, and returns its address.
func respond(t *testing.T, answer string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("écoute: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte(answer))
		_ = conn.(*net.TCPConn).CloseWrite()
		_, _ = io.Copy(io.Discard, conn)
	}()
	return ln.Addr().String()
}

// A detection stays a detection even without a name: "" is reserved for a clean file.
func TestScanDetectionSansNom(t *testing.T) {
	for _, answer := range []string{"stream:  FOUND\x00", " FOUND\x00"} {
		got, err := antivirus.New(respond(t, answer)).Scan(ctx(t), []byte("bonjour"))
		if err != nil || got == "" {
			t.Errorf("réponse %q : signature %q, erreur %v (une détection est attendue)", answer, got, err)
		}
	}
}

// A scan that did not happen is an error, never a clean file.
func TestScanSansVerdict(t *testing.T) {
	t.Run("flux refusé par clamd", func(t *testing.T) {
		srv := clamdtest.Start(t)
		srv.LimitStream(1000)
		got, err := antivirus.New(srv.Addr).Scan(ctx(t), bytes.Repeat([]byte("x"), 1<<20))
		if err == nil || got != "" || !strings.Contains(err.Error(), "size limit exceeded") {
			t.Errorf("signature %q, erreur %v (le refus de clamd est attendu)", got, err)
		}
	})
	t.Run("démon arrêté", func(t *testing.T) {
		srv := clamdtest.Start(t)
		srv.Stop()
		s := antivirus.New(srv.Addr)
		if got, err := s.Scan(ctx(t), []byte("bonjour")); err == nil || got != "" {
			t.Errorf("Scan : signature %q, erreur %v (une erreur est attendue)", got, err)
		}
		if err := s.Ping(ctx(t)); err == nil {
			t.Errorf("Ping : une erreur est attendue")
		}
	})
	t.Run("démon muet", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("écoute: %v", err)
		}
		defer ln.Close()
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			time.Sleep(2 * time.Second)
		}()
		c, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancel()
		start := time.Now()
		if got, err := antivirus.New(ln.Addr().String()).Scan(c, []byte("bonjour")); err == nil || got != "" {
			t.Errorf("signature %q, erreur %v (une erreur est attendue)", got, err)
		}
		if waited := time.Since(start); waited > time.Second {
			t.Errorf("l'analyse a attendu %s malgré le délai du contexte", waited)
		}
	})
	// Only "stream: OK" is a verdict: anything else is an error.
	for _, answer := range []string{
		"stream: Can't allocate memory ERROR\x00",
		"OK\x00",
		"stream: OK",
		"stream: OK\n",
		"\x00",
		strings.Repeat("x", 1<<20) + "\x00",
	} {
		t.Run("réponse inattendue", func(t *testing.T) {
			got, err := antivirus.New(respond(t, answer)).Scan(ctx(t), []byte("bonjour"))
			if err == nil || got != "" {
				t.Errorf("réponse %.40q : signature %q, erreur %v (une erreur est attendue)", answer, got, err)
			}
			if err != nil && len(err.Error()) > 8<<10 {
				t.Errorf("réponse %.40q : erreur de %d octets, la réponse lue doit être bornée", answer, len(err.Error()))
			}
		})
	}
	t.Run("annulation en cours d'analyse", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("écoute: %v", err)
		}
		defer ln.Close()
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			_, _ = io.Copy(io.Discard, conn)
		}()
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		time.AfterFunc(100*time.Millisecond, cancel)
		start := time.Now()
		if got, err := antivirus.New(ln.Addr().String()).Scan(c, []byte("bonjour")); err == nil || got != "" {
			t.Errorf("signature %q, erreur %v (une erreur est attendue)", got, err)
		}
		if waited := time.Since(start); waited > 2*time.Second {
			t.Errorf("l'analyse a attendu %s après l'annulation du contexte", waited)
		}
	})
}
