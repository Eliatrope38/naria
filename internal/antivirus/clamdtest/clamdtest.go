// Package clamdtest provides a fake clamd daemon for tests. It speaks the real protocol (PING,
// INSTREAM) and only recognizes Marker.
package clamdtest

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

const (
	Marker    = "FICHIER-INFECTE"
	Signature = "Test.Signature"
)

type Server struct {
	Addr string

	ln        net.Listener
	mu        sync.Mutex
	maxStream int // 0 = no limit
	streams   [][]byte
}

func Start(t testing.TB) *Server {
	t.Helper()
	return listen(t, "tcp", "127.0.0.1:0")
}

// StartUnix starts a fake clamd on a socket created outside t.TempDir: on macOS its path exceeds
// the length allowed for a socket.
func StartUnix(t testing.TB) *Server {
	t.Helper()
	dir, err := os.MkdirTemp("", "clamd")
	if err != nil {
		t.Fatalf("répertoire du socket: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return listen(t, "unix", filepath.Join(dir, "clamd.sock"))
}

func listen(t testing.TB, network, addr string) *Server {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Fatalf("écoute du faux clamd: %v", err)
	}
	s := &Server{Addr: ln.Addr().String(), ln: ln}
	t.Cleanup(s.Stop)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(conn)
		}
	}()
	return s
}

func (s *Server) Stop() { _ = s.ln.Close() }

func (s *Server) LimitStream(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxStream = n
}

func (s *Server) Streams() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]byte(nil), s.streams...)
}

func (s *Server) serve(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	cmd, err := r.ReadString(0)
	if err != nil {
		return
	}
	switch cmd {
	case "zPING\x00":
		_, _ = conn.Write([]byte("PONG\x00"))
	case "zINSTREAM\x00":
		s.mu.Lock()
		limit := s.maxStream
		s.mu.Unlock()
		var data []byte
		for {
			var size [4]byte
			if _, err := io.ReadFull(r, size[:]); err != nil {
				return
			}
			n := binary.BigEndian.Uint32(size[:])
			if n == 0 {
				break
			}
			if limit > 0 && len(data)+int(n) > limit {
				_, _ = conn.Write([]byte("INSTREAM size limit exceeded. ERROR\x00"))
				// The real clamd closes without reading the rest, which can lose its reply. The fake
				// reads it to the end so the tests do not depend on a race.
				if half, ok := conn.(interface{ CloseWrite() error }); ok {
					_ = half.CloseWrite()
				}
				_, _ = io.Copy(io.Discard, r)
				return
			}
			chunk := make([]byte, n)
			if _, err := io.ReadFull(r, chunk); err != nil {
				return
			}
			data = append(data, chunk...)
		}
		s.mu.Lock()
		s.streams = append(s.streams, data)
		s.mu.Unlock()
		if bytes.Contains(data, []byte(Marker)) {
			_, _ = conn.Write([]byte("stream: " + Signature + " FOUND\x00"))
			return
		}
		_, _ = conn.Write([]byte("stream: OK\x00"))
	default:
		_, _ = conn.Write([]byte("UNKNOWN COMMAND\x00"))
	}
}
