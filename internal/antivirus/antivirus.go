// Package antivirus scans content with a clamd daemon the operator runs next to the instance. A
// remote address would send the traffic over the network in clear, since clamd does not encrypt it.
package antivirus

import (
	"bufio"
	"cmp"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const (
	// A missing daemon is detected quickly, without waiting for the scan timeout.
	dialTimeout = 3 * time.Second
	// chunkSize is the size of the stream blocks. clamd rejects a block larger than its
	// StreamMaxLength, which 64 KiB stays well under.
	chunkSize = 64 << 10
	// clamd replies with one line; a faulty daemon must not fill the memory.
	maxReply = 4 << 10
)

type Scanner struct {
	network, addr string
}

// New returns a Scanner for the given address, either "host:port" or the absolute path of a Unix
// socket. Without an address it returns nil, meaning no antivirus.
func New(addr string) *Scanner {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil
	}
	if strings.HasPrefix(addr, "/") {
		return &Scanner{network: "unix", addr: addr}
	}
	return &Scanner{network: "tcp", addr: addr}
}

func (s *Scanner) dial(ctx context.Context) (net.Conn, error) {
	d := net.Dialer{Timeout: dialTimeout}
	conn, err := d.DialContext(ctx, s.network, s.addr)
	if err != nil {
		return nil, fmt.Errorf("clamd injoignable: %w", err)
	}
	// The context deadline covers the whole exchange, not just the connection: it interrupts a
	// pending read or write.
	context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	return conn, nil
}

func reply(conn net.Conn) (string, error) {
	line, err := bufio.NewReader(io.LimitReader(conn, maxReply)).ReadString(0)
	if err != nil {
		return "", fmt.Errorf("réponse de clamd: %w", err)
	}
	return strings.TrimSuffix(line, "\x00"), nil
}

func (s *Scanner) Ping(ctx context.Context) error {
	conn, err := s.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("zPING\x00")); err != nil {
		return fmt.Errorf("envoi à clamd: %w", err)
	}
	got, err := reply(conn)
	if err != nil {
		return err
	}
	if got != "PONG" {
		return fmt.Errorf("réponse inattendue de clamd: %q", got)
	}
	return nil
}

// Scan returns the name of the matched signature, or "" if nothing is detected. An error means the
// scan did not happen: the content is neither clean nor infected, and the caller must not treat it
// as clean.
func (s *Scanner) Scan(ctx context.Context, data []byte) (string, error) {
	conn, err := s.dial(ctx)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	// INSTREAM: blocks prefixed by their size on four bytes, terminated by an empty block.
	w := bufio.NewWriterSize(conn, chunkSize+4)
	_, werr := w.WriteString("zINSTREAM\x00")
	var size [4]byte
	for len(data) > 0 && werr == nil {
		n := min(len(data), chunkSize)
		binary.BigEndian.PutUint32(size[:], uint32(n)) // #nosec G115 -- n <= chunkSize
		if _, werr = w.Write(size[:]); werr == nil {
			_, werr = w.Write(data[:n])
		}
		data = data[n:]
	}
	if werr == nil {
		_, werr = w.Write([]byte{0, 0, 0, 0})
	}
	if werr == nil {
		werr = w.Flush()
	}
	// clamd rejects an oversized stream by replying and closing the connection, so the write can
	// fail before the reply, which says why, is read.
	got, rerr := reply(conn)
	switch {
	case werr != nil && rerr != nil:
		return "", fmt.Errorf("envoi à clamd: %w", werr)
	case werr != nil:
		// A verdict on an incomplete stream is worthless, even "clean".
		return "", fmt.Errorf("envoi à clamd: %w (réponse %q)", werr, got)
	case rerr != nil:
		return "", rerr
	case got == "stream: OK":
		return "", nil
	}
	if signature, found := strings.CutSuffix(strings.TrimPrefix(got, "stream: "), " FOUND"); found {
		// For the caller, "" means clean: a detection without a name must not pass for one.
		return cmp.Or(signature, "signature sans nom"), nil
	}
	return "", fmt.Errorf("clamd: %q", got)
}
