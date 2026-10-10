package email

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

type SMTP struct {
	host     string
	port     int
	username string
	password string
	from     string
	tlsMode  string
}

// newSMTP creates the SMTP provider; it returns nil if the configuration is incomplete.
func newSMTP(o Options) Sender {
	if o.SMTPHost == "" || o.SMTPFrom == "" {
		return nil
	}
	port := o.SMTPPort
	if port == 0 {
		port = 587
	}
	mode := strings.ToLower(strings.TrimSpace(o.SMTPTLS))
	if mode == "" {
		if port == 465 {
			mode = "implicit"
		} else {
			mode = "starttls"
		}
	}
	return &SMTP{
		host: o.SMTPHost, port: port,
		username: o.SMTPUsername, password: o.SMTPPassword,
		from: o.SMTPFrom, tlsMode: mode,
	}
}

func (s *SMTP) Send(ctx context.Context, m Message) error {
	to := m.To
	msg := buildMIME(s.from, m, time.Now())
	addr := net.JoinHostPort(s.host, strconv.Itoa(s.port))

	var auth smtp.Auth
	if s.username != "" {
		auth = smtp.PlainAuth("", s.username, s.password, s.host)
	}

	switch s.tlsMode {
	case "implicit":
		return s.sendImplicitTLS(ctx, addr, auth, to, msg)
	case "none", "insecure":
		// Without enforced TLS, STARTTLS is still attempted but its absence is not an error. Reserved for relays
		// we trust on a private network: credentials and content may travel in clear.
		return smtp.SendMail(addr, auth, s.from, to, msg)
	default:
		// "starttls" (default): refuse to send if the server does not announce STARTTLS, rather than falling back to clear text.
		return s.sendSTARTTLS(ctx, addr, auth, to, msg)
	}
}

// sendSTARTTLS requires STARTTLS, with certificate verification for the configured host.
func (s *SMTP) sendSTARTTLS(ctx context.Context, addr string, auth smtp.Auth, to []string, msg []byte) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	applyDeadline(ctx, conn)
	c, err := smtp.NewClient(conn, s.host)
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer c.Close()

	if ok, _ := c.Extension("STARTTLS"); !ok {
		return fmt.Errorf("smtp: le serveur %s n'annonce pas STARTTLS ; envoi refusé (TLS obligatoire ; définir le mode TLS sur \"none\" pour autoriser le clair)", s.host)
	}
	// ServerName plus certificate verification (no InsecureSkipVerify).
	if err := c.StartTLS(&tls.Config{ServerName: s.host, MinVersion: tls.VersionTLS12}); err != nil {
		return err
	}
	if err := s.authenticate(c, auth); err != nil {
		return err
	}
	return deliver(c, s.from, to, msg)
}

func (s *SMTP) sendImplicitTLS(ctx context.Context, addr string, auth smtp.Auth, to []string, msg []byte) error {
	d := tls.Dialer{Config: &tls.Config{ServerName: s.host, MinVersion: tls.VersionTLS12}}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	applyDeadline(ctx, conn)
	c, err := smtp.NewClient(conn, s.host)
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer c.Close()

	if err := s.authenticate(c, auth); err != nil {
		return err
	}
	return deliver(c, s.from, to, msg)
}

// applyDeadline copies the context deadline onto the connection: without it, a server that stops
// replying mid-dialogue would block the send forever.
func applyDeadline(ctx context.Context, conn net.Conn) {
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
}

func (s *SMTP) authenticate(c *smtp.Client, auth smtp.Auth) error {
	if auth == nil {
		return nil
	}
	if ok, _ := c.Extension("AUTH"); ok {
		return c.Auth(auth)
	}
	return nil
}

func deliver(c *smtp.Client, from string, to []string, msg []byte) error {
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt); err != nil {
			return err
		}
	}
	wc, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := wc.Write(msg); err != nil {
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// buildMIME builds the message, as multipart/mixed when it carries attachments. The body goes out in base64
// wrapped at 76 columns: a submission can fit on one line longer than SMTP's 998 bytes.
func buildMIME(from string, m Message, now time.Time) []byte {
	recipients := make([]string, len(m.To))
	for i, addr := range m.To {
		recipients[i] = sanitizeHeader(addr)
	}
	var b bytes.Buffer
	b.WriteString("From: " + sanitizeHeader(from) + "\r\n")
	b.WriteString("To: " + strings.Join(recipients, ", ") + "\r\n")
	if m.ReplyTo != "" {
		b.WriteString("Reply-To: " + sanitizeHeader(m.ReplyTo) + "\r\n")
	}
	b.WriteString("Subject: " + mime.QEncoding.Encode("utf-8", sanitizeHeader(m.Subject)) + "\r\n")
	b.WriteString("Date: " + now.Format(time.RFC1123Z) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	if len(m.Attachments) == 0 {
		b.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
		b.WriteString("Content-Transfer-Encoding: base64\r\n")
		b.WriteString("\r\n")
		writeBase64(&b, []byte(m.HTML))
		return b.Bytes()
	}

	// Writes go to an in-memory buffer: they cannot fail.
	mw := multipart.NewWriter(&b)
	b.WriteString("Content-Type: multipart/mixed;\r\n boundary=" + mw.Boundary() + "\r\n")
	b.WriteString("\r\n")
	part, _ := mw.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {"text/html; charset=UTF-8"},
		"Content-Transfer-Encoding": {"base64"},
	})
	writeBase64(part, []byte(m.HTML))
	for _, a := range m.Attachments {
		// The type announced by the visitor is not reused. FormatMediaType encodes the name (RFC 2231),
		// line breaks included: it cannot add a header.
		part, _ = mw.CreatePart(textproto.MIMEHeader{
			"Content-Type":              {"application/octet-stream"},
			"Content-Transfer-Encoding": {"base64"},
			"Content-Disposition":       {mime.FormatMediaType("attachment", map[string]string{"filename": a.Name})},
		})
		writeBase64(part, a.Data)
	}
	_ = mw.Close()
	return b.Bytes()
}

func writeBase64(w io.Writer, data []byte) {
	var line [78]byte
	for len(data) > 0 {
		n := min(len(data), 57)
		base64.StdEncoding.Encode(line[:], data[:n])
		end := base64.StdEncoding.EncodedLen(n)
		line[end], line[end+1] = '\r', '\n'
		_, _ = w.Write(line[:end+2])
		data = data[n:]
	}
}

// sanitizeHeader strips CR/LF from a header value: header injection protection.
func sanitizeHeader(s string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}
