// Package email sends notifications over SMTP or Microsoft Graph, depending on the configuration.
package email

import "context"

type Message struct {
	To          []string
	ReplyTo     string // empty = no Reply-To header
	Subject     string
	HTML        string
	Attachments []Attachment
}

type Attachment struct {
	Name string
	Data []byte
}

// Sender: Send returns nil only if the service accepted the message. In email-only mode, this is what
// allows reporting success to the visitor. ErrTooLarge or ErrVolume if the message cannot be sent as is.
type Sender interface {
	Send(ctx context.Context, m Message) error
}

type Options struct {
	Provider string // "smtp" | "graph"

	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	SMTPFrom     string
	SMTPTLS      string // "starttls" | "implicit" | "none" ; empty = implicit on port 465, starttls otherwise

	GraphTenantID     string
	GraphClientID     string
	GraphClientSecret string
	GraphMailbox      string
}

// New returns nil (sending disabled) when SMTP is not configured.
func New(o Options) Sender {
	if o.Provider == "graph" {
		return NewGraph(o)
	}
	return newSMTP(o)
}

// MaxAttachmentBytes returns 0 for SMTP: only the server limit applies.
func MaxAttachmentBytes(s Sender) int64 {
	if _, ok := s.(*Graph); ok {
		return GraphMaxAttachmentBytes
	}
	return 0
}
