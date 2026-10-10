// Package graphtest provides a fake Microsoft for tests: the token endpoint
// of Entra and the email sending of Graph, as email.Graph calls them.
package graphtest

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"gitlab.com/detag_inno/naria/internal/email"
)

const (
	Tenant   = "11111111-2222-3333-4444-555555555555"
	ClientID = "66666666-7777-8888-9999-000000000000"
	Secret   = "s3cr3t~du~client"
	Mailbox  = "formulaires@exemple.fr"
)

const maxRequest = 4_000_000

type Attachment struct {
	Name        string
	ContentType string
	Data        []byte
}

type Mail struct {
	To          []string
	ReplyTo     []string
	Subject     string
	HTML        string
	Attachments []Attachment
	Saved       bool
}

type refusal struct {
	status     int
	body       string
	retryAfter string
}

type Server struct {
	t   testing.TB
	srv *httptest.Server
	// stop releases the requests held by Stall or Hold at the end of the test.
	stop chan struct{}

	mu            sync.Mutex
	tokenCalls    int
	issued        int
	valid         string
	expiresIn     int
	rejectTokens  bool
	calls         int
	mails         []Mail
	tokenRefusal  *refusal
	sendRefusal   *refusal
	tokenRedirect string
	sendRedirect  string
	stalled       chan struct{}
	hold          time.Duration
	inFlight      int
	maxInFlight   int
	filesInFlight int
	maxWithFiles  int
}

func Start(t testing.TB) *Server {
	t.Helper()
	s := &Server{t: t, stop: make(chan struct{}), expiresIn: 3599}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login/"+Tenant+"/oauth2/v2.0/token", s.token)
	mux.HandleFunc("POST /graph/v1.0/users/"+Mailbox+"/sendMail", s.sendMail)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("appel inattendu : %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	})
	s.srv = httptest.NewTLSServer(mux)
	t.Cleanup(func() {
		close(s.stop)
		s.srv.Close()
	})
	return s
}

func (s *Server) Sender() *email.Graph {
	g := email.NewGraph(email.Options{
		GraphTenantID: Tenant, GraphClientID: ClientID, GraphClientSecret: Secret, GraphMailbox: Mailbox,
	})
	// The transport only: the client keeps its refusal of redirects.
	g.Client.Transport = s.srv.Client().Transport
	g.LoginURL, g.APIURL = s.srv.URL+"/login", s.srv.URL+"/graph"
	return g
}

// Stop waits for the requests in progress: after Stall, call Release first.
func (s *Server) Stop() { s.srv.Close() }

func (s *Server) Mails() []Mail {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Mail(nil), s.mails...)
}

func (s *Server) TokenCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokenCalls
}

func (s *Server) Tokens() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.issued
}

func (s *Server) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func (s *Server) WaitCalls(n int) {
	s.t.Helper()
	s.waitFor(n, s.Calls, "appel(s) à sendMail")
}

func (s *Server) WaitTokenCalls(n int) {
	s.t.Helper()
	s.waitFor(n, s.TokenCalls, "demande(s) de jeton")
}

func (s *Server) waitFor(n int, count func() int, what string) {
	s.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for count() < n {
		if time.Now().After(deadline) {
			s.t.Fatalf("%d %s, %d attendus", count(), what, n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (s *Server) MaxInFlight() (all, withFiles int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.maxInFlight, s.maxWithFiles
}

func (s *Server) ExpiresIn(seconds int) {
	s.mu.Lock()
	s.expiresIn = seconds
	s.mu.Unlock()
}

// RevokeToken: sendMail refuses (401) the issued token until another one is requested.
func (s *Server) RevokeToken() {
	s.mu.Lock()
	s.valid = ""
	s.mu.Unlock()
}

// RejectTokens makes sendMail refuse (401) every token, even a new one.
func (s *Server) RejectTokens() {
	s.mu.Lock()
	s.rejectTokens = true
	s.mu.Unlock()
}

// RefuseToken: a zero status lifts the refusal.
func (s *Server) RefuseToken(status int, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if status == 0 {
		s.tokenRefusal = nil
		return
	}
	s.tokenRefusal = &refusal{status: status, body: body}
}

// RefuseSend: a zero status lifts the refusal.
func (s *Server) RefuseSend(status int, body, retryAfter string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if status == 0 {
		s.sendRefusal = nil
		return
	}
	s.sendRefusal = &refusal{status: status, body: body, retryAfter: retryAfter}
}

// RedirectToken and RedirectSend: a 307 would replay the request body.
func (s *Server) RedirectToken(target string) {
	s.mu.Lock()
	s.tokenRedirect = target
	s.mu.Unlock()
}

func (s *Server) RedirectSend(target string) {
	s.mu.Lock()
	s.sendRedirect = target
	s.mu.Unlock()
}

func (s *Server) Stall() {
	s.mu.Lock()
	s.stalled = make(chan struct{})
	s.mu.Unlock()
}

func (s *Server) Release() {
	s.mu.Lock()
	close(s.stalled)
	s.stalled = nil
	s.mu.Unlock()
}

func (s *Server) Hold(d time.Duration) {
	s.mu.Lock()
	s.hold = d
	s.mu.Unlock()
}

func (s *Server) wait(r *http.Request) bool {
	s.mu.Lock()
	stalled, hold := s.stalled, s.hold
	s.mu.Unlock()
	if stalled != nil {
		select {
		case <-stalled:
		case <-r.Context().Done():
			return false
		case <-s.stop:
			return false
		}
	}
	if hold > 0 {
		select {
		case <-time.After(hold):
		case <-r.Context().Done():
			return false
		case <-s.stop:
			return false
		}
	}
	return true
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.t.Errorf("jeton : formulaire illisible : %v", err)
	}
	s.mu.Lock()
	s.tokenCalls++
	s.mu.Unlock()
	if !s.wait(r) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if s.tokenRedirect != "" {
		http.Redirect(w, r, s.tokenRedirect, http.StatusTemporaryRedirect)
		return
	}
	if s.tokenRefusal != nil {
		w.WriteHeader(s.tokenRefusal.status)
		// nosemgrep: go.lang.security.audit.xss.no-io-writestring-to-responsewriter.no-io-writestring-to-responsewriter -- test fake, the body is JSON set by the test
		_, _ = io.WriteString(w, s.tokenRefusal.body)
		return
	}
	if r.PostFormValue("grant_type") != "client_credentials" || r.PostFormValue("scope") != "https://graph.microsoft.com/.default" {
		s.t.Errorf("jeton : grant_type %q, scope %q", r.PostFormValue("grant_type"), r.PostFormValue("scope"))
	}
	if r.PostFormValue("client_id") != ClientID || r.PostFormValue("client_secret") != Secret {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided.","error_codes":[7000215]}`)
		return
	}
	s.issued++
	s.valid = fmt.Sprintf("jeton-%d", s.issued)
	_ = json.NewEncoder(w).Encode(map[string]any{"token_type": "Bearer", "expires_in": s.expiresIn, "access_token": s.valid})
}

type recipient struct {
	EmailAddress struct {
		Address string `json:"address"`
	} `json:"emailAddress"`
}

type sendMailRequest struct {
	Message struct {
		Subject string `json:"subject"`
		Body    struct {
			ContentType string `json:"contentType"`
			Content     string `json:"content"`
		} `json:"body"`
		ToRecipients []recipient `json:"toRecipients"`
		ReplyTo      []recipient `json:"replyTo"`
		Attachments  []struct {
			Type         string  `json:"@odata.type"`
			Name         string  `json:"name"`
			ContentType  string  `json:"contentType"`
			ContentBytes *string `json:"contentBytes"`
		} `json:"attachments"`
	} `json:"message"`
	SaveToSentItems *bool `json:"saveToSentItems"`
}

func addresses(list []recipient) (out []string) {
	for _, r := range list {
		out = append(out, r.EmailAddress.Address)
	}
	return out
}

func (s *Server) sendMail(w http.ResponseWriter, r *http.Request) {
	// The body is read in full before any response: closing a connection with
	// unread bytes makes the client lose the response on Linux.
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return
	}
	var in sendMailRequest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	decodeErr := dec.Decode(&in)
	withFiles := len(in.Message.Attachments) > 0

	s.mu.Lock()
	s.calls++
	s.inFlight++
	s.maxInFlight = max(s.maxInFlight, s.inFlight)
	if withFiles {
		s.filesInFlight++
		s.maxWithFiles = max(s.maxWithFiles, s.filesInFlight)
	}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.inFlight--
		if withFiles {
			s.filesInFlight--
		}
		s.mu.Unlock()
	}()
	if !s.wait(r) {
		return
	}

	// Without the parameter, Graph keeps a copy in sent items.
	mail := Mail{
		To: addresses(in.Message.ToRecipients), ReplyTo: addresses(in.Message.ReplyTo),
		Subject: in.Message.Subject, HTML: in.Message.Body.Content,
		Saved: in.SaveToSentItems == nil || *in.SaveToSentItems,
	}
	for _, a := range in.Message.Attachments {
		if a.Type != "#microsoft.graph.fileAttachment" || a.ContentBytes == nil {
			s.t.Errorf("sendMail : pièce jointe %q de type %q, contenu présent=%v", a.Name, a.Type, a.ContentBytes != nil)
			continue
		}
		data, err := base64.StdEncoding.DecodeString(*a.ContentBytes)
		if err != nil {
			s.t.Errorf("sendMail : pièce jointe %q : base64 invalide : %v", a.Name, err)
		}
		mail.Attachments = append(mail.Attachments, Attachment{Name: a.Name, ContentType: a.ContentType, Data: data})
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch {
	case s.sendRedirect != "":
		http.Redirect(w, r, s.sendRedirect, http.StatusTemporaryRedirect)
		return
	case s.rejectTokens || s.valid == "" || r.Header.Get("Authorization") != "Bearer "+s.valid:
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":{"code":"InvalidAuthenticationToken","message":"Lifetime validation failed, the token is expired."}}`)
		return
	case s.sendRefusal != nil:
		if s.sendRefusal.retryAfter != "" {
			w.Header().Set("Retry-After", s.sendRefusal.retryAfter)
		}
		w.WriteHeader(s.sendRefusal.status)
		// nosemgrep: go.lang.security.audit.xss.no-io-writestring-to-responsewriter.no-io-writestring-to-responsewriter -- test fake, the body is JSON set by the test
		_, _ = io.WriteString(w, s.sendRefusal.body)
		return
	case len(raw) > maxRequest:
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	case decodeErr != nil:
		s.t.Errorf("sendMail : corps JSON refusé : %v", decodeErr)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":{"code":"BadRequest","message":"Unable to read JSON request payload."}}`)
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != "application/json" {
		s.t.Errorf("sendMail : Content-Type %q", ct)
	}
	if in.Message.Body.ContentType != "HTML" {
		s.t.Errorf("sendMail : corps de type %q, HTML attendu", in.Message.Body.ContentType)
	}
	s.mails = append(s.mails, mail)
	w.WriteHeader(http.StatusAccepted)
}
