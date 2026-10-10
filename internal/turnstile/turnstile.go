// Package turnstile verifies Cloudflare Turnstile tokens against the siteverify API.
// It keeps bots off the login form.
package turnstile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const DefaultEndpoint = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

const FormField = "cf-turnstile-response"

// Cloudflare caps tokens at 2048 bytes.
const maxTokenLen = 2048

// ErrRejected means Cloudflare answered but refused the token (missing, expired, replayed or forged).
// It is distinct from a transport error, so a bot can be told apart from an unreachable Cloudflare.
var ErrRejected = errors.New("turnstile: token rejected")

type Verifier struct {
	secret   string
	endpoint string
	client   *http.Client
}

// A short timeout keeps a slow Cloudflare from holding the login handler.
func New(secret string) *Verifier {
	return &Verifier{
		secret:   secret,
		endpoint: DefaultEndpoint,
		client:   &http.Client{Timeout: 5 * time.Second},
	}
}

func (v *Verifier) WithEndpoint(u string) *Verifier {
	v.endpoint = u
	return v
}

type siteverifyResponse struct {
	Success    bool     `json:"success"`
	ErrorCodes []string `json:"error-codes"`
}

// Verify returns nil if Cloudflare accepts the token, ErrRejected if it refuses it, and another
// error if the API is unreachable or returns garbage. An empty token is refused without a call.
func (v *Verifier) Verify(ctx context.Context, token, remoteIP string) error {
	token = strings.TrimSpace(token)
	if token == "" || len(token) > maxTokenLen {
		return ErrRejected
	}
	form := url.Values{"secret": {v.secret}, "response": {token}}
	if remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("turnstile: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("turnstile: siteverify: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("turnstile: siteverify: status %d", resp.StatusCode)
	}
	var out siteverifyResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out); err != nil {
		return fmt.Errorf("turnstile: siteverify: decode: %w", err)
	}
	if !out.Success {
		return fmt.Errorf("%w (%s)", ErrRejected, strings.Join(out.ErrorCodes, ","))
	}
	return nil
}
