package ui

import "context"

// Shared templates (header, logout form) read the token here instead of receiving it as a parameter.
type csrfCtxKey struct{}

// Call before Component.Render (see renderPage).
func WithCSRF(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, csrfCtxKey{}, token)
}

// Empty string if the token is absent.
func csrfToken(ctx context.Context) string {
	tok, _ := ctx.Value(csrfCtxKey{}).(string)
	return tok
}
