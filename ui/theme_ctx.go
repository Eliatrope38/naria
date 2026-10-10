package ui

import "context"

type themeCtxKey struct{}

// mode is "dark", "light", or empty when no choice is stored.
func WithTheme(ctx context.Context, mode string) context.Context {
	return context.WithValue(ctx, themeCtxKey{}, mode)
}

// data-theme value. When empty, the script in <head> follows prefers-color-scheme.
func ThemeAttr(ctx context.Context) string {
	if m, ok := ctx.Value(themeCtxKey{}).(string); ok && (m == "dark" || m == "light") {
		return m
	}
	return ""
}

// Opposite of the current theme. Without a stored choice, the link offers "dark".
func themeToggleTarget(ctx context.Context) string {
	if ThemeAttr(ctx) == "dark" {
		return "light"
	}
	return "dark"
}
