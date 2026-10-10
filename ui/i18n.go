package ui

import (
	"context"

	"gitlab.com/detag_inno/naria/internal/i18n"
)

// Read by the templates, like the CSRF token (see csrf.go).
type localizerCtxKey struct{}

// Call before rendering.
func WithLocalizer(ctx context.Context, loc *i18n.Localizer) context.Context {
	return context.WithValue(ctx, localizerCtxKey{}, loc)
}

// Falls back to French when absent, so templates never panic.
func LocalizerFrom(ctx context.Context) *i18n.Localizer {
	if loc, ok := ctx.Value(localizerCtxKey{}).(*i18n.Localizer); ok && loc != nil {
		return loc
	}
	return i18n.Get(i18n.DefaultLocale)
}

// Called from templ templates, where the context is named ctx.
func T(ctx context.Context, key string, args ...any) string {
	return LocalizerFrom(ctx).T(key, args...)
}

// Language code for the lang attribute of <html>.
func Lang(ctx context.Context) string {
	return LocalizerFrom(ctx).Lang()
}
