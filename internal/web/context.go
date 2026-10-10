package web

import (
	"context"

	"gitlab.com/detag_inno/naria/internal/database"
)

type ctxKey int

const userCtxKey ctxKey = iota

func WithUser(ctx context.Context, u *database.User) context.Context {
	return context.WithValue(ctx, userCtxKey, u)
}

// UserFrom returns nil if the request is not authenticated.
func UserFrom(ctx context.Context) *database.User {
	u, _ := ctx.Value(userCtxKey).(*database.User)
	return u
}
