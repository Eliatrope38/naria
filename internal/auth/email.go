package auth

import "strings"

// NormalizeEmail trims and lowercases an address. The users.email column is case-sensitive, so normalize before storing or looking up.
func NormalizeEmail(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
