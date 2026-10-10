package auth

import (
	"crypto/rand"
	"strings"
)

// Charset without I, O, 0 or 1. Its length of 32 avoids modulo bias.
const bcCharset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func GenerateBackupCodes(n int) ([]string, error) {
	codes := make([]string, 0, n)
	for i := 0; i < n; i++ {
		buf := make([]byte, 10)
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		var sb strings.Builder
		for j, b := range buf {
			if j == 5 {
				sb.WriteByte('-')
			}
			sb.WriteByte(bcCharset[int(b)%len(bcCharset)])
		}
		codes = append(codes, sb.String())
	}
	return codes, nil
}

// CanonicalCode returns the typo-tolerant form of a code, to apply before hashing or comparing.
func CanonicalCode(s string) string {
	var sb strings.Builder
	for _, r := range strings.ToUpper(s) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}
