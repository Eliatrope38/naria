package auth

import "github.com/alexedwards/argon2id"

// Fixed profile (OWASP recommendations) rather than argon2id.DefaultParams, which may change with the library.
// The parameters are stored in each hash, so existing hashes stay verifiable.
var argon2idParams = &argon2id.Params{
	Memory:      64 * 1024, // 64 MiB
	Iterations:  2,
	Parallelism: 2,
	SaltLength:  16,
	KeyLength:   32,
}

func HashPassword(plain string) (string, error) {
	return argon2id.CreateHash(plain, argon2idParams)
}

func VerifyPassword(plain, hash string) (bool, error) {
	return argon2id.ComparePasswordAndHash(plain, hash)
}

// A real argon2id hash with no associated account, used only by FakeVerify.
const dummyHash = "$argon2id$v=19$m=65536,t=2,p=2$1y/13HLwynz4fYHoWSVBdg$j+vzZSM3sAA3s6+Nbl8G1Gmy0znWXUcN6YUHS4YVic8"

// FakeVerify runs on the login path for unknown or inactive users, so response time no longer reveals
// whether an account exists. The hash is real, so the full argon2 computation runs.
func FakeVerify() {
	_, _ = VerifyPassword("timing-equalizer", dummyHash)
}
