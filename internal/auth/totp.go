package auth

import (
	"bytes"
	"encoding/base64"
	"image/png"
	"net/url"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

var totpIssuer = "Naria"

func SetTOTPIssuer(name string) {
	if name != "" {
		totpIssuer = name
	}
}

func GenerateTOTP(account string) (*otp.Key, error) {
	return totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuer,
		AccountName: account,
	})
}

func ValidateTOTP(code, secret string) bool {
	return totp.Validate(code, secret)
}

// QRCodeFromSecret rebuilds the QR code from the stored secret, so the key can be shown again without generating a new one.
func QRCodeFromSecret(account, secret string) (string, error) {
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", totpIssuer)
	u := url.URL{Scheme: "otpauth", Host: "totp", Path: "/" + totpIssuer + ":" + account, RawQuery: v.Encode()}
	key, err := otp.NewKeyFromURL(u.String())
	if err != nil {
		return "", err
	}
	return QRCodeDataURI(key)
}

func QRCodeDataURI(key *otp.Key) (string, error) {
	img, err := key.Image(220, 220)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}
