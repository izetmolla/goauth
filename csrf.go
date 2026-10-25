package goauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"
)

// CSRF protection uses the signed double-submit cookie pattern from Auth.js: the
// cookie stores "<token>|<hmac>" where hmac = HMAC-SHA256(token + secret). The
// same raw token must be echoed in the request body for unsafe (POST) actions.

// signValue returns the hex HMAC-SHA256 used to sign cookie values (CSRF
// token, flow intent). The value+secret message layout matches Auth.js and
// must not change, or previously issued cookies stop verifying.
func signValue(value, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(value + secret))
	return hex.EncodeToString(mac.Sum(nil))
}

// verifyCSRF reports whether the signed cookie is authentic and the submitted
// body token matches it. An empty body token never validates.
func verifyCSRF(cookieValue, bodyToken, secret string) bool {
	token, sig, ok := strings.Cut(cookieValue, "|")
	return ok && bodyToken != "" &&
		subtle.ConstantTimeCompare([]byte(sig), []byte(signValue(token, secret))) == 1 &&
		subtle.ConstantTimeCompare([]byte(bodyToken), []byte(token)) == 1
}
