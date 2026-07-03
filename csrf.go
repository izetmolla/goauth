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

func csrfHash(token, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(token + secret))
	return hex.EncodeToString(mac.Sum(nil))
}

// verifyCSRF validates the signed cookie and that the submitted body token
// matches. It returns the canonical token and whether validation passed.
func verifyCSRF(cookieValue, bodyToken, secret string) (token string, valid bool) {
	parts := strings.SplitN(cookieValue, "|", 2)
	if len(parts) != 2 {
		return "", false
	}
	token = parts[0]
	expected := csrfHash(token, secret)
	if subtle.ConstantTimeCompare([]byte(parts[1]), []byte(expected)) != 1 {
		return token, false
	}
	if bodyToken == "" {
		// Cookie is valid but no body token was submitted (e.g. a GET to fetch
		// the token). Callers decide whether that's acceptable.
		return token, false
	}
	if subtle.ConstantTimeCompare([]byte(bodyToken), []byte(token)) != 1 {
		return token, false
	}
	return token, true
}
