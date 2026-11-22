package goauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"slices"

	"github.com/golang-jwt/jwt/v5"
)

// randomString returns a URL-safe random string with the given number of bytes
// of entropy.
func randomString(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b) // never returns an error since Go 1.24
	return base64.RawURLEncoding.EncodeToString(b)
}

// pkceChallenge derives the S256 code challenge for a verifier, per RFC 7636.
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// providerUsesCheck reports whether an OAuth provider requested a given check.
func providerUsesCheck(p *OAuthProvider, check Check) bool {
	if p == nil {
		return false
	}
	return slices.Contains(p.Checks, check)
}

// checkIDTokenNonce verifies that the ID token returned with the tokens
// carries the nonce sent in the authorization request. The token comes
// straight from the token endpoint over TLS, so its payload is read without
// checking the signature (OpenID Connect Core 3.1.3.7). Providers that return
// no ID token are skipped: the nonce only protects ID tokens.
func checkIDTokenNonce(idToken, expected string) error {
	if idToken == "" {
		return nil
	}
	if expected == "" {
		return errors.New("missing nonce cookie; start the sign-in again")
	}
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(idToken, claims); err != nil {
		return errors.New("invalid ID token")
	}
	got, _ := claims["nonce"].(string)
	if subtle.ConstantTimeCompare([]byte(got), []byte(expected)) != 1 {
		return errors.New("ID token nonce does not match")
	}
	return nil
}
