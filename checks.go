package goauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
)

// randomString returns a URL-safe random string with the given number of bytes
// of entropy.
func randomString(n int) string {
	b := make([]byte, n)
	_, _ = io.ReadFull(rand.Reader, b)
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
	for _, c := range p.Checks {
		if c == check {
			return true
		}
	}
	return false
}
