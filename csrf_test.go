package goauth

import "testing"

func TestVerifyCSRF(t *testing.T) {
	const secret = "test-secret"
	const token = "random-token"
	cookie := token + "|" + signValue(token, secret)

	tests := []struct {
		name      string
		cookie    string
		body      string
		wantValid bool
	}{
		{name: "valid cookie and body", cookie: cookie, body: token, wantValid: true},
		{name: "body token mismatch", cookie: cookie, body: "other-token", wantValid: false},
		{name: "missing body token", cookie: cookie, body: "", wantValid: false},
		{name: "tampered signature", cookie: token + "|deadbeef", body: token, wantValid: false},
		{name: "malformed cookie", cookie: "no-separator", body: token, wantValid: false},
		{name: "empty cookie", cookie: "", body: token, wantValid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid := verifyCSRF(tt.cookie, tt.body, secret)
			if valid != tt.wantValid {
				t.Errorf("verifyCSRF(%q, %q) valid = %v, want %v", tt.cookie, tt.body, valid, tt.wantValid)
			}
		})
	}
}

func TestPasswordHashRoundTrip(t *testing.T) {
	hash, err := HashPassword("s3cret-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !CheckPassword(hash, "s3cret-password") {
		t.Error("CheckPassword rejected the correct password")
	}
	if CheckPassword(hash, "wrong-password") {
		t.Error("CheckPassword accepted a wrong password")
	}
	if CheckPassword("not-a-hash", "s3cret-password") {
		t.Error("CheckPassword accepted a malformed hash")
	}
}

// Stored hashes were produced by a hand-rolled PBKDF2; the stdlib
// crypto/pbkdf2 replacement must stay byte-compatible with them.
func TestPasswordHashKnownVector(t *testing.T) {
	// PBKDF2-HMAC-SHA256("password", "salt", 4096, 32).
	const hash = "$pbkdf2-sha256$4096$c2FsdA$xeR41ZKIyEGqUw22hFxMjZYok6ABzk4RpJY4c6qYE0o"
	if !CheckPassword(hash, "password") {
		t.Error("CheckPassword rejected a known-good PBKDF2 vector")
	}
}
