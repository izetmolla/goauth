package goauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"time"
)

// mfaChallengeKeyLabel derives the challenge encryption key from JWTSecret.
// The label keeps it distinct from every other value derived from the
// secret, so nothing signed or encrypted for another purpose can be replayed
// as an MFA challenge.
const mfaChallengeKeyLabel = "goauth.mfa.challenge.v2"

// mfaChallenge binds a pending MFA step to the identity that already passed
// the first factor. It is encrypted and authenticated with AES-GCM and carried
// as mfa_token. Encryption matters: Account can hold the OAuth provider's
// access and refresh tokens, which must not be readable by the browser.
type mfaChallenge struct {
	UserID   string   `json:"uid"`
	Method   string   `json:"m"`
	Redirect string   `json:"r,omitempty"`
	Exp      int64    `json:"exp"`
	Account  *Account `json:"a,omitempty"`
}

// mfaChallengeAEAD returns the AES-256-GCM cipher for challenges.
func (a *Authorization) mfaChallengeAEAD() (cipher.AEAD, error) {
	if a == nil || a.JWTSecret == "" {
		return nil, errors.New("JWTSecret is required")
	}
	mac := hmac.New(sha256.New, []byte(a.JWTSecret))
	mac.Write([]byte(mfaChallengeKeyLabel))
	block, err := aes.NewCipher(mac.Sum(nil))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// encodeMFAChallenge seals c into an opaque, URL-safe token.
func (a *Authorization) encodeMFAChallenge(c mfaChallenge) (string, error) {
	if c.UserID == "" {
		return "", errors.New("user id required")
	}
	if c.Exp == 0 {
		c.Exp = time.Now().UTC().Add(mfaChallengeTTL).Unix()
	}
	aead, err := a.mfaChallengeAEAD()
	if err != nil {
		return "", err
	}
	plain, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	_, _ = rand.Read(nonce) // never fails since Go 1.24
	return base64.RawURLEncoding.EncodeToString(aead.Seal(nonce, nonce, plain, nil)), nil
}

// decodeMFAChallenge opens a token made by encodeMFAChallenge. Tampered,
// foreign and expired tokens all yield errMFAInvalid.
func (a *Authorization) decodeMFAChallenge(token string) (mfaChallenge, error) {
	aead, err := a.mfaChallengeAEAD()
	if err != nil {
		return mfaChallenge{}, errMFAInvalid
	}
	blob, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(blob) < aead.NonceSize() {
		return mfaChallenge{}, errMFAInvalid
	}
	ns := aead.NonceSize()
	plain, err := aead.Open(nil, blob[:ns], blob[ns:], nil)
	if err != nil {
		return mfaChallenge{}, errMFAInvalid
	}
	var c mfaChallenge
	if err := json.Unmarshal(plain, &c); err != nil || c.UserID == "" {
		return mfaChallenge{}, errMFAInvalid
	}
	if time.Now().UTC().Unix() > c.Exp {
		return mfaChallenge{}, errMFAInvalid
	}
	return c, nil
}

// issueMFAChallenge builds a short-lived token for the MFA verify step.
func (a *Authorization) issueMFAChallenge(userID, method, redirect string, account *Account) (string, error) {
	return a.encodeMFAChallenge(mfaChallenge{
		UserID:   userID,
		Method:   method,
		Redirect: redirect,
		Exp:      time.Now().UTC().Add(mfaChallengeTTL).Unix(),
		Account:  account,
	})
}

// mfaRequiredPayload is the JSON body returned when the first factor succeeded
// but TOTP is still required.
func mfaRequiredPayload(token string) Map {
	return Map{
		"code":    codeMFARequired,
		"message": "Authenticator code required",
		"mfa": Map{
			"methods": []string{"totp"},
			"token":   token,
			"expires": strconv.FormatInt(time.Now().UTC().Add(mfaChallengeTTL).Unix(), 10),
		},
	}
}
