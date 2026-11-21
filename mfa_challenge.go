package goauth

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

// mfaChallengeSigPrefix separates challenge signatures from the other values
// signed with JWTSecret (CSRF and connect-intent cookies), so a value signed
// for one purpose can never be replayed as an MFA challenge.
const mfaChallengeSigPrefix = "goauth.mfa.v1."

// mfaChallenge binds a pending MFA step to the identity that already passed
// the first factor. It is signed with JWTSecret and carried as mfa_token.
type mfaChallenge struct {
	UserID   string   `json:"uid"`
	Method   string   `json:"m"`
	Redirect string   `json:"r,omitempty"`
	Exp      int64    `json:"exp"`
	Account  *Account `json:"a,omitempty"`
}

func (c mfaChallenge) payload() (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (a *Authorization) encodeMFAChallenge(c mfaChallenge) (string, error) {
	if a == nil || a.JWTSecret == "" {
		return "", errors.New("JWTSecret is required")
	}
	if c.UserID == "" {
		return "", errors.New("user id required")
	}
	if c.Exp == 0 {
		c.Exp = time.Now().UTC().Add(mfaChallengeTTL).Unix()
	}
	p, err := c.payload()
	if err != nil {
		return "", err
	}
	return p + "." + signValue(mfaChallengeSigPrefix+p, a.JWTSecret), nil
}

func (a *Authorization) decodeMFAChallenge(token string) (mfaChallenge, error) {
	p, sig, ok := strings.Cut(token, ".")
	if !ok || p == "" || sig == "" {
		return mfaChallenge{}, errMFAInvalid
	}
	if subtle.ConstantTimeCompare([]byte(sig), []byte(signValue(mfaChallengeSigPrefix+p, a.JWTSecret))) != 1 {
		return mfaChallenge{}, errMFAInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil {
		return mfaChallenge{}, errMFAInvalid
	}
	var c mfaChallenge
	if err := json.Unmarshal(raw, &c); err != nil || c.UserID == "" {
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
