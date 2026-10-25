package goauth

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	passwordSaltBytes    = 16
	passwordKeyBytes     = 32
	passwordIterations   = 600_000
	passwordHashPrefix   = "$pbkdf2-sha256$"
	passwordHashSegments = 3
)

// HashPassword returns a PBKDF2-SHA256 hash of password suitable for database
// storage. The encoded form is self-describing:
//
//	$pbkdf2-sha256$<iterations>$<salt>$<hash>
//
// Salt and hash segments use base64 raw URL encoding (no padding).
func HashPassword(password string) (string, error) {
	salt := make([]byte, passwordSaltBytes)
	_, _ = rand.Read(salt) // never returns an error since Go 1.24
	return encodePasswordHash(passwordIterations, salt, password)
}

// CheckPassword reports whether password matches a hash produced by HashPassword.
func CheckPassword(hash, password string) bool {
	iter, salt, want, err := decodePasswordHash(hash)
	if err != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

func encodePasswordHash(iterations int, salt []byte, password string) (string, error) {
	key, err := pbkdf2.Key(sha256.New, password, salt, iterations, passwordKeyBytes)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	return fmt.Sprintf("%s%d$%s$%s",
		passwordHashPrefix,
		iterations,
		enc.EncodeToString(salt),
		enc.EncodeToString(key),
	), nil
}

func decodePasswordHash(hash string) (iterations int, salt, key []byte, err error) {
	if !strings.HasPrefix(hash, passwordHashPrefix) {
		return 0, nil, nil, errors.New("goauth: unknown password hash format")
	}
	parts := strings.Split(hash[len(passwordHashPrefix):], "$")
	if len(parts) != passwordHashSegments {
		return 0, nil, nil, errors.New("goauth: malformed password hash")
	}
	iterations, err = strconv.Atoi(parts[0])
	if err != nil || iterations <= 0 {
		return 0, nil, nil, errors.New("goauth: invalid password hash iterations")
	}
	enc := base64.RawURLEncoding
	salt, err = enc.DecodeString(parts[1])
	if err != nil {
		return 0, nil, nil, errors.New("goauth: invalid password hash salt")
	}
	key, err = enc.DecodeString(parts[2])
	if err != nil {
		return 0, nil, nil, errors.New("goauth: invalid password hash digest")
	}
	return iterations, salt, key, nil
}
